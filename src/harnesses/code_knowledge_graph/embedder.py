import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_MODEL_PATH = Path(os.environ.get("EMBEDDING_MODEL_DIR", REPO_ROOT / "models" / "bge-large-en-v1.5")).resolve()


class BGEEmbedder:
    @staticmethod
    def _resolve_device(preferred_device: str | None) -> str:
        if preferred_device == "cuda" or preferred_device is None:
            try:
                import torch

                return "cuda" if torch.cuda.is_available() else "cpu"
            except ImportError:
                return "cpu"
        return preferred_device

    def __init__(self, model_path: str | Path = DEFAULT_MODEL_PATH, device: str | None = "cpu"):
        self.model_path = Path(model_path)
        if not self.model_path.exists():
            raise FileNotFoundError(f"Model path does not exist: {self.model_path}")

        try:
            from sentence_transformers import SentenceTransformer
        except ImportError:
            raise ImportError("Please install sentence-transformers library first: pip install sentence-transformers")

        final_device = self._resolve_device(device)
        logger.info(f"Loading BGE model: {self.model_path} on device: {final_device}")

        try:
            self.model = SentenceTransformer(str(self.model_path), device=final_device)
            self.device = final_device
        except RuntimeError as e:
            if "cuda" in str(e).lower() or "out of memory" in str(e).lower():
                logger.warning(f"GPU loading failed ({e}), falling back to CPU")
                self.model = SentenceTransformer(str(self.model_path), device="cpu")
                self.device = "cpu"
            else:
                raise

        get_dimension = getattr(self.model, "get_embedding_dimension", self.model.get_sentence_embedding_dimension)
        self.dimension = get_dimension()
        logger.info(f"Model loaded, vector dimension: {self.dimension}, device: {self.device}")

    def encode(
        self, texts: str | list[str], batch_size: int = 32, show_progress: bool = False, normalize: bool = True
    ) -> list[list[float]]:
        if isinstance(texts, str):
            texts = [texts]

        current_batch_size = batch_size
        while current_batch_size > 0:
            try:
                embeddings = self.model.encode(
                    texts, batch_size=current_batch_size, show_progress_bar=show_progress, normalize_embeddings=normalize
                )
                return embeddings.tolist()
            except RuntimeError as e:
                if "out of memory" in str(e).lower() or "cuda" in str(e).lower():
                    previous_batch_size = current_batch_size
                    current_batch_size = max(1, current_batch_size // 2)
                    logger.warning(f"Insufficient memory, batch_size reduced from {previous_batch_size} to {current_batch_size}")
                    continue
                raise

        logger.error("Cannot encode text: still insufficient memory even with batch_size=1, retrying on CPU")
        self.model.to("cpu")
        self.device = "cpu"
        return self.model.encode(texts, batch_size=1, show_progress_bar=show_progress, normalize_embeddings=normalize).tolist()

    def encode_single(self, text: str, normalize: bool = True) -> list[float]:
        return self.encode([text], normalize=normalize)[0]
