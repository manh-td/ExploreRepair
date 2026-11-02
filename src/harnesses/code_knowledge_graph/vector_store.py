from datetime import datetime
from pathlib import Path
from typing import Optional

UNKNOWN_CREATED_AT_TS = 9_999_999_999.0


def created_at_timestamp(created_at: Optional[str]) -> float:
    if not created_at:
        return UNKNOWN_CREATED_AT_TS
    return datetime.fromisoformat(created_at.replace("Z", "+00:00")).timestamp()


def get_collection(db_path: Path, collection_name: str, description: str = ""):
    import chromadb
    from chromadb.config import Settings

    db_path.mkdir(parents=True, exist_ok=True)
    client = chromadb.PersistentClient(path=str(db_path), settings=Settings(anonymized_telemetry=False))
    return client.get_or_create_collection(name=collection_name, metadata={"description": description})
