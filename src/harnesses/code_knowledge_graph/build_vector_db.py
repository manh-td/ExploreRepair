import argparse
import json
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from threading import Lock

from src.harnesses.code_knowledge_graph import build_graphs, repo_cache
from src.harnesses.code_knowledge_graph.embedder import DEFAULT_MODEL_PATH, BGEEmbedder
from src.harnesses.code_knowledge_graph.vector_store import get_collection
from src.harnesses.dataset import ALL_PATCHEVAL_CVES_WITH_UNIT_TEST_PATH, load_cve_record

COLLECTION_NAME = "code_graph_nodes"
SUMMARY_PATH = build_graphs.GRAPHS_DIR / "vector_db_summary.jsonl"
MARKER = "vector_db_ok.json"

MAX_CHARS = 4000
FILE_HEAD_CHARS = 1200


def db_dir(cve_id: str) -> Path:
    return build_graphs.graph_dir(cve_id) / "vec_DB"


def is_cached(cve_id: str) -> bool:
    return (build_graphs.graph_dir(cve_id) / MARKER).is_file()


def node_texts(graph: dict, root: Path) -> tuple[list[str], list[str], list[dict]]:
    sources: dict[str, str] = {}
    syms_by_path: dict[str, list[dict]] = {}
    for node in graph["nodes"]:
        if node["kind"] == "sym":
            syms_by_path.setdefault(node["path"], []).append(node)

    ids, texts, metadatas = [], [], []
    for node in graph["nodes"]:
        path = node["path"]
        if path not in sources:
            target = root / path
            sources[path] = target.read_text(errors="replace") if target.is_file() else ""
        source = sources[path]
        if not source:
            continue

        if node["kind"] == "file":
            names = ", ".join(sorted(s["name"] for s in syms_by_path.get(path, []))[:60])
            body = f"file: {path}\nsymbols: {names}\n\n{source[:FILE_HEAD_CHARS]}"
            metadata = {"kind": "file", "path": path}
        else:
            body = f"{path}::{node['qual']}\n\n" + source.encode(errors="replace")[
                node["start_byte"]:node["end_byte"]
            ].decode(errors="replace")
            metadata = {
                "kind": "sym", "path": path, "qual": node["qual"], "name": node["name"],
                "start_line": node["start_line"], "end_line": node["end_line"],
            }
        ids.append(node["id"])
        texts.append(body[:MAX_CHARS])
        metadatas.append(metadata)
    return ids, texts, metadatas


def build_one(cve_id: str, embedder: BGEEmbedder, batch_size: int = 64, force: bool = False) -> dict:
    t0 = time.monotonic()
    try:
        if is_cached(cve_id) and not force:
            return {"cve_id": cve_id, "status": "cached", "duration_s": 0.0}
        if not build_graphs.is_cached(cve_id):
            return {"cve_id": cve_id, "status": "no_graph", "duration_s": 0.0}

        graph = build_graphs.load(cve_id)
        with repo_cache.checkout_any(cve_id) as (root, sha, source):
            ids, texts, metadatas = node_texts(graph, root)

        if not ids:
            return {"cve_id": cve_id, "status": "no_text", "duration_s": round(time.monotonic() - t0, 1)}

        vectors = embedder.encode(texts, batch_size=batch_size)
        target = db_dir(cve_id)
        collection = get_collection(target, COLLECTION_NAME, description=f"code graph nodes for {cve_id}")
        for start in range(0, len(ids), 2000):
            stop = start + 2000
            collection.upsert(
                ids=ids[start:stop],
                embeddings=vectors[start:stop],
                documents=texts[start:stop],
                metadatas=metadatas[start:stop],
            )

        row = {
            "cve_id": cve_id,
            "status": "ok",
            "language": graph["language"],
            "source": source,
            "embedded": len(ids),
            "nodes": len(graph["nodes"]),
            "dimension": embedder.dimension,
            "duration_s": round(time.monotonic() - t0, 1),
        }
        (build_graphs.graph_dir(cve_id) / MARKER).write_text(json.dumps(row, indent=2))
        return row
    except Exception as e:
        return {"cve_id": cve_id, "status": "error", "error": repr(e),
                "traceback": traceback.format_exc(), "duration_s": round(time.monotonic() - t0, 1)}


def query(cve_id: str, text: str, embedder: BGEEmbedder, k: int = 5) -> list[dict]:
    collection = get_collection(db_dir(cve_id), COLLECTION_NAME)
    vector = embedder.encode([text])[0]
    result = collection.query(query_embeddings=[vector], n_results=k)
    return [
        {"id": node_id, "distance": distance, **metadata}
        for node_id, distance, metadata in zip(result["ids"][0], result["distances"][0], result["metadatas"][0])
    ]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cve", action="append")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--language", action="append")
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--batch-size", type=int, default=64)
    parser.add_argument("--device", default=None, help="cpu, mps or cuda (default: auto)")
    parser.add_argument("--model", default=str(DEFAULT_MODEL_PATH))
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args()

    if args.all:
        cve_ids = [c.strip() for c in ALL_PATCHEVAL_CVES_WITH_UNIT_TEST_PATH.read_text().splitlines() if c.strip()]
    elif args.cve:
        cve_ids = args.cve
    else:
        parser.error("pass --cve or --all")

    if args.language:
        wanted = set(args.language)
        cve_ids = [c for c in cve_ids if load_cve_record(c)["programming_language"] in wanted]

    pending = cve_ids if args.force else [c for c in cve_ids if not is_cached(c)]
    skipped = len(cve_ids) - len(pending)
    if args.limit:
        pending = pending[: args.limit]

    if args.list:
        for cve_id in pending:
            print(cve_id)
        print(f"\n{len(pending)} to embed, {skipped} already built")
        return

    print(f"embedding {len(pending)} CVE(s) ({skipped} already built) -> {build_graphs.GRAPHS_DIR}/<CVE>/vec_DB")
    if not pending:
        return

    device = args.device
    if device is None:
        try:
            import torch

            device = "cuda" if torch.cuda.is_available() else ("mps" if torch.backends.mps.is_available() else "cpu")
        except ImportError:
            device = "cpu"
    embedder = BGEEmbedder(model_path=args.model, device=device)

    SUMMARY_PATH.parent.mkdir(parents=True, exist_ok=True)
    lock = Lock()
    start = time.monotonic()
    counts: dict[str, int] = {}
    with open(SUMMARY_PATH, "a") as f_out, ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(build_one, c, embedder, args.batch_size, args.force): c for c in pending}
        for i, future in enumerate(as_completed(futures), 1):
            row = future.result()
            counts[row["status"]] = counts.get(row["status"], 0) + 1
            with lock:
                f_out.write(json.dumps(row) + "\n")
                f_out.flush()
            detail = f" {row['embedded']} nodes" if row["status"] == "ok" else ""
            print(f"  [{i}/{len(pending)}] {row['cve_id']}: {row['status']}{detail} ({row['duration_s']}s)", flush=True)

    print(f"\ndone in {(time.monotonic() - start) / 60:.1f}m: {counts}")
    print(f"summary: {SUMMARY_PATH}")


if __name__ == "__main__":
    main()
