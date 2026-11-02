import argparse
import hashlib
import json
import shutil
import subprocess
import threading
import time
import traceback
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

from src.harnesses.results import artifacts_dir

from src.benchmarks.vulnlocplus.images import image_for, repo_path
from src.benchmarks.vulnlocplus.loading import project_for
from src.benchmarks.vulnlocplus.locations import working_set
from src.harnesses.batch import append_summary
from src.harnesses.code_knowledge_graph import build_graphs, build_vector_db
from src.harnesses.code_knowledge_graph.extract import build_graph
from src.harnesses.code_knowledge_graph.vector_store import get_collection

LANGUAGE = "C"
TREES_DIR = Path("repos/vulnlocplus")
RESULTS_DIR = artifacts_dir("vulnlocplus") / "graphs"
DOCKER_TIMEOUT_S = 1800.0
DEFAULT_GRAPH_WORKERS = 8
EMBED_BATCH = 128
UPSERT_CHUNK = 2000
PROGRESS_CHUNK = 4096
HEARTBEAT_S = 60.0


def graph_key(cve_id: str) -> str:
    return f"vulnlocplus/{cve_id}"


def export_tree(cve_id: str) -> tuple[Path, str]:
    target = TREES_DIR / cve_id
    image = image_for(cve_id)
    sha = subprocess.run(["docker", "run", "--rm", image, "git", "-C", repo_path(cve_id), "rev-parse", "HEAD"],
                         capture_output=True, text=True, timeout=DOCKER_TIMEOUT_S).stdout.strip()
    if target.is_dir():
        return target, sha
    container = f"vulnlocplus-graph-{cve_id.lower()}"
    subprocess.run(["docker", "rm", "-f", container], capture_output=True, timeout=DOCKER_TIMEOUT_S)
    subprocess.run(["docker", "create", "--name", container, image], check=True, capture_output=True,
                   timeout=DOCKER_TIMEOUT_S)
    try:
        partial = target.with_name(f"{cve_id}.partial")
        shutil.rmtree(partial, ignore_errors=True)
        partial.mkdir(parents=True)
        top = Path(repo_path(cve_id)).name
        subprocess.run(["bash", "-c", f"docker cp {container}:{repo_path(cve_id)} - | "
                                      f"tar -x -C {partial} --strip-components=1 --exclude='{top}/.git'"],
                       check=True, capture_output=True, timeout=DOCKER_TIMEOUT_S)
        partial.rename(target)
    finally:
        subprocess.run(["docker", "rm", "-f", container], capture_output=True, timeout=DOCKER_TIMEOUT_S)
    return target, sha


def graph_one(cve_id: str, force: bool = False) -> dict:
    key = graph_key(cve_id)
    row = {"cve_id": cve_id, "key": key, "phase": "graph", "status": "error"}
    t0 = time.monotonic()
    try:
        if build_graphs.is_cached(key) and not force:
            row["status"] = "cached"
            return row
        root, sha = export_tree(cve_id)
        graph = build_graph(root, LANGUAGE)
        graph.update(commit=sha, source="image")
        build_graphs._write(key, graph, {"cve_id": cve_id, "commit": sha, "source": "image", **graph["stats"]})
        row.update(status="ok", commit=sha, **graph["stats"])
        return row
    except Exception as exc:
        row.update(error=repr(exc), traceback=traceback.format_exc())
        return row
    finally:
        row["duration_s"] = round(time.monotonic() - t0, 1)


def build_all_graphs(cve_ids: list[str], workers: int, force: bool, progress: dict) -> list[str]:
    progress.update(phase="graphs", done=0, total=len(cve_ids), running=set(cve_ids))
    built = []
    with ProcessPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(graph_one, cve_id, force): cve_id for cve_id in cve_ids}
        for future in as_completed(futures):
            row = future.result()
            progress["done"] += 1
            progress["running"].discard(row["cve_id"])
            append_summary(RESULTS_DIR, row)
            print(f"[graphs {progress['done']}/{len(cve_ids)}] {row['cve_id']:24} {row['status']:7} "
                  f"files={row.get('files')} symbols={row.get('symbols')} {row.get('error', '')} "
                  f"({row['duration_s']}s)", flush=True)
            if row["status"] in ("ok", "cached"):
                built.append(row["cve_id"])
    return built


def encode(embedder, texts: list[str], progress: dict):
    import numpy as np
    progress.update(encoded=0, to_encode=len(texts))
    parts = []
    for start in range(0, len(texts), PROGRESS_CHUNK):
        parts.append(embedder.model.encode(texts[start:start + PROGRESS_CHUNK], batch_size=EMBED_BATCH,
                                           normalize_embeddings=True, convert_to_numpy=True,
                                           show_progress_bar=False).astype(np.float32))
        progress["encoded"] = min(start + PROGRESS_CHUNK, len(texts))
    return np.concatenate(parts) if parts else np.zeros((0, embedder.dimension), dtype=np.float32)


def embed_project(project: str, cve_ids: list[str], embedder, progress: dict) -> list[dict]:
    per_cve, index_of, unique = {}, {}, []
    for cve_id in cve_ids:
        key = graph_key(cve_id)
        ids, texts, metadatas = build_vector_db.node_texts(build_graphs.load(key), TREES_DIR / cve_id)
        rows = []
        for text in texts:
            digest = hashlib.sha256(text.encode("utf-8", "replace")).digest()
            if digest not in index_of:
                index_of[digest] = len(unique)
                unique.append(text)
            rows.append(index_of[digest])
        per_cve[cve_id] = (ids, texts, metadatas, rows)
    total = sum(len(v[0]) for v in per_cve.values())
    progress.update(project=project, cves=len(cve_ids), texts=total)
    vectors = encode(embedder, unique, progress)

    results = []
    for cve_id, (ids, texts, metadatas, rows) in per_cve.items():
        t0 = time.monotonic()
        key = graph_key(cve_id)
        progress["storing"] = cve_id
        collection = get_collection(build_vector_db.db_dir(key), build_vector_db.COLLECTION_NAME,
                                    description=f"code graph nodes for {key}")
        for start in range(0, len(ids), UPSERT_CHUNK):
            stop = start + UPSERT_CHUNK
            collection.upsert(ids=ids[start:stop], embeddings=vectors[rows[start:stop]].tolist(),
                              documents=texts[start:stop], metadatas=metadatas[start:stop])
        marker = {"cve_id": cve_id, "embedded": len(ids), "dimension": embedder.dimension,
                  "device": getattr(embedder, "device", None)}
        (build_graphs.graph_dir(key) / build_vector_db.MARKER).write_text(json.dumps(marker, indent=2))
        results.append({"cve_id": cve_id, "key": key, "phase": "embed", "status": "ok", "embedded": len(ids),
                        "project": project, "project_texts": total, "project_unique": len(unique),
                        "duration_s": round(time.monotonic() - t0, 1)})
    progress.pop("storing", None)
    return results


def embed_all(cve_ids: list[str], embedder, force: bool, progress: dict) -> None:
    pending = [c for c in cve_ids if force or not build_vector_db.is_cached(graph_key(c))]
    by_project = defaultdict(list)
    for cve_id in pending:
        by_project[project_for(cve_id)].append(cve_id)
    progress.update(phase="embed", projects_done=0, projects=len(by_project))
    print(f"embedding {len(pending)} CVE(s) in {len(by_project)} project batch(es); "
          f"{len(cve_ids) - len(pending)} already embedded", flush=True)
    for project, group in sorted(by_project.items(), key=lambda item: len(item[1])):
        try:
            rows = embed_project(project, group, embedder, progress)
        except Exception as exc:
            rows = [{"cve_id": c, "key": graph_key(c), "phase": "embed", "status": "error", "project": project,
                     "error": repr(exc), "traceback": traceback.format_exc()} for c in group]
        progress["projects_done"] += 1
        for row in rows:
            append_summary(RESULTS_DIR, row)
        ok = rows and rows[0]["status"] == "ok"
        print(f"[embed {progress['projects_done']}/{len(by_project)}] {project:10} {len(group)} CVE(s) "
              + (f"{rows[0]['project_texts']} texts, {rows[0]['project_unique']} distinct encoded" if ok
                 else f"error {rows[0].get('error')}"), flush=True)


def heartbeat(progress: dict, stop: threading.Event) -> None:
    while not stop.wait(HEARTBEAT_S):
        elapsed = (time.monotonic() - progress["started"]) / 60
        if progress.get("phase") == "graphs":
            running = sorted(progress.get("running", ()))
            print(f"[{time.strftime('%H:%M:%S')}] HEARTBEAT graphs: {progress['done']}/{progress['total']} done, "
                  f"{len(running)} running ({', '.join(running[:4])}{'...' if len(running) > 4 else ''}), "
                  f"{elapsed:.1f}m total", flush=True)
        elif progress.get("phase") == "embed":
            where = (f"storing {progress['storing']}" if progress.get("storing")
                     else f"encoded {progress.get('encoded', 0)}/{progress.get('to_encode', '?')} distinct")
            print(f"[{time.strftime('%H:%M:%S')}] HEARTBEAT embed: project {progress['projects_done'] + 1}/"
                  f"{progress['projects']} {progress.get('project', '')} ({progress.get('cves', '?')} CVEs, "
                  f"{progress.get('texts', '?')} texts) {where}, {elapsed:.1f}m total", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the C code graphs, then the vector DBs, for the baked VulnLoc+ images.")
    parser.add_argument("--cve", action="append", help="CVE id (repeatable); default every working-set CVE")
    parser.add_argument("--device", default=None, help="torch device for the embedding model, e.g. cuda:1")
    parser.add_argument("--workers", type=int, default=DEFAULT_GRAPH_WORKERS, help="graph-building processes")
    parser.add_argument("--graphs-only", action="store_true", help="stop after phase 1")
    parser.add_argument("--force", action="store_true", help="rebuild graphs and vector DBs that already exist")
    args = parser.parse_args()

    cve_ids = args.cve or working_set()
    progress: dict = {"started": time.monotonic()}
    stop = threading.Event()
    threading.Thread(target=heartbeat, args=(progress, stop), daemon=True).start()
    try:
        built = build_all_graphs(cve_ids, args.workers, args.force, progress)
        if args.graphs_only:
            return
        from src.experiments.reactagent.tools.graph_tools import get_embedder
        embedder = get_embedder(args.device)
        if args.device and args.device.startswith("cuda") and not str(embedder.device).startswith("cuda"):
            raise SystemExit(f"asked for {args.device} but the embedder loaded on {embedder.device}")
        embed_all(built, embedder, args.force, progress)
    finally:
        stop.set()


if __name__ == "__main__":
    main()
