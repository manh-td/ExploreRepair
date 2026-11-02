import argparse
import json
import os
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from threading import Lock

from src.harnesses.code_knowledge_graph import repo_cache
from src.harnesses.code_knowledge_graph.coedit import add_co_edit
from src.harnesses.code_knowledge_graph.extract import EXTENSIONS, build_graph
from src.harnesses.code_knowledge_graph.validate import dangling_edges, vul_func_coverage
from src.harnesses.dataset import ALL_PATCHEVAL_CVES_WITH_UNIT_TEST_PATH, load_cve_record
from src.harnesses.results import WORKSPACE_ROOT

GRAPHS_DIR = Path(os.environ.get("CKG_GRAPHS_DIR", WORKSPACE_ROOT / "graphs"))
SUMMARY_PATH = GRAPHS_DIR / "build_summary.jsonl"
MARKER = "build_ok.json"


def graph_dir(cve_id: str) -> Path:
    return GRAPHS_DIR / cve_id


def graph_path(cve_id: str) -> Path:
    return graph_dir(cve_id) / "graph.json"


def is_cached(cve_id: str) -> bool:
    return (graph_dir(cve_id) / MARKER).is_file() and graph_path(cve_id).is_file()


def load(cve_id: str) -> dict:
    return json.loads(graph_path(cve_id).read_text())


def _write(cve_id: str, graph: dict, marker: dict) -> None:
    target = graph_dir(cve_id)
    target.mkdir(parents=True, exist_ok=True)
    tmp = target / "graph.json.tmp"
    with open(tmp, "w") as f:
        json.dump(graph, f)
    tmp.replace(graph_path(cve_id))
    (target / MARKER).write_text(json.dumps(marker, indent=2))


def build_one(cve_id: str, no_co_edit: bool = False, force: bool = False) -> dict:
    t0 = time.monotonic()
    try:
        if is_cached(cve_id) and not force:
            return {"cve_id": cve_id, "status": "cached", "duration_s": 0.0}

        record = load_cve_record(cve_id)
        language = record["programming_language"]
        if language not in EXTENSIONS:
            return {"cve_id": cve_id, "status": "unsupported_language", "language": language,
                    "duration_s": round(time.monotonic() - t0, 1)}

        with repo_cache.checkout_any(cve_id) as (path, sha, source):
            graph = build_graph(path, language)
            has_history = (path / ".git").exists()
            if not no_co_edit and has_history:
                add_co_edit(graph, path, sha)

        graph["cve_id"] = cve_id
        graph["commit"] = sha
        graph["source"] = source
        graph["repo"] = record["repo"]
        graph.pop("root", None)

        coverage = vul_func_coverage(graph, record)
        dangling = dangling_edges(graph)
        row = {
            "cve_id": cve_id,
            "status": "ok",
            "language": language,
            "commit": sha,
            "source": source,
            "nodes": len(graph["nodes"]),
            "edges": len(graph["edges"]),
            **graph["stats"],
            **coverage,
            "dangling_edges": len(dangling),
            "duration_s": round(time.monotonic() - t0, 1),
        }
        _write(cve_id, graph, row)
        return row
    except repo_cache.RepoError as e:
        return {"cve_id": cve_id, "status": "repo_error", "error": str(e),
                "duration_s": round(time.monotonic() - t0, 1)}
    except Exception as e:
        return {"cve_id": cve_id, "status": "error", "error": repr(e),
                "traceback": traceback.format_exc(), "duration_s": round(time.monotonic() - t0, 1)}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cve", action="append")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--language", action="append", choices=sorted(EXTENSIONS))
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--no-co-edit", action="store_true")
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
            print(f"{cve_id}\t{load_cve_record(cve_id)['programming_language']}\t{load_cve_record(cve_id)['repo']}")
        print(f"\n{len(pending)} to build, {skipped} already cached")
        return

    print(f"building {len(pending)} graph(s) with {args.workers} worker(s) "
          f"({skipped} already cached) -> {GRAPHS_DIR}/")
    if not pending:
        return

    SUMMARY_PATH.parent.mkdir(parents=True, exist_ok=True)
    lock = Lock()
    start = time.monotonic()
    counts: dict[str, int] = {}
    incomplete = []
    with open(SUMMARY_PATH, "a") as f_out, ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(build_one, c, args.no_co_edit, args.force): c for c in pending}
        for i, future in enumerate(as_completed(futures), 1):
            row = future.result()
            counts[row["status"]] = counts.get(row["status"], 0) + 1
            if row.get("vul_missing"):
                incomplete.append(row["cve_id"])
            with lock:
                f_out.write(json.dumps(row) + "\n")
                f_out.flush()
            detail = ""
            if row["status"] == "ok":
                detail = (f" {row['nodes']}n/{row['edges']}e "
                          f"vul {row['vul_syms_found']}/{row['vul_locations']}")
            print(f"  [{i}/{len(pending)}] {row['cve_id']}: {row['status']}{detail} ({row['duration_s']}s)",
                  flush=True)

    print(f"\ndone in {(time.monotonic() - start) / 60:.1f}m: {counts}")
    if incomplete:
        print(f"{len(incomplete)} graph(s) missing a vulnerable location: {' '.join(incomplete)}")
    print(f"summary: {SUMMARY_PATH}")


if __name__ == "__main__":
    main()
