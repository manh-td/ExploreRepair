import argparse
import asyncio
import json
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Optional

from dotenv import load_dotenv

from src.harnesses.dataset import ALL_PATCHEVAL_CVES_WITH_UNIT_TEST_PATH, load_cve_record, repo_dirname
from src.harnesses.results import results_dir
from src.harnesses.batch import append_patch
from src.harnesses.docker import (
    docker_exec,
    get_split_diffs,
    resolve_repo_dirname,
    restore_and_stop,
    sanitize_container,
    start_editable_container,
)
from src.baselines.intentfix.config import DEFAULT_LLM_MODEL
from src.baselines.intentfix.client import create_llm
from src.baselines.intentfix.upstream import load_upstream

load_dotenv()

RESULTS_DIR = results_dir("patcheval", "intentfix")
SUMMARY_PATH = RESULTS_DIR / "run_summary.jsonl"
PROGRESS_LOG_PATH = RESULTS_DIR / "progress.log"
PATCHES_PATH = RESULTS_DIR / "patches.jsonl"

DEFAULT_CVE_IDS = ["CVE-2025-27154", "CVE-2022-23536", "CVE-2021-21360"]

FULL_FILE_LINE_RATIO = 0.6
MERGE_SANITY_LINE_RATIO = 0.85

_MERGE_PROMPT = """You are given the ORIGINAL source file and a SECURITY FIX SNIPPET produced by a \
separate security tool. The snippet is meant to be integrated into the original file at the \
correct location(s) to fix a vulnerability - it is NOT a replacement for the whole file.

Produce the complete, corrected file: the full ORIGINAL file content with the fix from the \
SECURITY FIX SNIPPET integrated at the appropriate place(s). Keep every unrelated line of the \
original file exactly as-is. Do not summarize, truncate, or omit any part of the original file.

ORIGINAL FILE:
```
{original}
```

SECURITY FIX SNIPPET:
```
{snippet}
```

Respond with only the complete merged file in a single code block.
"""


def _looks_like_full_file(reference: str, candidate: str) -> bool:
    reference_lines = reference.count("\n") + 1
    candidate_lines = candidate.count("\n") + 1
    return candidate_lines >= FULL_FILE_LINE_RATIO * reference_lines


def _merge_snippet_into_file(llm: Any, original: str, snippet: str, extract_code: Callable) -> Optional[str]:
    try:
        response = llm.query(_MERGE_PROMPT.format(original=original, snippet=snippet))
    except Exception as e:
        print(f"merge LLM call failed: {e!r}", flush=True)
        return None
    merged = extract_code(response) if response else None
    if not merged or merged.count("\n") + 1 < MERGE_SANITY_LINE_RATIO * (original.count("\n") + 1):
        return None
    return merged


def _log(msg: str) -> None:
    line = f"[{datetime.now().strftime('%H:%M:%S')}] {msg}"
    print(line, flush=True)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    with open(PROGRESS_LOG_PATH, "a") as f:
        f.write(line + "\n")




def _read_repo_file(container_name: str, dirname: str, path: str) -> str:
    result = docker_exec(container_name, ["cat", f"/workspace/{dirname}/{path}"])
    if result.returncode != 0:
        return f"error: {result.stderr.strip()}"
    return result.stdout


def _write_repo_file(container_name: str, dirname: str, path: str, content: str) -> str:
    container_path = f"/workspace/{dirname}/{path}"
    if not content.endswith("\n"):
        content += "\n"
    result = docker_exec(
        container_name,
        ["sh", "-c", f"mkdir -p \"$(dirname '{container_path}')\" && cat > '{container_path}'"],
        input_text=content,
    )
    if result.returncode != 0:
        return f"error: {result.stderr.strip()}"
    return f"wrote {len(content)} chars to {path}"


async def _patch_file(
    container_name: str, dirname: str, pipeline: Any, file_path: str, vul_entries: list[dict],
    cve_id: str, use_intent_modeling: bool, extract_code: Callable,
) -> list[dict]:
    ids = [v["id"] for v in vul_entries]
    tag = f"[{cve_id}]"

    original = await asyncio.to_thread(_read_repo_file, container_name, dirname, file_path)
    if original.startswith("error:"):
        return [{"id": vid, "status": "read_failed", "detail": original} for vid in ids]

    result = await asyncio.to_thread(pipeline.run, original, f"{cve_id}::{file_path}", str(RESULTS_DIR), use_intent_modeling)
    patch_code = result.get("outputs", {}).get("generated_patch")
    if result.get("status") != "SUCCESS" or not patch_code:
        return [{"id": vid, "status": result.get("status", "FAILED")} for vid in ids]

    content_to_write = patch_code
    if not _looks_like_full_file(original, patch_code):
        print(
            f"{tag} {file_path}: generated_patch ({patch_code.count(chr(10)) + 1} lines) looks like a "
            f"snippet, not the full file ({original.count(chr(10)) + 1} lines) - merging instead of overwriting",
            flush=True,
        )
        merged = await asyncio.to_thread(_merge_snippet_into_file, pipeline.llm, original, patch_code, extract_code)
        if merged is not None:
            content_to_write = merged
        else:
            print(f"{tag} {file_path}: merge failed, falling back to writing the raw snippet", flush=True)

    write_msg = await asyncio.to_thread(_write_repo_file, container_name, dirname, file_path, content_to_write)
    if write_msg.startswith("error:"):
        return [{"id": vid, "status": "write_failed", "detail": write_msg} for vid in ids]

    return [{"id": vid, "status": "patched"} for vid in ids]


async def run_one(cve_id: str, model: str, use_intent_modeling: bool) -> dict:
    tag = f"[{cve_id}]"
    t0 = time.monotonic()
    record = load_cve_record(cve_id)
    image = f"ghcr.io/anonymous2578-data/{cve_id.lower()}:latest"
    container_name = None
    dirname = None
    llm = None
    try:
        upstream = load_upstream(RESULTS_DIR)
        llm = create_llm(upstream.interface_class, model)
        container_name = await asyncio.to_thread(start_editable_container, cve_id, image)
        dirname = await asyncio.to_thread(resolve_repo_dirname, container_name, repo_dirname(record["repo"]))
        await asyncio.to_thread(sanitize_container, container_name)
        print(f"{tag} container ready ({container_name})", flush=True)

        pipeline = upstream.pipeline_class(llm)

        files: dict[str, list[dict]] = {}
        for vul_entry in record["vul_func"]:
            files.setdefault(vul_entry["file_path"], []).append(vul_entry)

        function_results: list[dict] = []
        for file_path, vul_entries in files.items():
            results = await _patch_file(
                container_name, dirname, pipeline, file_path, vul_entries, cve_id, use_intent_modeling, upstream.extract_code
            )
            function_results.extend(results)
            for r in results:
                print(f"{tag} {r['id']}: {r['status']}", flush=True)

        diffs = await asyncio.to_thread(get_split_diffs, container_name, dirname)
        fix_patch = diffs.fix_patch
        append_patch(PATCHES_PATH, cve_id, diffs)

        duration_s = round(time.monotonic() - t0, 1)
        n_patched = sum(1 for r in function_results if r["status"] == "patched")
        n_total = len(function_results)
        print(
            f"{tag} patch saved ({len(fix_patch)} chars, {n_patched}/{n_total} functions patched) - {duration_s}s",
            flush=True,
        )
        return {
            "cve_id": cve_id,
            "status": "ok" if n_patched > 0 else "no_patch",
            "patch_chars": len(fix_patch),
            "functions_patched": n_patched,
            "functions_total": n_total,
            "function_results": function_results,
            "duration_s": duration_s,
            "usage": llm.get_usage_stats(),
            "upstream_commit": upstream.revision,
        }
    except Exception as e:
        return {"cve_id": cve_id, "status": "error", "error": repr(e), "duration_s": round(time.monotonic() - t0, 1)}
    finally:
        if container_name and dirname:
            await asyncio.to_thread(restore_and_stop, container_name, dirname)
        elif container_name:
            subprocess.run(["docker", "rm", "-f", container_name], capture_output=True, timeout=30)


async def heartbeat(in_flight: dict[str, float], total: int, completed: list[str], interval: float) -> None:
    start = time.monotonic()
    while True:
        await asyncio.sleep(interval)
        elapsed = time.monotonic() - start
        n_done = len(completed)
        rate = n_done / elapsed if elapsed > 0 else 0
        eta_str = f"{(total - n_done) / rate / 60:.1f}m" if rate > 0 else "?"
        running = ", ".join(f"{cve} ({time.monotonic() - t0:.0f}s)" for cve, t0 in in_flight.items()) or "(none)"
        _log(f"HEARTBEAT: {n_done}/{total} done, elapsed {elapsed / 60:.1f}m, ETA {eta_str} | running: {running}")


def _load_already_attempted() -> set[str]:
    if not SUMMARY_PATH.exists():
        return set()
    done = set()
    for line in SUMMARY_PATH.read_text().splitlines():
        if line.strip():
            done.add(json.loads(line)["cve_id"])
    return done


async def main() -> None:
    global RESULTS_DIR, SUMMARY_PATH, PROGRESS_LOG_PATH, PATCHES_PATH
    parser = argparse.ArgumentParser()
    parser.add_argument("--cve", action="append", help="CVE id to run (repeatable) - default: the 3 starter CVEs")
    parser.add_argument("--all", action="store_true", help="run every CVE that has a configured unit test")
    parser.add_argument("--limit", type=int, default=None, help="cap how many CVEs to run this batch")
    parser.add_argument("--workers", type=int, default=3, help="how many CVEs to run concurrently (default 3)")
    parser.add_argument("--timeout", type=float, default=1800.0, help="per-CVE wall-clock timeout in seconds (default 1800)")
    parser.add_argument("--heartbeat-interval", type=float, default=30.0, help="seconds between progress heartbeats (default 30)")
    parser.add_argument("--model", default=DEFAULT_LLM_MODEL, help=f"IntentFix LLM model (default: {DEFAULT_LLM_MODEL})")
    parser.add_argument(
        "--no-intent-modeling", action="store_true",
        help="ablation: skip Phase 1 intent modeling (gap detection + patch synthesis only)",
    )
    args = parser.parse_args()
    RESULTS_DIR = results_dir("patcheval", "intentfix", args.model)
    SUMMARY_PATH = RESULTS_DIR / "run_summary.jsonl"
    PROGRESS_LOG_PATH = RESULTS_DIR / "progress.log"
    PATCHES_PATH = RESULTS_DIR / "patches.jsonl"

    if args.cve:
        cve_ids = args.cve
    elif args.all:
        cve_ids = [
            line.strip() for line in ALL_PATCHEVAL_CVES_WITH_UNIT_TEST_PATH.read_text().splitlines() if line.strip()
        ]
    else:
        cve_ids = DEFAULT_CVE_IDS
    if args.limit:
        cve_ids = cve_ids[: args.limit]

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    already_done = _load_already_attempted()
    pending = [c for c in cve_ids if c not in already_done]
    if already_done:
        _log(f"Skipping {len(already_done & set(cve_ids))} already-attempted CVE(s) (delete lines in {SUMMARY_PATH} to retry)")
    if not pending:
        _log("Nothing to do - every requested CVE is already in the run summary")
        return
    load_upstream(RESULTS_DIR)
    _log(f"Running {len(pending)} CVE(s) with {args.workers} worker(s), model={args.model}, {args.timeout:.0f}s timeout each")

    batch_start = time.monotonic()
    write_lock = asyncio.Lock()
    semaphore = asyncio.Semaphore(args.workers)

    in_flight: dict[str, float] = {}
    completed: list[str] = []
    hb_task = asyncio.create_task(heartbeat(in_flight, len(pending), completed, args.heartbeat_interval))

    async def run_and_log(cve_id: str) -> None:
        async with semaphore:
            in_flight[cve_id] = time.monotonic()
            _log(f"START {cve_id} ({len(in_flight)} running)")
            try:
                result = await asyncio.wait_for(
                    run_one(cve_id, args.model, not args.no_intent_modeling), timeout=args.timeout
                )
            except asyncio.TimeoutError:
                result = {"cve_id": cve_id, "status": "timeout", "duration_s": round(time.monotonic() - in_flight[cve_id], 1)}
            finally:
                in_flight.pop(cve_id, None)
            async with write_lock:
                completed.append(cve_id)
                with open(SUMMARY_PATH, "a") as f_out:
                    f_out.write(json.dumps(result) + "\n")
                _log(
                    f"DONE  {cve_id}: {result['status']} ({result.get('duration_s', '?')}s) "
                    f"[{len(completed)}/{len(pending)}]"
                )

    await asyncio.gather(*(run_and_log(c) for c in pending))

    hb_task.cancel()
    try:
        await hb_task
    except asyncio.CancelledError:
        pass

    total_elapsed = time.monotonic() - batch_start
    _log(f"Done in {total_elapsed / 60:.1f}m ({total_elapsed:.1f}s) for {len(pending)} CVE(s). Summary: {SUMMARY_PATH}")
    _log(f"Patches: {PATCHES_PATH}")


if __name__ == "__main__":
    asyncio.run(main())
