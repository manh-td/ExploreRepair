import argparse
import asyncio
import json
import time
from collections.abc import Awaitable, Callable, Iterable, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any

from src.harnesses.dataset import ALL_PATCHEVAL_CVES_WITH_UNIT_TEST_PATH
from src.harnesses.docker import StagedDiffs


def make_logger(results_dir: Path) -> Callable[[str], None]:
    def _log(msg: str) -> None:
        line = f"[{datetime.now().strftime('%H:%M:%S')}] {msg}"
        print(line, flush=True)
        results_dir.mkdir(parents=True, exist_ok=True)
        with open(results_dir / "progress.log", "a") as f:
            f.write(line + "\n")

    return _log


def load_already_attempted(summary_path: Path) -> set[str]:
    if not summary_path.exists():
        return set()
    return {
        json.loads(line)["cve_id"] for line in summary_path.read_text().splitlines() if line.strip()
    }


def append_summary(results_dir: Path, result: dict, summary_name: str = "run_summary.jsonl") -> None:
    results_dir.mkdir(parents=True, exist_ok=True)
    with open(results_dir / summary_name, "a") as f:
        f.write(json.dumps(result) + "\n")


def append_patch(patches_path: Path, cve_id: str, diffs: StagedDiffs) -> None:
    row = {
        "cve": cve_id,
        "fix_patch": diffs.fix_patch,
        "test_patch": diffs.test_patch,
        "dropped_files": diffs.dropped_files,
    }
    patches_path.parent.mkdir(parents=True, exist_ok=True)
    with open(patches_path, "a") as f:
        f.write(json.dumps(row) + "\n")


def add_common_args(parser: argparse.ArgumentParser, *, default_model: str | None, default_timeout: float = 1800.0,
                    default_workers: int = 3) -> argparse.ArgumentParser:
    parser.add_argument("--cve", action="append", help="CVE id to run (repeatable)")
    parser.add_argument("--all", action="store_true", help="run every CVE that has a configured unit test")
    parser.add_argument("--limit", type=int, default=None, help="cap how many CVEs to run this batch")
    parser.add_argument("--workers", type=int, default=default_workers, help=f"CVEs to run concurrently (default {default_workers})")
    parser.add_argument("--timeout", type=float, default=default_timeout, help=f"per-CVE wall-clock timeout in seconds (default {default_timeout:.0f})")
    parser.add_argument("--heartbeat-interval", type=float, default=30.0, help="seconds between progress heartbeats (default 30)")
    if default_model is not None:
        parser.add_argument("--model", default=default_model, help=f"LLM model, litellm-style id (default: {default_model})")
    return parser


def all_cves_with_unit_test() -> list[str]:
    return [line.strip() for line in ALL_PATCHEVAL_CVES_WITH_UNIT_TEST_PATH.read_text().splitlines() if line.strip()]


def select_cve_ids(args: argparse.Namespace, default_cve_ids: Sequence[str]) -> list[str]:
    if args.cve:
        cve_ids = list(args.cve)
    elif getattr(args, "all", False):
        cve_ids = all_cves_with_unit_test()
    else:
        cve_ids = list(default_cve_ids)
    if args.limit:
        cve_ids = cve_ids[: args.limit]
    return cve_ids


async def _heartbeat(log: Callable[[str], None], in_flight: dict[str, float], total: int, completed: list[str], interval: float) -> None:
    start = time.monotonic()
    while True:
        await asyncio.sleep(interval)
        elapsed = time.monotonic() - start
        n_done = len(completed)
        rate = n_done / elapsed if elapsed > 0 else 0
        eta_str = f"{(total - n_done) / rate / 60:.1f}m" if rate > 0 else "?"
        running = ", ".join(f"{cve} ({time.monotonic() - t0:.0f}s)" for cve, t0 in in_flight.items()) or "(none)"
        log(f"HEARTBEAT: {n_done}/{total} done, elapsed {elapsed / 60:.1f}m, ETA {eta_str} | running: {running}")


async def run_batch(
    *,
    items: Iterable[Any],
    run_one: Callable[[Any], Awaitable[dict]],
    results_dir: Path,
    workers: int,
    timeout: float,
    heartbeat_interval: float = 30.0,
    key: Callable[[Any], str] = lambda item: item,
    start_msg: str = "",
    done_msg: str = "",
    summary_name: str = "run_summary.jsonl",
) -> list[dict]:
    summary_path = results_dir / summary_name
    log = make_logger(results_dir)
    results_dir.mkdir(parents=True, exist_ok=True)

    items = list(items)
    already_done = load_already_attempted(summary_path)
    pending = [it for it in items if key(it) not in already_done]
    if already_done:
        n_skipped = len(items) - len(pending)
        log(f"Skipping {n_skipped} already-attempted CVE(s) (delete lines in {summary_path} to retry)")
    if not pending:
        log("Nothing to do - every requested CVE is already in the run summary")
        return []
    log(f"Running {len(pending)} CVE(s) with {workers} worker(s), {timeout:.0f}s timeout each{start_msg}")

    batch_start = time.monotonic()
    write_lock = asyncio.Lock()
    semaphore = asyncio.Semaphore(workers)
    in_flight: dict[str, float] = {}
    completed: list[str] = []
    results: list[dict] = []
    hb_task = asyncio.create_task(_heartbeat(log, in_flight, len(pending), completed, heartbeat_interval))

    async def run_and_log(item: Any) -> None:
        cve_id = key(item)
        async with semaphore:
            in_flight[cve_id] = time.monotonic()
            log(f"START {cve_id} ({len(in_flight)} running)")
            try:
                result = await asyncio.wait_for(run_one(item), timeout=timeout)
            except asyncio.TimeoutError:
                result = {"cve_id": cve_id, "status": "timeout",
                          "duration_s": round(time.monotonic() - in_flight[cve_id], 1)}
            finally:
                in_flight.pop(cve_id, None)
            async with write_lock:
                completed.append(cve_id)
                results.append(result)
                with open(summary_path, "a") as f_out:
                    f_out.write(json.dumps(result) + "\n")
                log(f"DONE  {cve_id}: {result.get('status')} ({result.get('duration_s', '?')}s) "
                    f"[{len(completed)}/{len(pending)}]")

    await asyncio.gather(*(run_and_log(it) for it in pending))

    hb_task.cancel()
    try:
        await hb_task
    except asyncio.CancelledError:
        pass

    elapsed = time.monotonic() - batch_start
    log(f"Done in {elapsed / 60:.1f}m ({elapsed:.1f}s) for {len(pending)} CVE(s). Summary: {summary_path}")
    if done_msg:
        log(done_msg)
    return results


if __name__ == "__main__":
    import tempfile

    async def _demo() -> None:
        async def fake_run_one(cve_id: str) -> dict:
            await asyncio.sleep(0.2)
            return {"cve_id": cve_id, "status": "ok", "duration_s": 0.2}

        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "demo-run"
            await run_batch(items=["CVE-0000-1", "CVE-0000-2", "CVE-0000-3"], run_one=fake_run_one,
                            results_dir=out, workers=2, timeout=10, heartbeat_interval=0.1)
            print("\n--- second pass, everything should be skipped ---")
            await run_batch(items=["CVE-0000-1", "CVE-0000-2", "CVE-0000-3"], run_one=fake_run_one,
                            results_dir=out, workers=2, timeout=10, heartbeat_interval=0.1)
            print("\nrun_summary.jsonl:")
            print((out / "run_summary.jsonl").read_text())

    asyncio.run(_demo())
