import argparse
import asyncio

from src.harnesses.batch import add_common_args, run_batch, select_cve_ids
from src.experiments.llm.run_single import DEFAULT_CVE_IDS, PATCHES_PATH, RESULTS_DIR, run_one
from src.experiments.llm.utils.llm_client import DEFAULT_MODEL


async def main() -> None:
    parser = add_common_args(argparse.ArgumentParser(), default_model=DEFAULT_MODEL, default_timeout=600.0)
    args = parser.parse_args()
    await run_batch(
        items=select_cve_ids(args, DEFAULT_CVE_IDS),
        run_one=lambda cve_id: run_one(cve_id, args.model),
        results_dir=RESULTS_DIR,
        workers=args.workers,
        timeout=args.timeout,
        heartbeat_interval=args.heartbeat_interval,
        start_msg=f", model={args.model}",
        done_msg=f"Patches: {PATCHES_PATH}",
    )


if __name__ == "__main__":
    asyncio.run(main())
