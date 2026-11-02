import argparse
import asyncio

from src.agentcore.config import DEFAULT_MODEL
from src.experiments.reactagent.executable.run_single import DEFAULT_CVE_IDS, PATCHES_PATH, RESULTS_DIR, run_one
from src.experiments.reactagent.shared.arm import DEFAULT_TIMEOUT_S, REASONING_EFFORT
from src.harnesses.batch import add_common_args, run_batch, select_cve_ids


async def main() -> None:
    args = add_common_args(argparse.ArgumentParser(), default_model=DEFAULT_MODEL,
                           default_timeout=DEFAULT_TIMEOUT_S).parse_args()
    await run_batch(
        items=select_cve_ids(args, DEFAULT_CVE_IDS),
        run_one=lambda cve_id: run_one(cve_id, args.model, args.timeout),
        results_dir=RESULTS_DIR,
        workers=args.workers,
        timeout=args.timeout,
        heartbeat_interval=args.heartbeat_interval,
        start_msg=f", model={args.model}, reasoning_effort={REASONING_EFFORT}",
        done_msg=f"Patches: {PATCHES_PATH}",
    )


if __name__ == "__main__":
    asyncio.run(main())
