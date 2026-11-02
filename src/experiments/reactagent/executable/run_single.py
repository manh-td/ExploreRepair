from src.experiments.reactagent.shared.arm import main, run_guided_agent
from src.harnesses.results import results_dir

RESULTS_DIR = results_dir("patcheval", "executable")
SUMMARY_PATH = RESULTS_DIR / "run_summary.jsonl"
PATCHES_PATH = RESULTS_DIR / "patches.jsonl"
DEFAULT_CVE_IDS = ["CVE-2025-27154", "CVE-2022-23536", "CVE-2021-21360"]

GUIDANCE = """Work in three phases, in this order.

1. Analyse the vulnerability. Read the vulnerable location and the code around it: which input \
reaches it, through which entry point, and what the code does with that input that it should not.

2. Prove it with a proof-of-concept test. Reach the weakness the way an attacker would, through the \
public API, CLI or endpoint that leads to it, and assert on the behaviour that comes back. Run the \
test yourself until it fails in a way that shows the vulnerability is present - executed evidence, \
not a plausible-sounding attack. Put the test at a path that is recognisably a test: inside a test/, \
tests/, spec/ or poc/ directory, or named test_*.py, *_test.go, *.test.js, *.spec.ts or similar. \
Only such files are collected as your test; a PoC anywhere else is treated as part of your fix.

3. Fix it. Repair the weakness in the production code, at its root and at every site that shares \
it, then run your PoC again and confirm it now passes. Making your own test pass is the check, not \
the goal: special-casing the input it happens to use is not a fix, and weakening the test to make it \
pass defeats it.

Do not run git commit, reset, checkout or stash."""


async def run_one(cve_id: str, model: str, timeout: float, verbose: bool = False) -> dict:
    return await run_guided_agent(cve_id, model, timeout, verbose, RESULTS_DIR, GUIDANCE)


if __name__ == "__main__":
    main(RESULTS_DIR, GUIDANCE, run_one, "The PoV agent (executable evidence) on one CVE")
