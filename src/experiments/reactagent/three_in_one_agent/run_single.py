from src.experiments.reactagent.semantic.run_single import _question
from src.experiments.reactagent.shared.arm import main, run_guided_agent
from src.experiments.reactagent.shared.intent_questions import STAGES
from src.experiments.reactagent.structural.run_single import _tools
from src.harnesses.results import results_dir

RESULTS_DIR = results_dir("patcheval", "3-in-1-agent")
SUMMARY_PATH = RESULTS_DIR / "run_summary.jsonl"
PATCHES_PATH = RESULTS_DIR / "patches.jsonl"
DEFAULT_CVE_IDS = ["CVE-2025-27154", "CVE-2022-23536", "CVE-2021-21360"]
GUIDANCE = (
    "Work in four phases, in this order.\n\n"
    "1. Work out what this code is meant to do. Answer the parts below in order, each building on the "
    "ones before it, citing file:line for what you read; say plainly where you could not establish "
    "something rather than filling the gap.\n\n"
    + "\n\n".join(_question(stage.prompt) for stage in STAGES)
    + """

2. Analyse the structural context of the vulnerability using the code-graph tools you have, \
`graph_neighbors` and `search_code`:
- the callers and entry points that reach the vulnerable location, followed back to where outside \
input comes in;
- what the vulnerable code calls and relies on - helpers, validators, shared utilities;
- sibling code paths that do the same job, and whether they guard it differently or share the flaw.

The graph returns locations; read the code at each one with your shell before relying on it. Write \
down what that structure tells you - where the fix belongs and which other sites it has to reach.

3. Prove it with a proof-of-concept test. Reach the weakness the way an attacker would, through the \
public API, CLI or endpoint that leads to it, and assert on the behaviour that comes back. Run the \
test yourself until it fails in a way that shows the vulnerability is present - executed evidence, \
not a plausible-sounding attack. Put the test at a path that is recognisably a test: inside a test/, \
tests/, spec/ or poc/ directory, or named test_*.py, *_test.go, *.test.js, *.spec.ts or similar. \
Only such files are collected as your test; a PoC anywhere else is treated as part of your fix.

4. Fix it. Repair the weakness in the production code, at its root and at every site that shares \
it, so that it restores the rules you found in phase 1, then run your PoC again and confirm it now \
passes. Making your own test pass is the check, not the goal: special-casing the input it happens to \
use is not a fix, and weakening the test to make it pass defeats it.

Do not run git commit, reset, checkout or stash."""
)


async def run_one(cve_id: str, model: str, timeout: float, verbose: bool = False) -> dict:
    return await run_guided_agent(cve_id, model, timeout, verbose, RESULTS_DIR, GUIDANCE, _tools)


if __name__ == "__main__":
    main(RESULTS_DIR, GUIDANCE, run_one, "The 3-in-1 Agent: intent, structure and PoV guidance with the graph tools in one agent, on one CVE")
