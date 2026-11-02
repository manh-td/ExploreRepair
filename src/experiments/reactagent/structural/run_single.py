from src.experiments.reactagent.shared.arm import main, run_guided_agent
from src.experiments.reactagent.tools import graph_tools
from src.harnesses.results import results_dir

RESULTS_DIR = results_dir("patcheval", "structural")
SUMMARY_PATH = RESULTS_DIR / "run_summary.jsonl"
PATCHES_PATH = RESULTS_DIR / "patches.jsonl"
DEFAULT_CVE_IDS = ["CVE-2025-27154", "CVE-2022-23536", "CVE-2021-21360"]
GUIDANCE = """Before you edit anything, analyse the structural context of the vulnerability using the \
code-graph tools you have, `graph_neighbors` and `search_code`:
- the callers and entry points that reach the vulnerable location, followed back to where outside \
input comes in;
- what the vulnerable code calls and relies on - helpers, validators, shared utilities;
- sibling code paths that do the same job, and whether they guard it differently or share the flaw.

The graph returns locations; read the code at each one with your shell before relying on it. Write \
down what that structure tells you - where the fix belongs and which other sites it has to reach - \
then make the fix."""


def _tools(cve_id: str):
    if not graph_tools.has_graph(cve_id):
        raise RuntimeError(f"no graph for {cve_id} - run scripts/harnesses/code_knowledge_graph/build_graphs.sh first")
    return graph_tools.build_tools(cve_id)


async def run_one(cve_id: str, model: str, timeout: float, verbose: bool = False) -> dict:
    return await run_guided_agent(cve_id, model, timeout, verbose, RESULTS_DIR, GUIDANCE, _tools)


if __name__ == "__main__":
    main(RESULTS_DIR, GUIDANCE, run_one, "The Code Knowledge Graph agent (structural evidence) on one CVE")
