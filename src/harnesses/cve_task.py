import os
from pathlib import Path

CVE_TASK_TEMPLATE = Path("src/harnesses/prompts/cve_task.md").read_text()


def _env_hint(record: dict) -> str:
    if record.get("programming_language") != "Python":
        return ""
    return (
        " The project's dependencies are already installed for "
        "/workspace/PoC_env/venv/bin/python - that is a different, separate interpreter from the "
        "bare `python`/`python3` on PATH, which won't have them. Use its full path to run or "
        "import anything from the project. That venv's bin/ has been stripped down to just the "
        "`python` binary itself - console scripts like `pytest` are not there (and a bare "
        "`pytest`/`python`/`python3` on PATH won't have the dependencies either), so run test "
        "tools as a module instead, e.g. `/workspace/PoC_env/venv/bin/python -m pytest ...`, "
        "never by a bare binary name."
    )


def _network_hint() -> str:
    return (
        " The container has no network access - anything that reaches the internet "
        "(curl/wget/git clone/git fetch/npm/pip/go get) will fail, so work only from the repo "
        "and its already-installed dependencies."
    )


def _fix_scope_hint() -> str:
    return (
        " Your fix is collected only from changes to source files (.py/.go/.js/.ts and the like). "
        "Edits to dependency manifests and lockfiles (package.json, package-lock.json, go.mod, "
        "go.sum, requirements.txt), config, or generated/vendored directories (node_modules/, "
        "vendor/, dist/, build/) are discarded and will not count as your fix, so the repair has to "
        "be in the project's own source code."
    )


def _verify_hint() -> str:
    return (
        " Before you finish, check two things. First, that `git diff` in the repository is not "
        "empty - an empty diff is graded as no fix at all, so if it comes back empty your edits "
        "did not land and you need to find out why. Second, that the project's existing test suite "
        "still passes - a patch that fixes the vulnerability but breaks the surrounding code grades "
        "no better than no patch, and a regression is easy to introduce and easy to catch."
    )


def _decisive_hint() -> str:
    return (
        " Before you finish, check three things. First, that `git diff` in the repository is not "
        "empty - an empty diff is graded as no fix at all, so if it comes back empty your edits "
        "did not land and you need to find out why. Second, that your fix actually refuses the "
        "unsafe input rather than merely noticing it: the unsafe path must fail - raise, return an "
        "error, reject the request - and that refusal must reach the caller. A check whose failure "
        "is caught and logged, or swallowed by a try/except, or skipped by a condition that the "
        "attacker controls, leaves the vulnerability exactly where it was. Breaking the attack is "
        "the point of the patch, so do not soften it to keep the unsafe case working. Third, that "
        "the project's existing test suite still passes - a fix that breaks unrelated behaviour "
        "grades no better than no patch. If an existing test only passes because the unsafe "
        "behaviour was allowed, the fix is still right: say so in your summary rather than "
        "weakening the fix to keep that test green."
    )

LEGACY_LOCATION_HINT = os.environ.get("CVE_TASK_LEGACY_LOCATION_HINT") == "1"

_LEGACY_SCOPE_SENTENCE = (
    "It marks where the weakness is, not every place involved in it - roughly one ground-truth fix "
    "in six also touches a file not listed above (a caller, a shared helper, a sibling code path "
    "carrying the same flaw)."
)
_SCOPE_SENTENCE = (
    "It marks where the weakness is, not every place involved in it: a fix may also need to reach a "
    "caller, a shared helper, or a sibling code path carrying the same flaw."
)


def _location_block(locations: list[dict]) -> str:
    lines = "\n".join(f"- {f['file_path']} (lines {f['start_line']}-{f['end_line']})" for f in locations)
    if not lines:
        return ""
    scope = _LEGACY_SCOPE_SENTENCE if LEGACY_LOCATION_HINT else _SCOPE_SENTENCE
    return (
        f"\n\nThe vulnerability is located at:\n{lines}\n\n"
        f"Treat that as a starting point, not the full picture. {scope} Trace how the vulnerable "
        "code is reached and what else relies on it before you settle on an answer."
    )


def _cve_context_block(record: dict) -> str:
    cwe_info = record.get("cwe_info") or {}
    cwe_lines = []
    for cwe_id in record.get("cwe_id") or []:
        info = cwe_info.get(cwe_id) or {}
        name = (info.get("name") or "").strip()
        detail = (info.get("description") or "").strip()
        head = f"- {cwe_id}: {name}" if name else f"- {cwe_id}"
        cwe_lines.append(f"{head}\n  {detail}" if detail else head)
    description = (record.get("cve_description") or "").strip()
    if not cwe_lines and not description:
        return ""

    body = ""
    if cwe_lines:
        body += "\n\nWeakness class:\n" + "\n".join(cwe_lines)
    if description:
        body += "\n\nReported description:\n" + description
    return (
        f"\n\nThe advisory published for this vulnerability is below.{body}\n\n"
        "Treat it as a report, not a specification: it describes what was observed and reported, "
        "which need not name every code path the weakness reaches, and it does not say how to "
        "repair it. Confirm each claim against the code before you rely on it."
    )


_NO_CVE_CONTEXT_SENTENCE = (
    "\n\nThere is no vulnerability description or CWE given anywhere - identifying the actual "
    "security issue at the location above is part of the task."
)


def _build_cve_task(record: dict, locations: list[dict], decisive: bool = False, cve_context: bool = False) -> str:
    description, _, _ = CVE_TASK_TEMPLATE.rpartition("\n\n")
    task = description.format(repo=record["repo"])
    closing = _decisive_hint() if decisive else _verify_hint()
    framing = (_cve_context_block(record) if cve_context else "") or _NO_CVE_CONTEXT_SENTENCE

    return (
        f"{task}{_location_block(locations)}{framing}{_fix_scope_hint()}"
        f"{_env_hint(record)}{_network_hint()}{closing}"
    )


def load_cve_task(record: dict, decisive: bool = False, cve_context: bool = False) -> str:
    return _build_cve_task(record, record.get("vul_func", []), decisive, cve_context)


def load_cve_task_for_location(record: dict, location: dict) -> str:
    return _build_cve_task(record, [location])
