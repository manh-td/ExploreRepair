import argparse

from src.benchmarks.base import UnsupportedFlag
from src.benchmarks.vulnlocplus.images import asan_requested, repo_path
from src.benchmarks.vulnlocplus.loading import load_record
from src.benchmarks.vulnlocplus.locations import locations
from src.harnesses.cve_task import (CVE_TASK_TEMPLATE, _NO_CVE_CONTEXT_SENTENCE,
                                    _decisive_hint, _location_block, _network_hint, _verify_hint)

SUPPORTED_FLAGS = frozenset({"decisive"})
NO_LOCATION_SENTENCE = (
    "\n\nNo location is given for this vulnerability, and there is no vulnerability description or CWE "
    "given anywhere - finding and identifying the actual security issue in the repository is part of the task."
)


def _c_fix_scope_hint() -> str:
    return (
        " Your fix is collected only from changes to the project's own source files "
        "(.c/.cc/.cpp/.h/.hpp). Edits to build files (configure.ac, Makefile.am, CMakeLists.txt), "
        "to generated files, or to anything under a vendored third-party directory are discarded "
        "and will not count as your fix, so the repair has to be in the project's own code."
    )


def _build_hint(cve_id: str) -> str:
    return (
        f" The repository at {repo_path(cve_id)} is already configured, so you can rebuild "
        f"incrementally with `make` rather than re-running ./configure from scratch - a full "
        f"reconfigure is slow and rarely what you want."
    )


def _asan_hint(cve_id: str) -> str:
    if not asan_requested(cve_id):
        return ""
    return (
        " Everything you build here is compiled with AddressSanitizer, so a program that reads or "
        "writes out of bounds aborts with a report naming the faulting line. No input that triggers "
        "this vulnerability is provided."
    )


def build_task(cve_id: str, **flags) -> str:
    unsupported = sorted(name for name, value in flags.items() if value and name not in SUPPORTED_FLAGS)
    if unsupported:
        raise UnsupportedFlag(f"vulnlocplus cannot honour {unsupported}: it has no cve_description, "
                              "no cwe_info, and the PoC is withheld for grading")
    record = load_record(cve_id)
    description, _, _ = CVE_TASK_TEMPLATE.rpartition("\n\n")
    task = description.format(repo=record["project"]["name"])
    closing = _decisive_hint() if flags.get("decisive") else _verify_hint()
    hint = locations(cve_id)
    framing = f"{_location_block(hint)}{_NO_CVE_CONTEXT_SENTENCE}" if hint else NO_LOCATION_SENTENCE
    return (f"{task}{framing}{_c_fix_scope_hint()}{_build_hint(cve_id)}{_asan_hint(cve_id)}"
            f"{_network_hint()}{closing}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Print one VulnLoc+ CVE's repair prompt.")
    parser.add_argument("--cve", default="CVE-2016-1838")
    parser.add_argument("--decisive", action="store_true")
    parser.add_argument("--cve-context", action="store_true", help="should raise: VulnLoc+ ships no advisory")
    args = parser.parse_args()
    try:
        print(build_task(args.cve, decisive=args.decisive, cve_context=args.cve_context))
    except UnsupportedFlag as exc:
        print(f"UnsupportedFlag: {exc}")


if __name__ == "__main__":
    main()
