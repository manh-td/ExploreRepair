import argparse
import json
from functools import lru_cache
from pathlib import Path

from src.harnesses.results import artifacts_dir

from src.benchmarks.vulnlocplus.extract_artifacts import PROJECT_OF

CVE_LIST_PATH = Path("resources/vulnlocplus.cves.txt")
NO_GOLDEN_PATCH_PATH = Path("resources/vulnlocplus.cves.no-golden-patch.txt")
ARTIFACTS_DIR = artifacts_dir("vulnlocplus") / "artifacts"


def cve_ids() -> list[str]:
    return [line.strip() for line in CVE_LIST_PATH.read_text().splitlines() if line.strip()]


def no_golden_patch_ids() -> set[str]:
    return {line.strip() for line in NO_GOLDEN_PATCH_PATH.read_text().splitlines() if line.strip()}


@lru_cache(maxsize=None)
def load_record(cve_id: str) -> dict:
    path = ARTIFACTS_DIR / cve_id / "bug.json"
    record = json.loads(path.read_text())
    record["cve_id"] = cve_id
    record.setdefault("project", {}).setdefault("name", PROJECT_OF.get(cve_id))
    return record


@lru_cache(maxsize=1)
def load_records() -> dict[str, dict]:
    records = {}
    for cve_id in cve_ids():
        path = ARTIFACTS_DIR / cve_id / "bug.json"
        if path.is_file():
            records[cve_id] = load_record(cve_id)
    return records


def project_for(cve_id: str) -> str:
    return PROJECT_OF[cve_id]


def subject_dir(cve_id: str) -> str:
    return f"/data/vulnloc/{project_for(cve_id)}/{cve_id}"


def main() -> None:
    parser = argparse.ArgumentParser(description="Read VulnLoc+'s extracted subject descriptions off disk. Pure: no container, no build, no")
    parser.add_argument("--cve", help="dump one CVE's extracted record")
    args = parser.parse_args()

    if args.cve:
        print(json.dumps(load_record(args.cve), indent=2))
        return

    ids = cve_ids()
    records = load_records()
    no_golden = no_golden_patch_ids()
    print(f"working set:        {len(ids)} CVEs")
    print(f"extracted so far:   {len(records)}/{len(ids)}")
    print(f"no golden patch:    {len(no_golden & set(ids))}")
    projects = sorted({project_for(c) for c in ids})
    print(f"projects:           {len(projects)} ({', '.join(projects)})")


if __name__ == "__main__":
    main()
