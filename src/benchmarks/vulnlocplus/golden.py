import argparse
from pathlib import Path

from src.benchmarks.vulnlocplus.loading import ARTIFACTS_DIR, cve_ids, no_golden_patch_ids


class NoGoldenPatch(ValueError):
    pass


def has_golden_patch(cve_id: str) -> bool:
    return cve_id not in no_golden_patch_ids()


def golden_diff_path(cve_id: str) -> Path:
    if not has_golden_patch(cve_id):
        raise NoGoldenPatch(f"{cve_id} has no dev-patch/fix.patch in the image - see "
                            "resources/vulnlocplus.cves.no-golden-patch.txt")
    return ARTIFACTS_DIR / cve_id / "dev-patch.patch"


def golden_diff(cve_id: str) -> str:
    return golden_diff_path(cve_id).read_text()


def gradeable_cve_ids() -> list[str]:
    return [c for c in cve_ids() if has_golden_patch(c)]


def main() -> None:
    parser = argparse.ArgumentParser(description='The golden fix for a VulnLoc+ CVE, stored as a normal unified diff.')
    parser.add_argument("--cve", default=None)
    args = parser.parse_args()

    if args.cve:
        if has_golden_patch(args.cve):
            print(golden_diff(args.cve))
        else:
            print(f"{args.cve}: no golden patch (see resources/vulnlocplus.cves.no-golden-patch.txt)")
        return

    gradeable = gradeable_cve_ids()
    print(f"working set:       {len(cve_ids())} CVEs")
    print(f"with golden patch: {len(gradeable)}")
    print(f"without:           {len(cve_ids()) - len(gradeable)}")


if __name__ == "__main__":
    main()
