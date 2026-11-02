import argparse
import json
import subprocess
from functools import lru_cache
from pathlib import Path

from src.benchmarks.vulnlocplus.loading import load_record, project_for, subject_dir

WORKING_SET_PATH = Path("resources/vulnlocplus.cves.discriminating.txt")
CRASH_SITES_PATH = Path("resources/vulnlocplus.crash_sites.json")
BASE_IMAGE = "fino2020/looprepair:v1.0"
LISTING_TIMEOUT_S = 900.0
SOURCE_SUFFIXES = (".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp")


def working_set() -> list[str]:
    return [line.strip() for line in WORKING_SET_PATH.read_text().splitlines() if line.strip()]


def source_listing(cve_ids: list[str]) -> dict[str, list[str]]:
    names = " -o ".join(f"-name '*{suffix}'" for suffix in SOURCE_SUFFIXES)
    script = "".join(
        f"echo '@@ {cve_id}'; cd {subject_dir(cve_id)}/src && find . -type f \\( {names} \\) | sed 's|^\\./||';"
        for cve_id in cve_ids)
    proc = subprocess.run(["docker", "run", "--rm", BASE_IMAGE, "bash", "-c", script],
                          capture_output=True, text=True, errors="replace", timeout=LISTING_TIMEOUT_S)
    listing: dict[str, list[str]] = {}
    current = None
    for line in proc.stdout.splitlines():
        if line.startswith("@@ "):
            current = line[3:]
            listing[current] = []
        elif current and line.strip():
            listing[current].append(line.strip())
    return listing


def resolve(path: str, files: list[str]) -> str | None:
    for candidate in (path, path[4:] if path.startswith("src/") else None):
        if candidate and candidate in files:
            return candidate
    suffix_hits = [f for f in files if f.endswith("/" + path)]
    if len(suffix_hits) == 1:
        return suffix_hits[0]
    base_hits = [f for f in files if Path(f).name == Path(path).name]
    return base_hits[0] if len(base_hits) == 1 else None


def crash_site(cve_id: str, files: list[str]) -> dict:
    tag = (load_record(cve_id).get("fuzzer") or {}).get("crash-tag")
    if not tag:
        return {"file_path": None, "line": None, "source": "none"}
    path, _, line = tag.split(";")[-1].rpartition(":")
    resolved = resolve(path, files)
    if resolved is None:
        return {"error": f"crash-tag {tag!r} does not resolve to one file"}
    return {"file_path": resolved, "line": int(line), "source": "crash-tag", "raw": tag}


@lru_cache(maxsize=1)
def crash_sites() -> dict[str, dict]:
    return json.loads(CRASH_SITES_PATH.read_text())


def locations(cve_id: str) -> list[dict]:
    site = crash_sites()[cve_id]
    if "error" in site:
        raise ValueError(f"{cve_id}: {site['error']} - fix {CRASH_SITES_PATH} first")
    if site["file_path"] is None:
        return []
    return [{"file_path": site["file_path"], "start_line": site["line"], "end_line": site["line"]}]


def main() -> None:
    argparse.ArgumentParser(description="Resolve each VulnLoc+ CVE's bug.json crash-tag into a location hint.").parse_args()
    cve_ids = working_set()
    listing = source_listing(cve_ids)
    sites = {cve_id: crash_site(cve_id, listing.get(cve_id, [])) for cve_id in cve_ids}
    CRASH_SITES_PATH.write_text(json.dumps(sites, indent=2) + "\n")
    for cve_id, site in sites.items():
        where = site.get("error") or (f"{site['file_path']}:{site['line']}" if site["file_path"] else "(no hint)")
        print(f"{cve_id:24} {project_for(cve_id):10} {where}")
    unresolved = [c for c, s in sites.items() if "error" in s]
    print(f"\n{sum(1 for s in sites.values() if s.get('file_path'))} with a hint, "
          f"{sum(1 for s in sites.values() if s.get('source') == 'none')} without -> {CRASH_SITES_PATH}")
    if unresolved:
        raise SystemExit(f"unresolved: {unresolved}")


if __name__ == "__main__":
    main()
