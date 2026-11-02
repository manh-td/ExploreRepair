import argparse
import json
import subprocess
import time
import traceback
from pathlib import Path

from src.harnesses.results import artifacts_dir

from src.harnesses.batch import add_common_args, append_summary, run_batch

IMAGE = "fino2020/looprepair:v1.0"
CVE_LIST_PATH = Path("resources/vulnlocplus.cves.txt")
RESULTS_DIR = artifacts_dir("vulnlocplus")
ARTIFACTS_DIR = RESULTS_DIR / "artifacts"

PROJECT_OF = {
    "CVE-2017-6965": "binutils", "CVE-2017-14745": "binutils", "CVE-2017-15025": "binutils",
    "gnubug-19784": "coreutils", "gnubug-25023": "coreutils",
    "CVE-2016-8691": "jasper", "CVE-2016-9557": "jasper",
    "REDTEAM-CVE-2020-27828": "jasper", "REDTEAM-CVE-2021-3272": "jasper",
    "CVE-2016-5844": "libarchive",
    "CVE-2012-2806": "libjpeg", "CVE-2017-15232": "libjpeg",
    "CVE-2016-9264": "libming", "CVE-2018-8806": "libming", "CVE-2018-8964": "libming",
    "bugzilla-2633": "libtiff", "bugzilla-2611": "libtiff", "CVE-2016-10092": "libtiff",
    "CVE-2016-10272": "libtiff", "CVE-2016-3186": "libtiff", "CVE-2016-5314": "libtiff",
    "CVE-2016-5321": "libtiff", "CVE-2016-9532": "libtiff", "CVE-2017-5225": "libtiff",
    "CVE-2017-7595": "libtiff", "CVE-2017-7601": "libtiff", "CVE-2017-7599": "libtiff",
    "CVE-2017-7600": "libtiff", "REDTEAM-CVE-2018-18557": "libtiff",
    "REDTEAM-CVE-2022-4645": "libtiff", "REDTEAM-CVE-2022-48281": "libtiff",
    "CVE-2012-5134": "libxml2", "CVE-2016-1838": "libxml2", "CVE-2016-1839": "libxml2",
    "CVE-2017-5969": "libxml2", "REDTEAM-CVE-2016-1833": "libxml2",
    "CVE-2013-7437": "potrace",
    "CVE-2017-5974": "zziplib", "CVE-2017-5975": "zziplib", "CVE-2017-5976": "zziplib",
}


def all_cve_ids() -> list[str]:
    return [line.strip() for line in CVE_LIST_PATH.read_text().splitlines() if line.strip()]


def select_cve_ids(args) -> list[str]:
    if args.cve:
        cve_ids = list(args.cve)
    elif getattr(args, "all", False):
        cve_ids = all_cve_ids()
    else:
        cve_ids = all_cve_ids()[:1]
    if args.limit:
        cve_ids = cve_ids[: args.limit]
    return cve_ids


def docker(args: list[str], timeout: float) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], capture_output=True, text=True,
                          errors="replace", timeout=timeout)


def exec_in(container: str, command: str, timeout: float) -> subprocess.CompletedProcess:
    return docker(["exec", container, "bash", "-c", command], timeout)


def subject_dir(cve_id: str, project: str) -> str:
    return f"/data/vulnloc/{project}/{cve_id}"


def extract_one_sync(cve_id: str, timeout: float = 120.0) -> dict:
    project = PROJECT_OF.get(cve_id)
    container = f"vulnlocplus-extract-{cve_id.lower()}"
    result = {"cve_id": cve_id, "project": project, "status": "error"}
    t0 = time.monotonic()
    if project is None:
        result["status"] = "unknown_project"
        return result
    try:
        directory = subject_dir(cve_id, project)
        out_dir = ARTIFACTS_DIR / cve_id
        out_dir.mkdir(parents=True, exist_ok=True)

        docker(["rm", "-f", container], 30)
        docker(["run", "-d", "--name", container, IMAGE, "sleep", "infinity"], 300)

        bug_json = None
        for name in ("bug.json", "bug.analysis.json"):
            found = exec_in(container, f"test -f {directory}/{name} && cat {directory}/{name}", 30)
            if found.returncode == 0 and found.stdout.strip():
                bug_json = found.stdout
                result["bug_json_name"] = name
                break
        if bug_json is None:
            result["status"] = "no_bug_json"
            return result
        (out_dir / "bug.json").write_text(bug_json)

        golden = exec_in(container, f"cat {directory}/dev-patch/fix.patch 2>/dev/null", 30)
        result["has_golden_patch"] = bool(golden.returncode == 0 and golden.stdout.strip())
        if result["has_golden_patch"]:
            (out_dir / "dev-patch.patch").write_text(golden.stdout)

        sha = exec_in(container, f"git -C {directory}/src status 2>/dev/null | head -1 | "
                                 r"grep -oE '[0-9a-f]{7,40}$'", 30)
        result["vulnerable_sha"] = sha.stdout.strip() or None

        if result["has_golden_patch"]:
            sources_dir = out_dir / "sources"
            sources_dir.mkdir(exist_ok=True)
            touched = sorted({m for m in
                              __import__("re").findall(r"^--- a/(\S+)", golden.stdout, __import__("re").M)})
            result["sources_extracted"] = []
            for rel_path in touched:
                content = exec_in(container, f"cat {directory}/src/{rel_path} 2>/dev/null", 30)
                if content.returncode == 0 and content.stdout:
                    (sources_dir / Path(rel_path).name).write_text(content.stdout)
                    result["sources_extracted"].append(rel_path)

        result["status"] = "ok"
        return result
    except Exception as exc:
        result["status"] = "error"
        result["error"] = repr(exc)
        result["traceback"] = traceback.format_exc()
        return result
    finally:
        result["duration_s"] = round(time.monotonic() - t0, 1)
        docker(["rm", "-f", container], 30)


async def extract_one(cve_id: str, timeout: float = 120.0) -> dict:
    import asyncio
    return await asyncio.to_thread(extract_one_sync, cve_id, timeout)


def main() -> None:
    parser = argparse.ArgumentParser(description="Pull VulnLoc+'s own grading artifacts out of the shared `fino2020/looprepair:v1.0` image, for")
    add_common_args(parser, default_model=None, default_timeout=120.0)
    args = parser.parse_args()

    cve_ids = select_cve_ids(args)
    if len(cve_ids) == 1:
        result = extract_one_sync(cve_ids[0], args.timeout)
        print(json.dumps(result, indent=2))
        append_summary(RESULTS_DIR, result)
        return

    import asyncio
    asyncio.run(run_batch(
        items=cve_ids,
        run_one=lambda cve_id: extract_one(cve_id, args.timeout),
        results_dir=RESULTS_DIR,
        workers=args.workers,
        timeout=args.timeout,
        heartbeat_interval=60.0,
        start_msg=f", image {IMAGE} -> {ARTIFACTS_DIR}",
    ))


if __name__ == "__main__":
    main()
