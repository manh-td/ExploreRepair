import re
import shlex
import subprocess
from pathlib import Path
from typing import NamedTuple

from src.harnesses.budget import (
    BASH_COMMAND_KILL_GRACE_S,
    BASH_COMMAND_TIMEOUT_S,
    BASH_OUTPUT_LIMIT_CHARS,
    DOCKER_EXEC_CLIENT_TIMEOUT_S,
    FILE_OP_TIMEOUT_S,
)

_DIFF_FILE_CHUNK_RE = re.compile(r"^diff --git a/\S+ b/\S+.*?(?=^diff --git a/|\Z)", re.MULTILINE | re.DOTALL)

SOURCE_EXTENSIONS = frozenset({".py", ".pyi", ".go", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"})

VENDOR_DIRS = frozenset({
    "node_modules", "vendor", "third_party", "external", ".venv", "venv", "site-packages",
    "dist", "build", ".git", "__pycache__", ".tox", ".mypy_cache", ".pytest_cache",
})

_TEST_PATH_RE = re.compile(
    r"(?:^|/)(?:tests?|specs?|__tests__|testing|testdata|poc|fixtures)(?:/|$)"
    r"|(?:^|/)(?:test|poc)[_.-][^/]*$"
    r"|(?:_test|\.test|\.spec|_spec|_poc|\.poc)\.[^/]+$"
    r"|(?:^|/)[^/]*_test\.[^/]+$"
    r"|(?:^|/)(?:test|spec|poc)\.[^/]+$",
    re.IGNORECASE,
)


def is_test_path(path: str) -> bool:
    return bool(_TEST_PATH_RE.search(path))


def is_vendored_path(path: str) -> bool:
    return bool(VENDOR_DIRS & set(path.split("/")))


def is_source_path(path: str) -> bool:
    if is_test_path(path) or is_vendored_path(path):
        return False
    return Path(path).suffix.lower() in SOURCE_EXTENSIONS


def _strip_binary_diff_chunks(diff_text: str) -> str:
    chunks = _DIFF_FILE_CHUNK_RE.findall(diff_text)
    return "".join(c for c in chunks if "Binary files" not in c and "GIT binary patch" not in c)


def _as_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def docker_exec(
    container_name: str,
    args: list[str],
    input_text: str | None = None,
    timeout: float | None = FILE_OP_TIMEOUT_S,
) -> subprocess.CompletedProcess:
    cmd = ["docker", "exec"]
    if input_text is not None:
        cmd.append("-i")
    cmd.append(container_name)
    cmd.extend(args)
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            input=input_text.encode("utf-8") if input_text is not None else None,
            timeout=timeout,
        )
        return subprocess.CompletedProcess(
            cmd, result.returncode, _as_text(result.stdout), _as_text(result.stderr)
        )
    except subprocess.TimeoutExpired as e:
        return subprocess.CompletedProcess(
            cmd,
            returncode=124,
            stdout=_as_text(e.stdout),
            stderr=_as_text(e.stderr) + f"\n[docker_exec timed out after {timeout}s]",
        )


def docker_exec_bash(container_name: str, cwd: str, command: str) -> subprocess.CompletedProcess:
    wrapped = (
        f"cd {shlex.quote(cwd)} && timeout -k {BASH_COMMAND_KILL_GRACE_S} {BASH_COMMAND_TIMEOUT_S} "
        f"sh -c {shlex.quote(command)}"
    )
    result = docker_exec(container_name, ["sh", "-c", wrapped], timeout=DOCKER_EXEC_CLIENT_TIMEOUT_S)
    return subprocess.CompletedProcess(
        result.args, result.returncode, _truncate(result.stdout), _truncate(result.stderr)
    )


def _truncate(text: str) -> str:
    if len(text) <= BASH_OUTPUT_LIMIT_CHARS:
        return text
    dropped = len(text) - BASH_OUTPUT_LIMIT_CHARS
    return text[:BASH_OUTPUT_LIMIT_CHARS] + f"\n[output truncated, {dropped} more characters]"


def start_editable_container(
    cve_id: str,
    image: str,
    name_suffix: str = "editable",
    mounts: list[tuple[str, str, str]] | None = None,
    network: str | None = "none",
) -> str:
    if subprocess.run(["docker", "image", "inspect", image], capture_output=True, timeout=30).returncode != 0:
        raise RuntimeError(f"image not pulled locally: {image!r} (docker pull {image})")

    container_name = f"{cve_id.lower()}_{name_suffix}"
    subprocess.run(["docker", "rm", "-f", container_name], capture_output=True, timeout=30)
    cmd = ["docker", "run", "-d", "--name", container_name]
    if network is not None:
        cmd += ["--network", network]
    for host_path, container_path, mode in mounts or []:
        cmd += ["-v", f"{Path(host_path).resolve()}:{container_path}:{mode}"]
    cmd += [image, "sleep", "infinity"]
    subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=60)
    return container_name


def resolve_repo_dirname(container_name: str, guessed_dirname: str) -> str:
    if docker_exec(container_name, ["test", "-d", f"/workspace/{guessed_dirname}"]).returncode == 0:
        return guessed_dirname

    result = docker_exec(
        container_name,
        ["find", "/workspace", "-mindepth", "1", "-maxdepth", "1", "-type", "d", "!", "-name", "PoC_env"],
    )
    candidates = [line.rsplit("/", 1)[-1] for line in result.stdout.splitlines() if line.strip()]
    if len(candidates) == 1:
        return candidates[0]
    raise RuntimeError(
        f"repo dirname mismatch: guessed {guessed_dirname!r} doesn't exist in the "
        f"container, and couldn't find exactly one fallback directory (found: {candidates})"
    )


def sanitize_container(container_name: str) -> bool:
    result = docker_exec(
        container_name, ["find", "/workspace/PoC_env", "-mindepth", "1", "-maxdepth", "1", "-type", "d"]
    )
    venv_dirs = [line for line in result.stdout.splitlines() if line.strip()]
    renamed = False
    if len(venv_dirs) == 1:
        docker_exec(container_name, ["mv", venv_dirs[0], "/workspace/PoC_env/venv"])
        docker_exec(
            container_name,
            ["find", "/workspace/PoC_env/venv/bin", "-mindepth", "1", "!", "-name", "python", "-delete"],
        )
        renamed = True

    docker_exec(
        container_name,
        [
            "sh", "-c",
            "cd /workspace && rm -f *.patch fix-run.sh vul-run.sh prepare.sh check_git_changes.sh clean_git.sh "
            "unit_test.sh",
        ],
    )
    return renamed


def restore_and_stop(container_name: str, repo_dirname: str) -> None:
    subprocess.run(["docker", "rm", "-f", container_name], capture_output=True, timeout=30)


def get_current_diff(container_name: str, repo_dirname: str, exclude_paths: list[str] | None = None) -> str:
    cmd = f"cd /workspace/{repo_dirname} && git diff --"
    if exclude_paths:
        cmd += " . " + " ".join(f"':(exclude){p}'" for p in exclude_paths)
    result = docker_exec(container_name, ["sh", "-c", cmd])
    return result.stdout


def get_staged_diff(container_name: str, repo_dirname: str, only_paths: list[str] | None = None) -> str:
    docker_exec(container_name, ["sh", "-c", f"cd /workspace/{repo_dirname} && git add -A"])
    cmd = f"cd /workspace/{repo_dirname} && git diff --cached --"
    if only_paths:
        cmd += " " + " ".join(f"'{p}'" for p in only_paths)
    cmd += " ':(exclude,glob)**/POC_RUN_CMD.txt'"
    result = docker_exec(container_name, ["sh", "-c", cmd])
    return _strip_binary_diff_chunks(result.stdout)


def _staged_paths(container_name: str, repo_dirname: str, base_sha: str | None = None) -> list[str]:
    docker_exec(container_name, ["sh", "-c", f"cd /workspace/{repo_dirname} && git add -A"])
    against = f" {base_sha}" if base_sha else ""
    result = docker_exec(
        container_name,
        ["sh", "-c", f"cd /workspace/{repo_dirname} && git diff --cached{against} --name-only"],
    )
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def split_staged_paths(paths: list[str]) -> tuple[list[str], list[str], list[str]]:
    source = [p for p in paths if is_source_path(p)]
    test = [p for p in paths if is_test_path(p)]
    classified = set(source) | set(test)
    return source, test, [p for p in paths if p not in classified]


class StagedDiffs(NamedTuple):
    fix_patch: str
    test_patch: str
    dropped_files: list[str]


def get_split_diffs(container_name: str, repo_dirname: str, base_sha: str | None = None) -> StagedDiffs:
    source, test, dropped = split_staged_paths(_staged_paths(container_name, repo_dirname, base_sha))
    return StagedDiffs(
        fix_patch=_diff_of_paths(container_name, repo_dirname, source, base_sha),
        test_patch=_diff_of_paths(container_name, repo_dirname, test, base_sha),
        dropped_files=dropped,
    )


def get_source_diff(container_name: str, repo_dirname: str) -> str:
    source, _, _ = split_staged_paths(_staged_paths(container_name, repo_dirname))
    return _diff_of_paths(container_name, repo_dirname, source)


def get_test_diff(container_name: str, repo_dirname: str) -> str:
    _, test, _ = split_staged_paths(_staged_paths(container_name, repo_dirname))
    return _diff_of_paths(container_name, repo_dirname, test)


def _diff_of_paths(
    container_name: str, repo_dirname: str, paths: list[str], base_sha: str | None = None
) -> str:
    if not paths:
        return ""
    against = f" {base_sha}" if base_sha else ""
    quoted = " ".join(shlex.quote(p) for p in paths)
    result = docker_exec(
        container_name,
        ["sh", "-c", f"cd /workspace/{repo_dirname} && git diff --cached{against} -- {quoted}"],
    )
    return _strip_binary_diff_chunks(result.stdout)


def configure_git_identity(container_name: str) -> None:
    docker_exec(
        container_name,
        ["sh", "-c", "git config --global user.email 'agent@patcheval.local' && git config --global user.name patcheval-agent"],
    )


def get_commit_sha(container_name: str, repo_dirname: str) -> str:
    return docker_exec(container_name, ["sh", "-c", f"cd /workspace/{repo_dirname} && git rev-parse HEAD"]).stdout.strip()


def get_commits_since(container_name: str, repo_dirname: str, base_sha: str) -> list[tuple[str, str]]:
    result = docker_exec(
        container_name,
        ["sh", "-c", f"cd /workspace/{repo_dirname} && git log --reverse --format='%H %s' {base_sha}..HEAD"],
    )
    commits = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        sha, _, subject = line.partition(" ")
        commits.append((sha, subject))
    return commits


def get_diff_between(container_name: str, repo_dirname: str, base_sha: str, target_sha: str) -> str:
    return docker_exec(container_name, ["sh", "-c", f"cd /workspace/{repo_dirname} && git diff {base_sha} {target_sha}"]).stdout


def get_staged_diff_since(
    container_name: str, repo_dirname: str, base_sha: str, only_paths: list[str] | None = None
) -> str:
    docker_exec(container_name, ["sh", "-c", f"cd /workspace/{repo_dirname} && git add -A"])
    cmd = f"cd /workspace/{repo_dirname} && git diff --cached {base_sha} --"
    if only_paths:
        cmd += " " + " ".join(f"'{p}'" for p in only_paths)
    result = docker_exec(container_name, ["sh", "-c", cmd])
    return _strip_binary_diff_chunks(result.stdout)


def read_file(container_name: str, path: str) -> str | None:
    result = docker_exec(container_name, ["cat", path])
    return result.stdout if result.returncode == 0 else None


def write_file(container_name: str, path: str, content: str) -> None:
    docker_exec(container_name, ["sh", "-c", f"cat > {path}"], input_text=content)


def apply_diff(container_name: str, repo_dirname: str, diff_text: str) -> subprocess.CompletedProcess:
    return docker_exec(
        container_name, ["sh", "-c", f"cd /workspace/{repo_dirname} && git apply -"], input_text=diff_text
    )


def commit_all(container_name: str, repo_dirname: str, message: str) -> None:
    docker_exec(
        container_name,
        ["sh", "-c", f"cd /workspace/{repo_dirname} && git add -A && git commit -m {shlex.quote(message)} --allow-empty"],
    )


def checkout_paths(container_name: str, repo_dirname: str, commit_sha: str, paths: list[str]) -> None:
    for path in paths:
        quoted = shlex.quote(path)
        exists = (
            docker_exec(
                container_name, ["sh", "-c", f"cd /workspace/{repo_dirname} && git cat-file -e {commit_sha}:{quoted}"]
            ).returncode
            == 0
        )
        if exists:
            docker_exec(container_name, ["sh", "-c", f"cd /workspace/{repo_dirname} && git checkout {commit_sha} -- {quoted}"])
        else:
            docker_exec(container_name, ["sh", "-c", f"cd /workspace/{repo_dirname} && rm -f {quoted}"])


def read_ground_truth_poc(cve_id: str, image: str) -> str:
    if subprocess.run(["docker", "image", "inspect", image], capture_output=True, timeout=30).returncode != 0:
        raise RuntimeError(f"image not pulled locally: {image!r} (docker pull {image})")

    container_name = f"{cve_id.lower()}_groundtruth"
    subprocess.run(["docker", "rm", "-f", container_name], capture_output=True, timeout=30)
    subprocess.run(
        ["docker", "run", "-d", "--name", container_name, image, "sleep", "infinity"],
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )
    try:
        return docker_exec(container_name, ["cat", "/workspace/test.patch"]).stdout
    finally:
        subprocess.run(["docker", "rm", "-f", container_name], capture_output=True, timeout=30)


def _test_diff_extraction(cve_id: str) -> None:
    from src.harnesses.dataset import load_cve_record, repo_dirname

    record = load_cve_record(cve_id)
    image = f"ghcr.io/anonymous2578-data/{cve_id.lower()}:latest"
    container_name = start_editable_container(cve_id, image)
    try:
        dirname = resolve_repo_dirname(container_name, repo_dirname(record["repo"]))

        clean_diff = get_current_diff(container_name, dirname)
        print(f"diff before any edit is empty: {clean_diff == ''}")

        target = docker_exec(
            container_name, ["sh", "-c", f"find /workspace/{dirname} -name '*.py' | head -1"]
        ).stdout.strip()
        docker_exec(container_name, ["sh", "-c", f"echo '# diff-extraction-test' >> {target}"])

        dirty_diff = get_current_diff(container_name, dirname)
        print("dirty_diff: ", dirty_diff)
        filename = target.rsplit("/", 1)[-1]
        print(f"diff after edit is non-empty: {dirty_diff != ''}")
        print(f"diff mentions the edited file ({filename}): {filename in dirty_diff}")
    finally:
        restore_and_stop(container_name, dirname)


def _test_full_lifecycle_sweep() -> None:
    from pathlib import Path

    from src.harnesses.dataset import ALL_PATCHEVAL_CVES_WITH_UNIT_TEST_PATH
    from src.harnesses.dataset import load_cve_record, repo_dirname

    log_path = Path("workspace/container-lifecycle-test.log")
    log_path.parent.mkdir(parents=True, exist_ok=True)

    def _log(line: str) -> None:
        print(line, flush=True)
        with open(log_path, "a") as f:
            f.write(line + "\n")

    cve_ids = [
        line.strip()
        for line in ALL_PATCHEVAL_CVES_WITH_UNIT_TEST_PATH.read_text().splitlines()
        if line.strip()
    ]
    _log(f"=== testing container lifecycle for {len(cve_ids)} CVEs ===")

    n_ok = 0
    for i, cve_id in enumerate(cve_ids, start=1):
        container_name = None
        dirname = None
        try:
            record = load_cve_record(cve_id)
            image = f"ghcr.io/anonymous2578-data/{cve_id.lower()}:latest"
            container_name = start_editable_container(cve_id, image)
            dirname = resolve_repo_dirname(container_name, repo_dirname(record["repo"]))

            docker_exec(container_name, ["sh", "-c", f"echo dirty > /workspace/{dirname}/CANARY"])
            dirty = docker_exec(container_name, ["test", "-f", f"/workspace/{dirname}/CANARY"]).returncode == 0

            n_ok += 1
            _log(f"[{i}/{len(cve_ids)}] OK   {cve_id}: dirname={dirname} dirtied={dirty}")
        except Exception as e:
            _log(f"[{i}/{len(cve_ids)}] FAIL {cve_id}: {e}")
        finally:
            if container_name:
                if dirname:
                    restore_and_stop(container_name, dirname)
                else:
                    subprocess.run(["docker", "rm", "-f", container_name], capture_output=True, timeout=30)

    _log(f"=== done: {n_ok}/{len(cve_ids)} ok, log at {log_path} ===")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--all", action="store_true", help="also sweep the full CVE list (slow)")
    args = parser.parse_args()

    _test_diff_extraction("CVE-2021-21360")

    if args.all:
        _test_full_lifecycle_sweep()
