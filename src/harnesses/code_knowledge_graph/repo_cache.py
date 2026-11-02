import os
import shutil
import subprocess
import threading
from collections import Counter
from contextlib import contextmanager
from pathlib import Path

from src.harnesses.dataset import load_cve_record, repo_dirname
from src.harnesses.docker import resolve_repo_dirname, start_editable_container

REPO_CACHE_DIR = Path("repos")
WORKTREE_DIR = REPO_CACHE_DIR / ".worktrees"

CLONE_TIMEOUT_S = 1800
GIT_TIMEOUT_S = 300
IMAGE_PULL_TIMEOUT_S = 3600
DOCKER_CP_TIMEOUT_S = 900

_locks: dict[str, threading.Lock] = {}
_locks_guard = threading.Lock()


class RepoError(RuntimeError):
    pass


def _lock(slug: str) -> threading.Lock:
    with _locks_guard:
        return _locks.setdefault(slug, threading.Lock())


def _git(*args: str, cwd: Path | None = None, timeout: int = GIT_TIMEOUT_S) -> subprocess.CompletedProcess:
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "", "SSH_ASKPASS": ""}
    return subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True, text=True, timeout=timeout,
        stdin=subprocess.DEVNULL, env=env,
    )


def repo_slug(repo_url: str) -> str:
    owner, name = repo_url.rstrip("/").replace(".git", "").rsplit("/", 2)[-2:]
    return f"{owner}__{name}"


def clone_dir(repo_url: str) -> Path:
    return REPO_CACHE_DIR / repo_slug(repo_url)


def vulnerable_commit(record: dict) -> str:
    commits = [f["commit"] for f in record["vul_func"] if f.get("commit")]
    if not commits:
        raise RepoError("record has no vul_func commit")
    return Counter(commits).most_common(1)[0][0]


def ensure_clone(repo_url: str) -> Path:
    target = clone_dir(repo_url)
    with _lock(repo_slug(repo_url)):
        if (target / ".git").is_dir():
            return target
        if target.exists():
            shutil.rmtree(target)
        target.parent.mkdir(parents=True, exist_ok=True)
        result = _git("clone", "--no-checkout", repo_url, str(target), timeout=CLONE_TIMEOUT_S)
        if result.returncode != 0:
            if target.exists():
                shutil.rmtree(target, ignore_errors=True)
            raise RepoError(f"clone failed for {repo_url}: {result.stderr.strip()[-500:]}")
        return target


def resolve_commit(clone: Path, prefix: str) -> str:
    for attempt in (0, 1):
        result = _git("rev-parse", "--verify", f"{prefix}^{{commit}}", cwd=clone)
        if result.returncode == 0:
            return result.stdout.strip()
        if attempt == 0:
            with _lock(clone.name):
                _git("fetch", "--tags", "--force", "origin",
                     "+refs/heads/*:refs/remotes/origin/*", "+refs/pull/*/head:refs/remotes/pull/*",
                     cwd=clone, timeout=CLONE_TIMEOUT_S)
    raise RepoError(f"commit {prefix!r} not found in {clone}")


@contextmanager
def checkout(cve_id: str):
    record = load_cve_record(cve_id)
    clone = ensure_clone(record["repo"])
    sha = resolve_commit(clone, vulnerable_commit(record))

    path = (WORKTREE_DIR / cve_id).resolve()
    with _lock(clone.name):
        if path.exists():
            _git("worktree", "remove", "--force", str(path), cwd=clone)
            shutil.rmtree(path, ignore_errors=True)
        path.parent.mkdir(parents=True, exist_ok=True)
        result = _git("worktree", "add", "--detach", "--force", str(path), sha,
                      cwd=clone, timeout=CLONE_TIMEOUT_S)
        if result.returncode != 0:
            raise RepoError(f"worktree add {sha} failed for {cve_id}: {result.stderr.strip()[-500:]}")
    try:
        yield path, sha
    finally:
        with _lock(clone.name):
            _git("worktree", "remove", "--force", str(path), cwd=clone)
        shutil.rmtree(path, ignore_errors=True)


def _image(cve_id: str) -> str:
    return f"ghcr.io/anonymous2578-data/{cve_id.lower()}:latest"


def ensure_image(cve_id: str) -> str:
    image = _image(cve_id)
    if subprocess.run(["docker", "image", "inspect", image], capture_output=True, timeout=60).returncode == 0:
        return image
    result = subprocess.run(["docker", "pull", image], capture_output=True, text=True, timeout=IMAGE_PULL_TIMEOUT_S)
    if result.returncode != 0:
        raise RepoError(f"docker pull {image} failed: {result.stderr.strip()[-300:]}")
    return image


@contextmanager
def checkout_from_image(cve_id: str):
    record = load_cve_record(cve_id)
    image = ensure_image(cve_id)
    container = None
    path = (WORKTREE_DIR / f"{cve_id}.image").resolve()
    try:
        container = start_editable_container(cve_id, image, "graphextract")
        dirname = resolve_repo_dirname(container, repo_dirname(record["repo"]))
        shutil.rmtree(path, ignore_errors=True)
        path.mkdir(parents=True, exist_ok=True)
        result = subprocess.run(
            ["docker", "cp", f"{container}:/workspace/{dirname}/.", str(path)],
            capture_output=True, text=True, timeout=DOCKER_CP_TIMEOUT_S,
        )
        if result.returncode != 0:
            raise RepoError(f"docker cp failed for {cve_id}: {result.stderr.strip()[-300:]}")
        head = _git("rev-parse", "HEAD", cwd=path)
        sha = head.stdout.strip() if head.returncode == 0 else vulnerable_commit(record)
        yield path, sha
    finally:
        if container:
            subprocess.run(["docker", "rm", "-f", container], capture_output=True, timeout=60)
        shutil.rmtree(path, ignore_errors=True)


@contextmanager
def checkout_any(cve_id: str):
    manager = checkout(cve_id)
    try:
        path, sha = manager.__enter__()
    except RepoError:
        manager = None
    if manager is not None:
        try:
            yield path, sha, "clone"
        finally:
            manager.__exit__(None, None, None)
        return
    with checkout_from_image(cve_id) as (path, sha):
        yield path, sha, "image"
