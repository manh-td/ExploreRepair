import json
from pathlib import Path

LFS_POINTER_PREFIX = "version https://git-lfs.github.com/spec/"


class LfsPointerError(RuntimeError):
    pass


def read_jsonl(path: Path, *, strict: bool = False) -> list[dict]:
    path = Path(path)
    if not path.exists():
        return []
    text = path.read_text()
    if text.startswith(LFS_POINTER_PREFIX):
        raise LfsPointerError(
            f"{path} is an unfetched Git LFS pointer, not the real file - run "
            f"`git lfs install && git lfs pull` in the results repository"
        )

    rows = []
    for lineno, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            if strict:
                raise
            print(f"{path}:{lineno}: skipping unparseable line")
    return rows

def last_per_key(rows: list[dict], key: str = "cve_id") -> dict[str, dict]:
    return {r[key]: r for r in rows if key in r}
