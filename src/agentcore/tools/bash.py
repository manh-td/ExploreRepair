import shlex
import subprocess

from src.agentcore.config import (
    COMMAND_TIMEOUT_S,
    CONTAINER_WORKDIR,
    CVE_IMAGE,
    DOCKER_CLIENT_SLACK_S,
    HEAD_SHARE,
    KILL_GRACE_S,
    OUTPUT_LIMIT_CHARS,
    TIMEOUT_EXIT_CODE,
)


def _decode(raw: bytes | None) -> str:
    return raw.decode("utf-8", errors="replace") if raw else ""


def _truncate(text: str, limit: int = OUTPUT_LIMIT_CHARS) -> str:
    if len(text) <= limit:
        return text
    head = int(limit * HEAD_SHARE)
    tail = limit - head
    dropped = len(text) - head - tail
    return f"{text[:head]}\n\n[... {dropped} characters of output elided ...]\n\n{text[-tail:]}"


def _format(stdout: str, stderr: str, returncode: int, limit: int = OUTPUT_LIMIT_CHARS) -> str:
    parts = [p for p in (stdout.rstrip(), f"[stderr]\n{stderr.rstrip()}" if stderr.strip() else "") if p]
    out = "\n".join(parts) or "(empty output)"
    if returncode != 0:
        out += f"\n[exit code {returncode}]"
    return _truncate(out, limit)


def bash(command: str, cwd: str = ".", container: str = "", timeout: int = COMMAND_TIMEOUT_S,
         output_limit: int = OUTPUT_LIMIT_CHARS) -> str:
    if container:
        wrapped = (f"cd {shlex.quote(cwd)} && timeout -k {KILL_GRACE_S} {timeout} "
                   f"bash -c {shlex.quote(command)}")
        args, run_cwd, wait = ["docker", "exec", container, "sh", "-c", wrapped], None, timeout + KILL_GRACE_S + DOCKER_CLIENT_SLACK_S
    else:
        args, run_cwd, wait = ["bash", "-lc", command], cwd, timeout

    try:
        result = subprocess.run(args, cwd=run_cwd, capture_output=True, timeout=wait)
    except subprocess.TimeoutExpired as e:
        partial = _format(_decode(e.stdout), _decode(e.stderr), TIMEOUT_EXIT_CODE, output_limit)
        return f"ERROR: timed out after {timeout}s\n{partial}"
    except Exception as e:
        return f"ERROR: {type(e).__name__}: {e}"

    return _format(_decode(result.stdout), _decode(result.stderr), result.returncode, output_limit)


TOOL_SCHEMA = {
    "type": "function",
    "function": {
        "name": "bash",
        "description": (
            "Run a bash command in the working directory and return its combined output. "
            "State does not persist between calls: 'cd' affects only the command it is part of, "
            "so chain with && instead. Do not run interactive commands - they hang until the "
            "timeout. Large output is truncated in the middle, so narrow the command rather than "
            "re-running it unchanged."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "Shell command to execute, e.g. 'grep -rn parse_header src/'",
                },
            },
            "required": ["command"],
        },
    },
}


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Demo the bash tool locally and in a CVE container")
    parser.add_argument("--cve", default="CVE-2025-27154", help="CVE whose image to run the container cases in")
    parser.add_argument("--local", action="store_true", help="skip the container cases")
    args = parser.parse_args()

    def show(label: str, *call_args, **call_kwargs) -> None:
        print(f"\n--- {label} ---")
        print(bash(*call_args, **call_kwargs))

    show("plain command", "echo hello && echo world")
    show("cwd is honoured", "pwd && ls | head -3", cwd="src/agentcore/tools")
    show("stderr and a non-zero exit are both surfaced", "echo out; echo bad >&2; exit 3")
    show("no output at all", "true")
    show("a timeout keeps whatever was printed first", "echo started; sleep 5", timeout=1)
    show("binary output does not kill the observation", "head -c 64 /dev/urandom")

    print(f"\n--- output over {OUTPUT_LIMIT_CHARS} chars is truncated in the middle ---")
    long_output = bash("seq 1 200000")
    marker = long_output.index("[...")
    print(f"{long_output[:60]}".replace("\n", " "))
    print(f"  ...{long_output[marker - 20:marker + 60]}".replace("\n", " "))

    if args.local:
        raise SystemExit(0)

    slug = args.cve.lower()
    image = CVE_IMAGE.format(slug=slug)
    container = f"{slug}_agentcore_demo"
    if subprocess.run(["docker", "image", "inspect", image], capture_output=True).returncode != 0:
        raise SystemExit(f"\nimage not pulled locally: {image}\nrun: bash scripts/download/patcheval_images.sh")

    subprocess.run(["docker", "rm", "-f", container], capture_output=True)
    subprocess.run(["docker", "run", "-d", "--name", container, "--network", "none", image, "sleep", "infinity"], check=True, capture_output=True)
    print(f"\n=== the same tool, inside container {container} ===")
    try:
        show("cwd, user and the checked-out repo", "pwd && whoami && ls", cwd=CONTAINER_WORKDIR, container=container)
        show("exit codes come back from inside the container too", "ls /nope", cwd=CONTAINER_WORKDIR, container=container)
        show("the container's own timeout kills a hung command", "echo started; sleep 30", cwd=CONTAINER_WORKDIR, container=container, timeout=2)
    finally:
        subprocess.run(["docker", "rm", "-f", container], capture_output=True)
        print(f"\nremoved {container}")
