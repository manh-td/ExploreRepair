import asyncio
import json
import subprocess
import time
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv

from src.harnesses.batch import append_patch, append_summary
from src.harnesses.dataset import load_cve_record, repo_dirname
from src.harnesses.results import results_dir
from src.harnesses.docker import (
    docker_exec,
    get_split_diffs,
    resolve_repo_dirname,
    restore_and_stop,
    sanitize_container,
    start_editable_container,
)
from src.experiments.llm.utils.llm_client import DEFAULT_MODEL, generate_patches
from src.experiments.llm.utils.prompts import SYSTEM_PROMPT, build_user_prompt

load_dotenv()

RESULTS_DIR = results_dir("patcheval", "llm")
SUMMARY_PATH = RESULTS_DIR / "run_summary.jsonl"
PATCHES_PATH = RESULTS_DIR / "patches.jsonl"

DEFAULT_CVE_IDS = ["CVE-2025-27154", "CVE-2022-23536", "CVE-2021-21360"]


def _splice(file_content: str, start_line: int, end_line: int, replacement: str) -> str:
    lines = file_content.splitlines(keepends=True)
    replacement_lines = replacement.splitlines(keepends=True)
    if replacement_lines and not replacement_lines[-1].endswith("\n"):
        replacement_lines[-1] += "\n"
    return "".join(lines[: start_line - 1] + replacement_lines + lines[end_line:])


def _read_repo_file(container_name: str, dirname: str, path: str) -> str:
    result = docker_exec(container_name, ["cat", f"/workspace/{dirname}/{path}"])
    if result.returncode != 0:
        return f"error: {result.stderr.strip()}"
    return result.stdout


def _write_repo_file(container_name: str, dirname: str, path: str, content: str) -> str:
    container_path = f"/workspace/{dirname}/{path}"
    if not content.endswith("\n"):
        content += "\n"
    result = docker_exec(
        container_name,
        ["sh", "-c", f"mkdir -p \"$(dirname '{container_path}')\" && cat > '{container_path}'"],
        input_text=content,
    )
    if result.returncode != 0:
        return f"error: {result.stderr.strip()}"
    return f"wrote {len(content)} chars to {path}"


async def _patch_file(
    container_name: str, dirname: str, file_path: str, vul_entries: list[dict], patches: dict[str, str]
) -> list[dict]:
    original = await asyncio.to_thread(_read_repo_file, container_name, dirname, file_path)
    if original.startswith("error:"):
        return [{"id": v["id"], "status": "read_failed", "detail": original} for v in vul_entries]

    content = original
    results = []
    for vul_entry in sorted(vul_entries, key=lambda v: v["start_line"], reverse=True):
        patch_code = patches.get(vul_entry["id"])
        if not patch_code:
            results.append({"id": vul_entry["id"], "status": "no_patch"})
            continue
        content = _splice(content, vul_entry["start_line"], vul_entry["end_line"], patch_code)
        results.append({"id": vul_entry["id"], "status": "patched"})

    if any(r["status"] == "patched" for r in results):
        write_msg = await asyncio.to_thread(_write_repo_file, container_name, dirname, file_path, content)
        if write_msg.startswith("error:"):
            return [{"id": v["id"], "status": "write_failed", "detail": write_msg} for v in vul_entries]

    return results


async def run_one(cve_id: str, model: str) -> dict:
    tag = f"[{cve_id}]"
    t0 = time.monotonic()
    record = load_cve_record(cve_id)
    image = f"ghcr.io/anonymous2578-data/{cve_id.lower()}:latest"
    container_name = None
    dirname = None
    try:
        container_name = await asyncio.to_thread(start_editable_container, cve_id, image)
        dirname = await asyncio.to_thread(resolve_repo_dirname, container_name, repo_dirname(record["repo"]))
        await asyncio.to_thread(sanitize_container, container_name)
        print(f"{tag} container ready ({container_name})", flush=True)

        user_prompt = build_user_prompt(record)
        patches, usage = await asyncio.to_thread(generate_patches, model, SYSTEM_PROMPT, user_prompt)
        print(f"{tag} LLM returned {len(patches)} patch(es)", flush=True)

        files: dict[str, list[dict]] = {}
        for vul_entry in record["vul_func"]:
            files.setdefault(vul_entry["file_path"], []).append(vul_entry)

        function_results: list[dict] = []
        for file_path, vul_entries in files.items():
            results = await _patch_file(container_name, dirname, file_path, vul_entries, patches)
            function_results.extend(results)
            for r in results:
                print(f"{tag} {r['id']}: {r['status']}", flush=True)

        diffs = await asyncio.to_thread(get_split_diffs, container_name, dirname)
        fix_patch = diffs.fix_patch
        append_patch(PATCHES_PATH, cve_id, diffs)

        duration_s = round(time.monotonic() - t0, 1)
        n_patched = sum(1 for r in function_results if r["status"] == "patched")
        n_total = len(function_results)
        print(
            f"{tag} patch saved ({len(fix_patch)} chars, {n_patched}/{n_total} functions patched) - {duration_s}s",
            flush=True,
        )
        return {
            "cve_id": cve_id,
            "status": "ok" if n_patched > 0 else "no_patch",
            "patch_chars": len(fix_patch),
            "functions_patched": n_patched,
            "functions_total": n_total,
            "function_results": function_results,
            "duration_s": duration_s,
            "usage": usage,
        }
    except Exception as e:
        return {"cve_id": cve_id, "status": "error", "error": repr(e), "duration_s": round(time.monotonic() - t0, 1)}
    finally:
        if container_name and dirname:
            await asyncio.to_thread(restore_and_stop, container_name, dirname)
        elif container_name:
            subprocess.run(["docker", "rm", "-f", container_name], capture_output=True, timeout=30)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Run this experiment on a single CVE")
    parser.add_argument("--cve", default=DEFAULT_CVE_IDS[0], help="CVE id to patch")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="LLM model, litellm-style id")
    parser.add_argument("--no-summary", action="store_true", help="don't append a row to run_summary.jsonl")
    args = parser.parse_args()

    result = asyncio.run(run_one(args.cve, args.model))
    if not args.no_summary:
        append_summary(RESULTS_DIR, result)
    print(json.dumps(result, indent=2))
