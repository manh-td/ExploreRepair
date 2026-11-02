def _overlap(a_start: int, a_end: int, b_start: int, b_end: int) -> int:
    return max(0, min(a_end, b_end) - max(a_start, b_start) + 1)


def vul_func_coverage(graph: dict, record: dict, min_ratio: float = 0.5) -> dict:
    file_paths = {node["path"] for node in graph["nodes"] if node["kind"] == "file"}
    syms_by_path: dict[str, list[dict]] = {}
    for node in graph["nodes"]:
        if node["kind"] == "sym":
            syms_by_path.setdefault(node["path"], []).append(node)

    locations = record["vul_func"]
    files_found = 0
    syms_found = 0
    missing = []
    for location in locations:
        path = location["file_path"].removeprefix("./")
        start, end = int(location["start_line"]), int(location["end_line"])
        if path in file_paths:
            files_found += 1
        else:
            missing.append(f"{path}:{start} (file)")
            continue
        span = max(1, end - start + 1)
        best = max(
            (_overlap(start, end, s["start_line"], s["end_line"]) for s in syms_by_path.get(path, [])),
            default=0,
        )
        if best / span >= min_ratio:
            syms_found += 1
        else:
            missing.append(f"{path}:{start} (sym)")

    return {
        "vul_locations": len(locations),
        "vul_files_found": files_found,
        "vul_syms_found": syms_found,
        "vul_missing": missing,
    }


def dangling_edges(graph: dict) -> list[dict]:
    ids = {node["id"] for node in graph["nodes"]}
    return [e for e in graph["edges"] if e["source"] not in ids or e["target"] not in ids]
