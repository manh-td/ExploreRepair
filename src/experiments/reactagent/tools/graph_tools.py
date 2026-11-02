import threading
from collections.abc import Sequence

from src.harnesses.code_knowledge_graph import build_graphs, build_vector_db

_GRAPH_CACHE: dict[str, dict] = {}
_GRAPH_LOCK = threading.Lock()
_EMBEDDER = None
_EMBEDDER_LOCK = threading.Lock()
DEFAULT_EDGE_KINDS = ("call", "import", "co_edit")
DEFAULT_SEARCH_K = 5
DEFAULT_NEIGHBOR_LIMIT = 20
MAX_RESOLVED_NODES = 5
GRAPH_USAGE = ""


def get_graph(cve_id: str) -> dict:
    with _GRAPH_LOCK:
        if cve_id not in _GRAPH_CACHE:
            _GRAPH_CACHE[cve_id] = build_graphs.load(cve_id)
        return _GRAPH_CACHE[cve_id]


def get_embedder(device: str | None = None):
    global _EMBEDDER
    with _EMBEDDER_LOCK:
        if _EMBEDDER is None:
            from src.harnesses.code_knowledge_graph.embedder import BGEEmbedder

            _EMBEDDER = BGEEmbedder(device=device)
        return _EMBEDDER


def has_graph(cve_id: str) -> bool:
    return build_graphs.is_cached(cve_id)


def has_vector_db(cve_id: str) -> bool:
    return build_vector_db.is_cached(cve_id)


def _resolve(graph: dict, symbol: str) -> list[dict]:
    exact = [n for n in graph["nodes"] if n["id"] == symbol]
    if exact:
        return exact
    candidates = [
        n for n in graph["nodes"]
        if n["kind"] == "sym" and symbol in (n["qual"], n["name"], f"{n['path']}::{n['qual']}")
    ]
    if candidates:
        return candidates
    return [n for n in graph["nodes"] if n["kind"] == "file" and n["path"] == symbol]


def _describe(node: dict) -> str:
    if node["kind"] == "file":
        return f"file {node['path']}"
    return f"{node['path']}::{node['qual']} (lines {node['start_line']}-{node['end_line']})"


def neighbors_text(cve_id: str, symbol: str, edge_kinds: Sequence[str], limit: int) -> str:
    graph = get_graph(cve_id)
    matches = _resolve(graph, symbol)
    if not matches:
        return f"No node matching {symbol!r}. Use search_code to find one, or pass a `path::symbol`."
    by_id = {n["id"]: n for n in graph["nodes"]}
    kinds = set(edge_kinds)

    blocks = []
    for node in matches[:MAX_RESOLVED_NODES]:
        out_lines, in_lines = [], []
        for edge in graph["edges"]:
            if edge["kind"] not in kinds:
                continue
            if edge["source"] == node["id"] and edge["target"] in by_id:
                out_lines.append(f"  -> [{edge['kind']}] {_describe(by_id[edge['target']])}")
            elif edge["target"] == node["id"] and edge["source"] in by_id:
                in_lines.append(f"  <- [{edge['kind']}] {_describe(by_id[edge['source']])}")
        body = "\n".join(
            [f"{_describe(node)}", "outgoing (this uses):"] + (out_lines[:limit] or ["  (none)"])
            + ["incoming (uses this):"] + (in_lines[:limit] or ["  (none)"])
        )
        blocks.append(body)
    return "\n\n".join(blocks)


def search_text(cve_id: str, query: str, k: int, device: str | None) -> str:
    if not has_vector_db(cve_id):
        return f"No vector index built for {cve_id}."
    hits = build_vector_db.query(cve_id, query, get_embedder(device), k=k)
    if not hits:
        return "No matches."
    lines = []
    for hit in hits:
        if hit.get("kind") == "file":
            where = f"file {hit['path']}"
        else:
            where = f"{hit['path']}::{hit['qual']} (lines {hit['start_line']}-{hit['end_line']})"
        lines.append(f"[{hit['distance']:.3f}] {where}")
    return "\n".join(lines)


SEARCH_CODE_SCHEMA = {
    "type": "function",
    "function": {
        "name": "search_code",
        "description": (
            "Semantic search over this repository's functions, classes and files. "
            "Returns locations only - read the actual code with your shell. Locations "
            "come from a snapshot of the repository, so line numbers drift once you edit."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "What you are looking for, in natural language or as code",
                },
                "k": {"type": "integer", "description": "How many results to return"},
            },
            "required": ["query"],
        },
    },
}

GRAPH_NEIGHBORS_SCHEMA = {
    "type": "function",
    "function": {
        "name": "graph_neighbors",
        "description": (
            "List what a function/class/file calls or imports, and what calls or imports "
            "it, from this repository's static code graph. Use it to find the callers of "
            "a suspicious function or the entry points that reach it."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "symbol": {
                    "type": "string",
                    "description": "A `path::symbol`, a symbol name, or a file path",
                },
                "limit": {"type": "integer", "description": "Max neighbours to list per direction"},
            },
            "required": ["symbol"],
        },
    },
}


def build_tools(cve_id: str, device: str | None = None) -> list[tuple[dict, object]]:
    def graph_neighbors(symbol: str, limit: int = DEFAULT_NEIGHBOR_LIMIT) -> str:
        return neighbors_text(cve_id, symbol, DEFAULT_EDGE_KINDS, limit)

    def search_code(query: str, k: int = DEFAULT_SEARCH_K) -> str:
        return search_text(cve_id, query, k, device)

    tools = [(GRAPH_NEIGHBORS_SCHEMA, graph_neighbors)]
    if has_vector_db(cve_id):
        tools.append((SEARCH_CODE_SCHEMA, search_code))
    return tools


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Query one CVE's code graph the way the agent's tools do")
    parser.add_argument("--cve", required=True)
    parser.add_argument("--symbol", default=None, help="symbol/file to list neighbours of")
    parser.add_argument("--query", default=None, help="natural-language query for semantic search")
    parser.add_argument("--k", type=int, default=DEFAULT_SEARCH_K)
    parser.add_argument("--limit", type=int, default=DEFAULT_NEIGHBOR_LIMIT)
    parser.add_argument("--device", default=None)
    args = parser.parse_args()

    print(f"graph cached: {has_graph(args.cve)}, vector db cached: {has_vector_db(args.cve)}")
    print(f"tools for this CVE: {[s['function']['name'] for s, _ in build_tools(args.cve, args.device)]}")
    if args.symbol:
        print(neighbors_text(args.cve, args.symbol, DEFAULT_EDGE_KINDS, args.limit))
    if args.query:
        print(search_text(args.cve, args.query, args.k, args.device))
    if not args.symbol and not args.query:
        graph = get_graph(args.cve)
        print(f"{len(graph['nodes'])} nodes, {len(graph['edges'])} edges")
        for node in graph["nodes"][:5]:
            print(" ", _describe(node))
