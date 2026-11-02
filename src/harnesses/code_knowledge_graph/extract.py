import re
from collections import Counter, defaultdict
from pathlib import Path

import tree_sitter_c
import tree_sitter_go
import tree_sitter_javascript
import tree_sitter_python
from tree_sitter import Language, Parser

PY_LANG = Language(tree_sitter_python.language())
JS_LANG = Language(tree_sitter_javascript.language())
GO_LANG = Language(tree_sitter_go.language())
C_LANG = Language(tree_sitter_c.language())

EXTENSIONS = {
    "Python": (".py",),
    "JavaScript": (".js", ".jsx", ".mjs", ".cjs"),
    "Go": (".go",),
    "C": (".c", ".h"),
}

_LANGUAGES = {"Python": PY_LANG, "JavaScript": JS_LANG, "Go": GO_LANG, "C": C_LANG}

SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "vendor",
    "dist", "build", ".tox", ".mypy_cache", "site-packages", "third_party",
}

MAX_FILE_BYTES = 2_000_000

_PY_DEFS = {"function_definition", "class_definition"}
_JS_DEFS = {
    "function_declaration", "generator_function_declaration",
    "class_declaration", "method_definition",
}
_GO_DEFS = {"function_declaration", "method_declaration", "type_spec"}
_C_DEFS = {"function_definition", "struct_specifier", "union_specifier", "enum_specifier"}
_DEFS = {"Python": _PY_DEFS, "JavaScript": _JS_DEFS, "Go": _GO_DEFS, "C": _C_DEFS}


def source_files(root: Path, language: str) -> list[Path]:
    exts = EXTENSIONS[language]
    out = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix not in exts:
            continue
        if SKIP_DIRS & set(path.relative_to(root).parts):
            continue
        if path.stat().st_size > MAX_FILE_BYTES:
            continue
        out.append(path)
    return out


def _text(node, src: bytes) -> str:
    return src[node.start_byte:node.end_byte].decode("utf-8", "replace")


def _c_def_name(node, src: bytes) -> str | None:
    if node.type != "function_definition":
        name = node.child_by_field_name("name")
        return _text(name, src) if name is not None and node.child_by_field_name("body") is not None else None
    declarator = node.child_by_field_name("declarator")
    while declarator is not None and declarator.type != "function_declarator":
        declarator = declarator.child_by_field_name("declarator")
    inner = declarator.child_by_field_name("declarator") if declarator is not None else None
    while inner is not None and inner.type not in ("identifier", "field_identifier"):
        inner = inner.child_by_field_name("declarator")
    return _text(inner, src) if inner is not None else None


def _def_name(node, src: bytes, language: str) -> str | None:
    if language == "C":
        return _c_def_name(node, src)
    if language == "Go" and node.type == "method_declaration":
        receiver = node.child_by_field_name("receiver")
        name = node.child_by_field_name("name")
        if name is None:
            return None
        recv_type = None
        if receiver is not None:
            for child in receiver.named_children:
                type_node = child.child_by_field_name("type") or child
                recv_type = _text(type_node, src).lstrip("*")
        return f"{recv_type}.{_text(name, src)}" if recv_type else _text(name, src)
    name = node.child_by_field_name("name")
    return _text(name, src) if name is not None else None


_JS_FUNC_VALUES = {"arrow_function", "function_expression", "function"}


def _js_named_value(node, src: bytes):
    if node.type == "variable_declarator":
        name, value = node.child_by_field_name("name"), node.child_by_field_name("value")
    elif node.type == "assignment_expression":
        name, value = node.child_by_field_name("left"), node.child_by_field_name("right")
    elif node.type == "pair":
        name, value = node.child_by_field_name("key"), node.child_by_field_name("value")
    else:
        return None, None
    if name is None or value is None or value.type not in _JS_FUNC_VALUES:
        return None, None
    label = _text(name, src).strip("\"'")
    if not label or "\n" in label:
        return None, None
    return label, value


def _collect_defs(tree, src: bytes, language: str) -> list[tuple[str, object]]:
    defs = []
    claimed: set[int] = set()
    stack = [(child, "") for child in reversed(tree.root_node.named_children)]
    while stack:
        child, scope = stack.pop()
        name = None
        target = child
        if child.type in _DEFS[language]:
            name = _def_name(child, src, language)
        elif language == "JavaScript":
            name, value = _js_named_value(child, src)
            if name:
                claimed.add(value.id)
                target = value
            elif child.type in _JS_FUNC_VALUES and child.id not in claimed:
                name = f"anonymous@{child.start_point[0] + 1}"
        if name:
            scope = f"{scope}.{name}" if scope else name
            defs.append((scope, target))
        stack.extend((grandchild, scope) for grandchild in reversed(child.named_children))
    return defs


def _enclosing(node, def_by_id: dict[int, str]) -> str | None:
    current = node.parent
    while current is not None:
        qual = def_by_id.get(current.id)
        if qual is not None:
            return qual
        current = current.parent
    return None


def _callee_name(node, src: bytes) -> str | None:
    func = node.child_by_field_name("function")
    if func is None:
        return None
    if func.type == "identifier":
        return _text(func, src)
    if func.type in ("attribute", "member_expression", "selector_expression", "field_expression"):
        field = (
            func.child_by_field_name("attribute")
            or func.child_by_field_name("property")
            or func.child_by_field_name("field")
        )
        if field is not None:
            return _text(field, src)
    return None


def _collect_calls(tree, src: bytes, def_by_id: dict[int, str]) -> list[tuple[str, str]]:
    calls = []
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if node.type in ("call", "call_expression"):
            name = _callee_name(node, src)
            caller = _enclosing(node, def_by_id)
            if name and caller:
                calls.append((caller, name))
        stack.extend(node.named_children)
    return calls


def _string_value(node, src: bytes) -> str:
    return _text(node, src).strip("\"'`")


def _python_import_specs(tree, src: bytes) -> list[tuple[int, str]]:
    specs = []
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if node.type == "import_from_statement":
            module = node.child_by_field_name("module_name")
            if module is not None:
                raw = _text(module, src)
                level = len(raw) - len(raw.lstrip("."))
                specs.append((level, raw.lstrip(".")))
        elif node.type == "import_statement":
            for child in node.named_children:
                target = child.child_by_field_name("name") if child.type == "aliased_import" else child
                if target is not None and target.type in ("dotted_name", "identifier"):
                    specs.append((0, _text(target, src)))
        stack.extend(node.named_children)
    return specs


def _js_import_specs(tree, src: bytes) -> list[str]:
    specs = []
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if node.type in ("import_statement", "export_statement"):
            source = node.child_by_field_name("source")
            if source is not None:
                specs.append(_string_value(source, src))
        elif node.type == "call_expression":
            func = node.child_by_field_name("function")
            args = node.child_by_field_name("arguments")
            if func is not None and _text(func, src) == "require" and args is not None:
                for arg in args.named_children:
                    if arg.type == "string":
                        specs.append(_string_value(arg, src))
        stack.extend(node.named_children)
    return specs


def _go_import_specs(tree, src: bytes) -> list[str]:
    specs = []
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if node.type == "import_spec":
            path = node.child_by_field_name("path")
            if path is not None:
                specs.append(_string_value(path, src))
        stack.extend(node.named_children)
    return specs


def _c_include_specs(tree, src: bytes) -> list[str]:
    specs = []
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if node.type == "preproc_include":
            path = node.child_by_field_name("path")
            if path is not None and path.type == "string_literal":
                specs.append(_string_value(path, src))
        stack.extend(node.named_children)
    return specs


def _resolve_c(root: Path, path: Path, spec: str, files_by_name: dict[str, list[Path]]) -> list[Path]:
    candidate = (path.parent / spec).resolve()
    if candidate.is_file() and candidate.is_relative_to(root):
        return [candidate]
    hits = files_by_name.get(Path(spec).name, [])
    return hits if len(hits) == 1 else []


def _resolve_python(root: Path, path: Path, level: int, dotted: str) -> list[Path]:
    bases = []
    if level:
        base = path.parent
        for _ in range(level - 1):
            base = base.parent
        bases.append(base)
    else:
        bases.append(root)
        bases.append(root / root.name)
    parts = dotted.split(".") if dotted else []
    out = []
    for base in bases:
        candidate = base.joinpath(*parts) if parts else base
        for target in (candidate.with_suffix(".py"), candidate / "__init__.py"):
            if target.is_file() and target.is_relative_to(root):
                out.append(target)
        if not parts:
            continue
        parent = base.joinpath(*parts[:-1])
        for target in (parent.with_suffix(".py"), parent / "__init__.py"):
            if target.is_file() and target.is_relative_to(root):
                out.append(target)
    return out


def _resolve_js(root: Path, path: Path, spec: str) -> list[Path]:
    if not spec.startswith("."):
        return []
    candidate = (path.parent / spec).resolve()
    for target in (
        candidate,
        *(candidate.with_suffix(ext) for ext in EXTENSIONS["JavaScript"]),
        *(candidate / f"index{ext}" for ext in EXTENSIONS["JavaScript"]),
    ):
        if target.is_file() and target.is_relative_to(root):
            return [target]
    return []


def _go_module_path(root: Path) -> str | None:
    go_mod = root / "go.mod"
    if not go_mod.is_file():
        return None
    match = re.search(r"^module\s+(\S+)", go_mod.read_text(errors="ignore"), re.M)
    return match.group(1) if match else None


def _resolve_go(root: Path, module: str | None, spec: str, files_by_dir: dict[Path, list[Path]]) -> list[Path]:
    if not module or not spec.startswith(module):
        return []
    relative = spec[len(module):].strip("/")
    directory = (root / relative) if relative else root
    return files_by_dir.get(directory, [])


def build_graph(root: Path, language: str) -> dict:
    root = Path(root).resolve()
    parser = Parser(_LANGUAGES[language])
    files = source_files(root, language)
    rel = {path: str(path.relative_to(root)) for path in files}

    files_by_dir: dict[Path, list[Path]] = defaultdict(list)
    for path in files:
        files_by_dir[path.parent].append(path)

    go_module = _go_module_path(root) if language == "Go" else None
    files_by_name: dict[str, list[Path]] = defaultdict(list)
    for path in files:
        files_by_name[path.name].append(path)

    nodes = []
    sym_ids_by_file: dict[Path, dict[str, str]] = {}
    calls_by_file: dict[Path, list[tuple[str, str]]] = {}
    import_edges: list[tuple[str, str]] = []
    parse_errors = 0

    for path in files:
        src = path.read_bytes()
        tree = parser.parse(src)
        if tree.root_node.has_error:
            parse_errors += 1

        file_id = f"file:{rel[path]}"
        nodes.append({
            "id": file_id,
            "kind": "file",
            "path": rel[path],
            "language": language,
            "size": len(src),
        })

        defs = _collect_defs(tree, src, language)
        sym_ids_by_file[path] = {}
        for qual, node in defs:
            if qual in sym_ids_by_file[path]:
                qual = f"{qual}@{node.start_point[0] + 1}"
                if qual in sym_ids_by_file[path]:
                    continue
            sym_id = f"sym:{rel[path]}::{qual}"
            sym_ids_by_file[path][qual] = sym_id
            nodes.append({
                "id": sym_id,
                "kind": "sym",
                "path": rel[path],
                "qual": qual,
                "name": qual.rsplit(".", 1)[-1],
                "type": node.type,
                "start_line": node.start_point[0] + 1,
                "end_line": node.end_point[0] + 1,
                "start_byte": node.start_byte,
                "end_byte": node.end_byte,
            })

        def_by_id = {node.id: qual for qual, node in defs}
        calls_by_file[path] = _collect_calls(tree, src, def_by_id)

        targets: list[Path] = []
        if language == "Python":
            for level, dotted in _python_import_specs(tree, src):
                targets += _resolve_python(root, path, level, dotted)
        elif language == "JavaScript":
            for spec in _js_import_specs(tree, src):
                targets += _resolve_js(root, path, spec)
        elif language == "C":
            for spec in _c_include_specs(tree, src):
                targets += _resolve_c(root, path, spec, files_by_name)
        else:
            for spec in _go_import_specs(tree, src):
                targets += _resolve_go(root, go_module, spec, files_by_dir)
        for target in targets:
            if target in rel and target != path:
                import_edges.append((file_id, f"file:{rel[target]}"))

    if language == "Go":
        for directory, group in files_by_dir.items():
            for a in group:
                for b in group:
                    if a is not b:
                        import_edges.append((f"file:{rel[a]}", f"file:{rel[b]}"))

    imports_by_file: dict[str, set[str]] = defaultdict(set)
    for source, target in import_edges:
        imports_by_file[source].add(target)

    syms_by_file_name: dict[str, dict[str, list[str]]] = {}
    for path, quals in sym_ids_by_file.items():
        by_name: dict[str, list[str]] = defaultdict(list)
        for qual, sym_id in quals.items():
            by_name[qual.rsplit(".", 1)[-1]].append(sym_id)
        syms_by_file_name[f"file:{rel[path]}"] = by_name

    call_edges: list[tuple[str, str]] = []
    unresolved = 0
    unresolved_no_candidate = 0
    unresolved_ambiguous = 0
    ambiguous_degree: list[int] = []
    c_functions: dict[str, list[str]] = defaultdict(list)
    if language == "C":
        for node in nodes:
            if node["kind"] == "sym" and node["type"] == "function_definition":
                c_functions[node["name"]].append(node["id"])
    for path, calls in calls_by_file.items():
        file_id = f"file:{rel[path]}"
        scope = [file_id] + sorted(imports_by_file.get(file_id, ()))
        in_scope: dict[str, list[str]] = defaultdict(list)
        for scope_file in scope:
            for name, sym_ids in syms_by_file_name.get(scope_file, {}).items():
                in_scope[name] += sym_ids
        for caller_qual, name in calls:
            caller = sym_ids_by_file[path].get(caller_qual)
            if caller is None:
                continue
            if language == "C":
                own = syms_by_file_name.get(file_id, {}).get(name, [])
                candidates = [c for c in (own or c_functions.get(name, ())) if c != caller]
            else:
                candidates = [c for c in in_scope.get(name, ()) if c != caller]
            if len(candidates) == 1:
                call_edges.append((caller, candidates[0]))
            else:
                unresolved += 1
                if candidates:
                    unresolved_ambiguous += 1
                    ambiguous_degree.append(len(candidates))
                else:
                    unresolved_no_candidate += 1

    edges = _weighted(import_edges, "import") + _weighted(call_edges, "call")
    return {
        "root": str(root),
        "language": language,
        "nodes": nodes,
        "edges": edges,
        "stats": {
            "files": len(files),
            "symbols": sum(len(v) for v in sym_ids_by_file.values()),
            "parse_errors": parse_errors,
            "unresolved_calls": unresolved,
            "unresolved_no_candidate": unresolved_no_candidate,
            "unresolved_ambiguous": unresolved_ambiguous,
            "ambiguous_mean_degree": (
                sum(ambiguous_degree) / len(ambiguous_degree) if ambiguous_degree else 0.0
            ),
        },
    }


def _weighted(pairs, kind: str) -> list[dict]:
    counts = Counter(pairs)
    return [
        {"source": source, "target": target, "kind": kind, "weight": weight}
        for (source, target), weight in sorted(counts.items())
    ]
