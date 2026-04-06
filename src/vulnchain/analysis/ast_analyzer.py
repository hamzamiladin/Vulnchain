"""Tree-sitter multilingual AST analysis for security-relevant code patterns."""

import logging
import re

from vulnchain.analysis.models import APIEndpoint, ASTResult, FunctionDef
from vulnchain.ingestion.models import SourceFile

logger = logging.getLogger(__name__)

try:
    import tree_sitter_language_pack as tslp
    from tree_sitter import Node, Parser
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False

CSHARP_HTTP_ANNOTATIONS = frozenset([
    "HttpGet", "HttpPost", "HttpPut", "HttpDelete", "HttpPatch", "Route",
    "MapGet", "MapPost", "MapPut", "MapDelete",
])
CSHARP_AUTH_ANNOTATIONS = frozenset([
    "Authorize", "AllowAnonymous", "RequireAuthorization",
])

PYTHON_ROUTE_DECORATORS = frozenset([
    "app.route", "router.get", "router.post", "router.put", "router.delete",
    "router.patch", "app.get", "app.post", "app.put", "app.delete", "app.patch",
    "bp.route", "blueprint.route",
])
PYTHON_AUTH_DECORATORS = frozenset([
    "login_required", "requires_auth", "authenticate", "jwt_required",
    "token_required", "permission_required", "require_permissions",
    "security", "dependencies",
])

# PHP superglobal patterns that indicate HTTP request handling
_PHP_REQUEST_RE = re.compile(
    r"\$_(GET|POST|REQUEST|SERVER|COOKIE|FILES)\s*\[",
    re.IGNORECASE,
)
_PHP_FUNC_RE = re.compile(r"^\s*(?:public\s+|protected\s+|private\s+|static\s+)*function\s+(\w+)\s*\(", re.MULTILINE)

# TypeScript/JavaScript route patterns (Express, Fastify, Hono, NestJS)
_TS_ROUTE_RE = re.compile(
    r"(?:app|router|server)\.(get|post|put|delete|patch|all)\s*\(\s*['\"`]([^'\"`]+)['\"`]",
    re.IGNORECASE,
)
_TS_NEST_RE = re.compile(
    r"@(Get|Post|Put|Delete|Patch)\s*\(\s*['\"`]?([^'\"`\)]*)['\"`]?\s*\)",
    re.IGNORECASE,
)
_TS_AUTH_RE = re.compile(
    r"@(UseGuards|Authorized|Roles|JwtAuthGuard|AuthGuard|requireAuth|authenticate)",
    re.IGNORECASE,
)
_TS_FUNC_RE = re.compile(
    r"(?:async\s+)?(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\()",
)

# Java/Spring route patterns
_JAVA_ROUTE_RE = re.compile(
    r"@(GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping)\s*"
    r"(?:\(\s*(?:value\s*=\s*)?['\"]([^'\"]+)['\"])?",
)
_JAVA_AUTH_RE = re.compile(
    r"@(Secured|PreAuthorize|RolesAllowed|PermitAll|DenyAll)",
)
_JAVA_METHOD_RE = re.compile(
    r"(?:public|protected|private)\s+(?:static\s+)?(?:\S+\s+)+(\w+)\s*\(",
)


def _get_parser(language: str):
    if not TREE_SITTER_AVAILABLE:
        return None
    try:
        lang_obj = tslp.get_language(language)
        parser = Parser()
        parser.set_language(lang_obj)
        return parser
    except Exception as exc:
        logger.debug("No Tree-sitter parser for %s: %s", language, exc)
        return None


def _node_text(node, source: bytes) -> str:
    return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _walk_dfs(node):
    yield node
    for child in node.children:
        yield from _walk_dfs(child)


def _extract_annotation_arg(annotation_text: str) -> str:
    """Extract the first string argument from an annotation like [HttpGet("users/{id}")]."""
    m = re.search(r'["\']([^"\']+)["\']', annotation_text)
    return m.group(1) if m else ""


# ---------------------------------------------------------------------------
# C# analysis
# ---------------------------------------------------------------------------

def _analyze_csharp(source: str, file_path: str) -> ASTResult:
    result = ASTResult(file_path=file_path, language="csharp")
    parser = _get_parser("c_sharp")
    if parser is None:
        return _analyze_csharp_regex(source, file_path)

    src_bytes = source.encode("utf-8")
    try:
        tree = parser.parse(src_bytes)
    except Exception as exc:
        result.parse_errors.append(str(exc))
        return _analyze_csharp_regex(source, file_path)

    # Collect full annotation text (name + arguments) per node
    current_annotations: list[tuple[str, str]] = []  # (name, full_text)

    for node in _walk_dfs(tree.root_node):
        ntype = node.type

        if ntype == "attribute":
            full_text = _node_text(node, src_bytes)
            name_node = node.child_by_field_name("name") or (node.children[0] if node.children else None)
            if name_node:
                ann_name = _node_text(name_node, src_bytes).split("(")[0].strip()
                current_annotations.append((ann_name, full_text))

        elif ntype in ("method_declaration", "local_function_statement"):
            name_node = node.child_by_field_name("name")
            func_name = _node_text(name_node, src_bytes) if name_node else "unknown"
            start_line = node.start_point[0] + 1
            end_line = node.end_point[0] + 1

            params: list[str] = []
            params_node = node.child_by_field_name("parameters")
            if params_node:
                for p in params_node.children:
                    if p.type == "parameter":
                        pname = p.child_by_field_name("name")
                        if pname:
                            params.append(_node_text(pname, src_bytes))

            is_async = any(
                _node_text(c, src_bytes) == "async"
                for c in node.children if c.type == "modifier"
            )

            result.functions.append(FunctionDef(
                name=func_name, start_line=start_line, end_line=end_line,
                is_async=is_async, parameters=params,
            ))

            ann_names = [a[0] for a in current_annotations]
            http_anns = [(n, t) for n, t in current_annotations if n in CSHARP_HTTP_ANNOTATIONS]
            if http_anns:
                has_auth = any(n in CSHARP_AUTH_ANNOTATIONS for n in ann_names)
                ann_name, ann_text = http_anns[0]
                method = ann_name.replace("Http", "").upper() if ann_name.startswith("Http") else "ANY"
                # Extract actual route from annotation argument; fall back to function name
                route = _extract_annotation_arg(ann_text) or f"/{func_name}"
                if not route.startswith("/"):
                    route = "/" + route
                result.api_endpoints.append(APIEndpoint(
                    method=method, route=route,
                    handler_name=func_name, line=start_line, has_auth_decorator=has_auth,
                ))
            current_annotations = []

        elif ntype == "class_declaration":
            name_node = node.child_by_field_name("name")
            if name_node:
                result.class_names.append(_node_text(name_node, src_bytes))
            current_annotations = []

        elif ntype == "using_directive":
            result.imports.append(_node_text(node, src_bytes).strip())

    return result


def _analyze_csharp_regex(source: str, file_path: str) -> ASTResult:
    result = ASTResult(file_path=file_path, language="csharp")
    lines = source.splitlines()

    method_re = re.compile(
        r"^\s*(public|private|protected|internal|static|async|virtual|override|abstract)"
        r"[\s\w<>\[\],?]+\s+(\w+)\s*\("
    )
    ann_re = re.compile(r"^\s*\[(\w+)(?:\(([^\)]*)\))?")
    class_re = re.compile(r"^\s*(?:public|internal|private)?\s*(?:partial\s+)?class\s+(\w+)")
    using_re = re.compile(r"^\s*using\s+(.+);")

    # Store (name, full_line) pairs
    pending_annotations: list[tuple[str, str]] = []

    for i, line in enumerate(lines, 1):
        if m := ann_re.match(line):
            pending_annotations.append((m.group(1), line.strip()))
        elif m := class_re.match(line):
            result.class_names.append(m.group(1))
            pending_annotations = []
        elif m := method_re.match(line):
            func_name = m.group(2)
            is_async = "async" in line
            result.functions.append(FunctionDef(
                name=func_name, start_line=i, end_line=i, is_async=is_async,
            ))
            ann_names = [a[0] for a in pending_annotations]
            http_anns = [(n, t) for n, t in pending_annotations if n in CSHARP_HTTP_ANNOTATIONS]
            if http_anns:
                has_auth = any(n in CSHARP_AUTH_ANNOTATIONS for n in ann_names)
                ann_name, ann_text = http_anns[0]
                method = ann_name.replace("Http", "").upper() if ann_name.startswith("Http") else "ANY"
                route = _extract_annotation_arg(ann_text) or f"/{func_name}"
                if not route.startswith("/"):
                    route = "/" + route
                result.api_endpoints.append(APIEndpoint(
                    method=method, route=route,
                    handler_name=func_name, line=i, has_auth_decorator=has_auth,
                ))
            pending_annotations = []
        elif m := using_re.match(line):
            result.imports.append(m.group(1).strip())
        elif line.strip() and not line.strip().startswith("//"):
            pending_annotations = []

    return result


# ---------------------------------------------------------------------------
# Python analysis
# ---------------------------------------------------------------------------

def _analyze_python(source: str, file_path: str) -> ASTResult:
    result = ASTResult(file_path=file_path, language="python")
    parser = _get_parser("python")
    if parser is None:
        return _analyze_python_regex(source, file_path)

    src_bytes = source.encode("utf-8")
    try:
        tree = parser.parse(src_bytes)
    except Exception as exc:
        result.parse_errors.append(str(exc))
        return _analyze_python_regex(source, file_path)

    for node in _walk_dfs(tree.root_node):
        ntype = node.type

        # tree-sitter Python: async functions are "function_definition" with
        # an "async" keyword child, NOT "async_function_def"
        if ntype == "function_definition":
            name_node = node.child_by_field_name("name")
            func_name = _node_text(name_node, src_bytes) if name_node else "unknown"
            start_line = node.start_point[0] + 1
            end_line = node.end_point[0] + 1
            is_async = any(c.type == "async" for c in node.children)

            params: list[str] = []
            params_node = node.child_by_field_name("parameters")
            if params_node:
                for p in params_node.children:
                    if p.type == "identifier":
                        params.append(_node_text(p, src_bytes))

            result.functions.append(FunctionDef(
                name=func_name, start_line=start_line, end_line=end_line,
                is_async=is_async, parameters=params,
            ))

            decorators = _collect_decorators_before(node, src_bytes)
            route_decs = [d for d in decorators if any(r in d for r in PYTHON_ROUTE_DECORATORS)]
            if route_decs:
                has_auth = any(a in d for a in PYTHON_AUTH_DECORATORS for d in decorators)
                method = "ANY"
                route = f"/{func_name}"
                for d in route_decs:
                    for m in ("get", "post", "put", "delete", "patch"):
                        if f".{m}" in d.lower():
                            method = m.upper()
                            break
                    rm = re.search(r'["\']([^"\']+)["\']', d)
                    if rm:
                        route = rm.group(1)
                    break
                result.api_endpoints.append(APIEndpoint(
                    method=method, route=route, handler_name=func_name,
                    line=start_line, has_auth_decorator=has_auth,
                ))

        elif ntype == "class_definition":
            name_node = node.child_by_field_name("name")
            if name_node:
                result.class_names.append(_node_text(name_node, src_bytes))

        elif ntype in ("import_statement", "import_from_statement"):
            result.imports.append(_node_text(node, src_bytes).strip())

    return result


def _collect_decorators_before(node, source: bytes) -> list[str]:
    decorators: list[str] = []
    if node.parent is None:
        return decorators
    siblings = node.parent.children
    idx = siblings.index(node)
    for sib in reversed(siblings[:idx]):
        if sib.type == "decorator":
            decorators.append(_node_text(sib, source))
        else:
            break
    return decorators


def _analyze_python_regex(source: str, file_path: str) -> ASTResult:
    result = ASTResult(file_path=file_path, language="python")
    lines = source.splitlines()

    func_re = re.compile(r"^\s*(async\s+)?def\s+(\w+)\s*\(")
    class_re = re.compile(r"^\s*class\s+(\w+)")
    import_re = re.compile(r"^\s*(import|from)\s+(.+)")
    decorator_re = re.compile(r"^\s*@(.+)")

    pending_decorators: list[str] = []

    for i, line in enumerate(lines, 1):
        if m := decorator_re.match(line):
            pending_decorators.append(m.group(1))
        elif m := class_re.match(line):
            result.class_names.append(m.group(1))
            pending_decorators = []
        elif m := func_re.match(line):
            func_name = m.group(2)
            is_async = bool(m.group(1))
            result.functions.append(FunctionDef(
                name=func_name, start_line=i, end_line=i, is_async=is_async,
            ))
            route_decs = [d for d in pending_decorators if any(r in d for r in PYTHON_ROUTE_DECORATORS)]
            if route_decs:
                has_auth = any(a in d for a in PYTHON_AUTH_DECORATORS for d in pending_decorators)
                method = "ANY"
                route = f"/{func_name}"
                for dec in route_decs:
                    for meth in ("get", "post", "put", "delete", "patch"):
                        if f".{meth}" in dec.lower():
                            method = meth.upper()
                            break
                    rm = re.search(r'["\']([^"\']+)["\']', dec)
                    if rm:
                        route = rm.group(1)
                    break
                result.api_endpoints.append(APIEndpoint(
                    method=method, route=route,
                    handler_name=func_name, line=i, has_auth_decorator=has_auth,
                ))
            pending_decorators = []
        elif m := import_re.match(line):
            result.imports.append(line.strip())
            pending_decorators = []
        elif line.strip() and not line.strip().startswith("#"):
            pending_decorators = []

    return result


# ---------------------------------------------------------------------------
# PHP analysis
# ---------------------------------------------------------------------------

def _analyze_php(source: str, file_path: str) -> ASTResult:
    result = ASTResult(file_path=file_path, language="php")
    lines = source.splitlines()

    func_re = re.compile(
        r"^\s*(?:public\s+|protected\s+|private\s+|static\s+)*function\s+(\w+)\s*\(",
        re.IGNORECASE,
    )
    class_re = re.compile(r"^\s*(?:abstract\s+|final\s+)?class\s+(\w+)", re.IGNORECASE)
    require_re = re.compile(r"^\s*(?:require|include)(?:_once)?\s*[(\s]['\"]([^'\"]+)['\"]")

    for i, line in enumerate(lines, 1):
        if m := class_re.match(line):
            result.class_names.append(m.group(1))
        elif m := func_re.match(line):
            func_name = m.group(1)
            result.functions.append(FunctionDef(
                name=func_name, start_line=i, end_line=i, is_async=False,
            ))
            # Scan function body (next 30 lines) for $_GET/$_POST usage
            body = "\n".join(lines[i:min(i + 30, len(lines))])
            if _PHP_REQUEST_RE.search(body):
                result.api_endpoints.append(APIEndpoint(
                    method="ANY", route=f"/{func_name}",
                    handler_name=func_name, line=i, has_auth_decorator=False,
                ))
        elif m := require_re.match(line):
            result.imports.append(m.group(1))

    # Top-level PHP files that use $_GET/$_POST are themselves endpoints
    if _PHP_REQUEST_RE.search(source) and not result.api_endpoints:
        filename = file_path.split("/")[-1].replace(".php", "")
        result.api_endpoints.append(APIEndpoint(
            method="ANY", route=f"/{filename}",
            handler_name=filename, line=1, has_auth_decorator=False,
        ))

    return result


# ---------------------------------------------------------------------------
# TypeScript / JavaScript analysis
# ---------------------------------------------------------------------------

def _analyze_typescript(source: str, file_path: str) -> ASTResult:
    result = ASTResult(file_path=file_path, language="typescript")

    # Express-style routes: app.get("/path", handler)
    for m in _TS_ROUTE_RE.finditer(source):
        method = m.group(1).upper()
        route = m.group(2)
        line = source[:m.start()].count("\n") + 1
        result.api_endpoints.append(APIEndpoint(
            method=method, route=route,
            handler_name=route.strip("/").replace("/", "_") or "handler",
            line=line, has_auth_decorator=False,
        ))

    # NestJS decorator-style routes
    lines = source.splitlines()
    pending_nest_route: tuple[str, str] | None = None
    pending_has_auth = False

    for i, line in enumerate(lines, 1):
        if m := _TS_NEST_RE.search(line):
            pending_nest_route = (m.group(1).upper(), "/" + m.group(2).lstrip("/"))
        if _TS_AUTH_RE.search(line):
            pending_has_auth = True
        # Arrow function or regular function after decorator
        if pending_nest_route and re.search(r"(?:async\s+)?\w+\s*\(", line) and "=>" not in line:
            fm = re.search(r"(?:async\s+)?(\w+)\s*\(", line)
            if fm:
                result.api_endpoints.append(APIEndpoint(
                    method=pending_nest_route[0],
                    route=pending_nest_route[1],
                    handler_name=fm.group(1),
                    line=i, has_auth_decorator=pending_has_auth,
                ))
            pending_nest_route = None
            pending_has_auth = False

    # Extract function/const definitions
    func_re = re.compile(
        r"(?:async\s+)?(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\()"
    )
    for m in func_re.finditer(source):
        name = m.group(1) or m.group(2)
        if name:
            line = source[:m.start()].count("\n") + 1
            result.functions.append(FunctionDef(
                name=name, start_line=line, end_line=line, is_async="async" in source[max(0, m.start()-6):m.start()+6],
            ))

    # Extract class names
    for m in re.finditer(r"(?:export\s+)?(?:abstract\s+)?class\s+(\w+)", source):
        result.class_names.append(m.group(1))

    # Extract imports
    for m in re.finditer(r"(?:import\s+.+\s+from\s+['\"][^'\"]+['\"]|require\(['\"][^'\"]+['\"]\))", source):
        result.imports.append(m.group(0))

    return result


# ---------------------------------------------------------------------------
# Java analysis
# ---------------------------------------------------------------------------

def _analyze_java(source: str, file_path: str) -> ASTResult:
    result = ASTResult(file_path=file_path, language="java")
    lines = source.splitlines()

    pending_route: tuple[str, str] | None = None
    pending_has_auth = False

    for i, line in enumerate(lines, 1):
        if m := _JAVA_ROUTE_RE.search(line):
            ann = m.group(1)
            route_path = m.group(2) or ""
            method = ann.replace("Mapping", "").upper() if ann != "RequestMapping" else "ANY"
            pending_route = (method, "/" + route_path.lstrip("/"))

        if _JAVA_AUTH_RE.search(line):
            pending_has_auth = True

        if m := _JAVA_METHOD_RE.search(line):
            func_name = m.group(1)
            result.functions.append(FunctionDef(
                name=func_name, start_line=i, end_line=i, is_async=False,
            ))
            if pending_route:
                result.api_endpoints.append(APIEndpoint(
                    method=pending_route[0],
                    route=pending_route[1] or f"/{func_name}",
                    handler_name=func_name,
                    line=i, has_auth_decorator=pending_has_auth,
                ))
                pending_route = None
                pending_has_auth = False

        if re.match(r"^\s*(?:public|abstract|final)\s+class\s+(\w+)", line):
            cm = re.search(r"class\s+(\w+)", line)
            if cm:
                result.class_names.append(cm.group(1))

    for m in re.finditer(r"^\s*import\s+(.+);", source, re.MULTILINE):
        result.imports.append(m.group(1).strip())

    return result


# ---------------------------------------------------------------------------
# Generic dispatcher
# ---------------------------------------------------------------------------

LANGUAGE_ANALYZERS = {
    "csharp": _analyze_csharp,
    "python": _analyze_python,
    "php": _analyze_php,
    "typescript": _analyze_typescript,
    "javascript": _analyze_typescript,  # same patterns
    "java": _analyze_java,
}


def _analyze_generic_regex(source: str, file_path: str, language: str) -> ASTResult:
    result = ASTResult(file_path=file_path, language=language)
    func_re = re.compile(r"(?:func|function|def|fn)\s+(\w+)\s*\(")
    for i, line in enumerate(source.splitlines(), 1):
        if m := func_re.search(line):
            result.functions.append(FunctionDef(
                name=m.group(1), start_line=i, end_line=i, is_async=False,
            ))
    return result


def analyze_file(sf: SourceFile) -> ASTResult:
    """Dispatch to the appropriate AST analyzer for a source file."""
    analyzer = LANGUAGE_ANALYZERS.get(sf.language)
    if analyzer:
        try:
            return analyzer(sf.content, sf.relative_path)
        except Exception as exc:
            logger.warning("AST analysis failed for %s: %s", sf.relative_path, exc)
            result = ASTResult(file_path=sf.relative_path, language=sf.language)
            result.parse_errors.append(str(exc))
            return result
    return _analyze_generic_regex(sf.content, sf.relative_path, sf.language)


def analyze_files(source_files: list[SourceFile]) -> list[ASTResult]:
    """Analyze all source files and return AST results."""
    results: list[ASTResult] = []
    for sf in source_files:
        result = analyze_file(sf)
        results.append(result)
        logger.debug(
            "Analyzed %s: %d functions, %d endpoints",
            sf.relative_path, len(result.functions), len(result.api_endpoints),
        )
    return results
