"""Python AST parser — maps execution, file, and network surface."""

from __future__ import annotations

import ast
from pathlib import Path

from rippleguard.models import EdgeKind, Finding, Language, Node, NodeKind, Severity, TrustGraph
from rippleguard.parseutil import (
    add_command,
    add_env,
    add_host,
    ensure_file_node,
    host_from_url,
    hosts_from_text,
    looks_like_env_file,
    snippet_at,
)
from rippleguard.redact import find_secret_shapes

_SUBPROCESS_FUNCS = {"run", "call", "Popen", "check_output", "check_call", "getoutput", "getstatusoutput"}
_OS_EXEC = {"system", "popen", "execl", "execle", "execlp", "execlpe", "execv", "execve", "execvp", "execvpe"}
_PICKLE_FUNCS = {"load", "loads"}
_REQUEST_FUNCS = {"get", "post", "put", "delete", "patch", "request", "head"}


class _ImportMap:
    def __init__(self) -> None:
        self.bound: dict[str, tuple[str, str | None]] = {}

    def handle(self, node: ast.AST) -> None:
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.asname or alias.name.split(".", 1)[0]
                self.bound[name] = (alias.name, None)
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            for alias in node.names:
                local = alias.asname or alias.name
                self.bound[local] = (mod, alias.name)

    def resolve_call(self, node: ast.Call) -> tuple[str, str] | None:
        func = node.func
        if isinstance(func, ast.Name):
            binding = self.bound.get(func.id)
            if binding and binding[1]:
                return (binding[0], binding[1])
            return (func.id, func.id)
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            owner = func.value.id
            binding = self.bound.get(owner)
            if binding:
                return (binding[0], func.attr)
            return (owner, func.attr)
        if (
            isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Attribute)
            and isinstance(func.value.value, ast.Name)
        ):
            owner = func.value.value.id
            binding = self.bound.get(owner)
            mod = binding[0] if binding else owner
            return (mod, func.attr)
        return None


def _const_str(node: ast.AST | None) -> str | None:
    if node is None:
        return None
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for v in node.values:
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                parts.append(v.value)
            else:
                parts.append("${}")
        return "".join(parts)
    return None


def _kw(node: ast.Call, name: str) -> ast.AST | None:
    for kw in node.keywords:
        if kw.arg == name:
            return kw.value
    return None


def _is_true(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _loader_is_safe(call: ast.Call) -> bool:
    loader = _kw(call, "Loader")
    if loader is None:
        return False
    if isinstance(loader, ast.Attribute) and loader.attr in {"SafeLoader", "CSafeLoader"}:
        return True
    if isinstance(loader, ast.Name) and loader.id in {"SafeLoader", "CSafeLoader"}:
        return True
    return False


def parse_python(path: Path, text: str, rel: str, graph: TrustGraph) -> list[Finding]:
    del path  # interface symmetry with other parsers
    findings: list[Finding] = []
    file_id = ensure_file_node(graph, rel)
    imports = _ImportMap()

    try:
        tree = ast.parse(text, filename=rel)
    except SyntaxError as exc:
        findings.append(
            Finding(
                id="PY-SYNTAX",
                severity=Severity.LOW,
                language=Language.PYTHON,
                path=rel,
                line=exc.lineno or 1,
                message="File could not be parsed as Python; skipped for AST surface mapping.",
                harden="Fix the syntax error so Rippleguard can map this file's trust surface.",
                snippet=snippet_at(text, exc.lineno or 1),
            )
        )
        return findings

    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            imports.handle(node)

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            findings.extend(_handle_call(node, imports, rel, text, graph, file_id))
        elif isinstance(node, ast.Subscript):
            _handle_subscript(node, imports, graph, file_id)

    for host in hosts_from_text(text):
        add_host(graph, file_id, host, via="literal")

    for hit in find_secret_shapes(text):
        findings.append(
            Finding(
                id="SECRET-SHAPE",
                severity=Severity.HIGH,
                language=Language.PYTHON,
                path=rel,
                line=hit.line,
                message=(
                    f"A value matching secret shape `{hit.shape}` is present in source. "
                    f"Redacted form: `{hit.masked}`."
                ),
                harden=(
                    "Remove credentials from the repository. Rotate the credential if it was ever real. "
                    "Load secrets from a manager or a gitignored env file at runtime."
                ),
                snippet=snippet_at(text, hit.line),
                extra={"shape": hit.shape, "masked": hit.masked},
            )
        )
        sid = f"secret:{rel}:{hit.line}"
        graph.add_node(Node(id=sid, kind=NodeKind.SECRET_SHAPE, label=hit.shape))
        graph.add_edge(file_id, sid, EdgeKind.CONTAINS)

    return findings


def _handle_subscript(node: ast.Subscript, imports: _ImportMap, graph: TrustGraph, file_id: str) -> None:
    # os.environ["TOKEN"]
    sl = node.slice
    name = _const_str(sl)
    if not name:
        return
    target = node.value
    if isinstance(target, ast.Attribute) and target.attr == "environ":
        if isinstance(target.value, ast.Name) and target.value.id in {"os", "environ"}:
            add_env(graph, file_id, name)
            return
    if isinstance(target, ast.Name):
        binding = imports.bound.get(target.id)
        if binding and binding[0] in {"os", "os.environ"} and (binding[1] in {None, "environ"}):
            add_env(graph, file_id, name)


def _handle_call(
    node: ast.Call,
    imports: _ImportMap,
    rel: str,
    text: str,
    graph: TrustGraph,
    file_id: str,
) -> list[Finding]:
    findings: list[Finding] = []
    resolved = imports.resolve_call(node)
    line = getattr(node, "lineno", 1)
    snip = snippet_at(text, line)

    func_name = None
    if isinstance(node.func, ast.Name):
        func_name = node.func.id

    if func_name in {"eval", "exec", "compile"}:
        add_command(graph, file_id, func_name)
        findings.append(
            Finding(
                id=f"PY-{func_name.upper()}",
                severity=Severity.HIGH if func_name in {"eval", "exec"} else Severity.MEDIUM,
                language=Language.PYTHON,
                path=rel,
                line=line,
                message=(
                    f"`{func_name}()` executes dynamically constructed code and expands "
                    "the trust surface to that string."
                ),
                harden=(
                    "Do not evaluate untrusted strings. Use `ast.literal_eval` for literals, "
                    "a real parser for config, or an allowlisted dispatcher instead of eval/exec."
                ),
                snippet=snip,
            )
        )
        _maybe_hosts_from_args(node, graph, file_id)

    if func_name == "open" or (resolved and resolved[1] == "open" and resolved[0] in {"open", "builtins", "io"}):
        _handle_open(node, rel, text, graph, file_id, findings)

    if not resolved:
        return findings

    mod, func = resolved
    mod_root = mod.split(".", 1)[0]

    if mod_root == "subprocess" and func in _SUBPROCESS_FUNCS:
        shell = _is_true(_kw(node, "shell"))
        add_command(graph, file_id, f"subprocess.{func}")
        _maybe_hosts_from_args(node, graph, file_id)
        if shell:
            findings.append(
                Finding(
                    id="PY-SUBPROCESS-SHELL",
                    severity=Severity.HIGH,
                    language=Language.PYTHON,
                    path=rel,
                    line=line,
                    message=(
                        "`subprocess` is invoked with `shell=True`, so the system shell "
                        "can interpret metacharacters."
                    ),
                    harden=(
                        "Pass a list of arguments (`['curl', url]`) and keep `shell=False`. "
                        "If a shell is unavoidable, pass only trusted constants."
                    ),
                    snippet=snip,
                )
            )
        first = _const_str(node.args[0]) if node.args else None
        if first:
            for h in hosts_from_text(first):
                add_host(graph, file_id, h, via="subprocess")

    if mod_root == "os" and func in _OS_EXEC:
        add_command(graph, file_id, f"os.{func}")
        findings.append(
            Finding(
                id="PY-OS-SYSTEM" if func in {"system", "popen"} else "PY-OS-EXEC",
                severity=Severity.HIGH,
                language=Language.PYTHON,
                path=rel,
                line=line,
                message=f"`os.{func}()` starts a process through a shell-like interface and expands executable trust.",
                harden=(
                    "Replace with `subprocess.run([...], shell=False, check=True)` and a fixed argument list. "
                    "Avoid interpolating untrusted strings into the command."
                ),
                snippet=snip,
            )
        )
        _maybe_hosts_from_args(node, graph, file_id)

    if (mod_root == "pickle" or mod.endswith("pickle")) and func in _PICKLE_FUNCS:
        add_command(graph, file_id, f"pickle.{func}")
        findings.append(
            Finding(
                id="PY-PICKLE",
                severity=Severity.HIGH,
                language=Language.PYTHON,
                path=rel,
                line=line,
                message="`pickle.load(s)` can execute constructor payloads from the byte stream — a trust-surface expansion.",
                harden="Use `json` or `hmac`-authenticated formats for untrusted data. Never unpickle bytes you did not write.",
                snippet=snip,
            )
        )

    if mod_root == "yaml" and func == "load" and not _loader_is_safe(node):
        add_command(graph, file_id, "yaml.load")
        findings.append(
            Finding(
                id="PY-YAML-LOAD",
                severity=Severity.HIGH,
                language=Language.PYTHON,
                path=rel,
                line=line,
                message="`yaml.load` without `SafeLoader` can construct arbitrary Python objects from YAML.",
                harden="Switch to `yaml.safe_load(...)` (or pass `Loader=yaml.SafeLoader`).",
                snippet=snip,
            )
        )

    if mod_root == "yaml" and func == "unsafe_load":
        add_command(graph, file_id, "yaml.unsafe_load")
        findings.append(
            Finding(
                id="PY-YAML-LOAD",
                severity=Severity.HIGH,
                language=Language.PYTHON,
                path=rel,
                line=line,
                message="`yaml.unsafe_load` is an explicit unsafe loader.",
                harden="Replace with `yaml.safe_load`.",
                snippet=snip,
            )
        )

    if mod_root in {"requests", "httpx"} and func in _REQUEST_FUNCS:
        add_command(graph, file_id, f"{mod_root}.{func}")
        url = _const_str(node.args[0]) if node.args else _const_str(_kw(node, "url"))
        host = host_from_url(url) if url else None
        if host:
            add_host(graph, file_id, host, via=f"{mod_root}.{func}")
        findings.append(
            Finding(
                id="PY-URL-REQUEST",
                severity=Severity.MEDIUM,
                language=Language.PYTHON,
                path=rel,
                line=line,
                message=(
                    f"Outbound HTTP via `{mod_root}.{func}`"
                    + (f" to `{host}`" if host else " (URL not a constant — host is dynamic)")
                    + " adds a network edge to the trust surface."
                ),
                harden=(
                    "Pin the scheme and host to an allowlist. Do not build URLs from untrusted input. "
                    "Prefer TLS and leave certificate verification enabled."
                ),
                snippet=snip,
                extra={"host": host, "url_constant": bool(url)},
            )
        )

    if (mod_root in {"urllib.request", "urllib"} or mod == "urllib.request") and func in {
        "urlopen",
        "urlretrieve",
    }:
        add_command(graph, file_id, f"urllib.{func}")
        url = _const_str(node.args[0]) if node.args else None
        host = host_from_url(url) if url else None
        if host:
            add_host(graph, file_id, host, via="urllib")
        findings.append(
            Finding(
                id="PY-URL-REQUEST",
                severity=Severity.MEDIUM,
                language=Language.PYTHON,
                path=rel,
                line=line,
                message="`urllib` fetches a remote resource, adding a network edge.",
                harden="Allowlist hosts and use HTTPS. Avoid fetching installer scripts and executing them.",
                snippet=snip,
            )
        )

    if mod_root == "os" and func == "getenv":
        name = _const_str(node.args[0]) if node.args else None
        if name:
            add_env(graph, file_id, name)

    if func == "get" and (
        (isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Attribute) and node.func.value.attr == "environ")
        or (mod in {"os.environ", "environ"})
    ):
        name = _const_str(node.args[0]) if node.args else None
        if name:
            add_env(graph, file_id, name)

    return findings


def _handle_open(
    node: ast.Call,
    rel: str,
    text: str,
    graph: TrustGraph,
    file_id: str,
    findings: list[Finding],
) -> None:
    target = _const_str(node.args[0]) if node.args else None
    if not target:
        return
    line = getattr(node, "lineno", 1)
    if looks_like_env_file(target):
        add_command(graph, file_id, "open")
        findings.append(
            Finding(
                id="PY-ENV-FILE",
                severity=Severity.MEDIUM,
                language=Language.PYTHON,
                path=rel,
                line=line,
                message=f"Opens `{target}`, which looks like a credentials or env file, adding a sensitive-read edge.",
                harden=(
                    "Keep env files gitignored. Read them through a dedicated secrets helper, "
                    "and never log the contents."
                ),
                snippet=snippet_at(text, line),
                extra={"target": target},
            )
        )


def _maybe_hosts_from_args(node: ast.Call, graph: TrustGraph, file_id: str) -> None:
    for arg in list(node.args) + [kw.value for kw in node.keywords]:
        s = _const_str(arg)
        if s:
            for h in hosts_from_text(s):
                add_host(graph, file_id, h, via="call-arg")
