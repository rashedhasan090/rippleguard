"""Scan orchestration and git/path diffs."""

from __future__ import annotations

from pathlib import Path

from rippleguard.models import (
    DiffResult,
    EdgeKind,
    Finding,
    Language,
    Node,
    NodeKind,
    ScanResult,
    Severity,
    TrustGraph,
    sorted_findings,
)
from rippleguard.parsers.bash import parse_bash
from rippleguard.parsers.gha import parse_gha
from rippleguard.parsers.python_ast import parse_python
from rippleguard.parseutil import ensure_file_node, snippet_at
from rippleguard.redact import find_secret_shapes
from rippleguard.walk import iter_scan_targets


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def scan_tree(root: Path, exclude: list[str] | None = None) -> ScanResult:
    root = root.resolve()
    graph = TrustGraph()
    findings: list[Finding] = []
    errors: list[str] = []
    scanned: list[str] = []

    for path, lang in iter_scan_targets(root, exclude=exclude):
        rel = path.relative_to(root).as_posix()
        scanned.append(rel)
        try:
            text = _read(path)
        except OSError as exc:
            errors.append(f"{rel}: {exc}")
            continue
        try:
            if lang == "python":
                findings.extend(parse_python(path, text, rel, graph))
            elif lang == "bash":
                findings.extend(parse_bash(path, text, rel, graph))
            elif lang == "gha":
                findings.extend(parse_gha(path, text, rel, graph))
            elif lang == "env":
                findings.extend(parse_env_file(path, text, rel, graph))
        except Exception as exc:  # pragma: no cover - defensive
            errors.append(f"{rel}: {type(exc).__name__}: {exc}")

    findings = sorted_findings(findings)
    return ScanResult(
        root=str(root),
        files_scanned=scanned,
        findings=findings,
        graph=graph,
        errors=errors,
    )


def parse_env_file(path: Path, text: str, rel: str, graph: TrustGraph) -> list[Finding]:
    del path
    findings: list[Finding] = []
    file_id = ensure_file_node(graph, rel)
    for hit in find_secret_shapes(text):
        findings.append(
            Finding(
                id="SECRET-SHAPE",
                severity=Severity.HIGH,
                language=Language.GENERIC,
                path=rel,
                line=hit.line,
                message=(
                    f"A value matching secret shape `{hit.shape}` is present. "
                    f"Redacted form: `{hit.masked}`."
                ),
                harden=(
                    "Remove the value from the repository, rotate it if it was ever real, "
                    "and load it from a secret manager or a gitignored file."
                ),
                snippet=snippet_at(text, hit.line),
                extra={"shape": hit.shape, "masked": hit.masked},
            )
        )
        sid = f"secret:{rel}:{hit.line}"
        graph.add_node(Node(id=sid, kind=NodeKind.SECRET_SHAPE, label=hit.shape))
        graph.add_edge(file_id, sid, EdgeKind.CONTAINS)
    return findings


def diff_results(base: ScanResult, head: ScanResult, base_label: str, head_label: str) -> DiffResult:
    base_fp = {f.fingerprint(): f for f in base.findings}
    head_fp = {f.fingerprint(): f for f in head.findings}
    added = sorted_findings(f for fp, f in head_fp.items() if fp not in base_fp)
    removed = sorted_findings(f for fp, f in base_fp.items() if fp not in head_fp)

    base_nodes = set(base.graph.nodes)
    head_nodes = set(head.graph.nodes)
    added_nodes = [head.graph.nodes[i] for i in sorted(head_nodes - base_nodes)]
    removed_nodes = [base.graph.nodes[i] for i in sorted(base_nodes - head_nodes)]
    return DiffResult(
        base_label=base_label,
        head_label=head_label,
        added=added,
        removed=removed,
        added_nodes=added_nodes,
        removed_nodes=removed_nodes,
    )
