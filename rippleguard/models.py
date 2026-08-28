from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Iterable


class Severity(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        return {Severity.HIGH: 3, Severity.MEDIUM: 2, Severity.LOW: 1}[self]


class Language(str, Enum):
    PYTHON = "python"
    BASH = "bash"
    GHA = "gha"
    GENERIC = "generic"


class NodeKind(str, Enum):
    FILE = "file"
    COMMAND = "command"
    HOST = "host"
    ENV = "env"
    ACTION = "action"
    SECRET_SHAPE = "secret_shape"


class EdgeKind(str, Enum):
    INVOKES = "invokes"
    READS = "reads"
    REACHES = "reaches"
    USES = "uses"
    EXPANDS = "expands"
    CONTAINS = "contains"


@dataclass(frozen=True)
class Finding:
    """A single hardening opportunity on the trust surface."""

    id: str
    severity: Severity
    language: Language
    path: str
    line: int
    message: str
    harden: str
    snippet: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def fingerprint(self) -> str:
        """Stable identity across line shifts: id + path + normalized snippet."""
        snip = " ".join(self.snippet.split())[:160]
        return f"{self.id}|{self.path}|{snip}"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["language"] = self.language.value
        d["fingerprint"] = self.fingerprint()
        return d


@dataclass
class Node:
    id: str
    kind: NodeKind
    label: str
    meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "kind": self.kind.value, "label": self.label, "meta": self.meta}


@dataclass
class Edge:
    src: str
    dst: str
    kind: EdgeKind
    meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"src": self.src, "dst": self.dst, "kind": self.kind.value, "meta": self.meta}


@dataclass
class TrustGraph:
    nodes: dict[str, Node] = field(default_factory=dict)
    edges: list[Edge] = field(default_factory=list)

    def add_node(self, node: Node) -> Node:
        existing = self.nodes.get(node.id)
        if existing is None:
            self.nodes[node.id] = node
            return node
        if node.meta:
            existing.meta.update({k: v for k, v in node.meta.items() if v is not None})
        return existing

    def add_edge(self, src: str, dst: str, kind: EdgeKind, **meta: Any) -> None:
        key = (src, dst, kind)
        for e in self.edges:
            if (e.src, e.dst, e.kind) == key:
                e.meta.update(meta)
                return
        self.edges.append(Edge(src=src, dst=dst, kind=kind, meta=meta))

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges],
        }


@dataclass
class ScanResult:
    root: str
    files_scanned: list[str]
    findings: list[Finding]
    graph: TrustGraph
    errors: list[str] = field(default_factory=list)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity is Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity is Severity.MEDIUM)

    def finding_ids(self) -> set[str]:
        return {f.id for f in self.findings}

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": self.root,
            "files_scanned": self.files_scanned,
            "finding_counts": {
                "total": len(self.findings),
                "high": self.high_count,
                "medium": self.medium_count,
                "low": sum(1 for f in self.findings if f.severity is Severity.LOW),
            },
            "findings": [f.to_dict() for f in self.findings],
            "graph": self.graph.to_dict(),
            "errors": self.errors,
        }


@dataclass
class DiffResult:
    base_label: str
    head_label: str
    added: list[Finding]
    removed: list[Finding]
    added_nodes: list[Node]
    removed_nodes: list[Node]

    @property
    def added_high(self) -> list[Finding]:
        return [f for f in self.added if f.severity is Severity.HIGH]

    def to_dict(self) -> dict[str, Any]:
        return {
            "base": self.base_label,
            "head": self.head_label,
            "added": [f.to_dict() for f in self.added],
            "removed": [f.to_dict() for f in self.removed],
            "added_high_count": len(self.added_high),
            "added_nodes": [n.to_dict() for n in self.added_nodes],
            "removed_nodes": [n.to_dict() for n in self.removed_nodes],
        }


def sorted_findings(findings: Iterable[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (-f.severity.rank, f.path, f.line, f.id),
    )
