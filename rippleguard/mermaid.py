"""Mermaid export for a trust graph."""

from __future__ import annotations

import re

from rippleguard.models import TrustGraph

_KIND_SHAPE = {
    "file": "([%s])",
    "command": "[%s]",
    "host": "{{%s}}",
    "env": "([%s])",
    "action": "[/%s/]",
    "secret_shape": "[[%s]]",
}


def _slug(node_id: str) -> str:
    s = re.sub(r"[^A-Za-z0-9_]", "_", node_id)
    if s and s[0].isdigit():
        s = "n_" + s
    return s or "node"


def _label(text: str, limit: int = 42) -> str:
    text = text.replace('"', "'").replace("|", "/").replace("[", "(").replace("]", ")")
    text = text.replace("{", "(").replace("}", ")")
    if len(text) > limit:
        return text[: limit - 1] + "…"
    return text


def to_mermaid(graph: TrustGraph, max_nodes: int = 48) -> str:
    nodes = list(graph.nodes.values())
    # Prefer files, hosts, commands, actions
    rank = {"file": 0, "action": 1, "command": 2, "host": 3, "env": 4, "secret_shape": 5}
    nodes.sort(key=lambda n: (rank.get(n.kind.value, 9), n.label))
    if len(nodes) > max_nodes:
        nodes = nodes[:max_nodes]
    keep = {n.id for n in nodes}

    lines = ["flowchart LR"]
    for n in nodes:
        slug = _slug(n.id)
        shape = _KIND_SHAPE.get(n.kind.value, "[%s]")
        body = shape % _label(n.label)
        lines.append(f'  {slug}{body}')

    seen_edge: set[tuple[str, str, str]] = set()
    for e in graph.edges:
        if e.src not in keep or e.dst not in keep:
            continue
        key = (e.src, e.dst, e.kind.value)
        if key in seen_edge:
            continue
        seen_edge.add(key)
        lines.append(f"  {_slug(e.src)} -->|{e.kind.value}| {_slug(e.dst)}")

    if len(lines) == 1:
        lines.append("  empty([no surface nodes])")
    return "\n".join(lines) + "\n"
