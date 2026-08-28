"""Shared helpers for parsers: hosts, file nodes, snippet clipping."""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlparse

from rippleguard.models import EdgeKind, Node, NodeKind, TrustGraph
from rippleguard.redact import redact_text

HOST_IN_URL = re.compile(r"https?://([A-Za-z0-9.-]+)")
SSH_USERHOST = re.compile(r"(?:ssh\s+(?:-i\s+\S+\s+)?)?(?:[A-Za-z0-9._-]+@)([A-Za-z0-9.-]+)")
ENV_FILE_HINTS = (".env", "credentials", "id_rsa", "id_ed25519", ".pem", "secrets.json", "secret.yaml")


def relpath(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def file_node_id(rel: str) -> str:
    return f"file:{rel}"


def command_node_id(cmd: str) -> str:
    return f"cmd:{cmd.strip().lower()}"


def host_node_id(host: str) -> str:
    return f"host:{host.lower()}"


def env_node_id(name: str) -> str:
    return f"env:{name}"


def action_node_id(uses: str) -> str:
    return f"action:{uses}"


def ensure_file_node(graph: TrustGraph, rel: str) -> str:
    nid = file_node_id(rel)
    graph.add_node(Node(id=nid, kind=NodeKind.FILE, label=rel))
    return nid


def add_host(graph: TrustGraph, file_id: str, host: str, via: str = "literal") -> str:
    host = host.lower().rstrip(".")
    hid = host_node_id(host)
    graph.add_node(Node(id=hid, kind=NodeKind.HOST, label=host, meta={"via": via}))
    graph.add_edge(file_id, hid, EdgeKind.REACHES, via=via)
    return hid


def add_command(graph: TrustGraph, file_id: str, cmd: str) -> str:
    cid = command_node_id(cmd)
    graph.add_node(Node(id=cid, kind=NodeKind.COMMAND, label=cmd))
    graph.add_edge(file_id, cid, EdgeKind.INVOKES)
    return cid


def add_env(graph: TrustGraph, file_id: str, name: str) -> str:
    eid = env_node_id(name)
    graph.add_node(Node(id=eid, kind=NodeKind.ENV, label=name))
    graph.add_edge(file_id, eid, EdgeKind.READS)
    return eid


def hosts_from_text(text: str) -> list[str]:
    hosts: list[str] = []
    for m in HOST_IN_URL.finditer(text):
        hosts.append(m.group(1))
    for m in SSH_USERHOST.finditer(text):
        hosts.append(m.group(1))
    # ssh-style host without scheme: user@host
    seen: list[str] = []
    for h in hosts:
        h = h.lower()
        if h not in seen:
            seen.append(h)
    return seen


def host_from_url(url: str) -> str | None:
    try:
        parsed = urlparse(url)
    except Exception:
        return None
    if parsed.hostname:
        return parsed.hostname.lower()
    m = HOST_IN_URL.search(url)
    return m.group(1).lower() if m else None


def looks_like_env_file(path_str: str) -> bool:
    lowered = path_str.lower()
    return any(hint in lowered for hint in ENV_FILE_HINTS)


def snippet_at(text: str, line: int, width: int = 120) -> str:
    lines = text.splitlines()
    if line < 1 or line > len(lines):
        return ""
    return redact_text(lines[line - 1].strip())[:width]


def looks_like_sha(ref: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-fA-F]{40}", ref))
