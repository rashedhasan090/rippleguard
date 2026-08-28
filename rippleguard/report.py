"""Human / JSON / mermaid reports. ANSI when stdout is a TTY."""

from __future__ import annotations

import json
import os
import sys
from typing import TextIO

from rippleguard.mermaid import to_mermaid
from rippleguard.models import DiffResult, Finding, ScanResult, Severity

_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_RED = "\033[31m"
_YEL = "\033[33m"
_CYN = "\033[36m"
_GRN = "\033[32m"
_MAG = "\033[35m"


def _use_color(stream: TextIO) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return hasattr(stream, "isatty") and stream.isatty()


class Paint:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def wrap(self, code: str, text: str) -> str:
        if not self.enabled:
            return text
        return f"{code}{text}{_RESET}"

    def bold(self, t: str) -> str:
        return self.wrap(_BOLD, t)

    def dim(self, t: str) -> str:
        return self.wrap(_DIM, t)

    def sev(self, severity: Severity, t: str | None = None) -> str:
        text = t or severity.value.upper()
        color = {Severity.HIGH: _RED, Severity.MEDIUM: _YEL, Severity.LOW: _CYN}[severity]
        return self.wrap(color + _BOLD, text)


def _sev_bar(p: Paint, title: str) -> str:
    return p.bold(f"── {title} " + "─" * max(8, 52 - len(title)))


def format_finding(f: Finding, p: Paint) -> str:
    loc = f"{f.path}:{f.line}"
    lines = [
        f"{p.sev(f.severity)}  {p.bold(f.id)}  {p.dim(loc)}",
        f"      {f.message}",
        f"      {p.wrap(_GRN, 'Harden:')} {f.harden}",
    ]
    if f.snippet:
        lines.append(f"      {p.dim(f.snippet)}")
    return "\n".join(lines)


def format_scan(result: ScanResult, mermaid: bool = True, json_block: bool = True) -> str:
    p = Paint(_use_color(sys.stdout))
    high = result.high_count
    med = result.medium_count
    low = len(result.findings) - high - med
    parts = [
        p.wrap(_MAG + _BOLD, "Rippleguard") + p.dim("  trust-surface scan"),
        f"  target    {result.root}",
        f"  files     {len(result.files_scanned)} scanned",
        f"  graph     {len(result.graph.nodes)} nodes · {len(result.graph.edges)} edges",
        (
            f"  findings  {len(result.findings)}  "
            f"({p.sev(Severity.HIGH, str(high))} high · "
            f"{p.sev(Severity.MEDIUM, str(med))} medium · "
            f"{p.sev(Severity.LOW, str(low))} low)"
        ),
        "",
    ]
    if result.errors:
        parts.append(p.wrap(_YEL, "  warnings:"))
        for err in result.errors:
            parts.append(f"    {err}")
        parts.append("")
    if not result.findings:
        parts.append(p.wrap(_GRN, "  No trust-surface expansions matched the catalog."))
    else:
        current: Severity | None = None
        for f in result.findings:
            if f.severity is not current:
                current = f.severity
                parts.append(_sev_bar(p, f.severity.value.upper()))
            parts.append(format_finding(f, p))
            parts.append("")
    if mermaid:
        parts.append(_sev_bar(p, "GRAPH (mermaid)"))
        parts.append("```mermaid")
        parts.append(to_mermaid(result.graph).rstrip())
        parts.append("```")
        parts.append("")
    if json_block:
        parts.append(_sev_bar(p, "JSON"))
        parts.append(json.dumps(result.to_dict(), indent=2, sort_keys=False))
    return "\n".join(parts).rstrip() + "\n"


def format_diff(diff: DiffResult, mermaid: bool = False, json_block: bool = True) -> str:
    p = Paint(_use_color(sys.stdout))
    parts = [
        p.wrap(_MAG + _BOLD, "Rippleguard") + p.dim("  trust-surface diff"),
        f"  base      {diff.base_label}",
        f"  head      {diff.head_label}",
        (
            f"  added     {len(diff.added)} findings "
            f"({p.sev(Severity.HIGH, str(len(diff.added_high)))} high) · "
            f"{len(diff.added_nodes)} new graph nodes"
        ),
        f"  removed   {len(diff.removed)} findings · {len(diff.removed_nodes)} nodes",
        "",
    ]
    if diff.added:
        parts.append(_sev_bar(p, "NEW SURFACE"))
        for f in diff.added:
            parts.append(format_finding(f, p))
            parts.append("")
    else:
        parts.append(p.wrap(_GRN, "  No new trust-surface findings relative to base."))
        parts.append("")
    if diff.added_nodes:
        parts.append(_sev_bar(p, "NEW GRAPH NODES"))
        for n in diff.added_nodes:
            parts.append(f"  + {n.kind.value:12} {n.label}")
        parts.append("")
    if json_block:
        parts.append(_sev_bar(p, "JSON"))
        parts.append(json.dumps(diff.to_dict(), indent=2))
    return "\n".join(parts).rstrip() + "\n"
