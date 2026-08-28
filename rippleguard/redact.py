"""Detect secret *shapes* and redact values. Never store or print raw secrets."""

from __future__ import annotations

import re
from dataclasses import dataclass

# Shapes only — values are replaced with a mask before they leave this module.
# Intentionally narrow: do not flag GitHub `${{ secrets.* }}` mappings or identifiers
# that merely contain the word "secret" / "token".
_SHAPES: list[tuple[str, re.Pattern[str]]] = [
    ("aws-access-key-id", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("github-pat", re.compile(r"ghp_[A-Za-z0-9]{20,}")),
    ("github-fine-grained-pat", re.compile(r"github_pat_[A-Za-z0-9_]{20,}")),
    ("private-key-block", re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----")),
    (
        "generic-bearer",
        re.compile(r"(?i)(bearer\s+)([A-Za-z0-9\-._~+/]{20,}=*)"),
    ),
]


@dataclass(frozen=True)
class SecretHit:
    shape: str
    line: int
    masked: str


def mask_value(value: str, keep: int = 4) -> str:
    if len(value) <= keep:
        return "*" * len(value)
    return value[:keep] + ("*" * min(24, max(4, len(value) - keep)))


def _skip_line(line: str) -> bool:
    # References, not committed values.
    if "${{" in line:
        return True
    return False


def find_secret_shapes(text: str) -> list[SecretHit]:
    hits: list[SecretHit] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if _skip_line(line):
            continue
        for shape, pat in _SHAPES:
            for m in pat.finditer(line):
                raw = m.group(0)
                if shape == "generic-bearer" and m.lastindex and m.lastindex >= 2:
                    prefix = m.group(1)
                    masked = prefix + mask_value(m.group(2))
                else:
                    masked = mask_value(raw, keep=4)
                hits.append(SecretHit(shape=shape, line=lineno, masked=masked))
    return hits


def redact_text(text: str) -> str:
    """Return text with secret-shaped values masked. Safe to log."""
    out_lines: list[str] = []
    for line in text.splitlines():
        if _skip_line(line):
            out_lines.append(line)
            continue
        updated = line
        for hit_shape, pat in _SHAPES:
            def _sub(m: re.Match[str], shape: str = hit_shape) -> str:
                if shape == "generic-bearer" and m.lastindex and m.lastindex >= 2:
                    return m.group(1) + mask_value(m.group(2))
                return mask_value(m.group(0), keep=4)

            updated = pat.sub(_sub, updated)
        out_lines.append(updated)
    return "\n".join(out_lines)
