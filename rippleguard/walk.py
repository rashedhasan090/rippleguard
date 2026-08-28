"""Walk a tree for Python, Bash, and GitHub Actions files."""

from __future__ import annotations

import os
from pathlib import Path

SKIP_DIR_NAMES = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "__pycache__",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    "dist",
    "build",
    ".eggs",
    ".ruff_cache",
    "htmlcov",
}

PYTHON_SUFFIXES = {".py", ".pyw"}
BASH_SUFFIXES = {".sh", ".bash", ".ksh", ".zsh"}
YAML_SUFFIXES = {".yml", ".yaml"}

BASH_SHEBANGS = ("#!/bin/sh", "#!/bin/bash", "#!/usr/bin/env bash", "#!/usr/bin/env sh", "#!/usr/bin/bash")


def _is_excluded(path: Path, root: Path, exclude: list[str]) -> bool:
    rel = path.relative_to(root).as_posix()
    for rule in exclude:
        rule = rule.strip().rstrip("/")
        if not rule:
            continue
        if rel == rule or rel.startswith(rule + "/"):
            return True
        if path.name == rule:
            return True
    return False


def _looks_like_bash(path: Path) -> bool:
    if path.suffix.lower() in BASH_SUFFIXES:
        return True
    if path.suffix:
        return False
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            first = fh.readline()
    except OSError:
        return False
    stripped = first.strip()
    return any(stripped.startswith(s) for s in BASH_SHEBANGS)


def _is_gha_workflow(path: Path, root: Path) -> bool:
    if path.suffix.lower() not in YAML_SUFFIXES:
        return False
    rel = path.relative_to(root).as_posix()
    return "/.github/workflows/" in f"/{rel}" or rel.startswith(".github/workflows/")


def _looks_like_env_secret_file(path: Path) -> bool:
    name = path.name.lower()
    return name == ".env" or name.endswith(".env") or name.startswith(".env")


def iter_scan_targets(root: Path, exclude: list[str] | None = None) -> list[tuple[Path, str]]:
    """Return (path, language) pairs. language in python|bash|gha|env."""
    root = root.resolve()
    exclude = list(exclude or [])
    found: list[tuple[Path, str]] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIR_NAMES]
        base = Path(dirpath)
        for name in filenames:
            path = base / name
            if _is_excluded(path, root, exclude):
                continue
            if not path.is_file():
                continue
            if _is_gha_workflow(path, root):
                found.append((path, "gha"))
            elif path.suffix.lower() in PYTHON_SUFFIXES:
                found.append((path, "python"))
            elif _looks_like_bash(path):
                found.append((path, "bash"))
            elif _looks_like_env_secret_file(path):
                found.append((path, "env"))
    found.sort(key=lambda t: t[0].as_posix())
    return found
