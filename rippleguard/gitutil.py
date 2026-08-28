"""Git helpers for scanning a tree at a ref. Local git only — no remotes."""

from __future__ import annotations

import subprocess
import tarfile
import tempfile
from pathlib import Path


class GitError(RuntimeError):
    pass


def _run_git(args: list[str], cwd: Path) -> str:
    try:
        proc = subprocess.run(
            ["git", *args],
            cwd=cwd,
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise GitError("git is not installed") from exc
    if proc.returncode != 0:
        raise GitError(proc.stderr.strip() or proc.stdout.strip() or "git command failed")
    return proc.stdout


def is_git_repo(path: Path) -> bool:
    try:
        _run_git(["rev-parse", "--is-inside-work-tree"], cwd=path)
        return True
    except GitError:
        return False


def repo_root(path: Path) -> Path:
    out = _run_git(["rev-parse", "--show-toplevel"], cwd=path)
    return Path(out.strip())


def extract_tree(repo: Path, ref: str, dest: Path, subpath: str | None = None) -> Path:
    """Materialize `ref` into dest using `git archive` (no checkout, no network)."""
    args = ["archive", "--format=tar", ref]
    if subpath:
        args.append(subpath)
    try:
        proc = subprocess.run(
            ["git", *args],
            cwd=repo,
            capture_output=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise GitError("git is not installed") from exc
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", "replace").strip()
        raise GitError(err or f"git archive {ref} failed")
    dest.mkdir(parents=True, exist_ok=True)
    tar_path = dest / "tree.tar"
    tar_path.write_bytes(proc.stdout)
    with tarfile.open(tar_path, "r") as tf:
        tf.extractall(dest / "tree")
    tar_path.unlink(missing_ok=True)
    tree = dest / "tree"
    if subpath:
        candidate = tree / subpath
        if candidate.exists():
            return candidate
    return tree


def with_extracted(repo: Path, ref: str, subpath: str | None = None):
    tmp = tempfile.TemporaryDirectory(prefix="rippleguard-")
    root = extract_tree(repo, ref, Path(tmp.name), subpath=subpath)
    return tmp, root
