"""Rippleguard CLI."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import sys
from pathlib import Path

from rippleguard import __version__
from rippleguard.engine import diff_results, scan_tree
from rippleguard.gitutil import GitError, is_git_repo, repo_root
from rippleguard.models import Severity
from rippleguard.report import format_diff, format_scan

EXIT_CLEAN = 0
EXIT_SURFACE = 1
EXIT_ERROR = 2


def _fail_rank(name: str) -> int:
    return {"none": 99, "high": 3, "medium": 2, "low": 1}[name]


def _scan_exit(high: int, medium: int, low: int, fail_on: str) -> int:
    if fail_on == "none":
        return EXIT_CLEAN
    rank = _fail_rank(fail_on)
    worst = 0
    if high:
        worst = 3
    elif medium:
        worst = 2
    elif low:
        worst = 1
    return EXIT_SURFACE if worst >= rank else EXIT_CLEAN


def _add_common(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--exclude",
        action="append",
        default=[],
        help="Relative path prefix or directory name to skip (repeatable).",
    )
    p.add_argument(
        "--fail-on",
        choices=("high", "medium", "low", "none"),
        default="high",
        help="Minimum severity that yields exit code 1 (default: high).",
    )
    p.add_argument("--json", action="store_true", help="Print JSON only.")
    p.add_argument("--no-mermaid", action="store_true", help="Omit the mermaid graph from text output.")
    p.add_argument("--no-json-block", action="store_true", help="Omit the JSON block from text output.")
    p.add_argument(
        "--allow-network",
        action="store_true",
        default=False,
        help="Reserved. Rippleguard never makes network calls; hosts are recorded from literals only.",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rippleguard",
        description=(
            "Map the trust surface of Python, Bash, and GitHub Actions, "
            "then diff that graph across git history. Defensive only."
        ),
    )
    parser.add_argument("--version", action="version", version=f"rippleguard {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sc = sub.add_parser("scan", help="Scan a tree and print findings + graph.")
    sc.add_argument("path", nargs="?", default=".", help="Directory to scan (default: .)")
    _add_common(sc)

    df = sub.add_parser("diff", help="Show only NEW trust surface between two snapshots.")
    df.add_argument("path", nargs="?", default=".", help="Git repo or directory (default: .)")
    df.add_argument("--base", default=None, help="Git ref for the old snapshot (default: HEAD~1).")
    df.add_argument("--head", default=None, help="Git ref for the new snapshot (default: working tree).")
    df.add_argument(
        "--old",
        dest="old_path",
        default=None,
        help="Compare two directories instead of git refs (use with --new).",
    )
    df.add_argument(
        "--new",
        dest="new_path",
        default=None,
        help="Head directory when using --old/--new path mode.",
    )
    _add_common(df)

    hk = sub.add_parser("hook", help="Install or run the git hook companion.")
    hk_sub = hk.add_subparsers(dest="hook_cmd", required=True)
    inst = hk_sub.add_parser("install", help="Install pre-commit / pre-push hooks in this repo.")
    inst.add_argument("--pre-commit", action="store_true", default=True)
    inst.add_argument("--pre-push", action="store_true")
    inst.add_argument("--root", default=".", help="Repo root (default: .)")
    run = hk_sub.add_parser("run", help="Run the hook check (used by scripts/rippleguard-hook).")
    run.add_argument("--mode", choices=("pre-commit", "pre-push"), default="pre-commit")
    run.add_argument("path", nargs="?", default=".")
    _add_common(run)

    return parser


def _print_allow_network_note(allow: bool) -> None:
    if allow:
        print(
            "note: --allow-network is set, but this version still does not fetch URLs or resolve actions.",
            file=sys.stderr,
        )


def cmd_scan(args: argparse.Namespace) -> int:
    _print_allow_network_note(args.allow_network)
    root = Path(args.path).resolve()
    if not root.exists():
        print(f"rippleguard: path not found: {root}", file=sys.stderr)
        return EXIT_ERROR
    result = scan_tree(root, exclude=args.exclude)
    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        sys.stdout.write(
            format_scan(
                result,
                mermaid=not args.no_mermaid,
                json_block=not args.no_json_block,
            )
        )
    low = len(result.findings) - result.high_count - result.medium_count
    return _scan_exit(result.high_count, result.medium_count, low, args.fail_on)


def _scan_git_ref(repo: Path, ref: str, exclude: list[str], subpath: str | None) -> tuple:
    import tempfile

    from rippleguard.gitutil import extract_tree as _extract

    tmp = tempfile.TemporaryDirectory(prefix="rippleguard-")
    try:
        tree = _extract(repo, ref, Path(tmp.name), subpath=subpath)
        result = scan_tree(tree, exclude=exclude)
        return tmp, result
    except Exception:
        tmp.cleanup()
        raise


def cmd_diff(args: argparse.Namespace) -> int:
    _print_allow_network_note(args.allow_network)
    exclude = args.exclude
    temps: list = []
    try:
        if args.old_path or args.new_path:
            if not (args.old_path and args.new_path):
                print("rippleguard: --old and --new must be used together", file=sys.stderr)
                return EXIT_ERROR
            old_p = Path(args.old_path).resolve()
            new_p = Path(args.new_path).resolve()
            if not old_p.exists() or not new_p.exists():
                print("rippleguard: --old/--new path not found", file=sys.stderr)
                return EXIT_ERROR
            base = scan_tree(old_p, exclude=exclude)
            head = scan_tree(new_p, exclude=exclude)
            diff = diff_results(base, head, str(old_p), str(new_p))
        else:
            root = Path(args.path).resolve()
            if not is_git_repo(root):
                print(
                    "rippleguard: not a git repository; use --old/--new to diff two directories",
                    file=sys.stderr,
                )
                return EXIT_ERROR
            repo = repo_root(root)
            try:
                rel = root.resolve().relative_to(repo.resolve()).as_posix()
            except ValueError:
                rel = "."
            subpath = None if rel in {".", ""} else rel
            base_ref = args.base or "HEAD~1"
            head_ref = args.head  # None => working tree
            tmp_b, base = _scan_git_ref(repo, base_ref, exclude, subpath)
            temps.append(tmp_b)
            if head_ref:
                tmp_h, head = _scan_git_ref(repo, head_ref, exclude, subpath)
                temps.append(tmp_h)
                head_label = head_ref
            else:
                head = scan_tree(root, exclude=exclude)
                head_label = "working-tree"
            diff = diff_results(base, head, base_ref, head_label)

        if args.json:
            print(json.dumps(diff.to_dict(), indent=2))
        else:
            sys.stdout.write(
                format_diff(
                    diff,
                    mermaid=not args.no_mermaid,
                    json_block=not args.no_json_block,
                )
            )
        low = sum(1 for f in diff.added if f.severity is Severity.LOW)
        med = sum(1 for f in diff.added if f.severity is Severity.MEDIUM)
        return _scan_exit(len(diff.added_high), med, low, args.fail_on)
    except GitError as exc:
        print(f"rippleguard: {exc}", file=sys.stderr)
        return EXIT_ERROR
    finally:
        for t in temps:
            t.cleanup()


def _hook_script() -> Path:
    pkg = Path(__file__).resolve().parent / "data" / "rippleguard-hook"
    if pkg.exists():
        return pkg
    # repo checkout
    return Path(__file__).resolve().parents[1] / "scripts" / "rippleguard-hook"


def cmd_hook_install(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    if not is_git_repo(root):
        print("rippleguard: not a git repository", file=sys.stderr)
        return EXIT_ERROR
    repo = repo_root(root)
    hooks = repo / ".git" / "hooks"
    hooks.mkdir(parents=True, exist_ok=True)
    src = _hook_script()
    if not src.exists():
        print(f"rippleguard: hook script missing at {src}", file=sys.stderr)
        return EXIT_ERROR
    names = ["pre-commit"]
    if args.pre_push:
        names.append("pre-push")
    for name in names:
        dest = hooks / name
        shutil.copyfile(src, dest)
        dest.chmod(dest.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
        print(f"installed {dest}")
    return EXIT_CLEAN


def cmd_hook_run(args: argparse.Namespace) -> int:
    """pre-commit: working tree vs HEAD; pre-push: HEAD vs HEAD~1 (or upstream)."""
    root = Path(args.path).resolve()
    ns = argparse.Namespace(
        path=str(root),
        base="HEAD" if args.mode == "pre-commit" else (os.environ.get("RIPPLEGUARD_BASE") or "HEAD~1"),
        head=None if args.mode == "pre-commit" else "HEAD",
        old_path=None,
        new_path=None,
        exclude=args.exclude,
        fail_on=args.fail_on,
        json=args.json,
        no_mermaid=True,
        no_json_block=args.no_json_block,
        allow_network=False,
    )
    return cmd_diff(ns)


def main(argv: list[str] | None = None) -> int:
    try:
        parser = build_parser()
        args = parser.parse_args(argv)
        if args.cmd == "scan":
            return cmd_scan(args)
        if args.cmd == "diff":
            return cmd_diff(args)
        if args.cmd == "hook":
            if args.hook_cmd == "install":
                return cmd_hook_install(args)
            if args.hook_cmd == "run":
                return cmd_hook_run(args)
        parser.print_help()
        return EXIT_ERROR
    except KeyboardInterrupt:
        print("rippleguard: interrupted", file=sys.stderr)
        return EXIT_ERROR
    except BrokenPipeError:
        return EXIT_CLEAN


if __name__ == "__main__":
    raise SystemExit(main())
