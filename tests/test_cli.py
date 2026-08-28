from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _rg(*args: str, check: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "rippleguard", *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=check,
    )


def test_cli_scan_insecure_exit_1():
    proc = _rg("scan", "fixtures/insecure", "--no-json-block")
    assert proc.returncode == 1, proc.stderr + proc.stdout
    assert "PY-SUBPROCESS-SHELL" in proc.stdout
    assert "SH-CURL-BASH" in proc.stdout or "GHA-CURL-PIPE" in proc.stdout
    assert "flowchart" in proc.stdout
    assert "deploy.py:" in proc.stdout


def test_cli_scan_fixed_exit_0():
    proc = _rg("scan", "fixtures/fixed", "--fail-on", "high", "--no-json-block")
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_cli_json_only():
    proc = _rg("scan", "fixtures/insecure", "--json")
    assert proc.returncode == 1
    assert proc.stdout.lstrip().startswith("{")
    assert "findings" in proc.stdout


def test_cli_diff_old_new():
    proc = _rg(
        "diff",
        "--old",
        "fixtures/fixed",
        "--new",
        "fixtures/insecure",
        "--no-json-block",
    )
    assert proc.returncode == 1, proc.stderr + proc.stdout
    assert "NEW SURFACE" in proc.stdout or "PY-SUBPROCESS-SHELL" in proc.stdout


def test_cli_missing_path():
    proc = _rg("scan", "does-not-exist-rippleguard")
    assert proc.returncode == 2


def test_git_diff_generated_commits(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "dev@example.invalid"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "Rippleguard Fixture"], cwd=repo, check=True)

    def copytree(src: Path, dest: Path) -> None:
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(src, dest)

    copytree(ROOT / "fixtures" / "fixed", repo / "app")
    subprocess.run(["git", "add", "."], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "fixed"], cwd=repo, check=True, capture_output=True)

    copytree(ROOT / "fixtures" / "insecure", repo / "app")
    subprocess.run(["git", "add", "."], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "insecure expansions"], cwd=repo, check=True, capture_output=True)

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "rippleguard",
            "diff",
            str(repo / "app"),
            "--base",
            "HEAD~1",
            "--head",
            "HEAD",
            "--no-json-block",
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 1, proc.stderr + proc.stdout
    assert "SH-CURL-BASH" in proc.stdout or "PY-SUBPROCESS-SHELL" in proc.stdout
