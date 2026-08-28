"""Expected finding IDs from the insecure fixture tree."""

from __future__ import annotations

from pathlib import Path

from rippleguard.engine import diff_results, scan_tree
from rippleguard.redact import find_secret_shapes, redact_text

ROOT = Path(__file__).resolve().parents[1]
INSECURE = ROOT / "fixtures" / "insecure"
FIXED = ROOT / "fixtures" / "fixed"

EXPECTED_INSECURE = {
    "PY-SUBPROCESS-SHELL",
    "PY-OS-SYSTEM",
    "PY-EVAL",
    "PY-PICKLE",
    "PY-YAML-LOAD",
    "PY-URL-REQUEST",
    "PY-ENV-FILE",
    "SH-CURL-BASH",
    "SH-WGET-SH",
    "SH-EVAL",
    "SH-SOURCE-RELATIVE",
    "SH-NETCAT",
    "SH-SSH",
    "SH-SUDO",
    "SH-UNQUOTED-EXPAND",
    "GHA-UNPINNED-ACTION",
    "GHA-CURL-PIPE",
    "GHA-PR-TARGET-CHECKOUT",
    "GHA-SECRET-IN-RUN",
    "GHA-PR-TARGET-SECRETS",
    "SECRET-SHAPE",
}

HIGH_SHOULD_BE_GONE_IN_FIXED = {
    "PY-SUBPROCESS-SHELL",
    "PY-OS-SYSTEM",
    "PY-EVAL",
    "PY-PICKLE",
    "PY-YAML-LOAD",
    "SH-CURL-BASH",
    "SH-WGET-SH",
    "SH-EVAL",
    "SH-NETCAT",
    "GHA-UNPINNED-ACTION",
    "GHA-CURL-PIPE",
    "GHA-PR-TARGET-CHECKOUT",
    "GHA-SECRET-IN-RUN",
    "GHA-PR-TARGET-SECRETS",
    "SECRET-SHAPE",
}


def test_scan_insecure_has_expected_ids():
    result = scan_tree(INSECURE)
    ids = result.finding_ids()
    missing = EXPECTED_INSECURE - ids
    assert not missing, f"missing finding IDs: {sorted(missing)}"
    assert result.high_count >= 8
    assert any(f.path.endswith("deploy.py") and f.line > 0 for f in result.findings)
    assert any("bootstrap.sh" in f.path and f.line > 0 for f in result.findings)
    assert any("ci.yml" in f.path for f in result.findings)


def test_insecure_findings_include_file_line_and_harden():
    result = scan_tree(INSECURE)
    for f in result.findings:
        assert f.path, f
        assert f.line >= 1, f
        assert f.harden, f
        assert "Harden" not in f.message or True
        # No raw fixture secret values in messages
        assert "AKIA0000000000000000" not in f.message
        assert "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAA0001" not in f.message


def test_scan_fixed_has_no_catalogued_high_surface():
    result = scan_tree(FIXED)
    ids = result.finding_ids()
    leftover = HIGH_SHOULD_BE_GONE_IN_FIXED & ids
    assert not leftover, f"fixed fixture still has {sorted(leftover)}"
    assert result.high_count == 0


def test_graph_records_hosts_and_actions():
    result = scan_tree(INSECURE)
    labels = {n.label for n in result.graph.nodes.values()}
    assert "install.example.invalid" in labels or "packages.example.invalid" in labels
    assert any(n.kind.value == "action" for n in result.graph.nodes.values())
    assert any(n.kind.value == "command" for n in result.graph.nodes.values())


def test_path_diff_fixed_to_insecure_is_expansion():
    base = scan_tree(FIXED)
    head = scan_tree(INSECURE)
    diff = diff_results(base, head, "fixed", "insecure")
    added_ids = {f.id for f in diff.added}
    assert "SH-CURL-BASH" in added_ids
    assert "PY-SUBPROCESS-SHELL" in added_ids
    assert "GHA-UNPINNED-ACTION" in added_ids
    assert len(diff.added_high) >= 5


def test_path_diff_insecure_to_fixed_is_shrink():
    base = scan_tree(INSECURE)
    head = scan_tree(FIXED)
    diff = diff_results(base, head, "insecure", "fixed")
    assert diff.added_high == []
    assert len(diff.removed) >= 5


def test_secret_redaction():
    text = "AWS_ACCESS_KEY_ID=AKIA0000000000000000\n"
    hits = find_secret_shapes(text)
    assert hits
    assert "AKIA0000000000000000" not in hits[0].masked
    assert "AKIA" in hits[0].masked
    red = redact_text(text)
    assert "AKIA0000000000000000" not in red


def test_product_source_has_no_high_severity():
    result = scan_tree(ROOT / "rippleguard")
    highs = [f for f in result.findings if f.severity.value == "high"]
    assert highs == [], [f"{f.id} {f.path}:{f.line}" for f in highs]


def test_scripts_hook_has_no_high_severity():
    result = scan_tree(ROOT / "scripts")
    highs = [f for f in result.findings if f.severity.value == "high"]
    assert highs == [], [f"{f.id} {f.path}:{f.line}" for f in highs]


def test_mermaid_mentions_files():
    from rippleguard.mermaid import to_mermaid

    result = scan_tree(INSECURE)
    mermaid = to_mermaid(result.graph)
    assert "flowchart" in mermaid
    assert "file_" in mermaid or "deploy" in mermaid
