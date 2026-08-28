"""GitHub Actions workflow mapper — run scripts, actions, secrets, PR trust."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from rippleguard.models import EdgeKind, Finding, Language, Node, NodeKind, Severity, TrustGraph
from rippleguard.parsers.bash import parse_bash
from rippleguard.parseutil import action_node_id, ensure_file_node, looks_like_sha, snippet_at
from rippleguard.redact import find_secret_shapes

_SECRET_IN_RUN = re.compile(r"\$\{\{\s*secrets\.([A-Za-z0-9_]+)\s*\}\}")
_PR_HEAD_REF = re.compile(
    r"github\.event\.pull_request\.head\.(sha|ref)|github\.head_ref",
    re.IGNORECASE,
)


def _load_workflow(text: str) -> Any:
    # SafeLoader only. The workflow key `on` may arrive as boolean True (YAML 1.1).
    return yaml.safe_load(text)


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _trigger_names(doc: dict[str, Any]) -> list[str]:
    on = doc.get("on", doc.get(True))
    if on is None:
        return []
    if isinstance(on, str):
        return [on]
    if isinstance(on, list):
        return [str(x) for x in on]
    if isinstance(on, dict):
        names: list[str] = []
        for k in on.keys():
            if k is True:
                names.append("on")
            else:
                names.append(str(k))
        return names
    return [str(on)]


def _uses_ref(uses: str) -> tuple[str, str | None]:
    """Split 'owner/action@ref' or './local' or 'docker://'."""
    if uses.startswith("docker://") or uses.startswith("./") or uses.startswith(".\\"):
        return uses, None
    if "@" not in uses:
        return uses, None
    action, ref = uses.rsplit("@", 1)
    return action, ref


def parse_gha(path: Path, text: str, rel: str, graph: TrustGraph) -> list[Finding]:
    findings: list[Finding] = []
    file_id = ensure_file_node(graph, rel)

    try:
        doc = _load_workflow(text)
    except yaml.YAMLError as exc:
        findings.append(
            Finding(
                id="GHA-YAML-ERROR",
                severity=Severity.LOW,
                language=Language.GHA,
                path=rel,
                line=1,
                message=f"Workflow YAML could not be parsed: {exc.__class__.__name__}.",
                harden="Fix the YAML so Rippleguard can map jobs, steps, and secret edges.",
                snippet=snippet_at(text, 1),
            )
        )
        return findings

    if not isinstance(doc, dict):
        return findings

    triggers = {t.lower() for t in _trigger_names(doc)}
    has_pr_target = "pull_request_target" in triggers
    jobs = doc.get("jobs") or {}
    if not isinstance(jobs, dict):
        jobs = {}

    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        steps = job.get("steps") or []
        if not isinstance(steps, list):
            continue
        for step in steps:
            if not isinstance(step, dict):
                continue
            findings.extend(
                _scan_step(
                    step=step,
                    job_name=str(job_name),
                    rel=rel,
                    text=text,
                    graph=graph,
                    file_id=file_id,
                    has_pr_target=has_pr_target,
                )
            )

    if has_pr_target:
        # Workflow-level note if any secret is referenced anywhere
        if "secrets." in text:
            line = 1
            for i, raw in enumerate(text.splitlines(), start=1):
                if "pull_request_target" in raw:
                    line = i
                    break
            findings.append(
                Finding(
                    id="GHA-PR-TARGET-SECRETS",
                    severity=Severity.HIGH,
                    language=Language.GHA,
                    path=rel,
                    line=line,
                    message=(
                        "`pull_request_target` runs in the base-repo context, so secrets are available to the "
                        "workflow even for fork PRs. Combined with untrusted code this expands CI trust."
                    ),
                    harden=(
                        "Prefer `pull_request` for untrusted work. If `pull_request_target` is required, "
                        "never check out PR code, and do not pass secrets into steps that process PR content."
                    ),
                    snippet=snippet_at(text, line),
                )
            )

    for hit in find_secret_shapes(text):
        findings.append(
            Finding(
                id="SECRET-SHAPE",
                severity=Severity.HIGH,
                language=Language.GHA,
                path=rel,
                line=hit.line,
                message=f"Secret shape `{hit.shape}` in a workflow. Redacted: `{hit.masked}`.",
                harden="Never commit credential values. Use GitHub Actions secrets and map them via `env:`.",
                snippet=snippet_at(text, hit.line),
                extra={"shape": hit.shape, "masked": hit.masked},
            )
        )

    return findings


def _line_of(text: str, needle: str, default: int = 1) -> int:
    for i, raw in enumerate(text.splitlines(), start=1):
        if needle in raw:
            return i
    return default


def _scan_step(
    *,
    step: dict[str, Any],
    job_name: str,
    rel: str,
    text: str,
    graph: TrustGraph,
    file_id: str,
    has_pr_target: bool,
) -> list[Finding]:
    findings: list[Finding] = []
    uses = step.get("uses")
    run = step.get("run")

    if isinstance(uses, str):
        action, ref = _uses_ref(uses)
        nid = action_node_id(uses)
        graph.add_node(Node(id=nid, kind=NodeKind.ACTION, label=uses, meta={"job": job_name}))
        graph.add_edge(file_id, nid, EdgeKind.USES, job=job_name)
        line = _line_of(text, uses)
        local = uses.startswith("./") or uses.startswith(".\\")
        docker = uses.startswith("docker://")
        if not local and not docker and (ref is None or not looks_like_sha(ref)):
            findings.append(
                Finding(
                    id="GHA-UNPINNED-ACTION",
                    severity=Severity.HIGH,
                    language=Language.GHA,
                    path=rel,
                    line=line,
                    message=(
                        f"Action `{action}` is not pinned to a 40-character commit SHA"
                        + (f" (ref `{ref}`)." if ref else ".")
                    ),
                    harden=(
                        f"Pin `{action}` to a full commit SHA and leave the tag in a comment, "
                        f"e.g. `uses: {action}@<sha>  # vX.Y.Z`."
                    ),
                    snippet=snippet_at(text, line),
                    extra={"action": action, "ref": ref},
                )
            )
        with_block = step.get("with") or {}
        if has_pr_target and isinstance(with_block, dict):
            ref_val = str(with_block.get("ref") or "")
            if _PR_HEAD_REF.search(ref_val) or "pull_request.head" in ref_val:
                findings.append(
                    Finding(
                        id="GHA-PR-TARGET-CHECKOUT",
                        severity=Severity.HIGH,
                        language=Language.GHA,
                        path=rel,
                        line=line,
                        message=(
                            "This step checks out pull-request head code from a `pull_request_target` workflow, "
                            "so untrusted files run with base-repo privileges."
                        ),
                        harden=(
                            "Do not check out `github.event.pull_request.head.*` on `pull_request_target`. "
                            "Build untrusted code in `pull_request` without secrets, then promote artifacts."
                        ),
                        snippet=snippet_at(text, line),
                    )
                )

    if isinstance(run, str):
        line = _line_of(text, run.splitlines()[0][:40]) if run.splitlines() else 1
        # Parse the run block as bash — findings inherit this workflow path.
        bash_findings = parse_bash(Path(rel), run, rel, graph)
        for f in bash_findings:
            # Re-home as GHA language; keep SH-* ids so the catalog is stable, plus GHA-CURL-PIPE alias.
            if f.id in {"SH-CURL-BASH", "SH-WGET-SH"}:
                wf_line = line + max(0, (f.line or 1) - 1)
                findings.append(
                    Finding(
                        id="GHA-CURL-PIPE",
                        severity=Severity.HIGH,
                        language=Language.GHA,
                        path=rel,
                        line=wf_line,
                        message="A workflow `run:` step pipes remote content into a shell.",
                        harden=(
                            "Do not install tools with `curl | sh` in CI. Use a hashed action, a pinned package, "
                            "or a verified binary already in the runner image."
                        ),
                        snippet=f.snippet or snippet_at(text, wf_line),
                    )
                )
            elif f.id == "SECRET-SHAPE":
                continue
            else:
                wf_line = line + max(0, (f.line or 1) - 1)
                findings.append(
                    Finding(
                        id=f.id,
                        severity=f.severity,
                        language=Language.GHA,
                        path=rel,
                        line=wf_line,
                        message=f"`run:` step: {f.message}",
                        harden=f.harden,
                        snippet=f.snippet,
                        extra=f.extra,
                    )
                )
        for m in _SECRET_IN_RUN.finditer(run):
            name = m.group(1)
            graph.add_node(Node(id=f"env:secrets.{name}", kind=NodeKind.ENV, label=f"secrets.{name}"))
            graph.add_edge(file_id, f"env:secrets.{name}", EdgeKind.READS)
            findings.append(
                Finding(
                    id="GHA-SECRET-IN-RUN",
                    severity=Severity.HIGH,
                    language=Language.GHA,
                    path=rel,
                    line=line,
                    message=(
                        f"`secrets.{name}` is interpolated into a `run:` script. That expands the secret "
                        "into the process argv and log surface."
                    ),
                    harden=(
                        f"Map the secret through `env:` (e.g. `env: {{ TOKEN: ${{{{ secrets.{name} }}}} }}`) "
                        "and read `$TOKEN` inside the script. Never `${{ secrets.* }}` inside `run:`."
                    ),
                    snippet=snippet_at(text, line),
                    extra={"secret": name},
                )
            )

    return findings
