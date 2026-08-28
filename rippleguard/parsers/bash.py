"""Best-effort Bash surface mapper. Not a full shell parser — defensive heuristics."""

from __future__ import annotations

import re
from pathlib import Path

from rippleguard.models import EdgeKind, Finding, Language, Node, NodeKind, Severity, TrustGraph
from rippleguard.parseutil import (
    add_command,
    add_host,
    ensure_file_node,
    hosts_from_text,
    snippet_at,
)
from rippleguard.redact import find_secret_shapes

_COMMENT = re.compile(r"(^|\s)#" )
_PIPE_SINK = re.compile(
    r"\|\s*(sudo\s+)?(bash|sh|zsh|ksh|dash)\b",
    re.IGNORECASE,
)
_CURL = re.compile(r"(?:^|[;&|`(\n])\s*(curl)\b", re.IGNORECASE)
_WGET = re.compile(r"(?:^|[;&|`(\n])\s*(wget)\b", re.IGNORECASE)
_EVAL = re.compile(r"(?:^|[;&|`(\n])\s*eval\b")
_SOURCE = re.compile(r"(?:^|[;&|`(\n])\s*(?:source|\.)\s+(\S+)")
_NC = re.compile(r"(?:^|[;&|`(\n])\s*(nc|ncat|netcat)\b")
_SSH = re.compile(r"(?:^|[;&|`(\n])\s*ssh\b")
_SUDO = re.compile(r"(?:^|[;&|`(\n])\s*sudo\b")
_UNQUOTED = re.compile(r"(?<!\\)\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))")
_SAFE_SPECIAL = {"?", "#", "$", "!", "0"}

# Expansions we do not flag (positional / common well-known dirs used quoted in harden guidance)
_BENIGN_UNQUOTED = {
    "LINENO",
    "RANDOM",
    "SECONDS",
    "BASHPID",
    # GitHub Actions file-redirect targets; still better quoted, but not high-signal.
    "GITHUB_ENV",
    "GITHUB_OUTPUT",
    "GITHUB_PATH",
    "GITHUB_STEP_SUMMARY",
    "GITHUB_WORKSPACE",
    "GITHUB_ACTION_PATH",
}


def _join_continuations(text: str) -> str:
    lines = text.splitlines()
    out: list[str] = []
    buf = ""
    for line in lines:
        if buf:
            buf = buf + " " + line
        else:
            buf = line
        if buf.rstrip().endswith("\\"):
            buf = buf.rstrip()[:-1]
            continue
        out.append(buf)
        buf = ""
    if buf:
        out.append(buf)
    return "\n".join(out)


def _strip_quoted_regions(line: str) -> tuple[str, str]:
    """Return (line_with_quotes_blanked_for_detection, original)."""
    chars = list(line)
    i = 0
    n = len(chars)
    quote: str | None = None
    while i < n:
        c = chars[i]
        if quote:
            if c == quote and (quote == "'" or chars[i - 1] != "\\"):
                quote = None
            elif quote in {'"', "'"}:
                chars[i] = " "
            i += 1
            continue
        if c in {"'", '"'}:
            quote = c
            i += 1
            continue
        i += 1
    return "".join(chars), line


def _code_part(line: str) -> str:
    """Drop trailing comment if # is outside quotes."""
    in_s = in_d = False
    for i, c in enumerate(line):
        if c == "'" and not in_d:
            in_s = not in_s
        elif c == '"' and not in_s:
            if i == 0 or line[i - 1] != "\\":
                in_d = not in_d
        elif c == "#" and not in_s and not in_d:
            if i == 0 or line[i - 1].isspace():
                return line[:i]
    return line


def parse_bash(path: Path, text: str, rel: str, graph: TrustGraph) -> list[Finding]:
    findings: list[Finding] = []
    file_id = ensure_file_node(graph, rel)
    joined = _join_continuations(text)
    original_lines = text.splitlines()

    for lineno, raw in enumerate(joined.splitlines(), start=1):
        code = _code_part(raw).rstrip()
        if not code.strip():
            continue
        blanked, _ = _strip_quoted_regions(code)
        snip = snippet_at(text if lineno <= len(original_lines) else joined, min(lineno, max(1, len(original_lines))))
        # Prefer original file line when continuations didn't merge this index
        if lineno <= len(original_lines):
            snip = snippet_at(text, lineno)

        if _PIPE_SINK.search(code) and _CURL.search(code):
            add_command(graph, file_id, "curl|bash")
            findings.append(
                Finding(
                    id="SH-CURL-BASH",
                    severity=Severity.HIGH,
                    language=Language.BASH,
                    path=rel,
                    line=lineno,
                    message="A `curl | bash` (or `curl | sh`) pipeline executes remote bytes with the local shell.",
                    harden=(
                        "Download to a file, verify a checksum or signature you pin in-repo, then run the "
                        "verified file. Do not pipe vendor installers into a shell."
                    ),
                    snippet=snip,
                )
            )
        elif _PIPE_SINK.search(code) and _WGET.search(code):
            add_command(graph, file_id, "wget|sh")
            findings.append(
                Finding(
                    id="SH-WGET-SH",
                    severity=Severity.HIGH,
                    language=Language.BASH,
                    path=rel,
                    line=lineno,
                    message="A `wget | sh` pipeline executes remote bytes with the local shell.",
                    harden="Download, verify a pinned checksum, then execute the verified file — never a pipe to sh.",
                    snippet=snip,
                )
            )
        elif _PIPE_SINK.search(code):
            add_command(graph, file_id, "pipe-to-shell")
            findings.append(
                Finding(
                    id="SH-CURL-BASH",
                    severity=Severity.HIGH,
                    language=Language.BASH,
                    path=rel,
                    line=lineno,
                    message="A pipeline into `sh`/`bash` executes whatever the left-hand side emits.",
                    harden="Write output to a file, inspect/verify it, then run the verified file.",
                    snippet=snip,
                )
            )

        if _EVAL.search(blanked):
            add_command(graph, file_id, "eval")
            findings.append(
                Finding(
                    id="SH-EVAL",
                    severity=Severity.HIGH,
                    language=Language.BASH,
                    path=rel,
                    line=lineno,
                    message="`eval` re-parses a string as shell code, expanding the trust surface to that string.",
                    harden="Replace eval with a function call or an allowlisted command array. Quote expansions.",
                    snippet=snip,
                )
            )

        src = _SOURCE.search(code)
        if src:
            raw_target = src.group(1)
            target = raw_target.strip("\"'")
            anchored = bool(
                target.startswith("/")
                or raw_target.startswith("$")
                or "$" in raw_target
                or target.startswith("${")
            )
            if target and not anchored:
                add_command(graph, file_id, "source")
                findings.append(
                    Finding(
                        id="SH-SOURCE-RELATIVE",
                        severity=Severity.MEDIUM,
                        language=Language.BASH,
                        path=rel,
                        line=lineno,
                        message=f"`source {target}` loads a relative file; cwd changes expand what gets executed.",
                        harden=(
                            "Source using a path anchored at the script directory "
                            '(`source "${BASH_SOURCE[0]%/*}/helpers.sh"`) and quote it.'
                        ),
                        snippet=snip,
                        extra={"target": target},
                    )
                )

        if _NC.search(blanked):
            add_command(graph, file_id, "nc")
            findings.append(
                Finding(
                    id="SH-NETCAT",
                    severity=Severity.HIGH,
                    language=Language.BASH,
                    path=rel,
                    line=lineno,
                    message="`nc`/`ncat`/`netcat` is a raw-socket tool; its presence expands network trust.",
                    harden=(
                        "Remove netcat from install/deploy scripts. Use `curl`/`ssh` with pinned hosts, "
                        "or a first-party CLI, for the intended transfer."
                    ),
                    snippet=snip,
                )
            )

        if _SSH.search(blanked):
            add_command(graph, file_id, "ssh")
            findings.append(
                Finding(
                    id="SH-SSH",
                    severity=Severity.MEDIUM,
                    language=Language.BASH,
                    path=rel,
                    line=lineno,
                    message="`ssh` adds a remote-execution edge. Hosts on this line are recorded in the graph.",
                    harden=(
                        "Pin host keys (`IdentitiesOnly`, known_hosts), disable `StrictHostKeyChecking=no`, "
                        "and avoid `ssh user@host untrusted-command`."
                    ),
                    snippet=snip,
                )
            )

        if _SUDO.search(blanked):
            add_command(graph, file_id, "sudo")
            findings.append(
                Finding(
                    id="SH-SUDO",
                    severity=Severity.MEDIUM,
                    language=Language.BASH,
                    path=rel,
                    line=lineno,
                    message="`sudo` escalates the trust surface to root for this command.",
                    harden="Drop sudo from scripts that do not need root. If required, pin the exact argv and avoid `sudo sh`.",
                    snippet=snip,
                )
            )

        # Unquoted expansions: look at blanked (quotes already removed so quoted $VAR is gone)
        for m in _UNQUOTED.finditer(blanked):
            name = m.group(1) or m.group(2)
            if not name or name in _BENIGN_UNQUOTED:
                continue
            # skip positional-like
            if name.isdigit():
                continue
            findings.append(
                Finding(
                    id="SH-UNQUOTED-EXPAND",
                    severity=Severity.MEDIUM,
                    language=Language.BASH,
                    path=rel,
                    line=lineno,
                    message=f"Unquoted `${name}` is subject to word-splitting and globbing.",
                    harden=f'Quote the expansion: `"${name}"`. Prefer arrays instead of unquoted IFS splitting.',
                    snippet=snip,
                    extra={"name": name},
                )
            )
            graph.add_node(Node(id=f"env:{name}", kind=NodeKind.ENV, label=name))
            graph.add_edge(file_id, f"env:{name}", EdgeKind.EXPANDS)
            break  # one unquoted finding per line is enough

        for h in hosts_from_text(code):
            add_host(graph, file_id, h, via="bash")

    for hit in find_secret_shapes(text):
        findings.append(
            Finding(
                id="SECRET-SHAPE",
                severity=Severity.HIGH,
                language=Language.BASH,
                path=rel,
                line=hit.line,
                message=(
                    f"A value matching secret shape `{hit.shape}` is present. Redacted form: `{hit.masked}`."
                ),
                harden="Delete the credential from git history if it was real, rotate it, and load it from a secret manager.",
                snippet=snippet_at(text, hit.line),
                extra={"shape": hit.shape, "masked": hit.masked},
            )
        )
        graph.add_node(
            Node(
                id=f"secret:{rel}:{hit.line}",
                kind=NodeKind.SECRET_SHAPE,
                label=hit.shape,
            )
        )
        graph.add_edge(file_id, f"secret:{rel}:{hit.line}", EdgeKind.CONTAINS)

    return findings
