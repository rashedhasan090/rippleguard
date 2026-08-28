# Rippleguard tutorial transcript

This is the same walkthrough as `docs/tutorial.mp4`, written out for anyone who cannot play the video.

Rippleguard is a **defensive** tool. It maps what your Python, Bash, and GitHub Actions already can execute, then diffs that *trust surface* across git so a commit that quietly adds `curl | bash`, `subprocess(..., shell=True)`, or an unpinned Action shows up as a surface expansion. Findings tell you how to **harden your own code**. They never describe how to abuse a pattern.

## 1. Install

From a clone of this repository:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
rippleguard --version
```

Expected: `rippleguard 0.1.0`.

## 2. Scan the insecure fixtures

The `fixtures/insecure/` tree is a **labeled demo** of patterns to detect. It is not an exploit and is not meant to be executed against any system.

```bash
rippleguard scan fixtures/insecure
```

The command prints a human report, a mermaid graph, and JSON. Exit code `1` means high-severity surface was found (expected here). Exit `0` is clean; exit `2` is a tool error.

Look for finding IDs with `file:line`, for example:

- `PY-SUBPROCESS-SHELL` on `fixtures/insecure/deploy.py`
- `SH-CURL-BASH` on `fixtures/insecure/bootstrap.sh`
- `GHA-UNPINNED-ACTION` / `GHA-SECRET-IN-RUN` on `fixtures/insecure/.github/workflows/ci.yml`

Each finding ends with a **Harden:** sentence (safer API, quote the expansion, pin an action by SHA, map secrets through `env:`).

Secret-shaped values are reported as a *shape* plus location; the value is redacted.

## 3. Read the graph

In the `GRAPH (mermaid)` section, nodes are files, commands, hosts, env vars, and actions. Edges are `invokes`, `reads`, `reaches`, `uses`, and `expands`. Paste the block into any mermaid renderer (GitHub markdown preview works) to see how a Python file that shells out, a Bash installer, and a workflow share one trust surface.

## 4. Diff the delta

Compare the hardened fixtures against the insecure ones (no git history required):

```bash
rippleguard diff --old fixtures/fixed --new fixtures/insecure
```

Only **new** surface is printed. Exit code `1` because high-severity expansions were added.

Against real git history:

```bash
rippleguard diff . --base HEAD~1 --head HEAD
```

Default `rippleguard diff` is `HEAD~1` vs the working tree.

## 5. Install the Bash hook

```bash
rippleguard hook install --pre-commit
```

This copies `scripts/rippleguard-hook` to `.git/hooks/pre-commit`. The hook runs `rippleguard diff` and **fails the commit** if the delta introduces high-severity surface.

To install by hand:

```bash
chmod +x scripts/rippleguard-hook
cp scripts/rippleguard-hook .git/hooks/pre-commit
```

Optional: `rippleguard hook install --pre-push` after `--pre-commit` (the install command always writes `pre-commit`; pass `--pre-push` to also write `pre-push`).

## 6. Scan the hardened fixtures

```bash
rippleguard scan fixtures/fixed --fail-on high
```

Exit code `0`: the high-severity catalog items are gone (list argv, `yaml.safe_load`, quoted expansions, Actions pinned by SHA, secrets mapped via `env:`).
