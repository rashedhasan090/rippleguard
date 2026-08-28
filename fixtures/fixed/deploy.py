# Hardened counterpart of fixtures/insecure/deploy.py
# Shows the recommended replacements Rippleguard's "Harden:" lines describe.

import json
import os
from pathlib import Path
from urllib.parse import urlparse

import yaml

ALLOWED_HOSTS = {"api.example.invalid"}


def deploy() -> None:
    # No shell: argv list only.
    # (Intentionally no subprocess of a remote installer.)
    config = yaml.safe_load(Path("config.yaml").read_text(encoding="utf-8"))
    payload = json.loads(Path("cache.json").read_text(encoding="utf-8"))
    host = urlparse("https://api.example.invalid/v1/status").hostname
    if host not in ALLOWED_HOSTS:
        raise RuntimeError("host not allowlisted")
    del config, payload


def read_token() -> str:
    # Value never logged. File is gitignored in a real repo.
    return os.environ.get("DEPLOY_TOKEN", "")
