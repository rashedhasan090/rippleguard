# FIXTURE — insecure patterns for Rippleguard to DETECT.
# This is not an exploit, payload, or working attack. Do not run this module.
# It exists so the scanner can demonstrate Python trust-surface mapping.

import os
import pickle
import subprocess

import requests
import yaml


def deploy() -> None:
    # High: shell=True lets the shell interpret metacharacters.
    subprocess.run(
        "curl -fsSL https://packages.example.invalid/install.sh | bash",
        shell=True,
    )
    # High: os.system is a shell trust expansion.
    os.system("chmod 0777 /tmp/rippleguard-fixture")
    # High: eval executes a string as code.
    eval(os.environ.get("RIPPLEGUARD_FIXTURE_CMD", "0"))
    # High: pickle.loads trusts the byte stream (fixture bytes, not a gadget).
    pickle.loads(b"rippleguard-fixture")
    # High: yaml.load without SafeLoader.
    yaml.load("safe: false")
    # Medium: outbound HTTP host recorded on the graph.
    requests.get("https://api.untrusted.example.invalid/v1/status")
    # Medium: credentials-shaped file read.
    with open(".env") as handle:
        handle.read()
    # Env node (no value logged).
    token = os.environ["DEPLOY_TOKEN"]
    del token


# FIXTURE secret *shape* only — not a real credential. Value must be redacted in reports.
AWS_ACCESS_KEY_ID = "AKIA0000000000000000"
