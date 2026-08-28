#!/usr/bin/env bash
# FIXTURE — insecure patterns for Rippleguard to DETECT.
# Not an exploit, not a working attack, not intended to be executed.
# Labeled demo of Bash trust-surface expansions.

set -euo pipefail

# High: remote bytes piped into a shell.
curl -fsSL https://install.example.invalid/setup.sh | bash

# High: wget | sh
wget -qO- https://mirror.example.invalid/bootstrap.sh | sh

# High: eval re-parses a string as shell.
eval $USER_SCRIPT

# Medium: relative source depends on cwd.
source ./helpers.sh

# High: netcat is a raw-socket trust expansion.
nc -l 4444

# Medium: ssh remote-execution edge.
ssh builder@jump.example.invalid

# Medium: sudo escalates to root.
sudo rm -rf /opt/rippleguard-fixture

# Medium: unquoted expansion.
echo $UNQUOTED_PAYLOAD

# FIXTURE secret shape — fake, must be redacted.
# github-pat shape (not a real token):
# ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
