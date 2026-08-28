#!/usr/bin/env bash
# Hardened counterpart of fixtures/insecure/bootstrap.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source using a path anchored at the script, and quoted.
# shellcheck source=/dev/null
source "${ROOT}/helpers.sh"

# Quote expansions. No eval, no curl|bash, no netcat, no sudo.
user_name="${USER_NAME:-builder}"
printf 'hello %s\n' "${user_name}"
