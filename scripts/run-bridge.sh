#!/usr/bin/env bash
# Start the LDAP bridge with configuration loaded from the environment / .env.
#
# The bridge reads all of its configuration from environment variables and
# flags; run `go run ./cmd/ldap-bridge --help` for the authoritative reference.
# This wrapper just loads a .env file (without clobbering variables already set
# in the environment), prints the effective non-secret config, then execs the
# bridge, forwarding any extra CLI flags:
#
#   scripts/run-bridge.sh                        # run against IceWarp
#   scripts/run-bridge.sh --use-in-memory-dummy  # run the in-memory backend
#   scripts/run-bridge.sh --addr 127.0.0.1:3389  # override the listen address
#
# Variables already set in the environment win over .env, which wins over the
# in-code defaults. Override the env file path with ENV_FILE.
set -euo pipefail

cd "$(dirname "$0")/.."

ENV_FILE="${ENV_FILE:-.env}"
if [ -f "$ENV_FILE" ]; then
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line#"${line%%[![:space:]]*}"}" # strip leading whitespace
    case "$line" in '' | \#*) continue ;; esac
    line="${line#export }"
    key="${line%%=*}"
    val="${line#*=}"
    val="${val%\"}" val="${val#\"}" # strip optional surrounding quotes
    val="${val%\'}" val="${val#\'}"
    if [ -z "${!key:-}" ]; then
      export "$key=$val"
    fi
  done <"$ENV_FILE"
fi

# The image's default GOPATH (/go) isn't writable for the dev user, which breaks
# the module cache. Fall back to a writable one when that's the case.
if [ ! -w "$(go env GOPATH)" ]; then
  export GOPATH="$HOME/go"
fi

# Surface the effective config (password omitted) so a misconfigured run is
# obvious. "<default>" means the variable is unset and the in-code default wins.
echo "ldap-bridge configuration:" >&2
for v in LOG_LEVEL LDAP_USER_BASE_DN ICEWARP_URL ICEWARP_DOMAIN ICEWARP_ADMIN_EMAIL INTROSPECT_ICEWARP; do
  printf '  %s=%s\n' "$v" "${!v:-<default>}" >&2
done

exec go run ./cmd/ldap-bridge "$@"
