#!/bin/sh
# Container entrypoint: decrypt secrets at RUN time, then exec the real command.
#
# Pair with a Dockerfile that sets
#   ENTRYPOINT ["/usr/local/bin/sops-entrypoint.sh", "<the real entrypoint>"]
# so this script receives the real command as "$@" and hands off with exec.
#
# Decryption happens here and never at build time: a secret decrypted during
# `docker build` is baked into an image layer forever. The image carries only
# ciphertext (env/enc/<name>.env.enc, copied to $SOPS_SECRETS_FILE) plus the
# sops binary; the age key arrives at `docker run` via SOPS_AGE_KEY or
# SOPS_AGE_KEY_FILE and the plaintext exists only in this process's memory.
set -eu

: "${SOPS_SECRETS_FILE:=/app/secrets/app.env}"

# No ciphertext baked in: run the command unchanged.
if [ ! -f "$SOPS_SECRETS_FILE" ]; then
  exec "$@"
fi

if [ -z "${SOPS_AGE_KEY:-}" ] && [ -z "${SOPS_AGE_KEY_FILE:-}" ]; then
  if [ "${SOPS_REQUIRE_KEY:-0}" = "1" ]; then
    echo "sops-entrypoint: no SOPS_AGE_KEY or SOPS_AGE_KEY_FILE set (SOPS_REQUIRE_KEY=1)." >&2
    echo "  docker run -e SOPS_AGE_KEY=\"\$(cat ~/.config/sops/age/keys.txt)\" ..." >&2
    exit 1
  fi
  # Key-less start is allowed by default so the same image serves `--help`,
  # tests, and platforms that inject configuration themselves.
  echo "sops-entrypoint: no age key supplied; starting without decrypting $SOPS_SECRETS_FILE" >&2
  exec "$@"
fi

command -v sops >/dev/null 2>&1 || { echo "sops-entrypoint: sops binary not in image" >&2; exit 1; }

# `sops -d` writes to stdout; plaintext never touches the filesystem.
secrets=$(sops --decrypt --input-type dotenv --output-type dotenv "$SOPS_SECRETS_FILE") || {
  echo "sops-entrypoint: failed to decrypt $SOPS_SECRETS_FILE" >&2
  exit 1
}

# Parsed with read + export, never eval: a value containing `$(...)` stays a
# literal string instead of executing. Splitting on the first `=` only keeps
# URLs, base64 and JWTs intact. Variables already set in the container
# environment win, so an orchestrator can still override a single value.
while IFS='=' read -r key value; do
  case "$key" in
    '' | '#'* | sops_*) continue ;;
    *[!A-Za-z0-9_]* | [0-9]*) echo "sops-entrypoint: skipping invalid variable name" >&2; continue ;;
  esac
  if [ -z "$(eval "printf '%s' \"\${$key+x}\"")" ]; then
    export "$key=$value"
  fi
done <<EOF_SECRETS
$secrets
EOF_SECRETS
unset secrets

# The application replaces this shell and becomes PID 1, so `docker stop`
# delivers SIGTERM straight to it. (Not `sops exec-env`: that keeps sops as PID 1
# and it does not forward signals.)
exec "$@"
