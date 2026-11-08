#!/bin/sh
# Railway mounts volumes owned by root, but the server runs as the unprivileged
# "node" user. When started as root, hand the rules file's directory to node,
# then drop privileges. Started as non-root (e.g. local docker), run as-is.
set -e
if [ "$(id -u)" = "0" ]; then
  if [ -n "$YNAB_RULES_PATH" ]; then
    dir="$(dirname "$YNAB_RULES_PATH")"
    mkdir -p "$dir"
    chown node:node "$dir"
    [ -e "$YNAB_RULES_PATH" ] && chown node:node "$YNAB_RULES_PATH"
  fi
  exec su-exec node "$@"
fi
exec "$@"
