#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")/.."
[ ! -f .autohack-brand/banner.sh ] || bash .autohack-brand/banner.sh
if [ -f .env ]; then
  set -a
  # Read only the token instead of sourcing arbitrary shell syntax from .env.
  GITHUB_TOKEN="$(sed -n 's/^GITHUB_TOKEN=//p' .env | tail -n 1)"
  export GITHUB_TOKEN
  set +a
fi
exec python3 -u .autohack-next-stage/worker.py
