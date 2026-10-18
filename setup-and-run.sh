#!/usr/bin/env bash
# Install local application dependencies, initialize DB, and launch AutoHack.
# Never downloads target code or enables automatic bounty submission.
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
case "${1:-}" in
  ""|--verify-only) ;;
  *) echo "Usage: bash setup-and-run.sh [--verify-only]" >&2; exit 2 ;;
esac
source "$ROOT/scripts/node-runtime.sh"
for exe in node npm python3 flock; do
  command -v "$exe" >/dev/null 2>&1 || { echo "Missing $exe" >&2; exit 127; }
done
# Refuse to replace dependencies underneath a running supervised instance.
for LOCK in data/supervisor.lock data/orchestrator.lock; do
  if [[ -f "$LOCK" ]] && ! flock -n "$LOCK" true; then
    echo "Stop the running AutoHack instance before setup or host verification." >&2
    exit 2
  fi
done
echo "Installing locked Node dependencies for the selected runtime..."
npm ci
if [[ ! -f .env ]]; then
  echo "No .env in this checkout. Checking for the existing local installation..." >&2
  ORIGINAL="$HOME/isaiz-bugbounty/autohack/.env"
  if [[ -f "$ORIGINAL" ]]; then
    install -m 600 "$ORIGINAL" "$ROOT/.env"
    echo "Imported existing local configuration (permissions 0600)."
  else
    echo "No local runtime configuration found; cannot start configured services." >&2
    exit 2
  fi
fi
chmod 600 "$ROOT/.env"
# An existing node_modules may have been built by another Node version.
if ! node -e 'require("better-sqlite3") (":memory:").close()' >/dev/null 2>&1; then
  echo "Rebuilding SQLite for the selected Node runtime..."
  npm rebuild better-sqlite3
fi
export PROJECT_ROOT="$ROOT"
echo "Initializing application database..."
npm run db:push
echo "Checking local prerequisites..."
python3 scripts/doctor.py
echo "Running local acceptance checks..."
ACCEPTANCE_ARGS=(--report data/host-acceptance.json)
if [[ "${1:-}" == --verify-only ]]; then
  ACCEPTANCE_ARGS+=(--provider)
fi
python3 scripts/acceptance.py "${ACCEPTANCE_ARGS[@]}"
if [[ "${1:-}" == --verify-only ]]; then
  echo "Host verification passed. No AutoHack service was started."
  exit 0
fi
echo "Starting AutoHack..."
exec bash "$ROOT/run-complete-autohack.sh"
