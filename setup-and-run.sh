#!/usr/bin/env bash
# Install local application dependencies, initialize DB, and launch AutoHack.
# Never downloads target code or enables automatic bounty submission.
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
if ! command -v node >/dev/null 2>&1 || ! command -v npm >/dev/null 2>&1; then
  if [[ -s "$HOME/.nvm/nvm.sh" ]]; then
    # shellcheck disable=SC1091
    source "$HOME/.nvm/nvm.sh"
  fi
fi
for exe in node npm python3; do
  command -v "$exe" >/dev/null 2>&1 || { echo "Missing $exe" >&2; exit 127; }
done
if [[ ! -d node_modules ]]; then
  echo "Installing locked Node dependencies..."
  npm ci
fi
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
export PROJECT_ROOT="$ROOT"
echo "Initializing application database..."
npm run db:push
echo "Checking local prerequisites..."
python3 scripts/doctor.py
echo "Running local acceptance checks..."
python3 scripts/acceptance.py
echo "Starting AutoHack..."
exec bash "$ROOT/run-complete-autohack.sh"
