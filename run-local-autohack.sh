#!/usr/bin/env bash
# AutoHack local launcher. Resolves Node in non-interactive/systemd shells.
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
if [[ -f "$ROOT/.autohack-brand/banner.sh" ]]; then
  bash "$ROOT/.autohack-brand/banner.sh"
fi
source "$ROOT/scripts/node-runtime.sh"
command -v flock >/dev/null 2>&1 || { echo "flock (util-linux) is required." >&2; exit 127; }
mkdir -p data
exec 8>data/orchestrator.lock
flock -n 8 || { echo "AutoHack orchestrator is already running in this checkout." >&2; exit 2; }
if ! command -v npm >/dev/null 2>&1; then
  echo "AutoHack cannot start: npm is missing from PATH." >&2
  exit 127
fi
if [[ ! -d node_modules ]]; then
  echo "AutoHack dependencies missing. Run 'npm ci' in $ROOT first." >&2
  exit 1
fi
export CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1
export CLAUDE_CODE_MAX_CONTEXT_TOKENS="${CLAUDE_CODE_MAX_CONTEXT_TOKENS:-32768}"
# Keep the orchestrator as the supervised PID. npm adds a shell/process layer
# which can survive when only the launcher PID receives SIGTERM.
exec node --import tsx "$ROOT/orchestrator.ts"
