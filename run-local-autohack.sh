#!/usr/bin/env bash
# AutoHack local launcher. Resolves Node in non-interactive/systemd shells.
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
if [[ -f "$ROOT/.autohack-brand/banner.sh" ]]; then
  bash "$ROOT/.autohack-brand/banner.sh"
fi
export PATH="$HOME/.local/bin:$HOME/.npm-global/bin:$HOME/.nvm/current/bin:$HOME/.volta/bin:$HOME/.asdf/shims:/usr/local/bin:/usr/bin:$PATH"
if [[ -s "$HOME/.nvm/nvm.sh" ]]; then
  # shellcheck disable=SC1091
  source "$HOME/.nvm/nvm.sh"
  nvm use --silent default >/dev/null 2>&1 || true
fi
if ! command -v node >/dev/null 2>&1; then
  echo "AutoHack cannot start: node is missing from PATH (including nvm)." >&2
  exit 127
fi
if ! command -v npm >/dev/null 2>&1; then
  echo "AutoHack cannot start: npm is missing from PATH." >&2
  exit 127
fi
if [[ ! -d node_modules ]]; then
  echo "AutoHack dependencies missing. Run 'npm ci' in $ROOT first." >&2
  exit 1
fi
export LOCAL_OLLAMA_MODEL="${LOCAL_OLLAMA_MODEL:-qwen3:4b}"
export ANTHROPIC_BASE_URL="${ANTHROPIC_BASE_URL:-http://127.0.0.1:11434}"
export ANTHROPIC_AUTH_TOKEN="${ANTHROPIC_AUTH_TOKEN:-ollama}"
export ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY:-ollama}"
export CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1
export CLAUDE_CODE_MAX_CONTEXT_TOKENS="${CLAUDE_CODE_MAX_CONTEXT_TOKENS:-32768}"
# Keep the orchestrator as the supervised PID. npm adds a shell/process layer
# which can survive when only the launcher PID receives SIGTERM.
exec node --import tsx "$ROOT/orchestrator.ts"
