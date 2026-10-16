#!/usr/bin/env bash
[ ! -f "$HOME/isaiz-bugbounty/autohack/.autohack-brand/banner.sh" ] || bash "$HOME/isaiz-bugbounty/autohack/.autohack-brand/banner.sh"
set -Eeuo pipefail
cd "$(dirname "$0")"
export PATH="$HOME/.local/bin:$PATH"
export LOCAL_OLLAMA_MODEL=qwen3:4b
export ANTHROPIC_BASE_URL=http://127.0.0.1:11434
export ANTHROPIC_AUTH_TOKEN=ollama
export ANTHROPIC_API_KEY=ollama
export CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1
export CLAUDE_CODE_MAX_CONTEXT_TOKENS=32768
exec npm run dev
