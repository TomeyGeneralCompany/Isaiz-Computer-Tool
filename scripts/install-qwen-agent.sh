#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
python3 -m venv "$ROOT/.venv-qwen" || {
  echo 'Python venv support is required. On Ubuntu/Zorin install python3-venv, then retry.' >&2
  exit 1
}
"$ROOT/.venv-qwen/bin/python" -m pip install -r "$ROOT/scripts/qwen-agent-requirements.txt"
"$ROOT/.venv-qwen/bin/python" -c 'from qwen_agent.llm.function_calling import BaseFnCallModel; print("Qwen-Agent adapter installed")'
