#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
python3 -m venv "$ROOT/.venv-static"
"$ROOT/.venv-static/bin/python" -m pip install -r "$ROOT/scripts/static-analysis-requirements.txt"
"$ROOT/.venv-static/bin/solc-select" install 0.8.30
cp "$HOME/.solc-select/artifacts/solc-0.8.30/solc-0.8.30" "$ROOT/.venv-static/solc-0.8.30"
"$ROOT/.venv-static/solc-0.8.30" --version
"$ROOT/.venv-static/bin/semgrep" --version
"$ROOT/.venv-static/bin/slither" --version
