#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
python3 -m venv "$ROOT/.venv-static"
"$ROOT/.venv-static/bin/python" -m pip install -r "$ROOT/scripts/static-analysis-requirements.txt"
# Fetch a pinned compiler from Solidity's official binary mirror. Do not change
# the user's global solc-select version or depend on its latest-release endpoint.
python3 - "$ROOT/.venv-static/solc-0.8.30" <<'PYTHON'
import hashlib
import os
from pathlib import Path
import platform
import sys
import urllib.request

if platform.system() != 'Linux' or platform.machine() not in ('x86_64', 'amd64'):
    raise SystemExit('Static Solidity analysis currently requires Linux x86_64')
destination = Path(sys.argv[1])
expected = 'f3e987dc6ecebd4bd350c48edcbc320b46cf9e3109bd3fc3d88f1acaf4c428f7'
if not destination.is_file() or hashlib.sha256(destination.read_bytes()).hexdigest() != expected:
    url = 'https://raw.githubusercontent.com/ethereum/solc-bin/gh-pages/linux-amd64/solc-linux-amd64-v0.8.30+commit.73712a01'
    with urllib.request.urlopen(url, timeout=60) as response:
        data = response.read(32 * 1024 * 1024)
    if hashlib.sha256(data).hexdigest() != expected:
        raise SystemExit('Solidity compiler checksum mismatch; installation stopped')
    temporary = destination.with_suffix('.download')
    temporary.write_bytes(data)
    temporary.chmod(0o755)
    os.replace(temporary, destination)
PYTHON
"$ROOT/.venv-static/solc-0.8.30" --version
"$ROOT/.venv-static/bin/semgrep" --version
"$ROOT/.venv-static/bin/slither" --version
