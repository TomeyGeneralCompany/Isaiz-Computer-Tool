#!/usr/bin/env bash
# Install the local Solidity test toolchain; never executes target project scripts.
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
if ! command -v bwrap >/dev/null 2>&1; then
  if ! command -v apt-get >/dev/null 2>&1; then
    echo "Install bubblewrap with your system package manager, then rerun setup." >&2
    exit 2
  fi
  if [[ "$(id -u)" == 0 ]]; then
    apt-get update
    apt-get install -y bubblewrap
  else
    sudo apt-get update
    sudo apt-get install -y bubblewrap
  fi
fi
npm install --prefix "$ROOT/scripts/reproduction-runtime" --ignore-scripts --no-audit --no-fund
node -e 'const r=process.argv[1]; for (const name of ["solc","ethers","ganache"]) require(require.resolve(name,{paths:[r]}));' "$ROOT/scripts/reproduction-runtime"
if ! bwrap --unshare-all --die-with-parent --ro-bind / / -- /usr/bin/true; then
  echo "Bubblewrap is installed but this host denies the required namespaces. Resolve the host's user-namespace/AppArmor policy before running hunts, then rerun setup." >&2
  exit 2
fi
