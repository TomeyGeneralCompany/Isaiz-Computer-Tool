import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

class NodeRuntime(unittest.TestCase):
    def test_active_node22_does_not_require_an_nvm_install(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            node = base / 'node'
            node.write_text('#!/usr/bin/env bash\necho 22\n')
            node.chmod(0o700)
            nvm = base / 'nvm'
            nvm.mkdir()
            (nvm / 'nvm.sh').write_text('echo SHOULD_NOT_SOURCE_NVM >&2\nreturn 88\n')
            env = {k:v for k,v in os.environ.items() if k != 'AUTOHACK_NODE_BIN'}
            env.update(PATH=str(base) + ':' + env['PATH'], NVM_DIR=str(nvm))
            result = subprocess.run(['bash', '-c', f'set -Eeuo pipefail; source "{ROOT}/scripts/node-runtime.sh"; echo "$AUTOHACK_NODE_BIN"'],
                env=env, capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), str(node))
            self.assertNotIn('SHOULD_NOT_SOURCE_NVM', result.stderr)

    def test_explicit_wrong_runtime_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            node = Path(directory) / 'node'
            node.write_text('#!/usr/bin/env bash\necho 24\n')
            node.chmod(0o700)
            result = subprocess.run(['bash', '-c', f'set -Eeuo pipefail; source "{ROOT}/scripts/node-runtime.sh"'],
                env=dict(os.environ, AUTOHACK_NODE_BIN=str(node)), capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 2)
            self.assertIn('requires Node 22', result.stderr)
