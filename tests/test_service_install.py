"""Exercise service reinstallation without accessing the host's systemd."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

class ServiceInstall(unittest.TestCase):
    def test_reinstall_restarts_service_from_new_checkout(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / 'scripts').mkdir()
            (base / 'node_modules').mkdir()
            for name in ('install-user-service.sh', 'node-runtime.sh'):
                shutil.copy(ROOT / 'scripts' / name, base / 'scripts')
            original = 'FIXTURE_SECRET=unchanged\n'
            (base / '.env').write_text(original)
            node = base / 'node'
            node.write_text('#!/bin/sh\necho 22\n')
            node.chmod(0o700)
            control = base / 'systemctl'
            control.write_text('''#!/usr/bin/env python3
import os, sys
from pathlib import Path
home = Path(os.environ['HOME'])
args = sys.argv[1:]
with (home / 'calls').open('a') as log:
    log.write(' '.join(args) + '\\n')
# An active old process remains in place until an explicit restart.
if 'restart' in args:
    (home / 'running-checkout').write_text(str(home))
''')
            control.chmod(0o700)
            (base / 'running-checkout').write_text('/old/checkout')
            result = subprocess.run(['bash', 'scripts/install-user-service.sh'], cwd=base,
                env=dict(os.environ, HOME=str(base), PATH=str(base) + ':' + os.environ['PATH'],
                         AUTOHACK_NODE_BIN=str(node)), capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((base / 'running-checkout').read_text(), str(base))
            self.assertEqual((base / '.env').read_text(), original)
            calls = (base / 'calls').read_text().splitlines()
            self.assertLess(calls.index('--user daemon-reload'), calls.index('--user restart autohack.service'))
            self.assertIn('WorkingDirectory=' + str(base),
                          (base / '.config/systemd/user/autohack.service').read_text())
