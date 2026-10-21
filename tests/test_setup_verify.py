"""Exercise the real installer with owned fake prerequisites; no installs/network."""
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

class SetupVerification(unittest.TestCase):
    def test_update_installs_lockfile_and_verify_only_never_launches(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / 'scripts').mkdir()
            (base / 'node_modules').mkdir()  # Existing installs must update too.
            shutil.copy(ROOT / 'setup-and-run.sh', base)
            shutil.copy(ROOT / 'scripts/node-runtime.sh', base / 'scripts')
            shutil.copy(ROOT / 'scripts/install-reproduction-runtime.sh', base / 'scripts')
            (base / 'bwrap').write_text('#!/bin/sh\nexit 0\n')
            (base / 'bwrap').chmod(0o700)
            (base / '.env').write_text('FIXTURE_ONLY=true\n')
            (base / 'scripts/doctor.py').write_text('')
            (base / 'scripts/acceptance.py').write_text('import sys\nfrom pathlib import Path\nPath("acceptance-args.txt").write_text(" ".join(sys.argv[1:]))\n')
            (base / 'run-complete-autohack.sh').write_text('touch launched\n')
            node = base / 'node'
            node.write_text('#!/usr/bin/env bash\necho 22\n')
            node.chmod(0o700)
            npm = base / 'npm'
            npm.write_text('#!/usr/bin/env bash\nprintf "%s\\n" "$*" >> npm-calls.txt\n')
            npm.chmod(0o700)
            result = subprocess.run(['bash', 'setup-and-run.sh', '--verify-only'], cwd=base,
                env=dict(os.environ, AUTOHACK_NODE_BIN=str(node)), capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            calls=(base / 'npm-calls.txt').read_text().splitlines()
            self.assertEqual(calls[0], 'ci')
            self.assertIn('scripts/reproduction-runtime --ignore-scripts --no-audit --no-fund', calls[1])
            self.assertIn('--provider', (base / 'acceptance-args.txt').read_text())
            self.assertFalse((base / 'launched').exists())
            self.assertEqual(stat.S_IMODE((base / '.env').stat().st_mode), 0o600)
