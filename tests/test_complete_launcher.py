"""Run the actual complete launcher with owned sleeping workers; no research."""
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]

@unittest.skipUnless(shutil.which('flock'), 'flock required')
class CompleteLauncher(unittest.TestCase):
    def test_duplicate_denial_shutdown_and_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / 'scripts').mkdir()
            shutil.copy(ROOT / 'run-complete-autohack.sh', base)
            shutil.copy(ROOT / 'scripts/node-runtime.sh', base / 'scripts')
            # Runtime selection is exercised with a fake version responder.
            node = base / 'node'
            node.write_text('#!/usr/bin/env bash\necho 22\n')
            node.chmod(0o700)
            marker = base / 'main.pid'
            (base / 'run-local-autohack.sh').write_text(f'#!/usr/bin/env bash\necho $$ > "{marker}"\nexec sleep 90\n')
            (base / 'scripts/run-offline-workers.py').write_text('import time\ntime.sleep(90)\n')
            env = dict(os.environ, AUTOHACK_NODE_BIN=str(node))
            for iteration in range(2):
                marker.unlink(missing_ok=True)
                first = subprocess.Popen(['bash', 'run-complete-autohack.sh'], cwd=base,
                    env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, start_new_session=True)
                main_pid = None
                try:
                    deadline = time.monotonic() + 5
                    while not marker.exists() and time.monotonic() < deadline:
                        if first.poll() is not None:
                            self.fail(first.stderr.read().decode())
                        time.sleep(0.05)
                    self.assertTrue(marker.exists())
                    main_pid = int(marker.read_text())
                    duplicate = subprocess.run(['bash', 'run-complete-autohack.sh'], cwd=base,
                        env=env, capture_output=True, text=True, timeout=5)
                    self.assertEqual(duplicate.returncode, 2)
                    self.assertIn('already running', duplicate.stderr)
                    first.terminate()
                    first.wait(timeout=5)
                    with self.assertRaises(ProcessLookupError):
                        os.kill(main_pid, 0)
                finally:
                    try:
                        os.killpg(first.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    first.wait(timeout=5)
                    first.stderr.close()
