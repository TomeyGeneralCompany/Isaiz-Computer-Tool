"""Exercise real worker descendants without starting research or contacting targets."""
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
SUPERVISOR = ROOT / 'scripts/run-offline-workers.py'


def alive(pid):
    try:
        # A reparented zombie is already dead; some CI init processes reap late.
        return Path(f'/proc/{pid}/stat').read_text().split(') ')[1][0] != 'Z'
    except FileNotFoundError:
        return False


@unittest.skipUnless(sys.platform == 'linux', 'Requires Linux process groups')
class WorkerLifecycle(unittest.TestCase):
    def exercise(self, crash_leader):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            marker = base / 'descendant.pid'
            worker = base / 'worker.py'
            # The grandchild deliberately ignores graceful termination. The
            # supervisor must still remove it when stopping or replacing work.
            worker.write_text(
                'import subprocess, sys, time\n'
                'from pathlib import Path\n'
                'child = subprocess.Popen([sys.executable, "-c", '
                '"import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(90)"])\n'
                'time.sleep(0.2)\n'
                f'Path({str(marker)!r}).write_text(str(child.pid))\n'
                + ('raise SystemExit(3)\n' if crash_leader else 'time.sleep(90)\n'))
            code = (
                'import importlib.util, pathlib\n'
                f'spec=importlib.util.spec_from_file_location("supervisor", {str(SUPERVISOR)!r})\n'
                'module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)\n'
                f'module.ROOT=pathlib.Path({str(base)!r})\n'
                f'module.WORKERS={{"fixture":pathlib.Path({str(worker)!r})}}\n'
                'raise SystemExit(module.main())\n')
            runner = subprocess.Popen([sys.executable, '-c', code], stdout=subprocess.DEVNULL,
                                      stderr=subprocess.PIPE, start_new_session=True)
            descendant = None
            try:
                deadline = time.monotonic() + 8
                while not marker.is_file() and time.monotonic() < deadline:
                    if runner.poll() is not None:
                        self.fail(runner.stderr.read().decode())
                    time.sleep(0.05)
                self.assertTrue(marker.is_file(), 'Worker did not start')
                descendant = int(marker.read_text())
                if crash_leader:
                    deadline = time.monotonic() + 4
                    while alive(descendant) and time.monotonic() < deadline:
                        time.sleep(0.05)
                    self.assertFalse(alive(descendant), 'Crashed worker left a descendant before restart')
                runner.terminate()
                runner.wait(timeout=12)
                self.assertEqual(runner.returncode, 0)
                deadline = time.monotonic() + 2
                while alive(descendant) and time.monotonic() < deadline:
                    time.sleep(0.05)
                self.assertFalse(alive(descendant), 'Supervisor shutdown left a descendant')
            finally:
                if runner.poll() is None:
                    runner.kill()
                runner.wait()
                runner.stderr.close()
                if descendant and alive(descendant):
                    os.kill(descendant, signal.SIGKILL)

    def test_shutdown_removes_stubborn_descendant(self):
        self.exercise(False)

    def test_crashed_leader_descendants_removed_before_restart(self):
        self.exercise(True)
