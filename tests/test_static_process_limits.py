"""Regression for Linux's user-wide RLIMIT_NPROC scanner startup budget.

Only synthetic /proc data and mocked resource calls are used.
"""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import call, patch

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts' / 'source-static.py'
spec = importlib.util.spec_from_file_location('autohack_source_static', SCRIPT)
static = importlib.util.module_from_spec(spec)
spec.loader.exec_module(static)


class StaticScannerProcessLimitTests(unittest.TestCase):
    def test_counts_threads_for_real_uid_not_processes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for pid, uid, threads in ((101, 1000, 80), (102, 1000, 90),
                                      (103, 1001, 300)):
                process = root / str(pid)
                process.mkdir()
                (process / 'status').write_text(
                    f'Name:\tfixture\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n'
                    f'Threads:\t{threads}\n')
            (root / 'not-a-pid').mkdir()
            (root / '104').mkdir()  # A process that exited while being read.
            self.assertEqual(static.user_thread_count(root, 1000), 170)
            self.assertEqual(static.user_thread_count(root, 1001), 300)

    def test_unreadable_proc_uses_bounded_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsNone(static.user_thread_count(Path(tmp) / 'missing', 1000))
        with patch.object(static, 'user_thread_count', return_value=None), \
             patch.object(static.resource, 'getrlimit', return_value=(4096, 4096)):
            self.assertEqual(static.scanner_nproc_limit(), 512)

    def test_scanner_has_room_for_existing_user_threads(self):
        with patch.object(static, 'user_thread_count', return_value=170), \
             patch.object(static.resource, 'getrlimit', return_value=(4096, 4096)):
            self.assertEqual(static.scanner_nproc_limit(), 234)

    def test_never_exceeds_inherited_soft_limit(self):
        with patch.object(static, 'user_thread_count', return_value=170), \
             patch.object(static.resource, 'getrlimit', return_value=(200, 4096)):
            self.assertEqual(static.scanner_nproc_limit(), 200)

    def test_other_sandbox_resource_caps_stay_in_place(self):
        with patch.object(static, 'scanner_nproc_limit', return_value=234), \
             patch.object(static.resource, 'setrlimit') as setter:
            static.limits()
        self.assertIn(call(static.resource.RLIMIT_NPROC, (234, 234)),
                      setter.call_args_list)
        self.assertIn(call(static.resource.RLIMIT_CPU, (45, 45)),
                      setter.call_args_list)
        self.assertIn(call(static.resource.RLIMIT_FSIZE, (8 * 1024**2, 8 * 1024**2)),
                      setter.call_args_list)
        self.assertIn(call(static.resource.RLIMIT_CORE, (0, 0)),
                      setter.call_args_list)


if __name__ == '__main__':
    unittest.main()
