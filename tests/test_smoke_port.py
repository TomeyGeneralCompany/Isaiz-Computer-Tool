import importlib.util
from pathlib import Path
import socket
import unittest

spec = importlib.util.spec_from_file_location('restart', Path(__file__).resolve().parents[1] / 'scripts/test-service-restart.py')
restart = importlib.util.module_from_spec(spec)
spec.loader.exec_module(restart)

class SmokePort(unittest.TestCase):
    def test_uses_free_port_while_another_service_listens(self):
        with socket.socket() as existing:
            existing.bind(('127.0.0.1', 0))
            existing.listen()
            port = restart.choose_port()
            self.assertNotEqual(port, existing.getsockname()[1])
            with socket.socket() as smoke:
                smoke.bind(('127.0.0.1', port))
