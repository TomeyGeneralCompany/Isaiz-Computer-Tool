import argparse
import importlib.util
import json
import io
from unittest.mock import patch
from pathlib import Path
import stat
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("acceptance", Path(__file__).resolve().parents[1] / "scripts/acceptance.py")
acceptance = importlib.util.module_from_spec(spec)
spec.loader.exec_module(acceptance)

class AcceptanceConfig(unittest.TestCase):
    def test_production_model_failure_prevents_acceptance(self):
        settings = {"model": "qwen3:4b", "ollamaUrl": "http://127.0.0.1:11434/api/chat",
                    "toolProtocol": "json", "agentTimeoutMs": 600000, "discoveryDirect": False}
        responses = [io.StringIO(json.dumps({"models": [{"name": "qwen3:4b"}]})),
                     io.StringIO(json.dumps({"message": {"content": "READY"}}))]
        commands = {}
        def fake_run(name, args, timeout=120, env=None):
            commands[name] = args
            acceptance.record(name, name != "real_model_production_workflow", "owned fixture result")
        with patch.object(acceptance.sys, "argv", ["acceptance.py", "--model-only"]), \
             patch.object(acceptance, "runtime_settings", return_value=settings), \
             patch.object(acceptance.urllib.request, "urlopen", side_effect=responses), \
             patch.object(acceptance.shutil, "which", return_value="node"), \
             patch.object(acceptance, "run", side_effect=fake_run):
            self.assertEqual(acceptance.main(), 1)
        self.assertTrue(acceptance.RESULTS["real_model_fixture_pipeline"]["passed"])
        self.assertFalse(acceptance.RESULTS["real_model_production_workflow"]["passed"])
        self.assertEqual(commands["real_model_production_workflow"],
                         ["node", "--import", "tsx", "scripts/test-production-workflow.ts",
                          "--real-model", "--prefetch", "--host-timeout"])
        acceptance.RESULTS.clear()

    def test_endpoint_uses_configured_host_and_prefix(self):
        self.assertEqual(acceptance.ollama_tags_url("http://127.0.0.1:11435/proxy/api/chat"),
                         "http://127.0.0.1:11435/proxy/api/tags")
        for url in ("file:///api/chat", "https://user:secret@host/api/chat", "http://host/api/chat?key=secret", "http://host/wrong"):
            with self.assertRaises(ValueError):
                acceptance.ollama_tags_url(url)

    def test_report_never_claims_production_and_is_private(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.json"
            path.write_text("old")
            path.chmod(0o644)
            acceptance.RESULTS.clear()
            acceptance.record("fixture", True, "passed")
            self.assertEqual(acceptance.emit(argparse.Namespace(report=str(path)), "offline_regression"), 0)
            self.assertFalse(json.loads(path.read_text())["production_verified"])
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            acceptance.record("failure", False, "not passed")
            self.assertEqual(acceptance.emit(argparse.Namespace(report=None), "host_acceptance"), 1)
            acceptance.RESULTS.clear()
