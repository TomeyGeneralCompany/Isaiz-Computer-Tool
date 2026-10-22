"""Exercise the research adapter without a model or production repository."""
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import unittest
from unittest.mock import patch


class ResearchInferenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        source = Path(__file__).resolve().parents[1] / '.autohack-next-stage/research-engine/worker.py'
        spec = importlib.util.spec_from_file_location('research_inference_fixture', source)
        cls.worker = importlib.util.module_from_spec(spec)
        handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
        previous_bytecode = sys.dont_write_bytecode
        sys.dont_write_bytecode = True
        try:
            with patch.dict(os.environ, {'AUTOHACK_ROOT': cls.temp.name}):
                spec.loader.exec_module(cls.worker)
        finally:
            sys.dont_write_bytecode = previous_bytecode
            for sig, handler in handlers.items():
                signal.signal(sig, handler)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def invoke(self, response):
        body = response if isinstance(response, bytes) else json.dumps(response).encode()
        with patch.object(self.worker.urllib.request, 'urlopen', return_value=io.BytesIO(body)) as request:
            result = self.worker.ollama('Owned source fixture', 'mock')
            payload = json.loads(request.call_args.args[0].data)
            self.assertFalse(payload['think'])
            self.assertEqual(payload['options']['num_thread'], 4)
            self.assertEqual(payload['options']['num_ctx'], 8192)
            self.assertEqual(request.call_args.kwargs['timeout'], 600)
            return result

    def test_complete_object(self):
        self.assertEqual(self.invoke({'done': True, 'response': '{"test_source":""}'}), {'test_source': ''})

    def test_reject_incomplete_truncated_and_failed_responses(self):
        for response in ({'response': '{}'}, {'done': False, 'response': '{}'},
                         {'done': True, 'done_reason': 'length', 'response': '{}'},
                         {'done': True, 'error': 'fixture', 'response': '{}'},
                         {'done': True, 'response': '[]'}, {'done': True, 'response': '{'},
                         b'x' * (1024 * 1024 + 1)):
            with self.subTest(response=str(response)[:80]):
                with self.assertRaises(ValueError):
                    self.invoke(response)
        # Every failure must release the cross-process lock.
        self.assertEqual(self.invoke({'done': True, 'response': '{}'}), {})
