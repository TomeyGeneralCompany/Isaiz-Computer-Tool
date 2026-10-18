import importlib.util
import json
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('credentials', Path(__file__).resolve().parents[1] / 'scripts/configure-hackerone.py')
credentials = importlib.util.module_from_spec(spec)
spec.loader.exec_module(credentials)

class CredentialsSetup(unittest.TestCase):
    def test_preserves_other_settings_and_writes_private_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / '.env'
            path.write_text('# Keep this\nOTHER_SETTING=true\nexport HACKERONE_USERNAME=old\nHACKERONE_API_TOKEN=old-token\n')
            credentials.save_credentials(path, 'fixture-user', 'fixture-token')
            text = path.read_text()
            self.assertIn('OTHER_SETTING=true', text)
            self.assertIn('# Keep this', text)
            self.assertEqual(text.count('HACKERONE_API_TOKEN='), 1)
            self.assertIn('HACKERONE_USERNAME="fixture-user"', text)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_rejected_credentials_are_not_saved(self):
        response = subprocess.CompletedProcess([], 1, json.dumps({'passed':False,'detail':'HackerOne HTTP 401'}), '')
        with patch('builtins.input', return_value='fixture-user'), patch.object(credentials.getpass, 'getpass', return_value='fixture-token'), patch.object(credentials.subprocess, 'run', return_value=response), patch.object(credentials, 'save_credentials') as save:
            self.assertEqual(credentials.main(), 1)
            save.assert_not_called()

    def test_newlines_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                credentials.save_credentials(Path(directory) / '.env', 'user', 'token\nEXTRA=true')
            self.assertFalse((Path(directory) / '.env').exists())
