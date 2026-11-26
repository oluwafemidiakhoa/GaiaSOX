import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

CLI = Path(__file__).resolve().parents[1] / 'evidence_cli.py'

class CLITests(unittest.TestCase):
    def test_offline_roundtrip_and_rejections(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            def run(*args):
                return subprocess.run([sys.executable, str(CLI), *args], cwd=root, capture_output=True).returncode
            self.assertEqual(run('keygen', 'private.pem', 'public.pem'), 0)
            (root / 'input.json').write_text(json.dumps({'rows': [{'id': 'a', 'approved': False}], 'expected_ids': ['a']}))
            self.assertEqual(run('export', 'private.pem', 'input.json', 'evidence.json'), 0)
            self.assertEqual(run('verify', 'public.pem', 'evidence.json'), 0)
            original = (root / 'evidence.json').read_bytes()
            self.assertEqual(run('export', 'private.pem', 'input.json', 'evidence.json'), 2)
            self.assertEqual((root / 'evidence.json').read_bytes(), original)
            self.assertEqual(run('keygen', 'other.pem', 'other-public.pem'), 0)
            self.assertEqual(run('verify', 'other-public.pem', 'evidence.json'), 1)
            evidence = json.loads(original)
            evidence['payload']['rows'][0]['approved'] = True
            (root / 'evidence.json').write_text(json.dumps(evidence))
            self.assertEqual(run('verify', 'public.pem', 'evidence.json'), 1)
            (root / 'evidence.json').write_text('{"payload":{},"payload":{}}')
            self.assertEqual(run('verify', 'public.pem', 'evidence.json'), 2)
