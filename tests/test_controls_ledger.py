import unittest
import tempfile
from pathlib import Path
from controls import REGISTRY, collect_synthetic
from ledger import append, read_records, verify_chain

class Controls(unittest.TestCase):
    def test_all_rules(self):
        for control, (version, field) in REGISTRY.items():
            for value, expected in [(True, 'PASS'), (False, 'FAIL'), (None, 'INCOMPLETE'), ('true', 'INCOMPLETE')]:
                with self.subTest(control=control, value=value):
                    self.assertEqual(collect_synthetic(control, version, [{'id':'a', field:value}], ['a'])['result']['status'], expected)
    def test_missing_population(self):
        self.assertEqual(collect_synthetic('TLS-001','1.0.0',[],['a'])['result']['status'],'INCOMPLETE')
    def test_unknown_version(self):
        with self.assertRaises(ValueError):
            collect_synthetic('TLS-001','2',[],[])

class Ledger(unittest.TestCase):
    def test_chain_and_tampering(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)/'ledger.jsonl'
            append(p, {'id':'a'})
            head = append(p, {'id':'b'})
            records = read_records(p)
            self.assertEqual(verify_chain(records, head), head)
            with self.assertRaises(ValueError):
                verify_chain(records[:-1], head)
            with self.assertRaises(ValueError):
                verify_chain(records[::-1])
            records[0]['evidence']['id'] = 'changed'
            with self.assertRaises(ValueError):
                verify_chain(records)
    def test_lock(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)/'ledger.jsonl'
            Path(str(p)+'.lock').touch()
            with self.assertRaises(FileExistsError):
                append(p, {})
            self.assertFalse(p.exists())
