import unittest
from copy import deepcopy
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from gaiasox import collect, evaluate, verify

class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.generate()
        self.rows = [{"id": "a", "approved": True}]
        self.evidence = collect(self.rows, ["a"], self.key)

    def test_valid(self):
        self.assertTrue(verify(self.evidence, self.key.public_key()))
        self.assertEqual(self.evidence["payload"]["result"]["status"], "PASS")

    def test_tamper(self):
        e = deepcopy(self.evidence)
        e["payload"]["rows"][0]["approved"] = False
        self.assertFalse(verify(e, self.key.public_key()))

    def test_wrong_key(self):
        self.assertFalse(verify(self.evidence, Ed25519PrivateKey.generate().public_key()))

    def test_missing(self):
        self.assertEqual(evaluate([], ["a"])["status"], "INCOMPLETE")

    def test_duplicate(self):
        self.assertEqual(evaluate(self.rows * 2, ["a"])["status"], "INCOMPLETE")

    def test_unapproved(self):
        self.assertEqual(evaluate([{"id": "a", "approved": False}], ["a"])["status"], "FAIL")

    def test_invalid_type(self):
        self.assertEqual(evaluate([{"id": "a", "approved": "true"}], ["a"])["status"], "INCOMPLETE")

    def test_empty_scope(self):
        self.assertEqual(evaluate([], [])["status"], "INCOMPLETE")

    def test_malformed(self):
        self.assertFalse(verify({}, self.key.public_key()))
