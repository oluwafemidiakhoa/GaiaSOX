"""Synthetic privileged-access evidence prototype."""
import json
import hashlib
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.exceptions import InvalidSignature

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")

def evaluate(rows, expected_ids):
    if not isinstance(rows, list) or not isinstance(expected_ids, list) or not expected_ids:
        return {"status": "INCOMPLETE", "exceptions": []}
    if any(not isinstance(x, str) or not x for x in expected_ids) or len(set(expected_ids)) != len(expected_ids):
        return {"status": "INCOMPLETE", "exceptions": []}
    if any(not isinstance(r, dict) or not isinstance(r.get("id"), str) or type(r.get("approved")) is not bool for r in rows):
        return {"status": "INCOMPLETE", "exceptions": []}
    ids = [r["id"] for r in rows]
    if len(ids) != len(set(ids)) or set(ids) != set(expected_ids):
        return {"status": "INCOMPLETE", "exceptions": []}
    exceptions = sorted(r["id"] for r in rows if not r["approved"])
    return {"status": "FAIL" if exceptions else "PASS", "exceptions": exceptions}

def collect(rows, expected_ids, private_key):
    payload = {"schema": 1, "control": "SYNTH-ACCESS-001", "rule_version": "1.0.0",
               "source": "synthetic", "collected_at": datetime.now(timezone.utc).isoformat(),
               "rows": rows, "expected_ids": expected_ids,
               "result": evaluate(rows, expected_ids)}
    raw = canonical(payload)
    return {"payload": payload, "sha256": hashlib.sha256(raw).hexdigest(),
            "signature": private_key.sign(raw).hex()}

def verify(envelope, trusted_public_key):
    """Key must be supplied independently; never trust an embedded key."""
    try:
        p = envelope["payload"]
        raw = canonical(p)
        if hashlib.sha256(raw).hexdigest() != envelope["sha256"]:
            return False
        trusted_public_key.verify(bytes.fromhex(envelope["signature"]), raw)
        return (p["schema"] == 1 and p["control"] == "SYNTH-ACCESS-001"
                and p["rule_version"] == "1.0.0" and p["source"] == "synthetic"
                and p["result"] == evaluate(p["rows"], p["expected_ids"]))
    except (InvalidSignature, ValueError, TypeError, KeyError, AttributeError, OverflowError):
        return False

if __name__ == "__main__":
    key = Ed25519PrivateKey.generate()
    evidence = collect([{"id": "demo-admin", "approved": False}], ["demo-admin"], key)
    print(json.dumps({"evidence": evidence, "verified": verify(evidence, key.public_key())}, indent=2))
