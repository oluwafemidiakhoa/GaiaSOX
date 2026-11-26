"""Local single-writer hash chain. External trusted head required for truncation detection."""
import hashlib
import json
import os
from pathlib import Path
from gaiasox import canonical

GENESIS = '0' * 64

def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()

def verify_chain(records, trusted_head=None):
    head = GENESIS
    for i, record in enumerate(records):
        body = {'index': i, 'previous': head, 'evidence': record['evidence']}
        if record != {**body, 'hash': digest(body)}:
            raise ValueError('invalid chain')
        head = record['hash']
    if trusted_head is not None and head != trusted_head:
        raise ValueError('trusted head mismatch')
    return head

def read_records(path):
    path = Path(path)
    if not path.exists():
        return []
    with path.open(encoding='utf-8') as stream:
        return [json.loads(line) for line in stream]

def append(path, evidence):
    # Exclusive lock file: fail closed if another writer or stale lock exists.
    path = Path(path)
    lock = Path(str(path) + '.lock')
    fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        records = read_records(path)
        head = verify_chain(records)
        body = {'index': len(records), 'previous': head, 'evidence': evidence}
        record = {**body, 'hash': digest(body)}
        with os.fdopen(os.open(path, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600), 'ab') as stream:
            stream.write(canonical(record) + b'\n')
            stream.flush()
            os.fsync(stream.fileno())
        return record['hash']
    finally:
        os.close(fd)
        lock.unlink()
