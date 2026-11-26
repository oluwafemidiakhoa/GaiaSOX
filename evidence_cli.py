"""Offline synthetic evidence export and verification. No network calls."""
import argparse
import json
import os
import sys
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from gaiasox import collect, verify

LIMIT = 4 * 1024 * 1024

def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key')
        result[key] = value
    return result

def read(path):
    with Path(path).open('rb') as stream:
        data = stream.read(LIMIT + 1)
    if len(data) > LIMIT:
        raise ValueError('input too large')
    return data

def load(path):
    return json.loads(read(path), object_pairs_hook=unique)

def write_new(path, data):
    if len(data) > LIMIT:
        raise ValueError('output too large')
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    keygen = sub.add_parser('keygen')
    keygen.add_argument('private_key')
    keygen.add_argument('public_key')
    export = sub.add_parser('export')
    export.add_argument('private_key')
    export.add_argument('input')
    export.add_argument('output')
    check = sub.add_parser('verify')
    check.add_argument('public_key')
    check.add_argument('evidence')
    args = parser.parse_args(argv)
    try:
        if args.command == 'keygen':
            key = Ed25519PrivateKey.generate()
            write_new(args.private_key, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            write_new(args.public_key, key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        elif args.command == 'export':
            key = serialization.load_pem_private_key(read(args.private_key), password=None)
            if not isinstance(key, Ed25519PrivateKey):
                raise ValueError('wrong key type')
            data = load(args.input)
            envelope = collect(data['rows'], data['expected_ids'], key)
            write_new(args.output, json.dumps(envelope, indent=2, allow_nan=False).encode('utf-8'))
        else:
            key = serialization.load_pem_public_key(read(args.public_key))
            if not isinstance(key, Ed25519PublicKey) or not verify(load(args.evidence), key):
                print('INVALID')
                return 1
            print('VERIFIED: signature and rule result; not an audit opinion')
        return 0
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        print('ERROR: invalid input, key, or file operation', file=sys.stderr)
        return 2

if __name__ == '__main__':
    sys.exit(main())
