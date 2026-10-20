#!/usr/bin/env python3
"""Print the Cardano Plutus V3 script hash of an exported text envelope."""

import argparse
import hashlib
import json
from pathlib import Path


def decode_bytestring(encoded: bytes) -> bytes:
    if not encoded:
        raise ValueError("empty CBOR")
    head = encoded[0]
    if head >> 5 != 2:
        raise ValueError("expected a CBOR byte string")
    additional = head & 31
    if additional < 24:
        length, offset = additional, 1
    elif additional == 24:
        length, offset = int.from_bytes(encoded[1:2], "big"), 2
    elif additional == 25:
        length, offset = int.from_bytes(encoded[1:3], "big"), 3
    elif additional == 26:
        length, offset = int.from_bytes(encoded[1:5], "big"), 5
    else:
        raise ValueError("unsupported CBOR byte-string length")
    if offset > len(encoded) or len(encoded) != offset + length:
        raise ValueError("invalid CBOR byte-string length")
    return encoded[offset:]


def script_hash(envelope: dict) -> str:
    if envelope.get("type") != "PlutusScriptV3":
        raise ValueError("expected a PlutusScriptV3 text envelope")
    serialized = bytes.fromhex(envelope["cborHex"])
    decode_bytestring(serialized)
    return hashlib.blake2b(b"\x03" + serialized, digest_size=28).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("script", type=Path)
    args = parser.parse_args()
    print(script_hash(json.loads(args.script.read_text())))


if __name__ == "__main__":
    main()
