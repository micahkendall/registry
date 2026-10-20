#!/usr/bin/env python3
"""Verify CIP-26 property attestations against explicitly trusted Ed25519 keys.

The on-chain commitment authenticates the complete JSON bytes. This module
performs the separate CIP-26 per-property signature check for clients.
"""

from __future__ import annotations

import argparse
import base64
import json
import math
import struct
from pathlib import Path

from registry_content import canonical_content, digest, load_json
from registry_native_policy import evaluate_policy, key_hash, parse_policy, policy_id
from registry_preimage_claim import verify_preimage_claim


def _head(major: int, argument: int) -> bytes:
    if argument < 0:
        raise ValueError("negative CBOR argument")
    if argument < 24:
        return bytes([(major << 5) | argument])
    if argument < 256:
        return bytes([(major << 5) | 24, argument])
    if argument < 65536:
        return bytes([(major << 5) | 25]) + argument.to_bytes(2, "big")
    if argument < 2**32:
        return bytes([(major << 5) | 26]) + argument.to_bytes(4, "big")
    if argument < 2**64:
        return bytes([(major << 5) | 27]) + argument.to_bytes(8, "big")
    raise ValueError("CBOR argument exceeds 64 bits")


def cbor_json(value: object, *, float_width: str = "preferred") -> bytes:
    """Encode JSON values as definite-length RFC 8949 CBOR.

    Map keys are sorted by their encoded bytes and floats use the shortest
    exact width. The float64 option checks signatures from encoders that
    always use binary64 for JSON numbers.
    """
    if float_width not in {"preferred", "float64"}:
        raise ValueError("unsupported CBOR float width")
    if value is None:
        return b"\xf6"
    if value is False:
        return b"\xf4"
    if value is True:
        return b"\xf5"
    if type(value) is int:
        if value >= 0:
            if value < 2**64:
                return _head(0, value)
            payload = value.to_bytes((value.bit_length() + 7) // 8, "big")
            return _head(6, 2) + _head(2, len(payload)) + payload
        magnitude = -1 - value
        if magnitude < 2**64:
            return _head(1, magnitude)
        payload = magnitude.to_bytes((magnitude.bit_length() + 7) // 8, "big")
        return _head(6, 3) + _head(2, len(payload)) + payload
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError("nonfinite JSON number")
        if float_width == "preferred":
            for marker, fmt in ((b"\xf9", ">e"), (b"\xfa", ">f")):
                try:
                    encoded = struct.pack(fmt, value)
                    decoded = struct.unpack(fmt, encoded)[0]
                except OverflowError:
                    continue
                if decoded == value and (value != 0 or math.copysign(1, decoded) == math.copysign(1, value)):
                    return marker + encoded
        return b"\xfb" + struct.pack(">d", value)
    if isinstance(value, str):
        encoded = value.encode("utf-8")
        return _head(3, len(encoded)) + encoded
    if isinstance(value, list):
        return _head(4, len(value)) + b"".join(cbor_json(item, float_width=float_width) for item in value)
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise ValueError("JSON object keys must be strings")
        items = sorted(((cbor_json(key, float_width=float_width),
                         cbor_json(item, float_width=float_width)) for key, item in value.items()),
                       key=lambda pair: pair[0])
        return _head(5, len(items)) + b"".join(key + item for key, item in items)
    raise ValueError("unsupported JSON value")


def attestation_message(subject: str, name: str, value: object, sequence_number: int,
                        *, legacy_logo_bytes: bool = False, float_width: str = "preferred") -> bytes:
    if not isinstance(subject, str) or not isinstance(name, str):
        raise ValueError("subject and property name must be strings")
    if type(sequence_number) is not int or sequence_number < 0:
        raise ValueError("sequence number must be nonnegative integer")
    encoded_value = cbor_json(value, float_width=float_width)
    if legacy_logo_bytes and name == "logo" and isinstance(value, str):
        decoded = base64.b64decode(value, validate=True)
        encoded_value = _head(2, len(decoded)) + decoded
    encoded = (cbor_json(subject), cbor_json(name), encoded_value, cbor_json(sequence_number))
    return digest(b"".join(digest(piece) for piece in encoded))


def _verified_signatures(subject: str, name: str, entry: dict) -> tuple[set[str], bool]:
    """Return valid public keys and whether every supplied signature verified."""
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:
        raise RuntimeError("install the cryptography package to verify CIP-26 attestations") from exc
    if not isinstance(entry, dict) or not isinstance(entry.get("signatures"), list):
        return set(), False
    preferred = attestation_message(subject, name, entry["value"], entry["sequenceNumber"])
    messages = [preferred]
    binary64 = attestation_message(subject, name, entry["value"], entry["sequenceNumber"],
                                   float_width="float64")
    if binary64 != preferred:
        messages.append(binary64)
    if name == "logo":
        messages.append(attestation_message(subject, name, entry["value"],
                                            entry["sequenceNumber"], legacy_logo_bytes=True))
    verified = set()
    all_valid = True
    for annotation in entry["signatures"]:
        public_hex = annotation["publicKey"]
        try:
            public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex))
            signature = bytes.fromhex(annotation["signature"])
            for message in messages:
                try:
                    public_key.verify(signature, message)
                except InvalidSignature:
                    continue
                verified.add(public_hex.lower())
                break
            else:
                all_valid = False
        except (InvalidSignature, ValueError):
            all_valid = False
    return verified, all_valid


def verify_property(subject: str, name: str, entry: dict, trusted_keys: set[str]) -> bool:
    """Accept a property only with one valid signature by a trusted key."""
    verified, _ = _verified_signatures(subject, name, entry)
    return bool(verified & trusted_keys)


def parse_trusted_keys(value: object) -> set[str] | dict[str, set[str]]:
    """Read a global key array or a subject-scoped key map from JSON data."""
    def checked_group(keys: object) -> set[str]:
        if not isinstance(keys, list):
            raise ValueError("each trusted-key group must be an array")
        if any(not isinstance(key, str) or len(key) != 64
               or any(c not in "0123456789abcdef" for c in key) for key in keys):
            raise ValueError("trusted keys must be lowercase 32-byte public-key hex strings")
        return set(keys)

    if isinstance(value, list):
        result: set[str] | dict[str, set[str]] = checked_group(value)
    elif isinstance(value, dict):
        result = {}
        for subject, keys in value.items():
            if (not isinstance(subject, str) or not 56 <= len(subject) <= 120
                    or len(subject) % 2 or any(c not in "0123456789abcdef" for c in subject)):
                raise ValueError("trusted-key map subjects must be native-token base16 IDs")
            result[subject] = checked_group(keys)
    else:
        raise ValueError("trusted keys must be an array or subject-to-key-array object")
    return result


def verify_document(document: dict, trusted_keys: set[str] | dict[str, set[str]]) -> dict[str, bool]:
    """Return each property's trusted signature status after schema checks."""
    canonical_content(document)
    if isinstance(trusted_keys, set):
        keys = parse_trusted_keys(list(trusted_keys))
    elif isinstance(trusted_keys, dict):
        keys = parse_trusted_keys({subject: list(group) if isinstance(group, set) else group
                                   for subject, group in trusted_keys.items()})
    else:
        raise ValueError("trusted keys must be a set or subject-to-key-set map")
    subject_keys = keys if isinstance(keys, set) else keys.get(document["subject"], set())
    policy = None
    if "policy" in document:
        policy_hex = document["policy"]
        _, policy, _ = parse_policy(policy_hex)
        if not document["subject"].startswith(policy_id(policy_hex)):
            raise ValueError("native policy does not hash to subject policy ID")
    statuses = {}
    for name, entry in document.items():
        if name in {"subject", "policy", "preimage"}:
            continue
        verified, all_valid = _verified_signatures(document["subject"], name, entry)
        if policy is None:
            statuses[name] = bool(verified & subject_keys)
        else:
            statuses[name] = all_valid and evaluate_policy(policy, {key_hash(key) for key in verified})
    return statuses


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("document", type=Path)
    parser.add_argument("trusted_keys", type=Path,
                        help="JSON key array, or native-token subject to key-array map")
    args = parser.parse_args()
    try:
        keys = parse_trusted_keys(load_json(args.trusted_keys.read_text()))
        document = load_json(args.document.read_text())
        result = verify_document(document, keys)
        preimage_valid = verify_preimage_claim(document["subject"], document["preimage"]) if "preimage" in document else None
    except (ValueError, KeyError, TypeError, OSError, RuntimeError) as exc:
        parser.error(str(exc))
    print(json.dumps({"attestations": result, "preimageClaimValid": preimage_valid}, indent=2))
    if not all(result.values()) or preimage_valid is False:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
