#!/usr/bin/env python3
"""CIP-26 content commitments and individually uploadable preimages.

The output is an off-chain transaction plan, not a signed Cardano transaction.
The registry stores packed hashes; each preimage UTxO may arrive separately.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import io
import json
import re
import warnings
from pathlib import Path
from urllib.parse import urlsplit

CHUNK_BYTES = 12_000
MAX_CONTENT_BYTES = 380_000
URI_CHARS = re.compile(r"[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+\Z")
BAD_PERCENT_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")


def unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(payload: str | bytes) -> object:
    return json.loads(payload, object_pairs_hook=unique_object)


def digest(data: bytes) -> bytes:
    return hashlib.blake2b(data, digest_size=32).digest()


def segment_hash(payload: bytes) -> bytes:
    return digest(b"\x01" + payload)


def validate_logo_png(payload: bytes) -> None:
    """Decode a CIP-26 PNG, including its chunks and compressed pixel data."""
    if len(payload) > 64 * 1024:
        raise ValueError("logo must be a PNG of at most 64 KiB")
    try:
        from PIL import Image
    except ImportError as exc:
        raise RuntimeError("install Pillow to validate CIP-26 PNG logos") from exc
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(payload)) as image:
                if image.format != "PNG":
                    raise ValueError("logo must be a PNG of at most 64 KiB")
                image.verify()
            with Image.open(io.BytesIO(payload)) as image:
                image.load()
    except (OSError, SyntaxError, Image.DecompressionBombWarning,
            Image.DecompressionBombError) as exc:
        raise ValueError("logo must be a valid PNG of at most 64 KiB") from exc


def valid_uri(value: str) -> bool:
    if not value or len(value) > 250 or not URI_CHARS.fullmatch(value) or BAD_PERCENT_ESCAPE.search(value):
        return False
    try:
        parts = urlsplit(value)
        if not parts.scheme or (parts.scheme.lower() in {"http", "https"} and not parts.hostname):
            return False
        _ = parts.port
    except ValueError:
        return False
    return True


def canonical_content(entry: dict) -> bytes:
    """Validate the common CIP-26 envelope, preserving every extension value."""
    if not isinstance(entry, dict):
        raise ValueError("entry must be a JSON object")
    subject = entry.get("subject")
    if not isinstance(subject, str) or not 56 <= len(subject) <= 120 or len(subject) % 2:
        raise ValueError("subject must be a 28-byte policy id plus up to 32-byte asset name")
    if subject != subject.lower() or any(c not in "0123456789abcdef" for c in subject):
        raise ValueError("subject must be lowercase base16")
    for name, value in entry.items():
        if name == "subject":
            continue
        if name == "policy":
            if not isinstance(value, str) or len(value) % 2 or any(c not in "0123456789abcdefABCDEF" for c in value):
                raise ValueError("policy must be base16 CBOR")
            continue
        if name == "preimage":
            if not isinstance(value, dict) or set(value) != {"alg", "msg"}:
                raise ValueError("preimage must contain alg and msg")
            if not isinstance(value["alg"], str) or value["alg"] not in {"sha1", "sha", "sha3", "blake2b", "blake2s", "keccak", "md5"}:
                raise ValueError("unsupported preimage algorithm")
            msg = value["msg"]
            if not isinstance(msg, str) or len(msg) % 2 or any(c not in "0123456789abcdefABCDEF" for c in msg):
                raise ValueError("preimage msg must be base16")
            continue
        if not isinstance(value, dict) or not {"value", "sequenceNumber"} <= set(value) or set(value) - {"value", "sequenceNumber", "signatures"}:
            raise ValueError(f"{name} must contain value and sequenceNumber, with optional signatures")
        if not isinstance(value["sequenceNumber"], int) or isinstance(value["sequenceNumber"], bool) or value["sequenceNumber"] < 0:
            raise ValueError(f"{name} sequenceNumber must be a nonnegative integer")
        if not isinstance(value.get("signatures", []), list):
            raise ValueError(f"{name} signatures must be an array")
        for signature in value.get("signatures", []):
            if not isinstance(signature, dict) or set(signature) != {"publicKey", "signature"}:
                raise ValueError(f"{name} has an invalid annotated signature")
            for field, length in (("publicKey", 64), ("signature", 128)):
                encoded = signature[field]
                if not isinstance(encoded, str) or len(encoded) != length or any(c not in "0123456789abcdefABCDEF" for c in encoded):
                    raise ValueError(f"{name} {field} must be base16 of the expected length")
        actual = value["value"]
        if name in {"name", "description", "ticker", "url", "logo"} and not isinstance(actual, str):
            raise ValueError(f"{name} value must be a string")
        if name == "name" and not 1 <= len(actual) <= 50:
            raise ValueError("name exceeds CIP-26 bounds")
        if name == "description" and len(actual) > 500:
            raise ValueError("description exceeds CIP-26 bounds")
        if name == "ticker" and not 2 <= len(actual) <= 9:
            raise ValueError("ticker exceeds CIP-26 bounds")
        if name == "url" and not valid_uri(actual):
            raise ValueError("url must be a URI of at most 250 characters")
        if name == "logo":
            try:
                image = base64.b64decode(actual, validate=True)
            except (ValueError, binascii.Error) as exc:
                raise ValueError("logo must be base64") from exc
            validate_logo_png(image)
        if name == "decimals" and (not isinstance(actual, int) or isinstance(actual, bool) or not 0 <= actual <= 19):
            raise ValueError("decimals must be an integer between 0 and 19")
    encoded = json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    if len(encoded) > MAX_CONTENT_BYTES:
        raise ValueError("entry exceeds the 380,000-byte registry limit")
    return encoded


def chunks(content: bytes, size: int = CHUNK_BYTES) -> list[bytes]:
    if not 1 <= size <= CHUNK_BYTES:
        raise ValueError("chunk size must be between 1 and 12000 bytes")
    return [content[i : i + size] for i in range(0, len(content), size)]


def plan(entry: dict) -> dict:
    content = canonical_content(entry)
    parts = chunks(content)
    hashes = [segment_hash(part).hex() for part in parts]
    return {
        "subject": entry["subject"],
        "contentHash": digest(content).hex(),
        "segmentHashes": hashes,
        "contentBytes": len(content),
        "chunkSizeLimit": CHUNK_BYTES,
        "preimages": [
            {"subject": entry["subject"], "index": index, "hash": hashes[index], "bytesBase64": base64.b64encode(part).decode()}
            for index, part in enumerate(parts)
        ],
    }


def hash_only_commitment(subject: str, content_hash: str) -> dict:
    from registry_list import hash_only_ref
    return hash_only_ref(subject, content_hash)


def matches_commitment(upload: dict, existing: dict) -> bool:
    keys = ("subject", "contentHash") if existing.get("contentBytes") == 0 and existing.get("segmentHashes") == [] else (
        "subject", "contentHash", "contentBytes", "segmentHashes")
    return all(upload.get(key) == existing.get(key) for key in keys)


def verify_plan(upload: dict, *, require_complete: bool = True) -> bytes | None:
    hashes = upload["segmentHashes"]
    count = len(hashes)
    if not 1 <= count <= 32 or not all(isinstance(h, str) and len(h) == 64 and all(c in "0123456789abcdef" for c in h) for h in hashes):
        raise ValueError("invalid segment hash list")
    if not isinstance(upload["contentBytes"], int) or not 0 < upload["contentBytes"] <= MAX_CONTENT_BYTES:
        raise ValueError("invalid content length")
    if count != (upload["contentBytes"] + CHUNK_BYTES - 1) // CHUNK_BYTES:
        raise ValueError("segment count does not match content length")
    if upload["chunkSizeLimit"] != CHUNK_BYTES:
        raise ValueError("unsupported chunk size")
    if not isinstance(upload["contentHash"], str) or len(upload["contentHash"]) != 64 or any(c not in "0123456789abcdef" for c in upload["contentHash"]):
        raise ValueError("invalid full content hash")
    seen: dict[int, bytes] = {}
    for part in upload.get("preimages", []):
        if part.get("subject") != upload["subject"]:
            raise ValueError("preimage subject mismatch")
        index = part["index"]
        try:
            payload = base64.b64decode(part["bytesBase64"], validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ValueError("preimage bytes must be base64") from exc
        if not 0 <= index < count or not 0 < len(payload) <= CHUNK_BYTES or index in seen:
            raise ValueError("duplicate, empty, out-of-range or oversized preimage")
        actual_hash = segment_hash(payload).hex()
        if part["hash"] != upload["segmentHashes"][index] or actual_hash != part["hash"]:
            raise ValueError(f"content hash mismatch at segment {index}")
        if index < count - 1 and len(payload) != CHUNK_BYTES:
            raise ValueError("non-final segment must contain 12000 bytes")
        seen[index] = payload
    if not require_complete:
        return None
    if set(seen) != set(range(count)):
        raise ValueError("upload is incomplete")
    content = b"".join(seen[i] for i in range(count))
    if len(content) != upload["contentBytes"]:
        raise ValueError("content length mismatch")
    if digest(content).hex() != upload["contentHash"]:
        raise ValueError("full content hash mismatch")
    entry = load_json(content)
    if canonical_content(entry) != content or entry["subject"] != upload["subject"]:
        raise ValueError("content or subject mismatch")
    return content


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("entry", type=Path, nargs="?", help="CIP-26 JSON entry; omit for a hash-only commitment")
    parser.add_argument("--subject", help="native-token subject for a hash-only commitment")
    parser.add_argument("--content-hash", help="Blake2b-256 of the future canonical CIP-26 JSON")
    parser.add_argument("--lazy", action="store_true", help="print commitment only, without upload chunks")
    parser.add_argument("--expect-commitment", type=Path, help="require content to match an existing lazy commitment")
    args = parser.parse_args()
    if args.entry is None:
        if args.subject is None or args.content_hash is None or args.expect_commitment:
            parser.error("hash-only commitment requires --subject and --content-hash")
        print(json.dumps(hash_only_commitment(args.subject, args.content_hash), indent=2))
        return
    if args.subject is not None or args.content_hash is not None:
        parser.error("--subject and --content-hash are for hash-only commitments")
    upload = plan(load_json(args.entry.read_text()))
    if args.expect_commitment and not matches_commitment(upload, load_json(args.expect_commitment.read_text())):
        parser.error("content does not match the existing lazy commitment")
    if args.lazy:
        upload.pop("preimages")
    print(json.dumps(upload, indent=2))


if __name__ == "__main__":
    main()
