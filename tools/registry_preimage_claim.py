"""Verify the optional CIP-26 generic hash-preimage claim.

This is distinct from the registry's independently uploaded content segments.
The subject determines the expected digest size as specified by CIP-26.
"""

from __future__ import annotations

import hashlib
import hmac


def _digest(algorithm: str, message: bytes, size: int) -> bytes | None:
    if algorithm == "sha1":
        return hashlib.sha1(message).digest() if size == 20 else None
    if algorithm == "md5":
        return hashlib.md5(message).digest() if size == 16 else None
    if algorithm in {"sha", "sha3"}:
        bits = size * 8
        if bits not in {224, 256, 384, 512}:
            return None
        name = f"sha{bits}" if algorithm == "sha" else f"sha3_{bits}"
        return hashlib.new(name, message).digest()
    if algorithm == "blake2b":
        return hashlib.blake2b(message, digest_size=size).digest() if 1 <= size <= 64 else None
    if algorithm == "blake2s":
        return hashlib.blake2s(message, digest_size=size).digest() if 1 <= size <= 32 else None
    if algorithm == "keccak":
        if size * 8 not in {224, 256, 384, 512}:
            return None
        try:
            from Crypto.Hash import keccak
        except ImportError as exc:
            raise RuntimeError("install pycryptodome to verify Keccak CIP-26 preimages") from exc
        hasher = keccak.new(digest_bits=size * 8)
        hasher.update(message)
        return hasher.digest()
    raise ValueError("unsupported CIP-26 preimage algorithm")


def verify_preimage_claim(subject: str, claim: dict) -> bool:
    """Check hash(msg bytes) equals the base16 subject; false on mismatch."""
    if not isinstance(subject, str) or not isinstance(claim, dict) or set(claim) != {"alg", "msg"}:
        raise ValueError("invalid CIP-26 preimage claim")
    if len(subject) % 2 or not isinstance(claim["msg"], str) or len(claim["msg"]) % 2:
        raise ValueError("subject and preimage must be even-length base16")
    try:
        target = bytes.fromhex(subject)
        message = bytes.fromhex(claim["msg"])
    except ValueError as exc:
        raise ValueError("subject and preimage must be base16") from exc
    actual = _digest(claim["alg"], message, len(target))
    return actual is not None and hmac.compare_digest(actual, target)
