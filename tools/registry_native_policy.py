"""CIP-26 Cardano native-policy decoding, hashing, and signer evaluation."""

from __future__ import annotations

import hashlib


def _head(payload: bytes, offset: int) -> tuple[int, int, int]:
    if offset >= len(payload):
        raise ValueError("truncated native policy CBOR")
    head = payload[offset]
    major, additional = head >> 5, head & 31
    offset += 1
    if additional < 24:
        return major, additional, offset
    sizes = {24: 1, 25: 2, 26: 4, 27: 8}
    if additional not in sizes:
        raise ValueError("indefinite or unsupported native policy CBOR")
    size = sizes[additional]
    if offset + size > len(payload):
        raise ValueError("truncated native policy CBOR")
    return major, int.from_bytes(payload[offset:offset + size], "big"), offset + size


def _item(payload: bytes, offset: int, depth: int = 0) -> tuple[object, int]:
    if depth > 64:
        raise ValueError("native policy nesting is too deep")
    major, argument, offset = _head(payload, offset)
    if major == 0:
        return argument, offset
    if major == 2:
        end = offset + argument
        if end > len(payload):
            raise ValueError("truncated native policy bytes")
        return payload[offset:end], end
    if major == 4:
        if argument > 10000:
            raise ValueError("native policy list is too large")
        items = []
        for _ in range(argument):
            item, offset = _item(payload, offset, depth + 1)
            items.append(item)
        return items, offset
    raise ValueError("unsupported native policy CBOR value")


def _validate_script(script: object, version: int) -> None:
    if not isinstance(script, list) or not script or type(script[0]) is not int:
        raise ValueError("native script must be a tagged array")
    tag = script[0]
    if tag == 0:
        if len(script) != 2 or not isinstance(script[1], bytes) or len(script[1]) != 28:
            raise ValueError("native signature script needs a 28-byte key hash")
    elif tag in (1, 2):
        if len(script) != 2 or not isinstance(script[1], list):
            raise ValueError("native all/any script needs a list")
        for child in script[1]:
            _validate_script(child, version)
    elif tag == 3:
        if (len(script) != 3 or type(script[1]) is not int or not isinstance(script[2], list)):
            raise ValueError("native threshold script needs count and list")
        for child in script[2]:
            _validate_script(child, version)
    elif tag in (4, 5) and version == 1:
        if len(script) != 2 or type(script[1]) is not int:
            raise ValueError("native time-lock script needs a slot")
    else:
        raise ValueError("unsupported native script constructor")


def parse_policy(policy_hex: str) -> tuple[int, list, bytes]:
    """Return version, parsed script, and exact script bytes from [version, script]."""
    if not isinstance(policy_hex, str) or len(policy_hex) % 2:
        raise ValueError("policy must be even-length base16")
    try:
        payload = bytes.fromhex(policy_hex)
    except ValueError as exc:
        raise ValueError("policy must be base16") from exc
    major, count, offset = _head(payload, 0)
    if major != 4 or count != 2:
        raise ValueError("policy must be a two-item CBOR array")
    version, offset = _item(payload, offset)
    if type(version) is not int or version not in (0, 1):
        raise ValueError("policy script version must be 0 or 1")
    script_start = offset
    script, offset = _item(payload, offset)
    if offset != len(payload):
        raise ValueError("trailing bytes after native policy")
    _validate_script(script, version)
    return version, script, payload[script_start:offset]


def policy_id(policy_hex: str) -> str:
    _, _, script_bytes = parse_policy(policy_hex)
    return hashlib.blake2b(b"\x00" + script_bytes, digest_size=28).hexdigest()


def key_hash(public_key_hex: str) -> bytes:
    if not isinstance(public_key_hex, str) or len(public_key_hex) != 64:
        raise ValueError("Ed25519 public key must be 32-byte base16")
    return hashlib.blake2b(bytes.fromhex(public_key_hex), digest_size=28).digest()


def evaluate_policy(script: list, signer_hashes: set[bytes]) -> bool:
    """Evaluate policy ownership from valid attestation signers; ignore slots."""
    tag = script[0]
    if tag == 0:
        return script[1] in signer_hashes
    if tag == 1:
        return all(evaluate_policy(child, signer_hashes) for child in script[1])
    if tag == 2:
        return any(evaluate_policy(child, signer_hashes) for child in script[1])
    if tag == 3:
        return sum(evaluate_policy(child, signer_hashes) for child in script[2]) >= script[1]
    if tag in (4, 5):
        return True
    raise ValueError("unsupported native script constructor")
