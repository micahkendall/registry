#!/usr/bin/env python3
"""CIP-19 payment and reward script addresses for Plutus validator hashes."""

from __future__ import annotations

import argparse

ALPHABET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _convert_bits(data: bytes, source: int, target: int) -> list[int]:
    result = []
    accumulator = 0
    bits = 0
    for value in data:
        accumulator = (accumulator << source) | value
        bits += source
        while bits >= target:
            bits -= target
            result.append((accumulator >> bits) & ((1 << target) - 1))
    if bits:
        result.append((accumulator << (target - bits)) & ((1 << target) - 1))
    return result


def _polymod(values: list[int]) -> int:
    checksum = 1
    for value in values:
        top = checksum >> 25
        checksum = ((checksum & 0x1FFFFFF) << 5) ^ value
        for bit, generator in enumerate((0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)):
            if (top >> bit) & 1:
                checksum ^= generator
    return checksum


def _expand_hrp(hrp: str) -> list[int]:
    return [ord(char) >> 5 for char in hrp] + [0] + [ord(char) & 31 for char in hrp]


def encode_bech32(hrp: str, payload: bytes) -> str:
    if not hrp or any(not 33 <= ord(char) <= 126 or char != char.lower() for char in hrp):
        raise ValueError("invalid bech32 prefix")
    data = _convert_bits(payload, 8, 5)
    value = _polymod(_expand_hrp(hrp) + data + [0] * 6) ^ 1
    checksum = [(value >> (5 * (5 - index))) & 31 for index in range(6)]
    return hrp + "1" + "".join(ALPHABET[item] for item in data + checksum)


def script_address(script_hash: str, network: str) -> str:
    if network not in {"mainnet", "testnet"}:
        raise ValueError("network must be mainnet or testnet")
    if len(script_hash) != 56 or script_hash.lower() != script_hash:
        raise ValueError("script hash must be 28 lowercase base16 bytes")
    raw = bytes.fromhex(script_hash)
    network_tag = 1 if network == "mainnet" else 0
    prefix = "addr" if network_tag else "addr_test"
    return encode_bech32(prefix, bytes([(7 << 4) | network_tag]) + raw)


def script_reward_address(script_hash: str, network: str) -> str:
    if network not in {"mainnet", "testnet"}:
        raise ValueError("network must be mainnet or testnet")
    if len(script_hash) != 56 or script_hash.lower() != script_hash:
        raise ValueError("script hash must be 28 lowercase base16 bytes")
    raw = bytes.fromhex(script_hash)
    network_tag = 1 if network == "mainnet" else 0
    prefix = "stake" if network_tag else "stake_test"
    return encode_bech32(prefix, bytes([(15 << 4) | network_tag]) + raw)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("script_hash")
    parser.add_argument("network", choices=("mainnet", "testnet"))
    args = parser.parse_args()
    try:
        print(script_address(args.script_hash, args.network))
    except ValueError as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
