#!/usr/bin/env python3
"""Construct individual cardano-cli transaction build commands for uploads.

An upload spends only the payer's wallet UTxO. It does not spend the registry
script or governance NFT. Each call selects exactly one segment and produces
one unsigned transaction body; the payer signs and submits it separately.
"""

from __future__ import annotations

import argparse
import base64
import json
import re
import shlex
import subprocess
from pathlib import Path

from registry_address import script_address
from registry_content import load_json, matches_commitment, verify_plan
from registry_data import preimage_datum
from registry_state import decode_datum, read_state


def next_missing_index(manifest: dict, upload: dict, snapshot: dict, network: str) -> int:
    """Select the first preimage absent from a current, matching registry entry."""
    verify_plan(upload)
    if network not in {"mainnet", "testnet"}:
        raise ValueError("network must be mainnet or testnet")
    address = script_address(manifest["registryScriptHash"], network)
    if manifest.get("registryAddresses", {}).get(network) != address:
        raise ValueError("manifest registry address does not match script hash")
    state = read_state(snapshot, address, manifest["nodePolicyId"])
    current = next((item for item in state["entries"] if item["subject"] == upload["subject"]), None)
    if current is None or not matches_commitment(upload, current):
        raise ValueError("current registry commitment does not match the upload plan")
    expected = {(part["index"], part["hash"], base64.b64decode(part["bytesBase64"], validate=True))
                for part in upload["preimages"]}
    present = set()
    for output in snapshot.values():
        if not isinstance(output, dict) or output.get("address") != address:
            continue
        inline = output.get("inlineDatum")
        if inline is None:
            continue
        try:
            kind, item = decode_datum(inline)
        except ValueError:
            continue
        if kind == "preimage" and item["subject"] == upload["subject"]:
            candidate = (item["index"], item["hash"], item["bytes"])
            if candidate in expected:
                present.add(item["index"])
    for index in range(len(upload["preimages"])):
        if index not in present:
            return index
    raise ValueError("all upload segments are already published")


def upload_command(
    manifest: dict, upload: dict, datum_directory: Path, index: int, *,
    network: str, testnet_magic: int | None, funding_utxo: str,
    change_address: str, lovelace: int, body_file: Path,
    cli: str = "cardano-cli",
) -> list[str]:
    verify_plan(upload)
    if network not in {"mainnet", "testnet"}:
        raise ValueError("network must be mainnet or testnet")
    if network == "testnet" and (type(testnet_magic) is not int or testnet_magic < 0):
        raise ValueError("testnet magic is required")
    if network == "mainnet" and testnet_magic is not None:
        raise ValueError("mainnet must not have a testnet magic")
    if type(index) is not int or not 0 <= index < len(upload["preimages"]):
        raise ValueError("preimage index is out of range")
    if type(lovelace) is not int or lovelace <= 0:
        raise ValueError("output lovelace must be positive")
    if not isinstance(change_address, str) or not change_address:
        raise ValueError("change address is required")
    if not re.fullmatch(r"[0-9a-f]{64}#[0-9]+", funding_utxo):
        raise ValueError("funding UTxO must be lowercase TXID#INDEX")
    registry_hash = manifest["registryScriptHash"]
    address = script_address(registry_hash, network)
    if manifest.get("registryAddresses", {}).get(network) != address:
        raise ValueError("manifest registry address does not match script hash")
    part = upload["preimages"][index]
    if part["index"] != index:
        raise ValueError("preimage list is not ordered by index")
    datum_file = datum_directory / f"preimage-{index:03d}.datum.json"
    expected = preimage_datum(upload["subject"], index, part["hash"],
                              base64.b64decode(part["bytesBase64"], validate=True))
    if load_json(datum_file.read_text()) != expected:
        raise ValueError(f"preimage datum does not match upload plan: {datum_file}")
    command = [cli, "latest", "transaction", "build", "--tx-in", funding_utxo,
               "--tx-out", f"{address}+{lovelace}",
               "--tx-out-inline-datum-file", str(datum_file),
               "--change-address", change_address,
               "--out-file", str(body_file)]
    command.extend(["--mainnet"] if network == "mainnet" else ["--testnet-magic", str(testnet_magic)])
    return command


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("upload_plan", type=Path)
    parser.add_argument("datum_directory", type=Path)
    parser.add_argument("index", help="segment number or 'next' to resume from a registry snapshot")
    parser.add_argument("funding_utxo")
    parser.add_argument("change_address")
    parser.add_argument("lovelace", type=int, help="ADA amount in lovelace for the segment output")
    parser.add_argument("body_file", type=Path)
    parser.add_argument("--network", choices=("mainnet", "testnet"), required=True)
    parser.add_argument("--testnet-magic", type=int)
    parser.add_argument("--cli", default="cardano-cli")
    parser.add_argument("--registry-snapshot", type=Path,
                        help="complete cardano-cli UTxO snapshot, required with index 'next'")
    parser.add_argument("--build", action="store_true", help="invoke cardano-cli to build the unsigned body")
    args = parser.parse_args()
    try:
        manifest = load_json(args.manifest.read_text())
        upload = load_json(args.upload_plan.read_text())
        if args.index == "next":
            if args.registry_snapshot is None:
                raise ValueError("index 'next' requires --registry-snapshot")
            index = next_missing_index(manifest, upload,
                                       load_json(args.registry_snapshot.read_text()), args.network)
        else:
            if args.registry_snapshot is not None:
                raise ValueError("--registry-snapshot is only used with index 'next'")
            index = int(args.index)
        command = upload_command(
            manifest, upload, args.datum_directory, index, network=args.network,
            testnet_magic=args.testnet_magic, funding_utxo=args.funding_utxo,
            change_address=args.change_address, lovelace=args.lovelace,
            body_file=args.body_file, cli=args.cli,
        )
    except (ValueError, KeyError, TypeError, OSError) as exc:
        parser.error(str(exc))
    print(shlex.join(command))
    if args.build:
        subprocess.run(command, check=True)


if __name__ == "__main__":
    main()
