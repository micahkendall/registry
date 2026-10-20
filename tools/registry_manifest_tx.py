#!/usr/bin/env python3
"""Build one unsigned transaction to publish a segment layout for a hash-only registry entry."""

from __future__ import annotations

import argparse
import re
import shlex
import subprocess
from pathlib import Path

from registry_address import script_address
from registry_content import load_json, verify_plan
from registry_data import manifest_datum


def manifest_command(
    manifest: dict, upload: dict, datum_directory: Path, *,
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
    if type(lovelace) is not int or lovelace <= 0:
        raise ValueError("output lovelace must be positive")
    if not isinstance(change_address, str) or not change_address:
        raise ValueError("change address is required")
    if not re.fullmatch(r"[0-9a-f]{64}#[0-9]+", funding_utxo):
        raise ValueError("funding UTxO must be lowercase TXID#INDEX")
    address = script_address(manifest["registryScriptHash"], network)
    if manifest.get("registryAddresses", {}).get(network) != address:
        raise ValueError("manifest registry address does not match script hash")
    datum_file = datum_directory / "manifest.datum.json"
    if load_json(datum_file.read_text()) != manifest_datum(upload):
        raise ValueError(f"manifest datum does not match upload plan: {datum_file}")
    command = [cli, "latest", "transaction", "build", "--tx-in", funding_utxo,
               "--tx-out", f"{address}+{lovelace}",
               "--tx-out-inline-datum-file", str(datum_file),
               "--change-address", change_address, "--out-file", str(body_file)]
    command.extend(["--mainnet"] if network == "mainnet" else ["--testnet-magic", str(testnet_magic)])
    return command


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("upload_plan", type=Path)
    parser.add_argument("datum_directory", type=Path)
    parser.add_argument("funding_utxo")
    parser.add_argument("change_address")
    parser.add_argument("lovelace", type=int)
    parser.add_argument("body_file", type=Path)
    parser.add_argument("--network", choices=("mainnet", "testnet"), required=True)
    parser.add_argument("--testnet-magic", type=int)
    parser.add_argument("--cli", default="cardano-cli")
    parser.add_argument("--build", action="store_true")
    args = parser.parse_args()
    try:
        command = manifest_command(
            load_json(args.manifest.read_text()), load_json(args.upload_plan.read_text()),
            args.datum_directory, network=args.network, testnet_magic=args.testnet_magic,
            funding_utxo=args.funding_utxo, change_address=args.change_address,
            lovelace=args.lovelace, body_file=args.body_file, cli=args.cli)
    except (ValueError, KeyError, OSError) as exc:
        parser.error(str(exc))
    print(shlex.join(command))
    if args.build:
        subprocess.run(command, check=True)


if __name__ == "__main__":
    main()
