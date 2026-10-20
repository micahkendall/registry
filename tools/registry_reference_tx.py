#!/usr/bin/env python3
"""Build one unsigned transaction that publishes one registry reference script."""

from __future__ import annotations

import argparse
import re
import shlex
import subprocess
from pathlib import Path

from registry_content import load_json
from registry_script_hash import script_hash


SCRIPT_HASH_KEYS = {
    "governance": "governanceScriptHash",
    "governancePolicy": "governancePolicyId",
    "nodePolicy": "nodePolicyId",
    "registry": "registryScriptHash",
}


def reference_command(
    manifest: dict, script_dir: Path, kind: str, *,
    network: str, testnet_magic: int | None, funding_utxo: str,
    holder_address: str, change_address: str, lovelace: int,
    body_file: Path, cli: str = "cardano-cli",
) -> list[str]:
    if kind not in SCRIPT_HASH_KEYS:
        raise ValueError("unknown registry script kind")
    if network not in {"mainnet", "testnet"}:
        raise ValueError("network must be mainnet or testnet")
    if network == "testnet" and (type(testnet_magic) is not int or testnet_magic < 0):
        raise ValueError("testnet magic is required")
    if network == "mainnet" and testnet_magic is not None:
        raise ValueError("mainnet must not have a testnet magic")
    if not re.fullmatch(r"[0-9a-f]{64}#[0-9]+", funding_utxo):
        raise ValueError("funding UTxO must be lowercase TXID#INDEX")
    if not holder_address or not change_address:
        raise ValueError("holder and change addresses are required")
    if type(lovelace) is not int or lovelace <= 0:
        raise ValueError("reference output lovelace must be positive")
    script_file = script_dir / manifest["scripts"][kind]
    if script_hash(load_json(script_file.read_text())) != manifest[SCRIPT_HASH_KEYS[kind]]:
        raise ValueError("script bytes disagree with deployment manifest")
    command = [cli, "latest", "transaction", "build",
               "--tx-in", funding_utxo,
               "--tx-out", f"{holder_address}+{lovelace}",
               "--tx-out-reference-script-file", str(script_file),
               "--change-address", change_address, "--out-file", str(body_file)]
    command += ["--mainnet"] if network == "mainnet" else ["--testnet-magic", str(testnet_magic)]
    return command


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("script_dir", type=Path)
    parser.add_argument("kind", choices=tuple(SCRIPT_HASH_KEYS))
    parser.add_argument("funding_utxo")
    parser.add_argument("holder_address")
    parser.add_argument("change_address")
    parser.add_argument("lovelace", type=int)
    parser.add_argument("body_file", type=Path)
    parser.add_argument("--network", choices=("mainnet", "testnet"), required=True)
    parser.add_argument("--testnet-magic", type=int)
    parser.add_argument("--cli", default="cardano-cli")
    parser.add_argument("--build", action="store_true")
    args = parser.parse_args()
    try:
        command = reference_command(
            load_json(args.manifest.read_text()), args.script_dir, args.kind,
            network=args.network, testnet_magic=args.testnet_magic,
            funding_utxo=args.funding_utxo, holder_address=args.holder_address,
            change_address=args.change_address, lovelace=args.lovelace,
            body_file=args.body_file, cli=args.cli,
        )
    except (ValueError, KeyError, OSError) as exc:
        parser.error(str(exc))
    print(shlex.join(command))
    if args.build:
        subprocess.run(command, check=True)


if __name__ == "__main__":
    main()
