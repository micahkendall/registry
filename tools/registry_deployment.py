#!/usr/bin/env python3
"""Compile the four registry scripts in dependency order into a new directory.

This prepares script artifacts and their IDs; it does not broadcast transactions.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path

from registry_address import script_address
from registry_script_hash import script_hash

PROJECT = Path(__file__).resolve().parents[1]


def export(kind: str, parameters: list[str], target: Path) -> str:
    command = ["cabal", "run", "registry-export", "--", kind, *parameters, str(target)]
    subprocess.run(command, cwd=PROJECT, check=True)
    return script_hash(json.loads(target.read_text()))


def prepare(governance_seed: str, node_seed: str, token_hex: str, destination: Path) -> dict:
    seed_pattern = re.compile(r"[0-9a-fA-F]{64}#[0-9]+\Z")
    if not seed_pattern.fullmatch(governance_seed) or not seed_pattern.fullmatch(node_seed):
        raise ValueError("each seed must be TXID#INDEX with a 32-byte hexadecimal transaction ID")
    if governance_seed.lower() == node_seed.lower():
        raise ValueError("governance and node policies need distinct seed UTxOs")
    if len(token_hex) % 2 or len(token_hex) > 64 or any(c not in "0123456789abcdefABCDEF" for c in token_hex):
        raise ValueError("governance token name must be at most 32 bytes of base16")
    destination.mkdir(parents=True, exist_ok=False)
    governance_hash = export("governance", [], destination / "governance.plutus")
    governance_policy = export(
        "governance-policy", [governance_seed, token_hex, governance_hash],
        destination / "governance-policy.plutus",
    )
    node_policy = export(
        "node-policy", [node_seed, governance_policy, token_hex, governance_hash],
        destination / "node-policy.plutus",
    )
    registry_hash = export(
        "registry", [governance_policy, token_hex, governance_hash, node_policy],
        destination / "registry.plutus",
    )
    manifest = {
        "language": "PlutusScriptV3",
        "governanceScriptHash": governance_hash,
        "governancePolicyId": governance_policy,
        "governanceTokenName": token_hex.lower(),
        "nodePolicyId": node_policy,
        "registryScriptHash": registry_hash,
        "governanceAddresses": {
            network: script_address(governance_hash, network) for network in ("mainnet", "testnet")
        },
        "registryAddresses": {
            network: script_address(registry_hash, network) for network in ("mainnet", "testnet")
        },
        "governanceSeed": governance_seed,
        "nodeSeed": node_seed,
        "scripts": {
            "governance": "governance.plutus",
            "governancePolicy": "governance-policy.plutus",
            "nodePolicy": "node-policy.plutus",
            "registry": "registry.plutus",
        },
    }
    (destination / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("governance_seed", help="one-shot governance seed TXID#INDEX")
    parser.add_argument("node_seed", help="different one-shot root-node seed TXID#INDEX")
    parser.add_argument("governance_token_hex", help="governance NFT token name in base16")
    parser.add_argument("destination", type=Path, help="new output directory")
    args = parser.parse_args()
    try:
        manifest = prepare(args.governance_seed, args.node_seed, args.governance_token_hex, args.destination)
    except (ValueError, FileExistsError) as exc:
        parser.error(str(exc))
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
