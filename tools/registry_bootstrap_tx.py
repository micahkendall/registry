#!/usr/bin/env python3
"""Build unsigned one-shot governance-NFT and root-node bootstrap bodies."""

from __future__ import annotations

import argparse
import re
import shlex
import subprocess
from pathlib import Path

from registry_address import script_address
from registry_content import load_json
from registry_data import list_datum
from registry_list import node_token, root
from registry_script_hash import script_hash


def _outref(value: str) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}#[0-9]+", value) is not None


def _safe_rule(rule: object) -> bool:
    """Conservatively require a signer or withdrawal script on every success path."""
    if not isinstance(rule, dict) or set(rule) != {"constructor", "fields"}:
        return False
    tag, fields = rule["constructor"], rule["fields"]
    if not isinstance(fields, list):
        return False
    if tag in (0, 6):
        return len(fields) == 1
    if tag in (4, 5):
        return False
    if tag in (1, 2) and len(fields) == 1 and isinstance(fields[0], dict):
        children = fields[0].get("list")
        if not isinstance(children, list):
            return False
        return any(_safe_rule(child) for child in children) if tag == 1 else bool(children) and all(_safe_rule(child) for child in children)
    if tag == 3 and len(fields) == 2 and isinstance(fields[0], dict) and isinstance(fields[1], dict):
        required, children = fields[0].get("int"), fields[1].get("list")
        return (type(required) is int and isinstance(children, list)
                and required <= len(children)
                and required > sum(not _safe_rule(child) for child in children))
    return False


def bootstrap_command(
    manifest: dict, script_dir: Path, data_dir: Path, kind: str, *,
    network: str, testnet_magic: int | None, collateral_utxo: str,
    change_address: str, lovelace: int, body_file: Path,
    extra_funding_utxo: str | None = None, cli: str = "cardano-cli",
) -> list[str]:
    if kind not in {"governance", "root"}:
        raise ValueError("bootstrap kind must be governance or root")
    if network not in {"mainnet", "testnet"}:
        raise ValueError("network must be mainnet or testnet")
    if network == "testnet" and (type(testnet_magic) is not int or testnet_magic < 0):
        raise ValueError("testnet magic is required")
    if network == "mainnet" and testnet_magic is not None:
        raise ValueError("mainnet must not have a testnet magic")
    if type(lovelace) is not int or lovelace <= 0:
        raise ValueError("bootstrap output lovelace must be positive")
    if not change_address:
        raise ValueError("change address is required")
    seed = manifest["governanceSeed"] if kind == "governance" else manifest["nodeSeed"]
    if not _outref(seed) or not _outref(collateral_utxo) or (extra_funding_utxo is not None and not _outref(extra_funding_utxo)):
        raise ValueError("all inputs must be lowercase TXID#INDEX")
    if len({ref for ref in (seed, collateral_utxo, extra_funding_utxo) if ref is not None}) != 2 + int(extra_funding_utxo is not None):
        raise ValueError("seed, collateral, and extra funding UTxOs must be distinct")
    governance_address = script_address(manifest["governanceScriptHash"], network)
    registry_address = script_address(manifest["registryScriptHash"], network)
    if (manifest["governanceAddresses"][network] != governance_address
            or manifest["registryAddresses"][network] != registry_address):
        raise ValueError("manifest addresses disagree with script hashes")
    if kind == "governance":
        policy = manifest["governancePolicyId"]
        token = manifest["governanceTokenName"]
        address = governance_address
        filename = manifest["scripts"]["governancePolicy"]
        datum_file = data_dir / "governance.datum.json"
        mint_redeemer = data_dir / "mint.redeemer.json"
        datum = load_json(datum_file.read_text())
        if (not isinstance(datum, dict) or not isinstance(datum.get("list"), list)
                or len(datum["list"]) != 3
                or datum["list"][:2] != [{"bytes": policy}, {"bytes": token}]
                or not _safe_rule(datum["list"][2])):
            raise ValueError("initial governance datum must name the NFT and require authority")
        if load_json(mint_redeemer.read_text()) != {"int": 0}:
            raise ValueError("governance mint redeemer is not the expected unit integer")
    else:
        policy = manifest["nodePolicyId"]
        token = node_token("")
        address = registry_address
        filename = manifest["scripts"]["nodePolicy"]
        datum_file = data_dir / "root.datum.json"
        mint_redeemer = data_dir / "bootstrap.redeemer.json"
        if load_json(datum_file.read_text()) != list_datum(root()):
            raise ValueError("root datum is not the empty sentinel node")
        if load_json(mint_redeemer.read_text()) != {"constructor": 0, "fields": []}:
            raise ValueError("node mint redeemer is not bootstrap")
    script_file = script_dir / filename
    if script_hash(load_json(script_file.read_text())) != policy:
        raise ValueError("mint policy script does not match deployment manifest")
    command = [cli, "latest", "transaction", "build", "--tx-in", seed]
    if extra_funding_utxo is not None:
        command += ["--tx-in", extra_funding_utxo]
    command += ["--tx-in-collateral", collateral_utxo,
                "--tx-out", f"{address}+{lovelace}+1 {policy}.{token}",
                "--tx-out-inline-datum-file", str(datum_file),
                "--mint", f"1 {policy}.{token}",
                "--mint-script-file", str(script_file),
                "--mint-redeemer-file", str(mint_redeemer),
                "--change-address", change_address, "--out-file", str(body_file)]
    command += ["--mainnet"] if network == "mainnet" else ["--testnet-magic", str(testnet_magic)]
    return command


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("script_dir", type=Path)
    parser.add_argument("data_dir", type=Path)
    parser.add_argument("kind", choices=("governance", "root"))
    parser.add_argument("collateral_utxo")
    parser.add_argument("change_address")
    parser.add_argument("lovelace", type=int)
    parser.add_argument("body_file", type=Path)
    parser.add_argument("--extra-funding-utxo")
    parser.add_argument("--network", choices=("mainnet", "testnet"), required=True)
    parser.add_argument("--testnet-magic", type=int)
    parser.add_argument("--cli", default="cardano-cli")
    parser.add_argument("--build", action="store_true")
    args = parser.parse_args()
    try:
        command = bootstrap_command(
            load_json(args.manifest.read_text()), args.script_dir, args.data_dir,
            args.kind, network=args.network, testnet_magic=args.testnet_magic,
            collateral_utxo=args.collateral_utxo, change_address=args.change_address,
            lovelace=args.lovelace, body_file=args.body_file,
            extra_funding_utxo=args.extra_funding_utxo, cli=args.cli,
        )
    except (ValueError, KeyError, TypeError, OSError) as exc:
        parser.error(str(exc))
    print(shlex.join(command))
    if args.build:
        subprocess.run(command, check=True)


if __name__ == "__main__":
    main()
