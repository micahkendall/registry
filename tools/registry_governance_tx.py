#!/usr/bin/env python3
"""Build an unsigned governance-NFT rule rotation transaction."""

from __future__ import annotations

import argparse
import re
import shlex
import subprocess
from pathlib import Path

from registry_address import script_address
from registry_bootstrap_tx import _safe_rule
from registry_content import load_json
from registry_data import multisig_rule
from registry_script_hash import script_hash
from registry_withdrawal import withdrawal_args


def _outref(value: str) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}#[0-9]+", value) is not None


def rotation_command(
    manifest: dict, governance_snapshot: dict, new_rule: dict,
    new_data_dir: Path, script_dir: Path, *, network: str,
    testnet_magic: int | None, funding_utxo: str, collateral_utxo: str,
    change_address: str, governance_script_ref: str, body_file: Path,
    signer_hashes: list[str] | None = None,
    withdrawals: list[dict] | None = None,
    invalid_before: int | None = None, invalid_hereafter: int | None = None,
    cli: str = "cardano-cli",
) -> list[str]:
    if network not in {"mainnet", "testnet"}:
        raise ValueError("network must be mainnet or testnet")
    if network == "testnet" and (type(testnet_magic) is not int or testnet_magic < 0):
        raise ValueError("testnet magic is required")
    if network == "mainnet" and testnet_magic is not None:
        raise ValueError("mainnet must not have a testnet magic")
    if not change_address:
        raise ValueError("change address is required")
    for slot in (invalid_before, invalid_hereafter):
        if slot is not None and (type(slot) is not int or slot < 0):
            raise ValueError("validity bounds must be nonnegative slots")
    if invalid_before is not None and invalid_hereafter is not None and invalid_before >= invalid_hereafter:
        raise ValueError("invalid transaction validity interval")
    signers = signer_hashes or []
    if any(not isinstance(signer, str) or not re.fullmatch(r"[0-9a-f]{56}", signer) for signer in signers):
        raise ValueError("signer hashes must be lowercase 28-byte base16")
    if len(signers) != len(set(signers)):
        raise ValueError("duplicate required signer")
    if any(not _outref(ref) for ref in (funding_utxo, collateral_utxo, governance_script_ref)):
        raise ValueError("all UTxO references must be lowercase TXID#INDEX")
    governance_address = script_address(manifest["governanceScriptHash"], network)
    if manifest["governanceAddresses"][network] != governance_address:
        raise ValueError("manifest governance address disagrees with script hash")
    script_file = script_dir / manifest["scripts"]["governance"]
    if script_hash(load_json(script_file.read_text())) != manifest["governanceScriptHash"]:
        raise ValueError("governance script file disagrees with deployment manifest")
    policy = manifest["governancePolicyId"]
    token = manifest["governanceTokenName"]
    candidates = []
    for ref, output in governance_snapshot.items():
        if not isinstance(output, dict) or output.get("address") != governance_address:
            continue
        value = output.get("value")
        if isinstance(value, dict) and isinstance(value.get(policy), dict) and value[policy].get(token) == 1:
            candidates.append((ref, output))
    if len(candidates) != 1:
        raise ValueError("expected exactly one governance NFT UTxO")
    governance_ref, old_output = candidates[0]
    if not _outref(governance_ref) or len({governance_ref, funding_utxo, collateral_utxo, governance_script_ref}) != 4:
        raise ValueError("governance, funding, collateral, and reference UTxOs must be distinct")
    value = old_output["value"]
    lovelace = value.get("lovelace")
    if type(lovelace) is not int or lovelace <= 0 or value != {"lovelace": lovelace, policy: {token: 1}}:
        raise ValueError("governance NFT UTxO must contain only ADA and its NFT")
    old_datum = old_output.get("inlineDatum")
    if (not isinstance(old_datum, dict) or not isinstance(old_datum.get("list"), list)
            or len(old_datum["list"]) != 3
            or old_datum["list"][:2] != [{"bytes": policy}, {"bytes": token}]):
        raise ValueError("current governance datum does not name its NFT")
    next_datum = {"list": [{"bytes": policy}, {"bytes": token}, multisig_rule(new_rule)]}
    if not _safe_rule(next_datum["list"][2]):
        raise ValueError("new governance rule needs signer or withdrawal authority on every success path")
    datum_file = new_data_dir / "governance.datum.json"
    redeemer_file = new_data_dir / "spend.redeemer.json"
    if load_json(datum_file.read_text()) != next_datum:
        raise ValueError("new governance datum file disagrees with requested rule")
    if load_json(redeemer_file.read_text()) != {"int": 0}:
        raise ValueError("governance spend redeemer is not the expected unit integer")
    command = [cli, "latest", "transaction", "build",
               "--tx-in", governance_ref,
               "--spending-tx-in-reference", governance_script_ref,
               "--spending-plutus-script-v3",
               "--spending-reference-tx-in-inline-datum-present",
               "--spending-reference-tx-in-redeemer-file", str(redeemer_file),
               "--tx-in", funding_utxo,
               "--tx-in-collateral", collateral_utxo,
               "--tx-out", f"{governance_address}+{lovelace}+1 {policy}.{token}",
               "--tx-out-inline-datum-file", str(datum_file)]
    command += withdrawal_args(withdrawals, old_datum, network,
                               [governance_ref, funding_utxo, collateral_utxo, governance_script_ref])
    for signer in signers:
        command += ["--required-signer-hash", signer]
    if invalid_before is not None:
        command += ["--invalid-before", str(invalid_before)]
    if invalid_hereafter is not None:
        command += ["--invalid-hereafter", str(invalid_hereafter)]
    command += ["--change-address", change_address, "--out-file", str(body_file)]
    command += ["--mainnet"] if network == "mainnet" else ["--testnet-magic", str(testnet_magic)]
    return command


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("governance_snapshot", type=Path)
    parser.add_argument("new_rule", type=Path)
    parser.add_argument("new_data_dir", type=Path)
    parser.add_argument("script_dir", type=Path)
    parser.add_argument("funding_utxo")
    parser.add_argument("collateral_utxo")
    parser.add_argument("change_address")
    parser.add_argument("body_file", type=Path)
    parser.add_argument("--governance-script-ref", required=True)
    parser.add_argument("--network", choices=("mainnet", "testnet"), required=True)
    parser.add_argument("--testnet-magic", type=int)
    parser.add_argument("--signer-hash", action="append", default=[])
    parser.add_argument("--withdrawal-spec", type=Path, action="append", default=[])
    parser.add_argument("--invalid-before", type=int)
    parser.add_argument("--invalid-hereafter", type=int)
    parser.add_argument("--cli", default="cardano-cli")
    parser.add_argument("--build", action="store_true")
    args = parser.parse_args()
    try:
        command = rotation_command(
            load_json(args.manifest.read_text()), load_json(args.governance_snapshot.read_text()),
            load_json(args.new_rule.read_text()), args.new_data_dir, args.script_dir,
            network=args.network, testnet_magic=args.testnet_magic,
            funding_utxo=args.funding_utxo, collateral_utxo=args.collateral_utxo,
            change_address=args.change_address, governance_script_ref=args.governance_script_ref,
            body_file=args.body_file, signer_hashes=args.signer_hash,
            withdrawals=[load_json(path.read_text()) for path in args.withdrawal_spec],
            invalid_before=args.invalid_before, invalid_hereafter=args.invalid_hereafter,
            cli=args.cli)
    except (ValueError, KeyError, TypeError, OSError) as exc:
        parser.error(str(exc))
    print(shlex.join(command))
    if args.build:
        subprocess.run(command, check=True)


if __name__ == "__main__":
    main()
