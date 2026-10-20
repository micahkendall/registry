#!/usr/bin/env python3
"""Build unsigned governed insert, update, or split transactions with cardano-cli.

All authoritative inputs are matched to a registry/governance UTxO snapshot.
The generated operation datum and redeemer files are checked against the plan.
The caller supplies fresh funding, collateral, ADA output amounts, and the
signers/slot bounds required by the current multisig rule.
"""

from __future__ import annotations

import argparse
import re
import shlex
import subprocess
from pathlib import Path

from registry_address import script_address
from registry_content import load_json
from registry_data import operation_files
from registry_script_hash import script_hash
from registry_state import read_state
from registry_withdrawal import withdrawal_args


def _outref(value: str) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}#[0-9]+", value) is not None


def _lovelace(value: dict) -> int:
    amount = value.get("lovelace")
    if type(amount) is not int or amount <= 0:
        raise ValueError("script output must hold positive lovelace")
    return amount


def _script_file(directory: Path, filename: str, expected_hash: str) -> Path:
    path = directory / filename
    if script_hash(load_json(path.read_text())) != expected_hash:
        raise ValueError(f"script file does not match deployment manifest: {path}")
    return path


def _datum_file(path: Path, expected: dict) -> Path:
    if load_json(path.read_text()) != expected:
        raise ValueError(f"datum or redeemer file disagrees with plan: {path}")
    return path


def _asset_output(address: str, lovelace: int, policy: str, token: str) -> str:
    if type(lovelace) is not int or lovelace <= 0:
        raise ValueError("node output lovelace must be positive")
    return f"{address}+{lovelace}+1 {policy}.{token}"


def operation_command(
    manifest: dict, plan: dict, commitment: dict, operation_dir: Path,
    governance_dir: Path, registry_snapshot: dict, governance_snapshot: dict,
    script_dir: Path, *, network: str, testnet_magic: int | None,
    funding_utxo: str, collateral_utxo: str, change_address: str,
    registry_script_ref: str, governance_script_ref: str, node_policy_ref: str | None,
    left_lovelace: int, right_lovelace: int | None, body_file: Path,
    signer_hashes: list[str] | None = None,
    withdrawals: list[dict] | None = None,
    invalid_before: int | None = None, invalid_hereafter: int | None = None,
    treasury_utxo: str | None = None, treasury_change_lovelace: int = 0,
    cli: str = "cardano-cli",
) -> list[str]:
    if network not in {"mainnet", "testnet"}:
        raise ValueError("network must be mainnet or testnet")
    if network == "testnet" and (type(testnet_magic) is not int or testnet_magic < 0):
        raise ValueError("testnet magic is required")
    if network == "mainnet" and testnet_magic is not None:
        raise ValueError("mainnet must not have a testnet magic")
    if any(type(slot) is not int or slot < 0 for slot in (invalid_before, invalid_hereafter) if slot is not None):
        raise ValueError("validity bounds must be nonnegative slots")
    if (invalid_before is not None and invalid_hereafter is not None
            and invalid_before >= invalid_hereafter):
        raise ValueError("invalid transaction validity interval")
    signers = signer_hashes or []
    if any(not isinstance(signer, str) or not re.fullmatch(r"[0-9a-f]{56}", signer) for signer in signers):
        raise ValueError("signer hashes must be lowercase 28-byte base16")
    if len(signers) != len(set(signers)):
        raise ValueError("duplicate required signer")
    if not change_address:
        raise ValueError("change address is required")

    registry_address = script_address(manifest["registryScriptHash"], network)
    governance_address = script_address(manifest["governanceScriptHash"], network)
    if manifest["registryAddresses"][network] != registry_address or manifest["governanceAddresses"][network] != governance_address:
        raise ValueError("manifest addresses disagree with script hashes")
    policy = manifest["nodePolicyId"]
    gov_policy = manifest["governancePolicyId"]
    gov_token = manifest["governanceTokenName"]
    expected_files = operation_files(plan, commitment)
    for filename, expected in expected_files.items():
        _datum_file(operation_dir / filename, expected)
    action = plan["action"]
    kind = action["kind"]
    source_ref = action.get("sourceOutRef")
    if not _outref(source_ref):
        raise ValueError("operation needs a verified sourceOutRef")
    if not _outref(funding_utxo) or not _outref(collateral_utxo):
        raise ValueError("funding and collateral must be lowercase TXID#INDEX")
    if treasury_utxo is not None and not _outref(treasury_utxo):
        raise ValueError("treasury UTxO must be lowercase TXID#INDEX")
    if type(treasury_change_lovelace) is not int or treasury_change_lovelace < 0:
        raise ValueError("treasury change lovelace must be nonnegative")
    if treasury_utxo is None and treasury_change_lovelace:
        raise ValueError("treasury change requires a treasury input")
    if len({source_ref, funding_utxo, collateral_utxo}) != 3:
        raise ValueError("node, funding, and collateral UTxOs must be distinct")
    reference_utxos = [registry_script_ref, governance_script_ref]
    if kind == "split":
        reference_utxos.append(node_policy_ref)
    elif node_policy_ref is not None:
        raise ValueError("node policy reference is only used for a split")
    if any(not _outref(ref) for ref in reference_utxos):
        raise ValueError("all required script references must be lowercase TXID#INDEX")
    used_refs = reference_utxos + [source_ref, funding_utxo, collateral_utxo]
    if treasury_utxo is not None:
        used_refs.append(treasury_utxo)
    if len(set(used_refs)) != len(used_refs):
        raise ValueError("reference script UTxOs must be distinct from every spent or collateral UTxO")

    state = read_state(registry_snapshot, registry_address, policy)
    source = next((node for node in state["nodes"] if node["outRef"] == source_ref), None)
    if source is None or {key: source[key] for key in ("lowerBound", "nextBound", "entries")} != action["oldNode"]:
        raise ValueError("source node is absent or changed since planning")
    node_value = registry_snapshot[source_ref]["value"]
    if node_value != {"lovelace": _lovelace(node_value), policy: {action["oldNodeToken"]: 1}}:
        raise ValueError("source node must contain only ADA and its node NFT")
    old_ada = node_value["lovelace"]
    treasury_ada = 0
    if treasury_utxo is not None:
        treasury_output = registry_snapshot.get(treasury_utxo)
        if (not isinstance(treasury_output, dict)
                or treasury_output.get("address") != registry_address
                or any(key in treasury_output for key in ("inlineDatum", "datum", "datumHash", "datumhash"))):
            raise ValueError("treasury input must be a no-datum UTxO at the registry address")
        treasury_value = treasury_output.get("value")
        if not isinstance(treasury_value, dict) or treasury_value != {"lovelace": _lovelace(treasury_value)}:
            raise ValueError("treasury input must contain ADA only")
        treasury_ada = treasury_value["lovelace"]

    gov_datum_file = governance_dir / "governance.datum.json"
    gov_datum = load_json(gov_datum_file.read_text())
    if (not isinstance(gov_datum, dict) or not isinstance(gov_datum.get("list"), list)
            or gov_datum["list"][:2]
            != [{"bytes": gov_policy}, {"bytes": gov_token}]):
        raise ValueError("governance datum names a different NFT")
    gov_redeemer = _datum_file(governance_dir / "spend.redeemer.json", {"int": 0})
    gov_candidates = []
    for ref, output in governance_snapshot.items():
        if output.get("address") != governance_address:
            continue
        value = output.get("value", {})
        policy_value = value.get(gov_policy, {}) if isinstance(value, dict) else {}
        if isinstance(policy_value, dict) and policy_value.get(gov_token) == 1:
            gov_candidates.append((ref, output))
    if len(gov_candidates) != 1:
        raise ValueError("expected exactly one governance NFT UTxO")
    gov_ref, gov_output = gov_candidates[0]
    if not _outref(gov_ref) or gov_ref in set(used_refs):
        raise ValueError("invalid or reused governance UTxO reference")
    if gov_output.get("inlineDatum") != gov_datum:
        raise ValueError("governance rule has changed since datum generation")
    gov_value = gov_output["value"]
    if gov_value != {"lovelace": _lovelace(gov_value), gov_policy: {gov_token: 1}}:
        raise ValueError("governance output must contain only ADA and its NFT")

    new_nodes = action["newNodes"]
    if kind == "split":
        if type(right_lovelace) is not int or right_lovelace <= 0:
            raise ValueError("split requires right node lovelace")
    elif right_lovelace is not None:
        raise ValueError("right node lovelace is only for a split")
    if type(left_lovelace) is not int or left_lovelace <= 0:
        raise ValueError("left node lovelace must be positive")
    if left_lovelace + (right_lovelace or 0) + treasury_change_lovelace < old_ada + treasury_ada:
        raise ValueError("registry outputs must retain the node and treasury ADA")

    scripts = manifest["scripts"]
    _script_file(script_dir, scripts["registry"], manifest["registryScriptHash"])
    _script_file(script_dir, scripts["governance"], manifest["governanceScriptHash"])
    command = [cli, "latest", "transaction", "build",
               "--tx-in", source_ref,
               "--spending-tx-in-reference", registry_script_ref,
               "--spending-plutus-script-v3",
               "--spending-reference-tx-in-inline-datum-present",
               "--spending-reference-tx-in-redeemer-file", str(operation_dir / "spend.redeemer.json"),
               ]
    if treasury_utxo is not None:
        command += ["--tx-in", treasury_utxo,
                    "--spending-tx-in-reference", registry_script_ref,
                    "--spending-plutus-script-v3",
                    "--spending-reference-tx-in-redeemer-file", str(operation_dir / "treasury.redeemer.json")]
    command += ["--tx-in", gov_ref,
               "--spending-tx-in-reference", governance_script_ref,
               "--spending-plutus-script-v3",
               "--spending-reference-tx-in-inline-datum-present",
               "--spending-reference-tx-in-redeemer-file", str(gov_redeemer),
               "--tx-in", funding_utxo, "--tx-in-collateral", collateral_utxo,
               "--tx-out", _asset_output(registry_address, left_lovelace, policy, action["oldNodeToken"]),
               "--tx-out-inline-datum-file", str(operation_dir / "left-node.datum.json")]
    if kind == "split":
        command += ["--tx-out", _asset_output(registry_address, right_lovelace, policy, action["rightNodeToken"]),
                    "--tx-out-inline-datum-file", str(operation_dir / "right-node.datum.json")]
        _script_file(script_dir, scripts["nodePolicy"], policy)
        command += ["--mint", f"1 {policy}.{action['rightNodeToken']}",
                    "--mint-tx-in-reference", node_policy_ref,
                    "--mint-plutus-script-v3", "--policy-id", policy,
                    "--mint-reference-tx-in-redeemer-file", str(operation_dir / "mint.redeemer.json")]
    if treasury_change_lovelace:
        command += ["--tx-out", f"{registry_address}+{treasury_change_lovelace}"]
    command += ["--tx-out", _asset_output(governance_address, gov_value["lovelace"], gov_policy, gov_token),
                "--tx-out-inline-datum-file", str(gov_datum_file)]
    command += withdrawal_args(withdrawals, gov_datum, network, used_refs + [gov_ref])
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
    parser.add_argument("list_plan", type=Path)
    parser.add_argument("commitment", type=Path)
    parser.add_argument("operation_dir", type=Path)
    parser.add_argument("governance_dir", type=Path)
    parser.add_argument("registry_snapshot", type=Path)
    parser.add_argument("governance_snapshot", type=Path)
    parser.add_argument("script_dir", type=Path)
    parser.add_argument("funding_utxo")
    parser.add_argument("collateral_utxo")
    parser.add_argument("change_address")
    parser.add_argument("left_lovelace", type=int)
    parser.add_argument("body_file", type=Path)
    parser.add_argument("--registry-script-ref", required=True)
    parser.add_argument("--governance-script-ref", required=True)
    parser.add_argument("--node-policy-ref")
    parser.add_argument("--right-lovelace", type=int)
    parser.add_argument("--treasury-utxo")
    parser.add_argument("--treasury-change-lovelace", type=int, default=0)
    parser.add_argument("--network", choices=("mainnet", "testnet"), required=True)
    parser.add_argument("--testnet-magic", type=int)
    parser.add_argument("--signer-hash", action="append", default=[])
    parser.add_argument("--withdrawal-spec", type=Path, action="append", default=[])
    parser.add_argument("--invalid-before", type=int)
    parser.add_argument("--invalid-hereafter", type=int)
    parser.add_argument("--cli", default="cardano-cli")
    parser.add_argument("--build", action="store_true", help="invoke CLI to build the unsigned body")
    args = parser.parse_args()
    try:
        command = operation_command(
            load_json(args.manifest.read_text()), load_json(args.list_plan.read_text()),
            load_json(args.commitment.read_text()), args.operation_dir, args.governance_dir,
            load_json(args.registry_snapshot.read_text()), load_json(args.governance_snapshot.read_text()),
            args.script_dir, network=args.network, testnet_magic=args.testnet_magic,
            funding_utxo=args.funding_utxo, collateral_utxo=args.collateral_utxo,
            change_address=args.change_address,
            registry_script_ref=args.registry_script_ref,
            governance_script_ref=args.governance_script_ref,
            node_policy_ref=args.node_policy_ref,
            left_lovelace=args.left_lovelace,
            right_lovelace=args.right_lovelace, body_file=args.body_file,
            signer_hashes=args.signer_hash,
            withdrawals=[load_json(path.read_text()) for path in args.withdrawal_spec],
            invalid_before=args.invalid_before,
            invalid_hereafter=args.invalid_hereafter,
            treasury_utxo=args.treasury_utxo,
            treasury_change_lovelace=args.treasury_change_lovelace, cli=args.cli,
        )
    except (ValueError, KeyError, TypeError, OSError) as exc:
        parser.error(str(exc))
    print(shlex.join(command))
    if args.build:
        subprocess.run(command, check=True)


if __name__ == "__main__":
    main()
