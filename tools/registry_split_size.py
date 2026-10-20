#!/usr/bin/env python3
"""Estimate a synthetic worst-case packed split using cardano-cli.

Supply current Cardano CLI protocol parameters for the target network. The
fee and size estimate still uses fake UTxOs and supplied execution units; it
is not ledger acceptance or an execution-budget proof.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import tempfile
from pathlib import Path

from registry_content import MAX_CONTENT_BYTES
from registry_data import b, list_datum, listed, multisig_rule, operation_files
from registry_list import apply, node_token, root
from registry_operation_tx import operation_command
from registry_script_hash import decode_bytestring


def run(*arguments: str) -> str:
    return subprocess.check_output(arguments, text=True).strip()


def reference(number: int) -> str:
    return f"{number:064x}#0"


def maximum_reference(number: int) -> dict:
    return {"subject": "ab" * 28 + "00" * 31 + f"{number:02x}",
            "contentHash": "cd" * 32, "contentBytes": MAX_CONTENT_BYTES,
            "segmentHashes": [f"{index:064x}" for index in range(32)]}


def measure(manifest_path: Path, params_path: Path, executable: str) -> dict:
    manifest = json.loads(manifest_path.read_text())
    params = json.loads(params_path.read_text())
    old = root()
    old["entries"] = [maximum_reference(number) for number in (1, 2, 3, 4, 6, 7, 8, 9)]
    inserted = maximum_reference(5)
    successors, action = apply([old], inserted)
    if action["kind"] != "split":
        raise ValueError("maximum fixture did not split")
    action["sourceOutRef"] = reference(1)
    plan = {"action": action, "successorNodes": successors}
    files = operation_files(plan, inserted)
    registry = manifest["registryAddresses"]["testnet"]
    governance = manifest["governanceAddresses"]["testnet"]
    node_policy = manifest["nodePolicyId"]
    gov_nft = manifest["governancePolicyId"] + "." + manifest["governanceTokenName"]
    scripts = manifest["scripts"]
    reference_script_size = sum(len(decode_bytestring(bytes.fromhex(json.loads(
        (manifest_path.parent / scripts[name]).read_text())["cborHex"])))
        for name in ("registry", "governance", "nodePolicy"))

    with tempfile.TemporaryDirectory(prefix="registry-split-size-") as temporary:
        directory = Path(temporary)
        for name, value in files.items():
            (directory / name).write_text(json.dumps(value))
        signing_keys = []
        signer_hashes = []
        for index in range(3):
            signing_key = directory / f"signer-{index}.skey"
            verification_key = directory / f"signer-{index}.vkey"
            run(executable, "latest", "address", "key-gen",
                "--verification-key-file", str(verification_key),
                "--signing-key-file", str(signing_key))
            signer_hashes += ["--required-signer-hash", run(
                executable, "latest", "address", "key-hash",
                "--payment-verification-key-file", str(verification_key))]
            signing_keys += ["--signing-key-file", str(signing_key)]
        gov_datum = listed([b(manifest["governancePolicyId"]),
                            b(manifest["governanceTokenName"]),
                            multisig_rule({"signature": signer_hashes[1]})])
        (directory / "governance.datum.json").write_text(json.dumps(gov_datum))
        (directory / "governance.redeemer.json").write_text(json.dumps({"int": 0}))

        output_specs = {
            "leftNode": (f'{registry}+60000000+1 {node_policy}.{action["oldNodeToken"]}',
                         directory / "left-node.datum.json"),
            "rightNode": (f'{registry}+60000000+1 {node_policy}.{action["rightNodeToken"]}',
                          directory / "right-node.datum.json"),
            "governance": (f"{governance}+60000000+1 {gov_nft}",
                           directory / "governance.datum.json"),
            "treasury": (f"{registry}+3000000", None),
        }
        minimum_ada = {}
        for name, (output, datum) in output_specs.items():
            args = [executable, "latest", "transaction", "calculate-min-required-utxo",
                    "--protocol-params-file", str(params_path.resolve()), "--tx-out", output]
            if datum is not None:
                args += ["--tx-out-inline-datum-file", str(datum)]
            match = re.fullmatch(r"Coin (\d+)", run(*args))
            if match is None:
                raise ValueError(f"unexpected minimum UTxO output for {name}")
            minimum_ada[name] = int(match.group(1))
            output_ada = 3_000_000 if name == "treasury" else 60_000_000
            if minimum_ada[name] > output_ada:
                raise ValueError(f"synthetic {name} output is below its minimum ADA")

        body = directory / "split.body"
        signed = directory / "split.signed"
        command = [executable, "latest", "transaction", "build-estimate",
            "--tx-in", reference(1), "--spending-tx-in-reference", reference(11),
            "--spending-plutus-script-v3", "--spending-reference-tx-in-inline-datum-present",
            "--spending-reference-tx-in-redeemer-file", str(directory / "spend.redeemer.json"),
            "--spending-reference-tx-in-execution-units", "(700000000,2200000)",
            "--tx-in", reference(2), "--spending-tx-in-reference", reference(12),
            "--spending-plutus-script-v3", "--spending-reference-tx-in-inline-datum-present",
            "--spending-reference-tx-in-redeemer-file", str(directory / "governance.redeemer.json"),
            "--spending-reference-tx-in-execution-units", "(200000000,1000000)",
            "--tx-in", reference(3), "--tx-in-collateral", reference(4),
            "--tx-out-return-collateral", f"{registry}+3000000",
            "--tx-total-collateral", "3000000",
            "--tx-out", f'{registry}+60000000+1 {node_policy}.{action["oldNodeToken"]}',
            "--tx-out-inline-datum-file", str(directory / "left-node.datum.json"),
            "--tx-out", f'{registry}+60000000+1 {node_policy}.{action["rightNodeToken"]}',
            "--tx-out-inline-datum-file", str(directory / "right-node.datum.json"),
            "--tx-out", f"{governance}+60000000+1 {gov_nft}",
            "--tx-out-inline-datum-file", str(directory / "governance.datum.json"),
            "--tx-out", f"{registry}+3000000",
            "--mint", f'1 {node_policy}.{action["rightNodeToken"]}',
            "--mint-tx-in-reference", reference(13), "--mint-plutus-script-v3",
            "--mint-reference-tx-in-redeemer-file", str(directory / "mint.redeemer.json"),
            "--mint-reference-tx-in-execution-units", "(600000000,2000000)",
            "--policy-id", node_policy, *signer_hashes,
            "--shelley-key-witnesses", "3",
            "--reference-script-size", str(reference_script_size),
            "--total-utxo-value",
            f'193000000+1 {node_policy}.{action["oldNodeToken"]}+1 {gov_nft}',
            "--change-address", registry,
            "--protocol-params-file", str(params_path.resolve()),
            "--out-file", str(body)]
        run(*command)
        run(executable, "latest", "transaction", "sign", "--tx-body-file", str(body),
            *signing_keys, "--testnet-magic", "42", "--out-file", str(signed))
        size = len(bytes.fromhex(json.loads(signed.read_text())["cborHex"]))
        operation_dir = directory / "operation"
        governance_dir = directory / "governance"
        operation_dir.mkdir()
        governance_dir.mkdir()
        for name, value in files.items():
            (operation_dir / name).write_text(json.dumps(value))
        (governance_dir / "governance.datum.json").write_text(json.dumps(gov_datum))
        (governance_dir / "spend.redeemer.json").write_text(json.dumps({"int": 0}))
        registry_snapshot = {reference(1): {
            "address": registry,
            "value": {"lovelace": 60_000_000, node_policy: {node_token(""): 1}},
            "inlineDatum": list_datum(old)}}
        governance_snapshot = {reference(2): {
            "address": governance,
            "value": {"lovelace": 60_000_000,
                      manifest["governancePolicyId"]: {manifest["governanceTokenName"]: 1}},
            "inlineDatum": gov_datum}}
        builder_body = directory / "builder-split.body"
        builder_signed = directory / "builder-split.signed"
        builder = operation_command(
            manifest, plan, inserted, operation_dir, governance_dir,
            registry_snapshot, governance_snapshot, manifest_path.parent,
            network="testnet", testnet_magic=42, funding_utxo=reference(3),
            collateral_utxo=reference(4), change_address=registry,
            registry_script_ref=reference(11), governance_script_ref=reference(12),
            node_policy_ref=reference(13), left_lovelace=60_000_000,
            right_lovelace=60_000_000, body_file=builder_body,
            signer_hashes=signer_hashes[1::2], cli=executable)
        builder[3] = "build-estimate"
        builder = builder[:-2]  # Offline estimates have no network selection.
        estimated = []
        for argument in builder:
            estimated.append(argument)
            if argument == str(operation_dir / "spend.redeemer.json"):
                estimated += ["--spending-reference-tx-in-execution-units", "(700000000,2200000)"]
            elif argument == str(governance_dir / "spend.redeemer.json"):
                estimated += ["--spending-reference-tx-in-execution-units", "(200000000,1000000)"]
            elif argument == str(operation_dir / "mint.redeemer.json"):
                estimated += ["--mint-reference-tx-in-execution-units", "(600000000,2000000)"]
        estimated += ["--shelley-key-witnesses", "3",
                      "--reference-script-size", str(reference_script_size),
                      "--total-utxo-value",
                      f'193000000+1 {node_policy}.{action["oldNodeToken"]}+1 {gov_nft}',
                      "--protocol-params-file", str(params_path.resolve()),
                      "--tx-out-return-collateral", f"{registry}+3000000",
                      "--tx-total-collateral", "3000000"]
        run(*estimated)
        run(executable, "latest", "transaction", "sign", "--tx-body-file", str(builder_body),
            *signing_keys, "--testnet-magic", "42", "--out-file", str(builder_signed))
        builder_size = len(bytes.fromhex(json.loads(builder_signed.read_text())["cborHex"]))
    return {"signedSplitBytes": size, "protocolMaxTxBytes": params["maxTxSize"],
            "headroomBytes": params["maxTxSize"] - size,
            "builderSignedSplitBytes": builder_size,
            "builderHeadroomBytes": params["maxTxSize"] - builder_size,
            "packedReferencesBeforeSplit": 8, "referencesAfterInsertion": 9,
            "segmentHashesPerReference": 32, "keyWitnesses": 3,
            "referenceScriptBytes": reference_script_size,
            "minimumOutputAda": minimum_ada}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("protocol_params", type=Path)
    parser.add_argument("--cardano-cli", default="cardano-cli")
    args = parser.parse_args()
    result = measure(args.manifest, args.protocol_params, args.cardano_cli)
    print(json.dumps(result, indent=2))
    if result["headroomBytes"] < 0 or result["builderHeadroomBytes"] < 0:
        raise SystemExit("synthetic split exceeds the protocol maximum transaction size")


if __name__ == "__main__":
    main()
