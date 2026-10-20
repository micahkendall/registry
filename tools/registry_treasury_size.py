#!/usr/bin/env python3
"""Size a treasury-funded 12 KB segment using the actual transaction builder.

The Cardano CLI balances fake UTxOs with supplied execution units. This checks
CLI syntax, output minimum ADA, and signed size, not ledger acceptance.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import tempfile
from pathlib import Path

from registry_content import plan
from registry_data import create_governance, create_uploads
from registry_script_hash import decode_bytestring
from registry_treasury_tx import treasury_command


def run(*arguments: str) -> str:
    return subprocess.check_output(arguments, text=True).strip()


def reference(number: int) -> str:
    return f"{number:064x}#0"


def measure(manifest_path: Path, params_path: Path, executable: str) -> dict:
    manifest = json.loads(manifest_path.read_text())
    params = json.loads(params_path.read_text())
    registry = manifest["registryAddresses"]["testnet"]
    governance = manifest["governanceAddresses"]["testnet"]
    gov_asset = manifest["governancePolicyId"] + "." + manifest["governanceTokenName"]
    reference_script_size = sum(len(decode_bytestring(bytes.fromhex(json.loads(
        (manifest_path.parent / manifest["scripts"][name]).read_text())["cborHex"])))
        for name in ("registry", "governance"))
    upload = plan({"subject": "ab" * 28,
                   "extension": {"value": "x" * 12_000, "sequenceNumber": 0}})
    if len(upload["preimages"]) < 2:
        raise ValueError("test document did not create a full first segment")
    with tempfile.TemporaryDirectory(prefix="registry-treasury-size-") as temporary:
        directory = Path(temporary)
        governance_dir = directory / "governance"
        upload_dir = directory / "upload"
        signing_key = directory / "signer.skey"
        run(executable, "latest", "address", "key-gen",
            "--verification-key-file", str(directory / "signer.vkey"),
            "--signing-key-file", str(signing_key))
        signer_hash = run(executable, "latest", "address", "key-hash",
                          "--payment-verification-key-file", str(directory / "signer.vkey"))
        create_governance(manifest, {"signature": signer_hash}, governance_dir)
        create_uploads(upload, upload_dir)
        datum = upload_dir / "preimage-000.datum.json"
        measured = run(executable, "latest", "transaction", "calculate-min-required-utxo",
                       "--protocol-params-file", str(params_path.resolve()),
                       "--tx-out", f"{registry}+60000000",
                       "--tx-out-inline-datum-file", str(datum))
        match = re.fullmatch(r"Coin (\d+)", measured)
        if match is None:
            raise ValueError("unexpected minimum UTxO output")
        minimum_ada = int(match.group(1))
        if minimum_ada > 60_000_000:
            raise ValueError("funded preimage output is below its minimum ADA")
        governance_datum = json.loads((governance_dir / "governance.datum.json").read_text())
        registry_snapshot = {reference(1): {"address": registry, "value": {"lovelace": 130_000_000}}}
        governance_snapshot = {reference(2): {
            "address": governance,
            "value": {"lovelace": 60_000_000,
                      manifest["governancePolicyId"]: {manifest["governanceTokenName"]: 1}},
            "inlineDatum": governance_datum}}
        body = directory / "treasury.body"
        signed = directory / "treasury.signed"
        command = treasury_command(
            manifest, registry_snapshot, governance_snapshot, governance_dir,
            manifest_path.parent, [reference(1)], network="testnet", testnet_magic=42,
            collateral_utxo=reference(3), registry_script_ref=reference(11),
            governance_script_ref=reference(12), body_file=body,
            signer_hashes=[signer_hash], funded_upload=upload, funded_data_dir=upload_dir,
            funded_index=0, funded_lovelace=60_000_000, cli=executable)
        command[3] = "build-estimate"
        command = command[:-2]  # Offline estimates do not take a network flag.
        estimated = []
        witness_count = 0
        redeemer_path = str(governance_dir / "spend.redeemer.json")
        for argument in command:
            estimated.append(argument)
            if argument == redeemer_path:
                witness_count += 1
                estimated += ["--spending-reference-tx-in-execution-units", "(300000000,1000000)"]
        if witness_count != 2:
            raise ValueError("expected treasury and governance script witnesses")
        estimated += ["--shelley-key-witnesses", "1",
                      "--reference-script-size", str(reference_script_size),
                      "--total-utxo-value", f"190000000+1 {gov_asset}",
                      "--protocol-params-file", str(params_path.resolve()),
                      "--tx-out-return-collateral", f"{registry}+3000000",
                      "--tx-total-collateral", "3000000"]
        run(*estimated)
        run(executable, "latest", "transaction", "sign", "--tx-body-file", str(body),
            "--signing-key-file", str(signing_key), "--testnet-magic", "42",
            "--out-file", str(signed))
        size = len(bytes.fromhex(json.loads(signed.read_text())["cborHex"]))
    if size > params["maxTxSize"]:
        raise ValueError("treasury-funded upload exceeds the protocol transaction size limit")
    return {"builderSignedBytes": size, "protocolMaxTxBytes": params["maxTxSize"],
            "headroomBytes": params["maxTxSize"] - size,
            "minimumPreimageAda": minimum_ada, "referenceScriptBytes": reference_script_size,
            "syntheticScriptWitnesses": witness_count}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("protocol_params", type=Path)
    parser.add_argument("--cardano-cli", default="cardano-cli")
    args = parser.parse_args()
    print(json.dumps(measure(args.manifest, args.protocol_params, args.cardano_cli), indent=2))


if __name__ == "__main__":
    main()
