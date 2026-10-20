#!/usr/bin/env python3
"""Build a governed treasury spend for fees, donation, or a metadata upload."""

from __future__ import annotations

import argparse
import base64
import re
import shlex
import subprocess
from pathlib import Path

from registry_address import script_address
from registry_content import load_json, verify_plan
from registry_data import manifest_datum, preimage_datum
from registry_operation_tx import _datum_file, _lovelace, _outref, _script_file
from registry_withdrawal import withdrawal_args


def treasury_command(
    manifest: dict, registry_snapshot: dict, governance_snapshot: dict,
    governance_dir: Path, script_dir: Path, treasury_utxos: list[str], *,
    network: str, testnet_magic: int | None, collateral_utxo: str,
    registry_script_ref: str, governance_script_ref: str, body_file: Path,
    donation_lovelace: int = 0, signer_hashes: list[str] | None = None,
    funded_upload: dict | None = None, funded_data_dir: Path | None = None,
    funded_index: int | None = None, funded_lovelace: int | None = None,
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
    if type(donation_lovelace) is not int or donation_lovelace < 0:
        raise ValueError("treasury donation must be nonnegative lovelace")
    if any(value is not None for value in (funded_upload, funded_data_dir, funded_index, funded_lovelace)):
        if funded_upload is None or funded_data_dir is None or funded_lovelace is None:
            raise ValueError("treasury-funded upload requires plan, data directory, and output lovelace")
        if type(funded_lovelace) is not int or funded_lovelace <= 0:
            raise ValueError("funded upload lovelace must be positive")
        if funded_index is not None and (type(funded_index) is not int or funded_index < 0):
            raise ValueError("funded upload index must be nonnegative")
    if any(type(slot) is not int or slot < 0 for slot in (invalid_before, invalid_hereafter) if slot is not None):
        raise ValueError("validity bounds must be nonnegative slots")
    if invalid_before is not None and invalid_hereafter is not None and invalid_before >= invalid_hereafter:
        raise ValueError("invalid transaction validity interval")
    signers = signer_hashes or []
    if any(not isinstance(signer, str) or not re.fullmatch(r"[0-9a-f]{56}", signer) for signer in signers):
        raise ValueError("signer hashes must be lowercase 28-byte base16")
    if len(signers) != len(set(signers)):
        raise ValueError("duplicate required signer")
    if not treasury_utxos:
        raise ValueError("at least one treasury UTxO is required")
    refs = treasury_utxos + [collateral_utxo, registry_script_ref, governance_script_ref]
    if any(not _outref(ref) for ref in refs) or len(set(refs)) != len(refs):
        raise ValueError("treasury, collateral, and reference UTxOs must be valid and distinct")

    registry_address = script_address(manifest["registryScriptHash"], network)
    governance_address = script_address(manifest["governanceScriptHash"], network)
    if (manifest["registryAddresses"][network] != registry_address
            or manifest["governanceAddresses"][network] != governance_address):
        raise ValueError("manifest addresses disagree with script hashes")
    scripts = manifest["scripts"]
    _script_file(script_dir, scripts["registry"], manifest["registryScriptHash"])
    _script_file(script_dir, scripts["governance"], manifest["governanceScriptHash"])

    treasury_ada = 0
    for ref in treasury_utxos:
        output = registry_snapshot.get(ref)
        if (not isinstance(output, dict) or output.get("address") != registry_address
                or any(key in output for key in ("inlineDatum", "datum", "datumHash", "datumhash"))):
            raise ValueError("treasury input must be a no-datum UTxO at the registry address")
        value = output.get("value")
        if not isinstance(value, dict) or value != {"lovelace": _lovelace(value)}:
            raise ValueError("treasury input must contain ADA only")
        treasury_ada += value["lovelace"]
    if donation_lovelace + (funded_lovelace or 0) >= treasury_ada:
        raise ValueError("donation and funded upload must leave treasury ADA for fees and change")

    funded_datum_file = None
    if funded_upload is not None:
        verify_plan(funded_upload, require_complete=funded_index is not None)
        if funded_index is None:
            funded_datum_file = funded_data_dir / "manifest.datum.json"
            expected = manifest_datum(funded_upload)
        else:
            parts = funded_upload.get("preimages", [])
            if funded_index >= len(parts) or parts[funded_index]["index"] != funded_index:
                raise ValueError("funded preimage index is absent or unordered")
            part = parts[funded_index]
            funded_datum_file = funded_data_dir / f"preimage-{funded_index:03d}.datum.json"
            expected = preimage_datum(funded_upload["subject"], funded_index, part["hash"],
                                      base64.b64decode(part["bytesBase64"], validate=True))
        _datum_file(funded_datum_file, expected)

    policy = manifest["governancePolicyId"]
    token = manifest["governanceTokenName"]
    gov_datum_file = governance_dir / "governance.datum.json"
    gov_datum = load_json(gov_datum_file.read_text())
    if (not isinstance(gov_datum, dict) or not isinstance(gov_datum.get("list"), list)
            or len(gov_datum["list"]) != 3
            or gov_datum["list"][:2] != [{"bytes": policy}, {"bytes": token}]):
        raise ValueError("governance datum names a different NFT")
    gov_redeemer = _datum_file(governance_dir / "spend.redeemer.json", {"int": 0})
    candidates = []
    for ref, output in governance_snapshot.items():
        if not isinstance(output, dict) or output.get("address") != governance_address:
            continue
        value = output.get("value")
        if isinstance(value, dict) and isinstance(value.get(policy), dict) and value[policy].get(token) == 1:
            candidates.append((ref, output))
    if len(candidates) != 1:
        raise ValueError("expected exactly one governance NFT UTxO")
    gov_ref, gov_output = candidates[0]
    if not _outref(gov_ref) or gov_ref in refs:
        raise ValueError("invalid or reused governance UTxO reference")
    if gov_output.get("inlineDatum") != gov_datum:
        raise ValueError("governance rule has changed since datum generation")
    gov_value = gov_output["value"]
    gov_ada = _lovelace(gov_value)
    if gov_value != {"lovelace": gov_ada, policy: {token: 1}}:
        raise ValueError("governance NFT UTxO must contain only ADA and its NFT")

    command = [cli, "latest", "transaction", "build"]
    for ref in treasury_utxos:
        command += ["--tx-in", ref,
                    "--spending-tx-in-reference", registry_script_ref,
                    "--spending-plutus-script-v3",
                    "--spending-reference-tx-in-redeemer-file", str(gov_redeemer)]
    command += ["--tx-in", gov_ref,
                "--spending-tx-in-reference", governance_script_ref,
                "--spending-plutus-script-v3",
                "--spending-reference-tx-in-inline-datum-present",
                "--spending-reference-tx-in-redeemer-file", str(gov_redeemer),
                "--tx-in-collateral", collateral_utxo,
                "--tx-out", f"{governance_address}+{gov_ada}+1 {policy}.{token}",
                "--tx-out-inline-datum-file", str(gov_datum_file)]
    if funded_datum_file is not None:
        command += ["--tx-out", f"{registry_address}+{funded_lovelace}",
                    "--tx-out-inline-datum-file", str(funded_datum_file)]
    if donation_lovelace:
        command += ["--treasury-donation", str(donation_lovelace)]
    command += withdrawal_args(withdrawals, gov_datum, network, refs + [gov_ref])
    for signer in signers:
        command += ["--required-signer-hash", signer]
    if invalid_before is not None:
        command += ["--invalid-before", str(invalid_before)]
    if invalid_hereafter is not None:
        command += ["--invalid-hereafter", str(invalid_hereafter)]
    # The CLI's ADA remainder becomes a no-datum treasury output at this address.
    command += ["--change-address", registry_address, "--out-file", str(body_file)]
    command += ["--mainnet"] if network == "mainnet" else ["--testnet-magic", str(testnet_magic)]
    return command


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("registry_snapshot", type=Path)
    parser.add_argument("governance_snapshot", type=Path)
    parser.add_argument("governance_data_dir", type=Path)
    parser.add_argument("script_dir", type=Path)
    parser.add_argument("collateral_utxo")
    parser.add_argument("body_file", type=Path)
    parser.add_argument("--treasury-utxo", action="append", required=True)
    parser.add_argument("--registry-script-ref", required=True)
    parser.add_argument("--governance-script-ref", required=True)
    parser.add_argument("--network", choices=("mainnet", "testnet"), required=True)
    parser.add_argument("--testnet-magic", type=int)
    parser.add_argument("--donation-lovelace", type=int, default=0)
    parser.add_argument("--fund-upload-plan", type=Path,
                        help="full content plan to fund one manifest or preimage UTxO")
    parser.add_argument("--fund-upload-data-dir", type=Path)
    parser.add_argument("--fund-upload-index", type=int,
                        help="segment index; omit to fund the segment manifest")
    parser.add_argument("--fund-upload-lovelace", type=int)
    parser.add_argument("--signer-hash", action="append", default=[])
    parser.add_argument("--withdrawal-spec", type=Path, action="append", default=[])
    parser.add_argument("--invalid-before", type=int)
    parser.add_argument("--invalid-hereafter", type=int)
    parser.add_argument("--cli", default="cardano-cli")
    parser.add_argument("--build", action="store_true")
    args = parser.parse_args()
    try:
        command = treasury_command(
            load_json(args.manifest.read_text()), load_json(args.registry_snapshot.read_text()),
            load_json(args.governance_snapshot.read_text()), args.governance_data_dir,
            args.script_dir, args.treasury_utxo, network=args.network,
            testnet_magic=args.testnet_magic, collateral_utxo=args.collateral_utxo,
            registry_script_ref=args.registry_script_ref,
            governance_script_ref=args.governance_script_ref, body_file=args.body_file,
            donation_lovelace=args.donation_lovelace, signer_hashes=args.signer_hash,
            funded_upload=load_json(args.fund_upload_plan.read_text()) if args.fund_upload_plan else None,
            funded_data_dir=args.fund_upload_data_dir,
            funded_index=args.fund_upload_index,
            funded_lovelace=args.fund_upload_lovelace,
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
