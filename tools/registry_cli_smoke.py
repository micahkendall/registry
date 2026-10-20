#!/usr/bin/env python3
"""Cross-check exported scripts and size signed uploads with cardano-cli.

The upload uses a synthetic input and fee. It tests serialization, not ledger
acceptance, minimum ADA, execution budgets, or submission.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import subprocess
import tempfile
from pathlib import Path

from registry_content import MAX_CONTENT_BYTES, canonical_content, plan
from registry_data import preimage_datum


def cli(*args: str) -> str:
    return subprocess.check_output(args, text=True).strip()


def check(manifest_path: Path, executable: str, protocol_params: Path | None = None,
          *, large_upload: bool = False) -> dict:
    manifest = json.loads(manifest_path.read_text())
    directory = manifest_path.parent
    hashes = {
        "registry": "registryScriptHash",
        "governance": "governanceScriptHash",
        "nodePolicy": "nodePolicyId",
        "governancePolicy": "governancePolicyId",
    }
    for name, field in hashes.items():
        actual = cli(executable, "latest", "transaction", "policyid", "--script-file",
                     str(directory / manifest["scripts"][name]))
        if actual != manifest[field]:
            raise ValueError(f"{name} hash mismatch: {actual} != {manifest[field]}")
    for name, address_field in (("registry", "registryAddresses"),
                                ("governance", "governanceAddresses")):
        for network, flag in (("mainnet", ["--mainnet"]),
                              ("testnet", ["--testnet-magic", "42"])):
            actual = cli(executable, "latest", "address", "build", "--payment-script-file",
                         str(directory / manifest["scripts"][name]), *flag)
            if actual != manifest[address_field][network]:
                raise ValueError(f"{name} {network} address mismatch")

    minimum_ada = None
    large_upload_result = None
    with tempfile.TemporaryDirectory(prefix="registry-cli-smoke-") as temporary:
        base = Path(temporary)
        datum = base / "preimage.json"
        segment = b"x" * 12_000
        segment_hash = hashlib.blake2b(b"\x01" + segment, digest_size=32).hexdigest()
        datum.write_text(json.dumps(preimage_datum(
            "ab" * 28 + "00" * 32, 0, segment_hash, segment)))
        if protocol_params is not None:
            measured = cli(executable, "latest", "transaction", "calculate-min-required-utxo",
                           "--protocol-params-file", str(protocol_params.resolve()),
                           "--tx-out", manifest["registryAddresses"]["testnet"] + "+60000000",
                           "--tx-out-inline-datum-file", str(datum))
            match = re.fullmatch(r"Coin (\d+)", measured)
            if match is None:
                raise ValueError("unexpected minimum UTxO output for preimage")
            minimum_ada = int(match.group(1))
            if minimum_ada > 60_000_000:
                raise ValueError("synthetic preimage output is below its minimum ADA")
        body = base / "upload.body"
        signed = base / "upload.signed"
        signing_key = base / "payment.skey"
        cli(executable, "latest", "transaction", "build-raw",
            "--tx-in", "11" * 32 + "#0",
            "--tx-out", manifest["registryAddresses"]["testnet"] + "+60000000",
            "--tx-out-inline-datum-file", str(datum),
            "--fee", "200000", "--out-file", str(body))
        cli(executable, "latest", "address", "key-gen",
            "--verification-key-file", str(base / "payment.vkey"),
            "--signing-key-file", str(signing_key))
        cli(executable, "latest", "transaction", "sign", "--tx-body-file", str(body),
            "--signing-key-file", str(signing_key), "--testnet-magic", "42",
            "--out-file", str(signed))
        size = len(bytes.fromhex(json.loads(signed.read_text())["cborHex"]))
        if size >= 14_000:
            raise ValueError(f"signed upload is {size} bytes, above the 14 KB planning target")
        if large_upload:
            document = {"subject": "ab" * 28,
                        "extension": {"value": "", "sequenceNumber": 0}}
            overhead = len(canonical_content(document))
            document["extension"]["value"] = "x" * (MAX_CONTENT_BYTES - overhead)
            upload = plan(document)
            parts = upload["preimages"]
            if upload["contentBytes"] != MAX_CONTENT_BYTES or len(parts) != 32:
                raise ValueError("maximum-size entry must need 32 uploads")
            largest_signed = 0
            largest_minimum_ada = 0
            for index, part in enumerate(parts):
                segment_datum = base / f"segment-{index}.json"
                segment_datum.write_text(json.dumps(preimage_datum(
                    part["subject"], index, part["hash"],
                    base64.b64decode(part["bytesBase64"]))))
                if protocol_params is not None:
                    measured = cli(executable, "latest", "transaction", "calculate-min-required-utxo",
                                   "--protocol-params-file", str(protocol_params.resolve()),
                                   "--tx-out", manifest["registryAddresses"]["testnet"] + "+60000000",
                                   "--tx-out-inline-datum-file", str(segment_datum))
                    match = re.fullmatch(r"Coin (\d+)", measured)
                    if match is None:
                        raise ValueError(f"unexpected minimum UTxO output for segment {index}")
                    largest_minimum_ada = max(largest_minimum_ada, int(match.group(1)))
                    if int(match.group(1)) > 60_000_000:
                        raise ValueError(f"segment {index} output is below its minimum ADA")
                segment_body = base / f"segment-{index}.body"
                segment_signed = base / f"segment-{index}.signed"
                cli(executable, "latest", "transaction", "build-raw",
                    "--tx-in", f"{index + 1:064x}#0",
                    "--tx-out", manifest["registryAddresses"]["testnet"] + "+60000000",
                    "--tx-out-inline-datum-file", str(segment_datum),
                    "--fee", "200000", "--out-file", str(segment_body))
                cli(executable, "latest", "transaction", "sign", "--tx-body-file", str(segment_body),
                    "--signing-key-file", str(signing_key), "--testnet-magic", "42",
                    "--out-file", str(segment_signed))
                signed_size = len(bytes.fromhex(json.loads(segment_signed.read_text())["cborHex"]))
                largest_signed = max(largest_signed, signed_size)
                if signed_size >= 14_000:
                    raise ValueError(f"segment {index} signed upload is {signed_size} bytes")
            large_upload_result = {"contentBytes": upload["contentBytes"],
                                   "separateSignedTransactions": len(parts),
                                   "largestSignedTransactionBytes": largest_signed}
            if protocol_params is not None:
                large_upload_result["largestMinimumOutputAda"] = largest_minimum_ada
    result = {"scriptHashesChecked": 4, "addressesChecked": 4,
              "signedUploadBytes": size, "planningTargetBytes": 14_000}
    if minimum_ada is not None:
        result["minimumPreimageAda"] = minimum_ada
    if large_upload_result is not None:
        result["largeUpload"] = large_upload_result
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--cardano-cli", default="cardano-cli")
    parser.add_argument("--protocol-params", type=Path)
    parser.add_argument("--large-upload", action="store_true",
                        help="sign one synthetic transaction per segment of a 380,000-byte CIP-26 entry")
    args = parser.parse_args()
    print(json.dumps(check(args.manifest, args.cardano_cli, args.protocol_params,
                           large_upload=args.large_upload), indent=2))


if __name__ == "__main__":
    main()
