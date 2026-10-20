import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from registry_address import script_address
from registry_content import hash_only_commitment, plan
from registry_data import create_uploads
from registry_manifest_tx import manifest_command


class ManifestTransactionTests(unittest.TestCase):
    def test_hash_only_cli_needs_no_preimage_file(self):
        subject = "ab" * 28
        content_hash = "12" * 32
        process = subprocess.run(
            [sys.executable, str(Path(__file__).resolve().parents[1] / "tools" / "registry_content.py"),
             "--subject", subject, "--content-hash", content_hash],
            capture_output=True, text=True, check=True)
        self.assertEqual(json.loads(process.stdout), hash_only_commitment(subject, content_hash))

    def test_hash_only_then_permissionless_manifest_transaction(self):
        document = {"subject": "ab" * 28, "name": {"value": "Example", "sequenceNumber": 0}}
        upload = plan(document)
        self.assertEqual(hash_only_commitment(document["subject"], upload["contentHash"]),
                         {"subject": document["subject"], "contentHash": upload["contentHash"],
                          "contentBytes": 0, "segmentHashes": []})
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "upload-data"
            create_uploads(upload, directory)
            self.assertTrue((directory / "manifest.datum.json").exists())
            registry_hash = "12" * 28
            address = script_address(registry_hash, "testnet")
            manifest = {"registryScriptHash": registry_hash,
                        "registryAddresses": {"testnet": address}}
            command = manifest_command(
                manifest, upload, directory, network="testnet", testnet_magic=1,
                funding_utxo="aa" * 32 + "#0", change_address="addr_test1payer",
                lovelace=4_000_000, body_file=directory / "manifest.body")
            self.assertIn(address + "+4000000", command)
            self.assertIn(str(directory / "manifest.datum.json"), command)
            self.assertNotIn("--tx-in-collateral", command)
            datum_file = directory / "manifest.datum.json"
            datum = json.loads(datum_file.read_text())
            datum["fields"][0]["list"][1]["bytes"] = "00" * 32
            datum_file.write_text(json.dumps(datum))
            with self.assertRaisesRegex(ValueError, "does not match"):
                manifest_command(
                    manifest, upload, directory, network="testnet", testnet_magic=1,
                    funding_utxo="aa" * 32 + "#0", change_address="addr_test1payer",
                    lovelace=4_000_000, body_file=directory / "manifest.body")


if __name__ == "__main__":
    unittest.main()
