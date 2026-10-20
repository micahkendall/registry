import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from registry_address import script_address
from registry_content import plan
from registry_data import create_governance, create_uploads
from registry_script_hash import script_hash
from registry_treasury_tx import treasury_command


TREASURY_1 = "aa" * 32 + "#0"
TREASURY_2 = "bb" * 32 + "#1"
GOVERNANCE = "cc" * 32 + "#2"
COLLATERAL = "dd" * 32 + "#3"
REGISTRY_SCRIPT = "ee" * 32 + "#4"
GOVERNANCE_SCRIPT = "ff" * 32 + "#5"
SIGNER = "11" * 28


class TreasuryTransactionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)
        scripts = {}
        hashes = {}
        for name in ("registry", "governance"):
            raw = name.encode()
            envelope = {"type": "PlutusScriptV3", "cborHex": (bytes([0x40 + len(raw)]) + raw).hex()}
            filename = name + ".plutus"
            (self.directory / filename).write_text(json.dumps(envelope))
            scripts[name] = filename
            hashes[name] = script_hash(envelope)
        self.manifest = {
            "registryScriptHash": hashes["registry"],
            "governanceScriptHash": hashes["governance"],
            "registryAddresses": {network: script_address(hashes["registry"], network)
                                  for network in ("mainnet", "testnet")},
            "governanceAddresses": {network: script_address(hashes["governance"], network)
                                    for network in ("mainnet", "testnet")},
            "governancePolicyId": "12" * 28,
            "governanceTokenName": "474f56",
            "scripts": scripts,
        }
        self.gov_dir = self.directory / "governance-data"
        create_governance(self.manifest, {"signature": SIGNER}, self.gov_dir)
        self.registry_snapshot = {
            TREASURY_1: {"address": self.manifest["registryAddresses"]["testnet"],
                         "value": {"lovelace": 4_000_000}},
            TREASURY_2: {"address": self.manifest["registryAddresses"]["testnet"],
                         "value": {"lovelace": 5_000_000}},
        }
        self.gov_snapshot = {GOVERNANCE: {
            "address": self.manifest["governanceAddresses"]["testnet"],
            "value": {"lovelace": 3_000_000,
                      self.manifest["governancePolicyId"]: {self.manifest["governanceTokenName"]: 1}},
            "inlineDatum": json.loads((self.gov_dir / "governance.datum.json").read_text()),
        }}
        self.upload = plan({"subject": "ab" * 28,
                            "name": {"value": "Treasury funded", "sequenceNumber": 0}})
        self.upload_dir = self.directory / "upload-data"
        create_uploads(self.upload, self.upload_dir)

    def tearDown(self):
        self.temp.cleanup()

    def command(self, treasury_utxos=None, donation=2_000_000, **kwargs):
        return treasury_command(
            self.manifest, self.registry_snapshot, self.gov_snapshot,
            self.gov_dir, self.directory,
            [TREASURY_1, TREASURY_2] if treasury_utxos is None else treasury_utxos,
            network="testnet", testnet_magic=1, collateral_utxo=COLLATERAL,
            registry_script_ref=REGISTRY_SCRIPT, governance_script_ref=GOVERNANCE_SCRIPT,
            body_file=self.directory / "treasury.body", donation_lovelace=donation,
            signer_hashes=[SIGNER], invalid_before=10, invalid_hereafter=20, **kwargs)

    def test_multi_input_donation_keeps_change_at_registry(self):
        command = self.command()
        self.assertEqual(command.count("--tx-in"), 3)
        self.assertIn(TREASURY_1, command)
        self.assertIn(TREASURY_2, command)
        self.assertEqual(command.count("--spending-reference-tx-in-inline-datum-present"), 1)
        self.assertEqual(command[command.index("--change-address") + 1],
                         self.manifest["registryAddresses"]["testnet"])
        self.assertEqual(command[command.index("--treasury-donation") + 1], "2000000")
        self.assertIn(self.manifest["governanceAddresses"]["testnet"] + "+3000000+1",
                      command[command.index("--tx-out") + 1])
        self.assertEqual(command[command.index("--tx-out-inline-datum-file") + 1],
                         str(self.gov_dir / "governance.datum.json"))
        self.assertNotIn("--tx-out-datum-hash-file", command)
        self.assertIn(SIGNER, command)

    def test_rejects_bad_treasury_inputs_and_donation(self):
        with self.assertRaisesRegex(ValueError, "at least one"):
            self.command([])
        with self.assertRaisesRegex(ValueError, "distinct"):
            self.command([TREASURY_1, TREASURY_1])
        with self.assertRaisesRegex(ValueError, "leave treasury ADA"):
            self.command(donation=9_000_000)
        self.registry_snapshot[TREASURY_1]["value"]["ff" * 28] = {"00": 1}
        with self.assertRaisesRegex(ValueError, "ADA only"):
            self.command()
        del self.registry_snapshot[TREASURY_1]["value"]["ff" * 28]
        self.registry_snapshot[TREASURY_1]["inlineDatum"] = {"int": 0}
        with self.assertRaisesRegex(ValueError, "no-datum"):
            self.command()

    def test_rejects_changed_governance_rule(self):
        self.gov_snapshot[GOVERNANCE]["inlineDatum"]["list"][2] = {"int": 0}
        with self.assertRaisesRegex(ValueError, "rule has changed"):
            self.command()

    def test_treasury_can_fund_one_preimage_or_manifest_output(self):
        common = {"funded_upload": self.upload, "funded_data_dir": self.upload_dir,
                  "funded_lovelace": 2_000_000}
        segment = self.command(donation=0, funded_index=0, **common)
        self.assertEqual(segment.count("--tx-out-inline-datum-file"), 2)
        self.assertIn(str(self.upload_dir / "preimage-000.datum.json"), segment)
        self.assertIn(self.manifest["registryAddresses"]["testnet"] + "+2000000", segment)
        self.assertEqual(segment[segment.index("--change-address") + 1],
                         self.manifest["registryAddresses"]["testnet"])
        metadata_manifest = self.command(donation=0, **common)
        self.assertIn(str(self.upload_dir / "manifest.datum.json"), metadata_manifest)

    def test_rejects_incomplete_or_oversized_funded_upload(self):
        common = {"funded_upload": self.upload, "funded_data_dir": self.upload_dir,
                  "funded_index": 0, "funded_lovelace": 2_000_000}
        with self.assertRaisesRegex(ValueError, "requires plan"):
            self.command(donation=0, funded_index=0)
        with self.assertRaisesRegex(ValueError, "leave treasury ADA"):
            self.command(donation=0, **{**common, "funded_lovelace": 9_000_000})
        with self.assertRaisesRegex(ValueError, "absent or unordered"):
            self.command(donation=0, **{**common, "funded_index": 1})
        datum_file = self.upload_dir / "preimage-000.datum.json"
        datum_file.write_text(json.dumps({"int": 0}))
        with self.assertRaisesRegex(ValueError, "disagrees with plan"):
            self.command(donation=0, **common)


if __name__ == "__main__":
    unittest.main()
