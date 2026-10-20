import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from registry_address import script_address
from registry_data import create_governance, multisig_rule
from registry_governance_tx import rotation_command
from registry_script_hash import script_hash


GOV_REF = "aa" * 32 + "#0"
FUNDING = "bb" * 32 + "#1"
COLLATERAL = "cc" * 32 + "#2"
SCRIPT_REF = "dd" * 32 + "#3"
OLD_SIGNER = "11" * 28
NEW_SIGNER = "22" * 28


class GovernanceRotationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)
        raw = b"governance"
        envelope = {"type": "PlutusScriptV3", "cborHex": (bytes([0x40 + len(raw)]) + raw).hex()}
        (self.directory / "governance.plutus").write_text(json.dumps(envelope))
        script_hash_hex = script_hash(envelope)
        self.manifest = {"governanceScriptHash": script_hash_hex,
                         "governancePolicyId": "ab" * 28, "governanceTokenName": "474f56",
                         "governanceAddresses": {network: script_address(script_hash_hex, network)
                                                 for network in ("mainnet", "testnet")},
                         "scripts": {"governance": "governance.plutus"}}
        self.old_dir = self.directory / "old-data"
        self.new_dir = self.directory / "new-data"
        self.new_rule = {"atLeast": {"required": 2, "rules": [
            {"signature": NEW_SIGNER}, {"signature": OLD_SIGNER}, {"after": 1000}]}}
        create_governance(self.manifest, {"signature": OLD_SIGNER}, self.old_dir)
        create_governance(self.manifest, self.new_rule, self.new_dir)
        self.snapshot = {GOV_REF: {
            "address": self.manifest["governanceAddresses"]["testnet"],
            "value": {"lovelace": 3_000_000,
                      self.manifest["governancePolicyId"]: {self.manifest["governanceTokenName"]: 1}},
            "inlineDatum": json.loads((self.old_dir / "governance.datum.json").read_text())}}

    def tearDown(self):
        self.temp.cleanup()

    def command(self, rule=None, snapshot=None, funding=FUNDING):
        return rotation_command(
            self.manifest, self.snapshot if snapshot is None else snapshot,
            self.new_rule if rule is None else rule, self.new_dir, self.directory,
            network="testnet", testnet_magic=1, funding_utxo=funding,
            collateral_utxo=COLLATERAL, change_address="addr_test1payer",
            governance_script_ref=SCRIPT_REF, body_file=self.directory / "rotation.body",
            signer_hashes=[OLD_SIGNER], invalid_before=10, invalid_hereafter=20)

    def test_rotation_spends_old_rule_and_preserves_nft_and_ada(self):
        command = self.command()
        self.assertEqual(command.count("--spending-tx-in-reference"), 1)
        self.assertIn(GOV_REF, command)
        self.assertIn(OLD_SIGNER, command)
        self.assertNotIn(NEW_SIGNER, command)
        self.assertIn(self.manifest["governanceAddresses"]["testnet"] + "+3000000+1", command[command.index("--tx-out") + 1])
        self.assertEqual(command[command.index("--tx-out-inline-datum-file") + 1],
                         str(self.new_dir / "governance.datum.json"))

    def test_changed_snapshot_or_unsafe_new_rule_is_rejected(self):
        bad_snapshot = json.loads(json.dumps(self.snapshot))
        bad_snapshot[GOV_REF]["inlineDatum"]["list"][0] = {"bytes": "00" * 28}
        with self.assertRaisesRegex(ValueError, "does not name"):
            self.command(snapshot=bad_snapshot)
        with self.assertRaisesRegex(ValueError, "distinct"):
            self.command(funding=GOV_REF)
        with self.assertRaisesRegex(ValueError, "needs signer"):
            self.command(rule={"allOf": []})

    def test_old_rule_can_authorize_with_script_withdrawal(self):
        raw = b"withdrawal"
        envelope = {"type": "PlutusScriptV3", "cborHex": (bytes([0x40 + len(raw)]) + raw).hex()}
        script_file = self.directory / "withdrawal.plutus"
        script_file.write_text(json.dumps(envelope))
        redeemer_file = self.directory / "withdrawal.redeemer.json"
        redeemer_file.write_text('{"int":0}')
        hash_value = script_hash(envelope)
        self.snapshot[GOV_REF]["inlineDatum"]["list"][2] = multisig_rule({"script": hash_value})
        command = rotation_command(
            self.manifest, self.snapshot, self.new_rule, self.new_dir, self.directory,
            network="testnet", testnet_magic=1, funding_utxo=FUNDING,
            collateral_utxo=COLLATERAL, change_address="addr_test1payer",
            governance_script_ref=SCRIPT_REF, body_file=self.directory / "rotation.body",
            withdrawals=[{"scriptFile": str(script_file), "reference": "ee" * 32 + "#4",
                          "redeemerFile": str(redeemer_file)}])
        self.assertIn("--withdrawal", command)
        self.assertIn("--withdrawal-plutus-script-v3", command)
        self.assertNotIn("--required-signer-hash", command)


if __name__ == "__main__":
    unittest.main()
