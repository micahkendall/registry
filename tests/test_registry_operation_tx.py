import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from registry_address import script_address
from registry_content import digest
from registry_data import create_governance, create_operation, list_datum
from registry_list import apply, node_token, root
from registry_operation_tx import operation_command
from registry_script_hash import script_hash


FUNDER = "ee" * 32 + "#0"
COLLATERAL = "dd" * 32 + "#1"
NODE_REF = "aa" * 32 + "#2"
GOV_REF = "bb" * 32 + "#3"
GOV_TOKEN = "474f56"
REGISTRY_SCRIPT_REF = "cc" * 32 + "#4"
GOVERNANCE_SCRIPT_REF = "cc" * 32 + "#5"
NODE_POLICY_REF = "cc" * 32 + "#6"
TREASURY_REF = "ab" * 32 + "#7"


def ref(number):
    payload = bytes([number])
    return {"subject": number.to_bytes(28, "big").hex(), "contentHash": digest(payload).hex(),
            "contentBytes": 1, "segmentHashes": [digest(b"\x01" + payload).hex()]}


def envelope(raw):
    return {"type": "PlutusScriptV3", "cborHex": (bytes([0x40 + len(raw)]) + raw).hex()}


class GovernedTransactionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)
        scripts = {"governance": "governance.plutus", "nodePolicy": "node-policy.plutus",
                   "registry": "registry.plutus"}
        hashes = {}
        for key, filename in scripts.items():
            value = envelope(key.encode())
            (self.directory / filename).write_text(json.dumps(value))
            hashes[key] = script_hash(value)
        self.manifest = {"governanceScriptHash": hashes["governance"],
                         "governancePolicyId": "ab" * 28, "governanceTokenName": GOV_TOKEN,
                         "nodePolicyId": hashes["nodePolicy"], "registryScriptHash": hashes["registry"],
                         "governanceAddresses": {n: script_address(hashes["governance"], n) for n in ("mainnet", "testnet")},
                         "registryAddresses": {n: script_address(hashes["registry"], n) for n in ("mainnet", "testnet")},
                         "scripts": scripts}
        self.governance_dir = self.directory / "governance-data"
        create_governance(self.manifest, {"signature": "11" * 28}, self.governance_dir)
        gov_datum = json.loads((self.governance_dir / "governance.datum.json").read_text())
        self.gov_snapshot = {GOV_REF: {
            "address": self.manifest["governanceAddresses"]["testnet"],
            "value": {"lovelace": 3_000_000, self.manifest["governancePolicyId"]: {GOV_TOKEN: 1}},
            "inlineDatum": gov_datum}}

    def tearDown(self):
        self.temp.cleanup()

    def command(self, plan, commitment, original, *, right_lovelace=None,
                left_lovelace=10_000_000, treasury_lovelace=None,
                treasury_change_lovelace=0):
        operation_dir = self.directory / "operation"
        if not operation_dir.exists():
            create_operation(plan, commitment, operation_dir)
        registry_snapshot = {NODE_REF: {
            "address": self.manifest["registryAddresses"]["testnet"],
            "value": {"lovelace": 10_000_000, self.manifest["nodePolicyId"]:
                      {node_token(original["lowerBound"]): 1}},
            "inlineDatum": list_datum(original)}}
        if treasury_lovelace is not None:
            registry_snapshot[TREASURY_REF] = {
                "address": self.manifest["registryAddresses"]["testnet"],
                "value": {"lovelace": treasury_lovelace}}
        return operation_command(
            self.manifest, plan, commitment, operation_dir, self.governance_dir,
            registry_snapshot, self.gov_snapshot, self.directory, network="testnet",
            testnet_magic=1, funding_utxo=FUNDER, collateral_utxo=COLLATERAL,
            change_address="addr_test1payer",
            registry_script_ref=REGISTRY_SCRIPT_REF,
            governance_script_ref=GOVERNANCE_SCRIPT_REF,
            node_policy_ref=NODE_POLICY_REF if right_lovelace is not None else None,
            left_lovelace=left_lovelace,
            right_lovelace=right_lovelace, body_file=self.directory / "tx.body",
            signer_hashes=["11" * 28], invalid_before=100, invalid_hereafter=200,
            treasury_utxo=TREASURY_REF if treasury_lovelace is not None else None,
            treasury_change_lovelace=treasury_change_lovelace)

    def test_governed_insert_spends_both_scripts_and_preserves_nfts(self):
        original = root()
        nodes, action = apply([original], ref(1))
        action["sourceOutRef"] = NODE_REF
        command = self.command({"action": action, "successorNodes": nodes}, ref(1), original)
        self.assertEqual(command.count("--spending-tx-in-reference"), 2)
        self.assertNotIn("--tx-in-script-file", command)
        self.assertEqual(command.count("--tx-out-inline-datum-file"), 2)
        self.assertEqual(command.count("--tx-out"), 2)
        self.assertNotIn("--mint", command)
        self.assertIn(NODE_REF, command)
        self.assertIn(GOV_REF, command)
        self.assertIn("--required-signer-hash", command)

    def test_split_mints_right_nft_and_requires_third_datum(self):
        nodes = [root()]
        for number in range(1, 9):
            nodes, _ = apply(nodes, ref(number))
        original = nodes[0]
        successors, action = apply(nodes, ref(9))
        action["sourceOutRef"] = NODE_REF
        command = self.command({"action": action, "successorNodes": successors}, ref(9), original,
                               right_lovelace=5_000_000)
        self.assertEqual(command.count("--tx-out-inline-datum-file"), 3)
        self.assertEqual(command.count("--tx-out"), 3)
        self.assertIn("--mint", command)
        self.assertIn("--mint-tx-in-reference", command)
        self.assertNotIn("--mint-script-file", command)
        self.assertEqual(command[command.index("--mint") + 1],
                         f"1 {self.manifest['nodePolicyId']}.{action['rightNodeToken']}")

    def test_governed_update_replaces_one_commitment_without_minting(self):
        original_nodes, _ = apply([root()], ref(1))
        original = original_nodes[0]
        replacement = {**ref(1), "contentHash": digest(b"updated").hex()}
        successors, action = apply(original_nodes, replacement, update=True)
        action["sourceOutRef"] = NODE_REF
        command = self.command({"action": action, "successorNodes": successors}, replacement, original)
        self.assertEqual(command.count("--tx-out-inline-datum-file"), 2)
        self.assertNotIn("--mint", command)

    def test_split_can_draw_minimum_ada_from_no_datum_treasury(self):
        nodes = [root()]
        for number in range(1, 9):
            nodes, _ = apply(nodes, ref(number))
        successors, action = apply(nodes, ref(9))
        action["sourceOutRef"] = NODE_REF
        plan = {"action": action, "successorNodes": successors}
        command = self.command(plan, ref(9), nodes[0], right_lovelace=5_000_000,
                               treasury_lovelace=6_000_000, treasury_change_lovelace=1_000_000)
        self.assertEqual(command.count("--spending-tx-in-reference"), 3)
        self.assertEqual(command.count("--spending-reference-tx-in-inline-datum-present"), 2)
        self.assertEqual(command.count("--tx-out"), 4)
        self.assertIn(TREASURY_REF, command)
        self.assertIn("treasury.redeemer.json", " ".join(command))
        self.assertIn(self.manifest["registryAddresses"]["testnet"] + "+1000000", command)
        with self.assertRaisesRegex(ValueError, "retain the node and treasury ADA"):
            self.command(plan, ref(9), nodes[0], right_lovelace=5_000_000,
                         treasury_lovelace=6_000_000, treasury_change_lovelace=999_999)

    def test_insufficient_successor_ada_is_rejected(self):
        original = root()
        nodes, action = apply([original], ref(1))
        action["sourceOutRef"] = NODE_REF
        plan = {"action": action, "successorNodes": nodes}
        operation_dir = self.directory / "operation"
        create_operation(plan, ref(1), operation_dir)
        registry_snapshot = {NODE_REF: {
            "address": self.manifest["registryAddresses"]["testnet"],
            "value": {"lovelace": 10_000_000, self.manifest["nodePolicyId"]: {node_token(""): 1}},
            "inlineDatum": list_datum(original)}}
        with self.assertRaisesRegex(ValueError, "retain the node and treasury ADA"):
            operation_command(self.manifest, plan, ref(1), operation_dir, self.governance_dir,
                              registry_snapshot, self.gov_snapshot, self.directory,
                              network="testnet", testnet_magic=1, funding_utxo=FUNDER,
                              collateral_utxo=COLLATERAL, change_address="addr_test1payer",
                              registry_script_ref=REGISTRY_SCRIPT_REF,
                              governance_script_ref=GOVERNANCE_SCRIPT_REF,
                              node_policy_ref=None,
                              left_lovelace=1, right_lovelace=None, body_file=self.directory / "tx.body")

    def test_changed_governance_rule_is_rejected(self):
        original = root()
        nodes, action = apply([original], ref(1))
        action["sourceOutRef"] = NODE_REF
        self.gov_snapshot[GOV_REF]["inlineDatum"] = {"list": [
            {"bytes": self.manifest["governancePolicyId"]}, {"bytes": GOV_TOKEN},
            {"constructor": 0, "fields": [{"bytes": "22" * 28}]}]}
        with self.assertRaisesRegex(ValueError, "rule has changed"):
            self.command({"action": action, "successorNodes": nodes}, ref(1), original)


if __name__ == "__main__":
    unittest.main()
