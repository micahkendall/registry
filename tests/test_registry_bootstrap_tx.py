import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from registry_address import script_address
from registry_bootstrap_tx import bootstrap_command
from registry_data import create_governance, create_root
from registry_list import node_token
from registry_script_hash import script_hash


SEED1 = "aa" * 32 + "#0"
SEED2 = "bb" * 32 + "#1"
COLLATERAL = "cc" * 32 + "#2"


def envelope(raw):
    return {"type": "PlutusScriptV3", "cborHex": (bytes([0x40 + len(raw)]) + raw).hex()}


class BootstrapTransactionTests(unittest.TestCase):
    def test_separate_one_shot_mints_use_exact_addresses_and_datums(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            gov_script = envelope(b"governance")
            registry_script = envelope(b"registry")
            gov_policy = envelope(b"gov-policy")
            node_policy = envelope(b"node-policy")
            for filename, value in (("governance.plutus", gov_script), ("registry.plutus", registry_script),
                                    ("governance-policy.plutus", gov_policy), ("node-policy.plutus", node_policy)):
                (directory / filename).write_text(json.dumps(value))
            manifest = {
                "governanceSeed": SEED1, "nodeSeed": SEED2,
                "governanceScriptHash": script_hash(gov_script),
                "registryScriptHash": script_hash(registry_script),
                "governancePolicyId": script_hash(gov_policy),
                "nodePolicyId": script_hash(node_policy), "governanceTokenName": "474f56",
                "governanceAddresses": {n: script_address(script_hash(gov_script), n) for n in ("mainnet", "testnet")},
                "registryAddresses": {n: script_address(script_hash(registry_script), n) for n in ("mainnet", "testnet")},
                "scripts": {"governancePolicy": "governance-policy.plutus", "nodePolicy": "node-policy.plutus"},
            }
            governance_data = directory / "governance-data"
            root_data = directory / "root-data"
            create_governance(manifest, {"atLeast": {"required": 2, "rules": [
                {"signature": "11" * 28}, {"signature": "22" * 28}, {"after": 1000}]}}, governance_data)
            create_root(root_data)
            common = dict(network="testnet", testnet_magic=1, collateral_utxo=COLLATERAL,
                          change_address="addr_test1change", lovelace=10_000_000,
                          body_file=directory / "bootstrap.body")
            gov = bootstrap_command(manifest, directory, governance_data, "governance", **common)
            self.assertEqual(gov[gov.index("--tx-in") + 1], SEED1)
            self.assertIn(manifest["governanceAddresses"]["testnet"], gov[gov.index("--tx-out") + 1])
            self.assertIn(manifest["governancePolicyId"], gov[gov.index("--mint") + 1])
            root_cmd = bootstrap_command(manifest, directory, root_data, "root", **common)
            self.assertEqual(root_cmd[root_cmd.index("--tx-in") + 1], SEED2)
            self.assertIn(manifest["registryAddresses"]["testnet"], root_cmd[root_cmd.index("--tx-out") + 1])
            self.assertIn(node_token(""), root_cmd[root_cmd.index("--mint") + 1])

            unsafe = json.loads((governance_data / "governance.datum.json").read_text())
            unsafe["list"][2] = {"constructor": 1, "fields": [{"list": []}]}
            (governance_data / "governance.datum.json").write_text(json.dumps(unsafe))
            with self.assertRaisesRegex(ValueError, "require authority"):
                bootstrap_command(manifest, directory, governance_data, "governance", **common)


if __name__ == "__main__":
    unittest.main()
