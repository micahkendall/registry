import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from registry_address import script_reward_address
from registry_data import multisig_rule
from registry_script_hash import script_hash
from registry_withdrawal import script_rule_hashes, withdrawal_args


class WithdrawalWitnessTests(unittest.TestCase):
    def test_script_branch_builds_zero_withdrawal_witness(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            raw = b"withdraw"
            envelope = {"type": "PlutusScriptV3", "cborHex": (bytes([0x40 + len(raw)]) + raw).hex()}
            script_file = directory / "withdrawal.plutus"
            script_file.write_text(json.dumps(envelope))
            redeemer_file = directory / "redeemer.json"
            redeemer_file.write_text('{"int":0}')
            script_hash_hex = script_hash(envelope)
            datum = {"list": [{"bytes": "aa" * 28}, {"bytes": "474f56"},
                              multisig_rule({"atLeast": {"required": 1, "rules": [
                                  {"signature": "11" * 28}, {"script": script_hash_hex}]}})]}
            self.assertEqual(script_rule_hashes(datum["list"][2]), {script_hash_hex})
            ref = "ab" * 32 + "#0"
            spec = {"scriptFile": str(script_file), "reference": ref,
                    "redeemerFile": str(redeemer_file)}
            command = withdrawal_args([spec], datum, "testnet", ["cd" * 32 + "#1"])
            self.assertEqual(command[0:2], ["--withdrawal", script_reward_address(script_hash_hex, "testnet") + "+0"])
            self.assertIn("--withdrawal-plutus-script-v3", command)
            self.assertIn(ref, command)
            with self.assertRaisesRegex(ValueError, "distinct"):
                withdrawal_args([spec], datum, "testnet", [ref])
            with self.assertRaisesRegex(ValueError, "duplicate"):
                withdrawal_args([spec, {**spec, "reference": "ef" * 32 + "#2"}], datum, "testnet", [])
            unauthorized = {"list": datum["list"][:2] + [multisig_rule({"signature": "11" * 28})]}
            with self.assertRaisesRegex(ValueError, "absent"):
                withdrawal_args([spec], unauthorized, "testnet", [])


if __name__ == "__main__":
    unittest.main()
