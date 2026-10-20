import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from registry_reference_tx import SCRIPT_HASH_KEYS, reference_command
from registry_script_hash import script_hash


class ReferenceScriptTransactionTests(unittest.TestCase):
    def test_each_script_gets_a_separate_reference_output(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            manifest = {"scripts": {}}
            for kind, key in SCRIPT_HASH_KEYS.items():
                raw = kind.encode()
                envelope = {"type": "PlutusScriptV3", "cborHex": (bytes([0x40 + len(raw)]) + raw).hex()}
                filename = f"{kind}.plutus"
                (directory / filename).write_text(json.dumps(envelope))
                manifest["scripts"][kind] = filename
                manifest[key] = script_hash(envelope)
            for kind in SCRIPT_HASH_KEYS:
                command = reference_command(
                    manifest, directory, kind, network="testnet", testnet_magic=1,
                    funding_utxo="aa" * 32 + "#0", holder_address="addr_test1holder",
                    change_address="addr_test1change", lovelace=10_000_000,
                    body_file=directory / f"{kind}.body")
                self.assertEqual(command.count("--tx-out"), 1)
                self.assertEqual(command[command.index("--tx-out-reference-script-file") + 1],
                                 str(directory / f"{kind}.plutus"))

            (directory / "registry.plutus").write_text(json.dumps({"type": "PlutusScriptV3", "cborHex": "4161"}))
            with self.assertRaisesRegex(ValueError, "disagree"):
                reference_command(
                    manifest, directory, "registry", network="mainnet", testnet_magic=None,
                    funding_utxo="aa" * 32 + "#0", holder_address="addr1holder",
                    change_address="addr1change", lovelace=10_000_000,
                    body_file=directory / "bad.body")


if __name__ == "__main__":
    unittest.main()
