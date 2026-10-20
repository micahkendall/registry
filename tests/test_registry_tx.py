import base64
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from registry_address import script_address
from registry_content import plan
from registry_data import create_uploads, list_datum, preimage_datum
from registry_list import hash_only_ref, node_token, root
from registry_tx import next_missing_index, upload_command


SCRIPT_HASH = "ab" * 28
NODE_POLICY = "12" * 28
MANIFEST = {"registryScriptHash": SCRIPT_HASH, "nodePolicyId": NODE_POLICY,
            "registryAddresses": {network: script_address(SCRIPT_HASH, network)
                                  for network in ("mainnet", "testnet")}}
FUNDER = "cd" * 32 + "#0"


class UploadTransactionTests(unittest.TestCase):
    def test_resume_selects_missing_segments_from_matching_lazy_entry(self):
        upload = plan({"subject": "ef" * 28,
                       "extension": {"value": "x" * 25_000, "sequenceNumber": 0}})
        self.assertEqual(len(upload["preimages"]), 3)
        node = root()
        node["entries"] = [hash_only_ref(upload["subject"], upload["contentHash"])]
        address = MANIFEST["registryAddresses"]["testnet"]
        snapshot = {"aa" * 32 + "#0": {"address": address,
                    "value": {"lovelace": 3_000_000, NODE_POLICY: {node_token(""): 1}},
                    "inlineDatum": list_datum(node)}}

        def publish(index):
            part = upload["preimages"][index]
            snapshot[f"{'bb' * 32}#{index}"] = {"address": address,
                "value": {"lovelace": 60_000_000},
                "inlineDatum": preimage_datum(part["subject"], index, part["hash"],
                                               base64.b64decode(part["bytesBase64"]))}

        self.assertEqual(next_missing_index(MANIFEST, upload, snapshot, "testnet"), 0)
        publish(1)
        self.assertEqual(next_missing_index(MANIFEST, upload, snapshot, "testnet"), 0)
        publish(0)
        self.assertEqual(next_missing_index(MANIFEST, upload, snapshot, "testnet"), 2)
        publish(2)
        with self.assertRaisesRegex(ValueError, "already published"):
            next_missing_index(MANIFEST, upload, snapshot, "testnet")
        snapshot[f"{'bb' * 32}#2"]["inlineDatum"]["fields"][0]["list"][2]["bytes"] = "00" * 32
        self.assertEqual(next_missing_index(MANIFEST, upload, snapshot, "testnet"), 2)
        wrong = {**upload, "contentHash": "00" * 32}
        with self.assertRaises(ValueError):
            next_missing_index(MANIFEST, wrong, snapshot, "testnet")

    def test_each_segment_builds_one_independent_unsigned_body(self):
        entry = {"subject": "ef" * 28, "name": {"value": "N", "sequenceNumber": 0},
                 "description": {"value": "D", "sequenceNumber": 0},
                 "extension": {"value": "x" * 350_000, "sequenceNumber": 0}}
        upload = plan(entry)
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp) / "datums"
            create_uploads(upload, directory)
            self.assertGreaterEqual(len(upload["preimages"]), 30)
            for index in range(len(upload["preimages"])):
                command = upload_command(MANIFEST, upload, directory, index,
                    network="testnet", testnet_magic=1, funding_utxo=FUNDER,
                    change_address="addr_test1payer", lovelace=20_000_000,
                    body_file=Path(temp) / f"upload-{index}.body")
                self.assertEqual(command[:4], ["cardano-cli", "latest", "transaction", "build"])
                self.assertEqual(command[command.index("--tx-out") + 1],
                                 MANIFEST["registryAddresses"]["testnet"] + "+20000000")
                self.assertEqual(command[command.index("--tx-out-inline-datum-file") + 1],
                                 str(directory / f"preimage-{index:03d}.datum.json"))
                self.assertEqual(command.count("--tx-out"), 1)
                self.assertEqual(command[-2:], ["--testnet-magic", "1"])

    def test_tampered_datum_and_address_are_rejected(self):
        entry = {"subject": "ef" * 28, "name": {"value": "N", "sequenceNumber": 0},
                 "description": {"value": "D", "sequenceNumber": 0}}
        upload = plan(entry)
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp) / "datums"
            create_uploads(upload, directory)
            kwargs = dict(network="mainnet", testnet_magic=None, funding_utxo=FUNDER,
                          change_address="addr1payer", lovelace=3_000_000,
                          body_file=Path(temp) / "upload.body")
            self.assertIn("--mainnet", upload_command(MANIFEST, upload, directory, 0, **kwargs))
            wrong = {**MANIFEST, "registryAddresses": {"mainnet": "addr1wrong"}}
            with self.assertRaisesRegex(ValueError, "manifest registry address"):
                upload_command(wrong, upload, directory, 0, **kwargs)
            datum_file = directory / "preimage-000.datum.json"
            datum = json.loads(datum_file.read_text())
            datum["fields"][0]["list"][1]["int"] = 1
            datum_file.write_text(json.dumps(datum))
            with self.assertRaisesRegex(ValueError, "does not match upload plan"):
                upload_command(MANIFEST, upload, directory, 0, **kwargs)


if __name__ == "__main__":
    unittest.main()
