import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]


def run_script(name: str, *arguments: str) -> str:
    completed = subprocess.run(
        [sys.executable, str(PROJECT / "tools" / name), *arguments],
        cwd=PROJECT, check=True, text=True, capture_output=True,
    )
    return completed.stdout


class CliFlowTests(unittest.TestCase):
    def test_snapshot_to_list_plan_keeps_source_outref(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            subject = "ab" * 28
            entry = {"subject": subject, "name": {"value": "Token", "sequenceNumber": 0},
                     "description": {"value": "Metadata", "sequenceNumber": 0}}
            entry_path = directory / "entry.json"
            entry_path.write_text(json.dumps(entry))
            commitment = directory / "commitment.json"
            commitment.write_text(run_script("registry_content.py", str(entry_path), "--lazy"))
            run_script("registry_data.py", "root", str(directory / "root-data"))
            address = "addr_test1registryfixture"
            policy = "ef" * 28
            source_ref = "ab" * 32 + "#0"
            utxos = {source_ref: {"address": address, "value": {"lovelace": 3_000_000,
                     policy: {"0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8": 1}},
                     "inlineDatum": json.loads((directory / "root-data" / "root.datum.json").read_text())}}
            snapshot_path = directory / "snapshot.json"
            snapshot_path.write_text(json.dumps(utxos))
            state_path = directory / "state.json"
            state_path.write_text(run_script("registry_state.py", str(snapshot_path), address, policy))
            result = json.loads(run_script("registry_list.py", str(commitment), "--state", str(state_path)))
            self.assertEqual(result["action"]["sourceOutRef"], source_ref)
            self.assertEqual(result["successorNodes"][0]["entries"][0]["subject"], subject)

    def test_lazy_commitment_then_thirty_plus_separate_upload_files(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            entry = {"subject": "ab" * 28, "name": {"value": "Large token", "sequenceNumber": 0},
                     "description": {"value": "Metadata", "sequenceNumber": 0},
                     "extension": {"value": "x" * 350000, "sequenceNumber": 0}}
            entry_path = directory / "entry.json"
            entry_path.write_text(json.dumps(entry))
            full_plan = json.loads(run_script("registry_content.py", str(entry_path)))
            commitment_path = directory / "commitment.json"
            commitment_path.write_text(run_script("registry_content.py", "--subject", entry["subject"],
                                                  "--content-hash", full_plan["contentHash"]))
            self.assertEqual(json.loads(commitment_path.read_text())["segmentHashes"], [])
            upload_path = directory / "uploads.json"
            upload_path.write_text(run_script("registry_content.py", str(entry_path),
                                              "--expect-commitment", str(commitment_path)))
            list_path = directory / "list.json"
            list_path.write_text(run_script("registry_list.py", str(commitment_path)))
            run_script("registry_data.py", "root", str(directory / "root-data"))
            run_script("registry_data.py", "operation", str(list_path), str(commitment_path),
                       str(directory / "insert-data"))
            run_script("registry_data.py", "uploads", str(upload_path), str(directory / "upload-data"))
            count = len(json.loads(upload_path.read_text())["preimages"])
            self.assertGreaterEqual(count, 30)
            self.assertEqual(len(list((directory / "upload-data").glob("preimage-*.datum.json"))), count)
            self.assertTrue((directory / "upload-data" / "manifest.datum.json").exists())
            self.assertTrue((directory / "insert-data" / "spend.redeemer.json").exists())


if __name__ == "__main__":
    unittest.main()
