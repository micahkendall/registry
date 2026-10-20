import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from registry_content import digest, plan
from registry_data import create_governance, create_operation, create_root, create_uploads, multisig_rule
from registry_list import apply, root


def ref(number: int) -> dict:
    content = bytes([number])
    return {"subject": number.to_bytes(28, "big").hex(), "contentHash": digest(content).hex(),
            "contentBytes": 1, "segmentHashes": [digest(b"\x01" + content).hex()]}


class DatumFileTests(unittest.TestCase):
    def test_governance_datum_and_nested_multisig_layout(self):
        manifest = {"governancePolicyId": "ab" * 28, "governanceTokenName": "474f56"}
        rule = {"atLeast": {"required": 2, "rules": [
            {"signature": "11" * 28}, {"signature": "22" * 28}, {"after": 1700000000000}]}}
        self.assertEqual(multisig_rule(rule), {"constructor": 3, "fields": [
            {"int": 2}, {"list": [{"constructor": 0, "fields": [{"bytes": "11" * 28}]},
                                  {"constructor": 0, "fields": [{"bytes": "22" * 28}]},
                                  {"constructor": 5, "fields": [{"int": 1700000000000}]}]}]})
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "governance"
            create_governance(manifest, rule, target)
            datum = json.loads((target / "governance.datum.json").read_text())
            self.assertEqual(datum["list"][0], {"bytes": "ab" * 28})
            self.assertEqual(datum["list"][1], {"bytes": "474f56"})
            self.assertEqual(datum["list"][2], multisig_rule(rule))

    def test_root_layout_matches_plutarch_record_and_variant_encoding(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "root"
            create_root(target)
            datum = json.loads((target / "root.datum.json").read_text())
            self.assertEqual(datum, {"constructor": 0, "fields": [{"list": [
                {"bytes": ""}, {"bytes": "ff" * 61}, {"list": []}]}]})
            self.assertEqual(json.loads((target / "bootstrap.redeemer.json").read_text()),
                             {"constructor": 0, "fields": []})

    def test_full_content_produces_individual_preimage_datums(self):
        entry = {"subject": "ab" * 28, "name": {"value": "N", "sequenceNumber": 0},
                 "description": {"value": "D", "sequenceNumber": 0},
                 "extension": {"value": "x" * 26000, "sequenceNumber": 0}}
        upload = plan(entry)
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "uploads"
            create_uploads(upload, target)
            self.assertGreaterEqual(len(upload["preimages"]), 3)
            self.assertEqual(len(list(target.glob("preimage-*.datum.json"))), len(upload["preimages"]))
            first = json.loads((target / "preimage-000.datum.json").read_text())
            self.assertEqual(first["constructor"], 1)
            self.assertEqual(first["fields"][0]["list"][0], {"bytes": entry["subject"]})
            self.assertEqual(first["fields"][0]["list"][1], {"int": 0})
            self.assertEqual(len(first["fields"][0]["list"][3]["bytes"]), 24000)

    def test_insert_and_split_redeemers_match_plutarch_variants(self):
        with tempfile.TemporaryDirectory() as temp:
            nodes, insert = apply([root()], ref(1))
            insert_result = {"action": insert, "successorNodes": nodes}
            insert_target = Path(temp) / "insert"
            create_operation(insert_result, ref(1), insert_target)
            spend = json.loads((insert_target / "spend.redeemer.json").read_text())
            self.assertEqual(spend["constructor"], 0)
            self.assertEqual(spend["fields"][0]["list"][2], {"int": 1})
            self.assertEqual(spend["fields"][1], {"int": 0})

            for number in range(2, 9):
                nodes, _ = apply(nodes, ref(number))
            split_nodes, split = apply(nodes, ref(9))
            split_target = Path(temp) / "split"
            create_operation({"action": split, "successorNodes": split_nodes}, ref(9), split_target)
            split_spend = json.loads((split_target / "spend.redeemer.json").read_text())
            split_mint = json.loads((split_target / "mint.redeemer.json").read_text())
            self.assertEqual(split_spend["constructor"], 2)
            self.assertEqual(split_mint["constructor"], 1)
            self.assertEqual(split_mint["fields"][2], {"bytes": ""})
            self.assertEqual(split_mint["fields"][3], {"bytes": split["rightLowerBound"]})

    def test_tampered_operation_is_rejected(self):
        nodes, action = apply([root()], ref(1))
        action["newNodes"][0]["entries"].clear()
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(ValueError):
                create_operation({"action": action, "successorNodes": nodes}, ref(1), Path(temp) / "bad")


if __name__ == "__main__":
    unittest.main()
