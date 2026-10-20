import random
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from registry_content import digest
from registry_list import apply, node_token, root, validate_nodes


def reference(number: int, value: bytes = b"x") -> dict:
    return {
        "subject": number.to_bytes(28, "big").hex(),
        "contentHash": digest(value).hex(),
        "contentBytes": len(value),
        "segmentHashes": [digest(b"\x01" + value).hex()],
    }


class PackedListTests(unittest.TestCase):
    def test_root_token_golden(self):
        self.assertEqual(node_token(""), "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8")

    def test_many_insertions_split_and_preserve_order(self):
        nodes = [root()]
        values = list(range(1, 101))
        random.Random(26).shuffle(values)
        split_count = 0
        for number in values:
            nodes, action = apply(nodes, reference(number))
            split_count += action["kind"] == "split"
            validate_nodes(nodes)
            self.assertEqual(len(action["oldNodeToken"]), 64)
            if action["kind"] == "split":
                self.assertEqual(action["rightNodeToken"], node_token(action["rightLowerBound"]))
        self.assertGreater(split_count, 0)
        self.assertEqual([int(ref["subject"], 16) for node in nodes for ref in node["entries"]], list(range(1, 101)))
        self.assertTrue(all(len(node["entries"]) <= 8 for node in nodes))

    def test_update_and_duplicate_rejection(self):
        nodes, _ = apply([root()], reference(7))
        with self.assertRaises(ValueError):
            apply(nodes, reference(7))
        updated, action = apply(nodes, reference(7, b"replacement"), update=True)
        self.assertEqual(action["kind"], "update")
        self.assertNotEqual(updated[0]["entries"][0]["contentHash"], nodes[0]["entries"][0]["contentHash"])
        with self.assertRaises(ValueError):
            apply(nodes, reference(8), update=True)

    def test_broken_link_is_rejected(self):
        nodes = [root()]
        nodes[0]["nextBound"] = "00"
        with self.assertRaises(ValueError):
            validate_nodes(nodes)


if __name__ == "__main__":
    unittest.main()
