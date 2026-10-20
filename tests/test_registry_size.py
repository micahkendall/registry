"""Bound the on-chain data carried by worst-case upload and split transactions.

These checks measure Plutus Data CBOR, not a complete Cardano transaction.
Live protocol parameters, outputs, witnesses, and fees still need validation.
"""

import sys
import unittest
from pathlib import Path

import cbor2

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from registry_content import MAX_CONTENT_BYTES
from registry_data import b, listed, manifest_datum, multisig_rule, operation_files, preimage_datum
from registry_list import apply, root


def plutus_data(value):
    if set(value) == {"bytes"}:
        return bytes.fromhex(value["bytes"])
    if set(value) == {"int"}:
        return value["int"]
    if set(value) == {"list"}:
        return [plutus_data(item) for item in value["list"]]
    if set(value) == {"constructor", "fields"}:
        tag = value["constructor"]
        if not 0 <= tag <= 6:
            raise ValueError("test encoder only covers current registry constructors")
        return cbor2.CBORTag(121 + tag, [plutus_data(item) for item in value["fields"]])
    raise ValueError("unexpected Plutus Data JSON")


def byte_size(value):
    return len(cbor2.dumps(plutus_data(value)))


def maximum_reference(number):
    return {"subject": "ab" * 28 + "00" * 31 + format(number, "02x"),
            "contentHash": "cd" * 32, "contentBytes": MAX_CONTENT_BYTES,
            "segmentHashes": [format(index, "064x") for index in range(32)]}


class SerializedDatumSizeTests(unittest.TestCase):
    def test_twelve_kilobyte_segment_datum_leaves_transaction_headroom(self):
        ref = maximum_reference(1)
        datum = preimage_datum(ref["subject"], 0, ref["segmentHashes"][0], b"x" * 12_000)
        self.assertLess(byte_size(datum), 13_000)

    def test_maximum_packed_split_data_stays_below_fourteen_kilobytes(self):
        old = root()
        old["entries"] = [maximum_reference(n) for n in (1, 2, 3, 4, 6, 7, 8, 9)]
        inserted = maximum_reference(5)
        successors, action = apply([old], inserted)
        files = operation_files({"action": action, "successorNodes": successors}, inserted)
        governance = listed([b("ef" * 28), b("474f56"), multisig_rule({"signature": "11" * 28})])
        carried = sum(byte_size(files[name]) for name in (
            "left-node.datum.json", "right-node.datum.json",
            "spend.redeemer.json", "mint.redeemer.json")) + byte_size(governance)
        self.assertLess(carried, 14_000)
        self.assertLess(byte_size(manifest_datum(inserted)), 1_300)


if __name__ == "__main__":
    unittest.main()
