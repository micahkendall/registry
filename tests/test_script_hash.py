import hashlib
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from registry_script_hash import decode_bytestring, script_hash


class ScriptHashTests(unittest.TestCase):
    def test_v3_language_tag_and_cbor_wrapper(self):
        raw = b"example uplc"
        envelope = {"type": "PlutusScriptV3", "cborHex": (bytes([0x40 + len(raw)]) + raw).hex()}
        self.assertEqual(decode_bytestring(bytes.fromhex(envelope["cborHex"])), raw)
        self.assertEqual(script_hash(envelope), hashlib.blake2b(b"\x03" + bytes.fromhex(envelope["cborHex"]), digest_size=28).hexdigest())

    def test_rejects_trailing_bytes_and_wrong_language(self):
        with self.assertRaises(ValueError):
            decode_bytestring(b"\x41ab")
        with self.assertRaises(ValueError):
            script_hash({"type": "PlutusScriptV2", "cborHex": "4161"})


if __name__ == "__main__":
    unittest.main()
