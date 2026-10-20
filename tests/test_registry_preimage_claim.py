import hashlib
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from registry_preimage_claim import verify_preimage_claim

try:
    from Crypto.Hash import keccak
except ImportError:
    keccak = None


class PreimageClaimTests(unittest.TestCase):
    def test_supported_digest_families_and_subject_selected_size(self):
        message = b"CIP-26 preimage"
        for name, digest in (
            ("sha1", hashlib.sha1(message).digest()),
            ("sha", hashlib.sha224(message).digest()),
            ("sha3", hashlib.sha3_224(message).digest()),
            ("blake2b", hashlib.blake2b(message, digest_size=28).digest()),
            ("blake2s", hashlib.blake2s(message, digest_size=28).digest()),
            ("md5", hashlib.md5(message).digest()),
        ):
            claim = {"alg": name, "msg": message.hex()}
            self.assertTrue(verify_preimage_claim(digest.hex(), claim), name)
            self.assertFalse(verify_preimage_claim("00" * len(digest), claim), name)
        self.assertFalse(verify_preimage_claim("00" * 30, {"alg": "sha", "msg": message.hex()}))

    def test_malformed_claim_fails(self):
        for claim in ({"alg": "sha", "msg": "0"}, {"alg": "unknown", "msg": "00"},
                      {"alg": "sha", "msg": "zz"}):
            with self.assertRaises(ValueError):
                verify_preimage_claim("00" * 28, claim)

    @unittest.skipUnless(keccak is not None, "pycryptodome package is not installed")
    def test_keccak_is_distinct_from_sha3(self):
        target = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        self.assertTrue(verify_preimage_claim(target, {"alg": "keccak", "msg": ""}))
        self.assertFalse(verify_preimage_claim(target, {"alg": "sha3", "msg": ""}))


if __name__ == "__main__":
    unittest.main()
