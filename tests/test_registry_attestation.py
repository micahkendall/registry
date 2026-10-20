import base64
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from registry_attestation import attestation_message, cbor_json, parse_trusted_keys, verify_document, verify_property

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except ImportError:
    Ed25519PrivateKey = None


class AttestationTests(unittest.TestCase):
    def test_cip26_published_message_golden(self):
        self.assertEqual(
            attestation_message("a5408d0db0d942fd80374", "contact", "Cid Kramer", 0).hex(),
            "cd731afcc904c521e0c6b3cc0b560b8157ee29c3e41cd15f8dc8984edf600029")
        self.assertEqual(cbor_json({"z": True, "a": [None, 1]}),
                         bytes.fromhex("a2616182f601617af5"))

    def test_extension_floats_use_preferred_cbor_width(self):
        self.assertEqual(cbor_json(1.5), bytes.fromhex("f93e00"))
        self.assertEqual(cbor_json(1_000_000.5), bytes.fromhex("fa49742408"))
        self.assertEqual(cbor_json(1.5, float_width="float64"),
                         bytes.fromhex("fb3ff8000000000000"))
        self.assertEqual(cbor_json({"nested": [-0.0, 1.5]}),
                         bytes.fromhex("a1666e657374656482f98000f93e00"))

    @unittest.skipUnless(Ed25519PrivateKey is not None, "cryptography package is not installed")
    def test_extension_float_attestations_accept_preferred_and_float64(self):
        secret = Ed25519PrivateKey.generate()
        key = secret.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw).hex()
        subject = "ab" * 28
        value = {"ratio": 1.5, "samples": [1_000_000.5]}
        entry = {"value": value, "sequenceNumber": 7}
        for width in ("preferred", "float64"):
            message = attestation_message(subject, "measurements", value, 7, float_width=width)
            entry["signatures"] = [{"publicKey": key, "signature": secret.sign(message).hex()}]
            self.assertTrue(verify_property(subject, "measurements", entry, {key}))
        entry["value"] = {"ratio": 1.6, "samples": [1_000_000.5]}
        self.assertFalse(verify_property(subject, "measurements", entry, {key}))

    @unittest.skipUnless(Ed25519PrivateKey is not None, "cryptography package is not installed")
    def test_published_token_registry_signature(self):
        subject = "b377d03a568dde663534e040fc32a57323ec00970df0e863eba3f098717569640a"
        key = "bc77b3196b9da1620f70d2f5095ba42fe6a4e3c03494062d2034cdab2a690d04"
        entry = {"value": "Quid", "sequenceNumber": 0, "signatures": [{
            "publicKey": key,
            "signature": "02f259151779aa00307c411a4816d7f8343ae842b74593608ebd2e2597bce33d31c7cf72a26f8771a2635d13b178c1bdd5e4f60884b06898760af40f09aa5402"}]}
        self.assertTrue(verify_property(subject, "name", entry, {key}))
        self.assertFalse(verify_property(subject, "name", entry, set()))
        self.assertFalse(verify_property(subject, "ticker", entry, {key}))
        entry["signatures"][0]["publicKey"] = key.upper()
        entry["signatures"][0]["signature"] = entry["signatures"][0]["signature"].upper()
        self.assertTrue(verify_property(subject, "name", entry, {key}))

    @unittest.skipUnless(Ed25519PrivateKey is not None, "cryptography package is not installed")
    def test_each_property_needs_a_trusted_valid_signature(self):
        secret = Ed25519PrivateKey.generate()
        key = secret.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw).hex()
        subject = "ab" * 28
        document = {"subject": subject, "name": {"value": "Example", "sequenceNumber": 0},
                    "description": {"value": "A token", "sequenceNumber": 1}}
        for name in ("name", "description"):
            entry = document[name]
            signature = secret.sign(attestation_message(subject, name, entry["value"], entry["sequenceNumber"]))
            entry["signatures"] = [{"publicKey": key, "signature": signature.hex()}]
        self.assertEqual(verify_document(document, {key}), {"name": True, "description": True})
        document["description"]["value"] = "A changed token"
        self.assertEqual(verify_document(document, {key}), {"name": True, "description": False})
        document["description"]["value"] = "A token"
        self.assertEqual(verify_document(document, set()), {"name": False, "description": False})

    @unittest.skipUnless(Ed25519PrivateKey is not None, "cryptography package is not installed")
    def test_trusted_keys_can_be_scoped_to_one_subject(self):
        secret = Ed25519PrivateKey.generate()
        key = secret.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw).hex()
        first, second = "ab" * 28, "cd" * 28

        def signed_document(subject):
            value = "Example"
            return {"subject": subject, "name": {"value": value, "sequenceNumber": 0,
                    "signatures": [{"publicKey": key, "signature": secret.sign(
                        attestation_message(subject, "name", value, 0)).hex()}]}}

        scoped = parse_trusted_keys({first: [key]})
        self.assertEqual(verify_document(signed_document(first), scoped), {"name": True})
        self.assertEqual(verify_document(signed_document(second), scoped), {"name": False})
        self.assertEqual(verify_document(signed_document(second), parse_trusted_keys([key])),
                         {"name": True})
        with self.assertRaises(ValueError):
            parse_trusted_keys({first: [42]})
        with self.assertRaises(ValueError):
            parse_trusted_keys({"not-a-token": [key]})

    @unittest.skipUnless(Ed25519PrivateKey is not None, "cryptography package is not installed")
    def test_logo_supports_reference_implementation_byte_encoding(self):
        secret = Ed25519PrivateKey.generate()
        key = secret.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw).hex()
        subject = "ab" * 28
        logo = base64.b64encode(b"\x89PNG\r\n\x1a\nexample").decode()
        signature = secret.sign(attestation_message(subject, "logo", logo, 0, legacy_logo_bytes=True))
        self.assertTrue(verify_property(subject, "logo", {"value": logo, "sequenceNumber": 0,
                         "signatures": [{"publicKey": key, "signature": signature.hex()}]}, {key}))


if __name__ == "__main__":
    unittest.main()
