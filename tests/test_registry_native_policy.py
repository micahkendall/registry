import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from registry_attestation import attestation_message, verify_document
from registry_content import canonical_content, plan, verify_plan
from registry_native_policy import evaluate_policy, key_hash, parse_policy, policy_id

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except ImportError:
    Ed25519PrivateKey = None


class NativePolicyTests(unittest.TestCase):
    def test_published_native_policy_id(self):
        policy = "82008200581ce62601e8eeec975f3f124a288cd0ecb2973f5fc225629f1401a79b16"
        self.assertEqual(policy_id(policy),
                         "b377d03a568dde663534e040fc32a57323ec00970df0e863eba3f098")
        version, script, raw = parse_policy(policy)
        self.assertEqual(version, 0)
        self.assertEqual(script[0], 0)
        self.assertEqual(raw.hex(), policy[4:])
        self.assertTrue(evaluate_policy(script, {script[1]}))
        self.assertFalse(evaluate_policy(script, set()))
        self.assertEqual(key_hash("bc77b3196b9da1620f70d2f5095ba42fe6a4e3c03494062d2034cdab2a690d04"),
                         script[1])

    def test_invalid_native_policy_encoding_is_rejected(self):
        for bad in ("", "80", "82028200581c" + "00" * 28,
                    "82008200581c" + "00" * 28 + "00",
                    "82008200581b" + "00" * 27):
            with self.assertRaises(ValueError):
                parse_policy(bad)

    @unittest.skipUnless(Ed25519PrivateKey is not None, "cryptography package is not installed")
    def test_native_threshold_requires_verified_property_signers(self):
        secrets = [Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()]
        keys = [secret.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw).hex()
                for secret in secrets]
        leaves = [b"\x82\x00\x58\x1c" + key_hash(key) for key in keys]
        # Timelock is satisfiable for CIP-26 ownership; both signatures remain required.
        inner = b"\x83\x03\x03\x83" + leaves[0] + leaves[1] + b"\x82\x04\x18\x64"
        policy = (b"\x82\x01" + inner).hex()
        subject = policy_id(policy) + "746f6b656e"
        document = {"subject": subject, "policy": policy,
                    "name": {"value": "Policy token", "sequenceNumber": 0},
                    "description": {"value": "Two signers", "sequenceNumber": 0}}
        for name in ("name", "description"):
            entry = document[name]
            message = attestation_message(subject, name, entry["value"], 0)
            entry["signatures"] = [{"publicKey": key, "signature": secret.sign(message).hex()}
                                   for secret, key in zip(secrets, keys)]
        self.assertEqual(verify_document(document, set()), {"name": True, "description": True})
        document["description"]["signatures"].pop()
        self.assertEqual(verify_document(document, set()), {"name": True, "description": False})
        document["description"]["signatures"] = document["name"]["signatures"]
        self.assertEqual(verify_document(document, set()), {"name": True, "description": False})
        document["subject"] = "00" * 28
        with self.assertRaisesRegex(ValueError, "does not hash"):
            verify_document(document, set())

    @unittest.skipUnless(Ed25519PrivateKey is not None, "cryptography package is not installed")
    def test_published_policy_and_signature_together(self):
        subject = "b377d03a568dde663534e040fc32a57323ec00970df0e863eba3f098717569640a"
        key = "bc77b3196b9da1620f70d2f5095ba42fe6a4e3c03494062d2034cdab2a690d04"
        document = {"subject": subject,
                    "policy": "82008200581ce62601e8eeec975f3f124a288cd0ecb2973f5fc225629f1401a79b16",
                    "name": {"value": "Quid", "sequenceNumber": 0, "signatures": [{
                        "publicKey": key,
                        "signature": "02f259151779aa00307c411a4816d7f8343ae842b74593608ebd2e2597bce33d31c7cf72a26f8771a2635d13b178c1bdd5e4f60884b06898760af40f09aa5402"}]},
                    "description": {"value": "Unsigned", "sequenceNumber": 0, "signatures": []}}
        self.assertEqual(verify_document(document, set()), {"name": True, "description": False})

    @unittest.skipUnless(Ed25519PrivateKey is not None, "cryptography package is not installed")
    def test_published_native_token_entry_roundtrips_with_both_signatures(self):
        # From https://input-output-hk.github.io/offchain-metadata-tools/ tutorial.
        subject = "b377d03a568dde663534e040fc32a57323ec00970df0e863eba3f098717569640a"
        key = "bc77b3196b9da1620f70d2f5095ba42fe6a4e3c03494062d2034cdab2a690d04"
        document = {"subject": subject,
                    "policy": "82008200581ce62601e8eeec975f3f124a288cd0ecb2973f5fc225629f1401a79b16",
                    "name": {"value": "Quid", "sequenceNumber": 0, "signatures": [{
                        "publicKey": key,
                        "signature": "02f259151779aa00307c411a4816d7f8343ae842b74593608ebd2e2597bce33d31c7cf72a26f8771a2635d13b178c1bdd5e4f60884b06898760af40f09aa5402"}]},
                    "description": {"value": "The un-offical currency of Great Britain 2.",
                                    "sequenceNumber": 1, "signatures": [{
                                        "publicKey": key,
                                        "signature": "48d45b0f6317a49d4da9c331d4757352795ebb36ea21cf7341595801c0f8fbf7f02bc50eea29372cc591cbe8285b3ea28481b8c71ca9e755ad6890e670387c0e"}]}}
        upload = plan(document)
        self.assertEqual(verify_plan(upload), canonical_content(document))
        self.assertEqual(verify_document(document, set()), {"name": True, "description": True})
        document["description"]["value"] += " changed"
        self.assertEqual(verify_document(document, set()), {"name": True, "description": False})


if __name__ == "__main__":
    unittest.main()
