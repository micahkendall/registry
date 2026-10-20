import base64
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from registry_content import MAX_CONTENT_BYTES, canonical_content, hash_only_commitment, load_json, matches_commitment, plan, verify_plan


def entry(extra: str = "") -> dict:
    property_value = lambda value: {"value": value, "sequenceNumber": 0, "signatures": []}
    return {
        "subject": "ab" * 28 + "00ff",
        "name": property_value("Example"),
        "description": property_value("A native token"),
        "ticker": property_value("EXM"),
        "decimals": property_value(6),
        "extension": property_value({"nested": [True, None, extra]}),
    }


class RegistryContentTests(unittest.TestCase):
    def test_lazy_commitment_and_later_permissionless_upload(self):
        upload = plan(entry())
        commitment = {k: v for k, v in upload.items() if k != "preimages"}
        self.assertEqual(commitment["contentHash"], upload["contentHash"])
        self.assertTrue(matches_commitment(upload, commitment))
        self.assertTrue(matches_commitment(upload, hash_only_commitment(upload["subject"], upload["contentHash"])))
        self.assertFalse(matches_commitment(plan(entry("different")), commitment))
        self.assertFalse(matches_commitment(plan(entry("different")),
                                            hash_only_commitment(upload["subject"], upload["contentHash"])))
        self.assertEqual(verify_plan(upload), canonical_content(entry()))
        self.assertIsNone(verify_plan({**commitment, "preimages": []}, require_complete=False))

    def test_large_entry_needs_many_independent_preimages(self):
        upload = plan(entry("x" * 350_000))
        self.assertGreaterEqual(len(upload["segmentHashes"]), 30)
        for part in upload["preimages"]:
            self.assertIsNone(verify_plan({**upload, "preimages": [part]}, require_complete=False))
        self.assertEqual(verify_plan({**upload, "preimages": list(reversed(upload["preimages"]))}), canonical_content(entry("x" * 350_000)))
        self.assertEqual(len(verify_plan(upload)), upload["contentBytes"])

    def test_reference_registry_file_limit_is_exact(self):
        overhead = len(canonical_content(entry("")))
        document = entry("x" * (MAX_CONTENT_BYTES - overhead))
        upload = plan(document)
        self.assertEqual(upload["contentBytes"], 380_000)
        self.assertEqual(len(upload["segmentHashes"]), 32)
        self.assertEqual(verify_plan(upload), canonical_content(document))
        with self.assertRaisesRegex(ValueError, "380,000-byte"):
            plan(entry("x" * (MAX_CONTENT_BYTES - overhead + 1)))

    def test_tampering_and_missing_preimages_fail(self):
        upload = plan(entry("x" * 30_000))
        tampered = [dict(part) for part in upload["preimages"]]
        tampered[0]["hash"] = "00" * 32
        with self.assertRaises(ValueError):
            verify_plan({**upload, "preimages": tampered})
        with self.assertRaises(ValueError):
            verify_plan({**upload, "preimages": upload["preimages"][:-1]})
        with self.assertRaises(ValueError):
            verify_plan({**upload, "preimages": upload["preimages"] + upload["preimages"][:1]})
        with self.assertRaises(ValueError):
            verify_plan({**upload, "segmentHashes": []}, require_complete=False)
        wrong_subject = [dict(part) for part in upload["preimages"]]
        wrong_subject[0]["subject"] = "00" * 28
        with self.assertRaises(ValueError):
            verify_plan({**upload, "preimages": wrong_subject})
        with self.assertRaises(ValueError):
            load_json('{"subject":"one","subject":"two"}')

    def test_cip_property_structure_and_bounds(self):
        value = entry()
        value["subject"] += "0"
        with self.assertRaises(ValueError):
            plan(value)
        value = entry()
        value["decimals"]["value"] = 20
        with self.assertRaises(ValueError):
            plan(value)
        value = entry()
        value["name"]["signatures"] = [{"publicKey": "00" * 32, "signature": "11" * 64}]
        self.assertEqual(json.loads(verify_plan(plan(value)))["name"]["signatures"], value["name"]["signatures"])
        value["name"].pop("signatures")
        value["url"] = {"value": "ipfs://example", "sequenceNumber": 1}
        self.assertEqual(json.loads(verify_plan(plan(value)))["url"]["value"], "ipfs://example")
        for malformed in ("https://example.com/a b", "https://example.com/%Q0", "http://[broken"):
            value["url"]["value"] = malformed
            with self.assertRaisesRegex(ValueError, "URI"):
                plan(value)
        value["url"]["value"] = "ipfs://example"
        value["preimage"] = {"alg": "blake2b", "msg": "00ff"}
        self.assertEqual(json.loads(verify_plan(plan(value)))["preimage"], value["preimage"])
        value["preimage"]["alg"] = []
        with self.assertRaisesRegex(ValueError, "unsupported preimage algorithm"):
            plan(value)
        value = entry()
        value["logo"] = {"value": "%%%", "sequenceNumber": 0}
        with self.assertRaisesRegex(ValueError, "logo must be base64"):
            plan(value)
        upload = plan(entry())
        upload["preimages"][0]["bytesBase64"] = "%%%"
        with self.assertRaisesRegex(ValueError, "preimage bytes must be base64"):
            verify_plan(upload)

    def test_optional_well_known_properties_and_extension_only_entry(self):
        subject = "ab" * 28 + "00ff"
        extension_only = {"subject": subject,
                          "issuerContact": {"value": {"email": "issuer@example.test"},
                                            "sequenceNumber": 0}}
        upload = plan(extension_only)
        self.assertEqual(json.loads(verify_plan(upload)), extension_only)
        name_only = {"subject": subject,
                     "name": {"value": "Example", "sequenceNumber": 0}}
        self.assertEqual(json.loads(verify_plan(plan(name_only))), name_only)

    def test_logo_requires_decodable_png(self):
        png = base64.b64decode(
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGP4z8DwHwAFAAH/iZk9HQAAAABJRU5ErkJggg==")
        document = entry()
        document["logo"] = {"value": base64.b64encode(png).decode(), "sequenceNumber": 0}
        self.assertEqual(json.loads(verify_plan(plan(document)))["logo"], document["logo"])
        for malformed in (b"\x89PNG\r\n\x1a\nexample", png[:-12]):
            document["logo"]["value"] = base64.b64encode(malformed).decode()
            with self.assertRaisesRegex(ValueError, "valid PNG"):
                plan(document)


if __name__ == "__main__":
    unittest.main()
