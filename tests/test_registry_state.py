import base64
import copy
import hashlib
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from registry_content import MAX_CONTENT_BYTES, canonical_content, plan
from registry_attestation import attestation_message
from registry_data import list_datum, manifest_datum, preimage_datum
from registry_list import apply, hash_only_ref, node_token, root
from registry_state import read_state

try:
    import cryptography
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except ImportError:
    cryptography = None


ADDRESS = "addr_test1registryfixture"
POLICY = "ef" * 28


def utxo(datum, token=None):
    value = {"lovelace": 3_000_000}
    if token is not None:
        value[POLICY] = {token: 1}
    return {"address": ADDRESS, "value": value, "inlineDatum": datum}


def snapshot(nodes, uploads=(), manifests=()):
    result = {}
    for index, node in enumerate(nodes):
        result[f"{'ab' * 32}#{index}"] = utxo(list_datum(node), node_token(node["lowerBound"]))
    for index, part in enumerate(uploads):
        result[f"{'cd' * 32}#{index}"] = utxo(preimage_datum(
            part["subject"], part["index"], part["hash"], base64.b64decode(part["bytesBase64"])))
    for index, upload in enumerate(manifests):
        result[f"{'ef' * 32}#{index}"] = utxo(manifest_datum(upload))
    return result


def entry(number, extension=""):
    return {"subject": number.to_bytes(28, "big").hex(),
            "name": {"value": "Name", "sequenceNumber": 0},
            "description": {"value": "Description", "sequenceNumber": 0},
            "extra": {"value": extension, "sequenceNumber": 0}}


def reference(upload):
    return {key: upload[key] for key in ("subject", "contentHash", "contentBytes", "segmentHashes")}


class RegistryStateTests(unittest.TestCase):
    def test_hash_only_commitment_resolves_via_later_manifest_and_segments(self):
        upload = plan(entry(2, "x" * 350_000))
        commitment = hash_only_ref(upload["subject"], upload["contentHash"])
        nodes, _ = apply([root()], commitment)
        self.assertEqual(read_state(snapshot(nodes), ADDRESS, POLICY)["entries"][0]["contentBytes"], 0)
        manifest_only = read_state(snapshot(nodes, manifests=[upload]), ADDRESS, POLICY)
        self.assertFalse(manifest_only["entries"][0]["complete"])
        self.assertEqual(manifest_only["entries"][0]["manifestOutRef"], "ef" * 32 + "#0")
        complete = read_state(snapshot(nodes, upload["preimages"], [upload]),
                              ADDRESS, POLICY, include_metadata=True)["entries"][0]
        self.assertTrue(complete["complete"])
        self.assertEqual(len(complete["availableSegments"]), len(upload["preimages"]))
        self.assertEqual(complete["metadata"], entry(2, "x" * 350_000))

    def test_bad_manifest_cannot_override_complete_hash_only_content(self):
        upload = plan(entry(1, "x" * 25_000))
        commitment = hash_only_ref(upload["subject"], upload["contentHash"])
        nodes, _ = apply([root()], commitment)
        bad_manifest = {**upload, "segmentHashes": ["00" * 32] + upload["segmentHashes"][1:]}
        state = read_state(snapshot(nodes, upload["preimages"], [bad_manifest, upload]),
                           ADDRESS, POLICY)
        self.assertTrue(state["entries"][0]["complete"])
        self.assertEqual(state["entries"][0]["manifestOutRef"], "ef" * 32 + "#1")

    def test_thirty_separate_preimage_utxos_complete_large_entry(self):
        upload = plan(entry(2, "x" * 350_000))
        self.assertGreaterEqual(len(upload["preimages"]), 30)
        nodes, _ = apply([root()], reference(upload))
        all_outputs = snapshot(nodes, upload["preimages"])
        state = read_state(all_outputs, ADDRESS, POLICY, include_metadata=True)
        self.assertTrue(state["entries"][0]["complete"])
        self.assertEqual(len(state["entries"][0]["preimageOutRefs"]), len(upload["preimages"]))
        self.assertEqual(state["entries"][0]["metadata"], entry(2, "x" * 350_000))

    def test_reference_registry_maximum_reconstructs_from_32_utxos(self):
        overhead = len(canonical_content(entry(2)))
        document = entry(2, "x" * (MAX_CONTENT_BYTES - overhead))
        upload = plan(document)
        self.assertEqual(upload["contentBytes"], 380_000)
        self.assertEqual(len(upload["preimages"]), 32)
        nodes, _ = apply([root()], reference(upload))
        result = read_state(snapshot(nodes, upload["preimages"]), ADDRESS, POLICY,
                            include_metadata=True)["entries"][0]
        self.assertTrue(result["complete"])
        self.assertEqual(len(result["preimageOutRefs"]), 32)
        self.assertEqual(result["metadata"], document)

    def test_lazy_entry_and_independent_segment_uploads(self):
        upload = plan(entry(1, "x" * 26_000))
        nodes, _ = apply([root()], reference(upload))
        lazy = read_state(snapshot(nodes), ADDRESS, POLICY)
        self.assertEqual(lazy["entries"][0]["availableSegments"], [])
        self.assertFalse(lazy["entries"][0]["complete"])

        first = read_state(snapshot(nodes, upload["preimages"][:1]), ADDRESS, POLICY)
        self.assertEqual(first["entries"][0]["availableSegments"], [0])
        self.assertFalse(first["entries"][0]["complete"])

        complete = read_state(snapshot(nodes, upload["preimages"]), ADDRESS, POLICY, include_metadata=True)
        self.assertEqual(complete["entries"][0]["availableSegments"], list(range(len(upload["preimages"]))))
        self.assertTrue(complete["entries"][0]["complete"])
        self.assertEqual(complete["entries"][0]["metadata"], entry(1, "x" * 26_000))

    def test_linked_nodes_and_nfts_are_authoritative(self):
        nodes = [root()]
        for number in range(1, 13):
            nodes, _ = apply(nodes, reference(plan(entry(number))))
        state = read_state(snapshot(nodes), ADDRESS, POLICY)
        self.assertGreaterEqual(len(state["nodes"]), 2)
        self.assertEqual(len(state["entries"]), 12)

        wrong_nft = snapshot(nodes)
        wrong_nft[next(iter(wrong_nft))]["value"][POLICY] = {"00" * 32: 1}
        with self.assertRaisesRegex(ValueError, "NFT disagrees"):
            read_state(wrong_nft, ADDRESS, POLICY)

        broken = snapshot(nodes)
        broken.pop(next(iter(list(broken)[1:])))
        with self.assertRaisesRegex(ValueError, "missing successor"):
            read_state(broken, ADDRESS, POLICY)

    def test_invalid_permissionless_preimage_cannot_complete_entry(self):
        upload = plan(entry(1, "x" * 12_500))
        nodes, _ = apply([root()], reference(upload))
        fixture = snapshot(nodes, upload["preimages"])
        last = list(fixture)[-1]
        bad = copy.deepcopy(fixture)
        bad[last]["inlineDatum"]["fields"][0]["list"][3]["bytes"] = "00"
        state = read_state(bad, ADDRESS, POLICY)
        self.assertFalse(state["entries"][0]["complete"])
        self.assertIn(last, state["ignoredOutRefs"])

    @unittest.skipUnless(cryptography is not None, "cryptography package is not installed")
    def test_optional_cip26_preimage_claim_is_reported_separately(self):
        message = b"native-token-preimage"
        document = entry(1)
        document["subject"] = hashlib.blake2b(message, digest_size=28).hexdigest()
        document["preimage"] = {"alg": "blake2b", "msg": message.hex()}
        upload = plan(document)
        nodes, _ = apply([root()], reference(upload))
        result = read_state(snapshot(nodes, upload["preimages"]), ADDRESS, POLICY, trusted_keys=set())
        self.assertTrue(result["entries"][0]["complete"])
        self.assertTrue(result["entries"][0]["preimageClaimValid"])
        self.assertFalse(result["entries"][0]["attestations"]["name"])

    @unittest.skipUnless(cryptography is not None, "cryptography package is not installed")
    def test_state_applies_trusted_keys_to_their_own_subject(self):
        secret = Ed25519PrivateKey.generate()
        key = secret.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw).hex()
        documents = [entry(1), entry(2)]
        for document in documents:
            subject = document["subject"]
            document["name"]["signatures"] = [{"publicKey": key, "signature": secret.sign(
                attestation_message(subject, "name", "Name", 0)).hex()}]
        uploads = [plan(document) for document in documents]
        nodes = [root()]
        for upload in uploads:
            nodes, _ = apply(nodes, reference(upload))
        result = read_state(snapshot(nodes, [part for upload in uploads for part in upload["preimages"]]),
                            ADDRESS, POLICY, trusted_keys={documents[0]["subject"]: {key}})
        by_subject = {item["subject"]: item for item in result["entries"]}
        self.assertTrue(by_subject[documents[0]["subject"]]["attestations"]["name"])
        self.assertFalse(by_subject[documents[1]["subject"]]["attestations"]["name"])


if __name__ == "__main__":
    unittest.main()
