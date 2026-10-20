#!/usr/bin/env python3
"""Read and verify registry state from cardano-cli query utxo JSON.

Query the complete registry address. Node NFTs identify the authoritative
linked list; arbitrary outputs sent to the same address cannot become nodes.
Preimage outputs are permissionless and are accepted only by matching the
current content commitment and the full reconstructed content hash.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from registry_content import CHUNK_BYTES, canonical_content, digest, load_json, segment_hash
from registry_attestation import parse_trusted_keys, verify_document
from registry_preimage_claim import verify_preimage_claim
from registry_list import FIRST_BOUND, LAST_BOUND, MAX_ENTRIES, node_token, validate_ref


def _fields(value: object, count: int) -> list:
    if not isinstance(value, dict) or set(value) != {"list"} or not isinstance(value["list"], list) or len(value["list"]) != count:
        raise ValueError(f"expected Plutus list of {count} fields")
    return value["list"]


def _bytes(value: object) -> str:
    if not isinstance(value, dict) or set(value) != {"bytes"} or not isinstance(value["bytes"], str):
        raise ValueError("expected Plutus bytes")
    encoded = value["bytes"]
    if len(encoded) % 2 or encoded.lower() != encoded:
        raise ValueError("Plutus bytes must be lowercase, even-length base16")
    bytes.fromhex(encoded)
    return encoded


def _int(value: object) -> int:
    if not isinstance(value, dict) or set(value) != {"int"} or type(value["int"]) is not int:
        raise ValueError("expected Plutus integer")
    return value["int"]


def _list(value: object) -> list:
    if not isinstance(value, dict) or set(value) != {"list"} or not isinstance(value["list"], list):
        raise ValueError("expected Plutus list")
    return value["list"]


def _variant(value: object) -> tuple[int, object]:
    if not isinstance(value, dict) or set(value) != {"constructor", "fields"} or type(value["constructor"]) is not int:
        raise ValueError("expected Plutus constructor")
    fields = value["fields"]
    if not isinstance(fields, list) or len(fields) != 1:
        raise ValueError("registry constructor must have one field")
    return value["constructor"], fields[0]


def decode_datum(value: object) -> tuple[str, dict]:
    tag, payload = _variant(value)
    if tag == 0:
        lower, upper, entries = _fields(payload, 3)
        refs = []
        for item in _list(entries):
            subject, content_hash, size, hashes = _fields(item, 4)
            ref = {"subject": _bytes(subject), "contentHash": _bytes(content_hash),
                   "contentBytes": _int(size), "segmentHashes": [_bytes(h) for h in _list(hashes)]}
            validate_ref(ref)
            refs.append(ref)
        return "node", {"lowerBound": _bytes(lower), "nextBound": _bytes(upper), "entries": refs}
    if tag == 1:
        subject, index, content_hash, body = _fields(payload, 4)
        return "preimage", {"subject": _bytes(subject), "index": _int(index),
                            "hash": _bytes(content_hash), "bytes": bytes.fromhex(_bytes(body))}
    if tag == 2:
        subject, content_hash, size, hashes = _fields(payload, 4)
        ref = {"subject": _bytes(subject), "contentHash": _bytes(content_hash),
               "contentBytes": _int(size), "segmentHashes": [_bytes(h) for h in _list(hashes)]}
        validate_ref(ref)
        if ref["contentBytes"] == 0:
            raise ValueError("manifest has no segment layout")
        return "manifest", ref
    raise ValueError("unrecognized registry datum constructor")


def _node_nfts(output: dict, policy: str) -> dict:
    value = output.get("value", {})
    if not isinstance(value, dict):
        raise ValueError("invalid UTxO value")
    tokens = value.get(policy, {})
    if not isinstance(tokens, dict) or any(type(q) is not int for q in tokens.values()):
        raise ValueError("invalid node policy value")
    return {name: quantity for name, quantity in tokens.items() if quantity != 0}


def read_state(snapshot: dict, registry_address: str, node_policy_id: str, *,
               include_metadata: bool = False,
               trusted_keys: set[str] | dict[str, set[str]] | None = None) -> dict:
    if not isinstance(snapshot, dict) or not isinstance(registry_address, str) or not registry_address:
        raise ValueError("invalid UTxO snapshot or registry address")
    if not isinstance(node_policy_id, str) or len(node_policy_id) != 56 or node_policy_id.lower() != node_policy_id:
        raise ValueError("node policy ID must be 28 bytes")
    bytes.fromhex(node_policy_id)
    nodes: dict[str, dict] = {}
    preimages: list[dict] = []
    manifests: list[dict] = []
    ignored: list[str] = []
    for outref, output in snapshot.items():
        if not isinstance(output, dict) or output.get("address") != registry_address:
            continue
        try:
            txid, index = outref.split("#", 1)
            if len(txid) != 64 or int(index) < 0 or str(int(index)) != index:
                raise ValueError("invalid outref")
            bytes.fromhex(txid)
        except (AttributeError, ValueError) as exc:
            raise ValueError(f"invalid UTxO reference: {outref}") from exc
        nft_map = _node_nfts(output, node_policy_id)
        inline = output.get("inlineDatum")
        if inline is None:
            if nft_map:
                raise ValueError(f"node NFT without inline datum: {outref}")
            ignored.append(outref)
            continue
        try:
            kind, datum = decode_datum(inline)
        except ValueError as exc:
            if nft_map:
                raise ValueError(f"invalid NFT node at {outref}: {exc}") from exc
            ignored.append(outref)
            continue
        if kind == "node":
            lower = datum["lowerBound"]
            token = node_token(lower)
            if nft_map != {token: 1}:
                if nft_map:
                    raise ValueError(f"node NFT disagrees with datum at {outref}")
                ignored.append(outref)
                continue
            if lower in nodes:
                raise ValueError(f"duplicate node lower bound {lower}")
            nodes[lower] = {**datum, "outRef": outref, "nodeToken": token}
        elif kind == "preimage":
            if nft_map:
                raise ValueError(f"node NFT appears in preimage at {outref}")
            datum["outRef"] = outref
            preimages.append(datum)
        else:
            if nft_map:
                raise ValueError(f"node NFT appears in manifest at {outref}")
            datum["outRef"] = outref
            manifests.append(datum)
    if FIRST_BOUND not in nodes:
        raise ValueError("root node NFT is absent")
    ordered = []
    cursor = FIRST_BOUND
    while cursor != LAST_BOUND:
        if cursor not in nodes:
            raise ValueError(f"missing successor node at {cursor}")
        node = nodes[cursor]
        upper = node["nextBound"]
        if not cursor < upper <= LAST_BOUND:
            raise ValueError(f"invalid node bounds at {node['outRef']}")
        subjects = [entry["subject"] for entry in node["entries"]]
        if len(subjects) > MAX_ENTRIES or subjects != sorted(set(subjects)):
            raise ValueError(f"unsorted or oversized node at {node['outRef']}")
        if any(not cursor <= subject < upper for subject in subjects):
            raise ValueError(f"entry outside node bounds at {node['outRef']}")
        if cursor != FIRST_BOUND and (not subjects or subjects[0] != cursor):
            raise ValueError(f"split boundary lacks its first subject at {node['outRef']}")
        ordered.append(node)
        cursor = upper
    if len(ordered) != len(nodes):
        raise ValueError("unlinked node NFT exists at registry address")
    if len(ordered) > 1 and not ordered[0]["entries"]:
        raise ValueError("split root node is empty")
    refs = {entry["subject"]: entry for node in ordered for entry in node["entries"]}
    if len(refs) != sum(len(node["entries"]) for node in ordered):
        raise ValueError("duplicate subject across nodes")
    manifests_by_subject: dict[tuple[str, str], list[dict]] = {}
    for item in manifests:
        ref = refs.get(item["subject"])
        if (ref is None or ref["contentBytes"] != 0
                or item["contentHash"] != ref["contentHash"]):
            ignored.append(item["outRef"])
        else:
            manifests_by_subject.setdefault((item["subject"], item["contentHash"]), []).append(item)

    preimages_by_subject: dict[str, list[dict]] = {}
    for item in preimages:
        payload = item["bytes"]
        if (0 < len(payload) <= CHUNK_BYTES
                and item["index"] >= 0
                and segment_hash(payload).hex() == item["hash"]):
            preimages_by_subject.setdefault(item["subject"], []).append(item)

    def segments_for(layout: dict) -> dict[int, dict]:
        available = {}
        for item in preimages_by_subject.get(layout["subject"], ()):
            index = item["index"]
            payload = item["bytes"]
            if (not index < len(layout["segmentHashes"])
                    or item["hash"] != layout["segmentHashes"][index]
                    or (index < len(layout["segmentHashes"]) - 1 and len(payload) != CHUNK_BYTES)):
                continue
            available.setdefault(index, item)
        return available

    used_preimages = set()
    entries = []
    for subject, ref in refs.items():
        layouts = ([ref] if ref["contentBytes"] else
                   manifests_by_subject.get((subject, ref["contentHash"]), ()))
        best = None
        for layout in layouts:
            segments = segments_for(layout)
            used_preimages.update(item["outRef"] for item in segments.values())
            verified = False
            document = None
            if len(segments) == len(layout["segmentHashes"]):
                content = b"".join(segments[index]["bytes"] for index in range(len(segments)))
                if len(content) == layout["contentBytes"] and digest(content).hex() == ref["contentHash"]:
                    try:
                        document = load_json(content)
                        verified = canonical_content(document) == content and document["subject"] == subject
                    except (ValueError, KeyError, TypeError):
                        verified = False
            candidate = (verified, len(segments), layout, segments, document)
            if best is None or candidate[:2] > best[:2]:
                best = candidate
        if best is None:
            best = (False, 0, ref, {}, None)
        verified, _, layout, segments, document = best
        result = {**ref, "availableSegments": sorted(segments), "complete": verified,
                  "preimageOutRefs": {str(i): item["outRef"] for i, item in sorted(segments.items())}}
        if ref["contentBytes"] == 0 and layout.get("outRef"):
            result["manifestOutRef"] = layout["outRef"]
        if verified and include_metadata:
            result["metadata"] = document
        if verified and trusted_keys is not None:
            result["attestations"] = verify_document(document, trusted_keys)
            if "preimage" in document:
                result["preimageClaimValid"] = verify_preimage_claim(subject, document["preimage"])
        entries.append(result)
    ignored.extend(item["outRef"] for item in preimages if item["outRef"] not in used_preimages)
    return {"nodes": ordered, "entries": entries, "ignoredOutRefs": sorted(ignored)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshot", type=Path, help="cardano-cli query utxo --output-json file for the registry address")
    parser.add_argument("registry_address")
    parser.add_argument("node_policy_id")
    parser.add_argument("--subject", help="restrict output to one base16 token subject")
    parser.add_argument("--include-metadata", action="store_true", help="include verified full CIP-26 JSON")
    parser.add_argument("--trusted-keys", type=Path,
                        help="JSON key array or native-token subject to key-array map for CIP-26 checks")
    args = parser.parse_args()
    try:
        trusted_keys = None
        if args.trusted_keys is not None:
            trusted_keys = parse_trusted_keys(load_json(args.trusted_keys.read_text()))
        state = read_state(load_json(args.snapshot.read_text()), args.registry_address, args.node_policy_id,
                           include_metadata=args.include_metadata, trusted_keys=trusted_keys)
        if args.subject:
            state["entries"] = [entry for entry in state["entries"] if entry["subject"] == args.subject]
        print(json.dumps(state, indent=2))
    except (ValueError, KeyError, TypeError, OSError, RuntimeError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
