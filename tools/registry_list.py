#!/usr/bin/env python3
"""Pure packed-node planner; it does not query chain state or sign transactions."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from registry_content import MAX_CONTENT_BYTES, digest, load_json

MAX_ENTRIES = 8
FIRST_BOUND = ""
LAST_BOUND = "ff" * 61


def node_token(lower_bound: str) -> str:
    return digest(bytes.fromhex(lower_bound)).hex()


def root() -> dict:
    return {"lowerBound": FIRST_BOUND, "nextBound": LAST_BOUND, "entries": []}


def validate_ref(ref: dict) -> None:
    subject = ref["subject"]
    if not isinstance(subject, str) or len(subject) % 2 or not 56 <= len(subject) <= 120 or subject != subject.lower():
        raise ValueError("invalid native-token subject")
    bytes.fromhex(subject)
    if not isinstance(ref["contentHash"], str) or len(ref["contentHash"]) != 64:
        raise ValueError("invalid full content hash")
    bytes.fromhex(ref["contentHash"])
    size = ref["contentBytes"]
    hashes = ref["segmentHashes"]
    if not isinstance(size, int) or isinstance(size, bool) or not 0 <= size <= MAX_CONTENT_BYTES:
        raise ValueError("invalid content length")
    if not isinstance(hashes, list) or len(hashes) != (size + 11999) // 12000:
        raise ValueError("segment count does not match content length")
    if any(not isinstance(h, str) or len(h) != 64 for h in hashes):
        raise ValueError("invalid segment hash")
    for h in hashes:
        bytes.fromhex(h)


def hash_only_ref(subject: str, content_hash: str) -> dict:
    ref = {"subject": subject, "contentHash": content_hash,
           "contentBytes": 0, "segmentHashes": []}
    validate_ref(ref)
    return ref


def validate_nodes(nodes: list[dict]) -> None:
    if not nodes or nodes[0]["lowerBound"] != FIRST_BOUND or nodes[-1]["nextBound"] != LAST_BOUND:
        raise ValueError("list sentinels are missing")
    for i, node in enumerate(nodes):
        lower, upper, entries = node["lowerBound"], node["nextBound"], node["entries"]
        if not isinstance(lower, str) or not isinstance(upper, str) or lower >= upper:
            raise ValueError("invalid node interval")
        if i and nodes[i - 1]["nextBound"] != lower:
            raise ValueError("broken node link")
        if not isinstance(entries, list) or len(entries) > MAX_ENTRIES or ((i or len(nodes) > 1) and not entries):
            raise ValueError("invalid node occupancy")
        previous = None
        for ref in entries:
            validate_ref(ref)
            subject = ref["subject"]
            if not lower <= subject < upper or (previous is not None and previous >= subject):
                raise ValueError("unordered or out-of-range subject")
            previous = subject


def apply(nodes: list[dict], ref: dict, *, update: bool = False) -> tuple[list[dict], dict]:
    validate_nodes(nodes)
    validate_ref(ref)
    subject = ref["subject"]
    for position, original in enumerate(nodes):
        if original["lowerBound"] <= subject < original["nextBound"]:
            entries = list(original["entries"])
            index = next((j for j, value in enumerate(entries) if value["subject"] >= subject), len(entries))
            exists = index < len(entries) and entries[index]["subject"] == subject
            if update != exists:
                raise ValueError("update requires an existing subject; insert requires a new subject")
            entries[index:index + int(update)] = [ref]
            next_nodes = [dict(node) for node in nodes]
            old_token = node_token(original["lowerBound"])
            if len(entries) <= MAX_ENTRIES:
                next_nodes[position] = {**original, "entries": entries}
                action = {"kind": "update" if update else "insert", "index": index, "oldNodeToken": old_token,
                          "oldNode": original, "newNodes": [next_nodes[position]]}
            else:
                pivot = len(entries) // 2
                boundary = entries[pivot]["subject"]
                left = {"lowerBound": original["lowerBound"], "nextBound": boundary, "entries": entries[:pivot]}
                right = {"lowerBound": boundary, "nextBound": original["nextBound"], "entries": entries[pivot:]}
                next_nodes[position:position + 1] = [left, right]
                action = {"kind": "split", "index": index, "oldNodeToken": old_token,
                          "rightLowerBound": boundary, "rightNodeToken": node_token(boundary),
                          "oldNode": original, "newNodes": [left, right]}
            validate_nodes(next_nodes)
            return next_nodes, action
    raise ValueError("subject falls outside the list")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("commitment", type=Path, help="JSON commitment from registry_content.py --lazy")
    parser.add_argument("--state", type=Path, help="current list snapshot JSON; defaults to an empty root")
    parser.add_argument("--update", action="store_true", help="replace an existing subject")
    args = parser.parse_args()
    commitment = load_json(args.commitment.read_text())
    state = load_json(args.state.read_text()) if args.state else [root()]
    if isinstance(state, dict):
        nodes = state.get("nodes", state.get("successorNodes"))
        if nodes is None:
            raise ValueError("state needs nodes or successorNodes")
    else:
        nodes = state
    source_nodes = nodes
    nodes = [{key: node[key] for key in ("lowerBound", "nextBound", "entries")} for node in source_nodes]
    ref = {key: commitment[key] for key in ("subject", "contentHash", "contentBytes", "segmentHashes")}
    successors, action = apply(nodes, ref, update=args.update)
    source = next((node for node in source_nodes if node["lowerBound"] == action["oldNode"]["lowerBound"]), None)
    if source and "outRef" in source:
        action["sourceOutRef"] = source["outRef"]
    print(json.dumps({"action": action, "successorNodes": successors}, indent=2))


if __name__ == "__main__":
    main()
