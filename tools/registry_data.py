#!/usr/bin/env python3
"""Create cardano-cli detailed-schema datum and redeemer files for registry plans."""

from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path

from registry_content import load_json, verify_plan
from registry_list import node_token, root, validate_nodes, validate_ref


def b(value: str) -> dict:
    bytes.fromhex(value)
    return {"bytes": value.lower()}


def i(value: int) -> dict:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError("Plutus integer expected")
    return {"int": value}


def listed(values: list[dict]) -> dict:
    return {"list": values}


def constr(index: int, fields: list[dict]) -> dict:
    return {"constructor": index, "fields": fields}


def content_ref(ref: dict) -> dict:
    validate_ref(ref)
    return listed([b(ref["subject"]), b(ref["contentHash"]), i(ref["contentBytes"]),
                   listed([b(h) for h in ref["segmentHashes"]])])


def packed_node(node: dict) -> dict:
    return listed([b(node["lowerBound"]), b(node["nextBound"]),
                   listed([content_ref(ref) for ref in node["entries"]])])


def list_datum(node: dict) -> dict:
    return constr(0, [packed_node(node)])


def preimage_datum(subject: str, index: int, segment_hash: str, payload: bytes) -> dict:
    return constr(1, [listed([b(subject), i(index), b(segment_hash), b(payload.hex())])])


def manifest_datum(ref: dict) -> dict:
    validate_ref(ref)
    if ref["contentBytes"] == 0:
        raise ValueError("segment manifest needs a full content layout")
    return constr(2, [content_ref(ref)])


def write(directory: Path, name: str, value: dict) -> None:
    (directory / name).write_text(json.dumps(value, indent=2) + "\n")


def create_root(directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=False)
    write(directory, "root.datum.json", list_datum(root()))
    write(directory, "bootstrap.redeemer.json", constr(0, []))


def multisig_rule(rule: dict) -> dict:
    if not isinstance(rule, dict) or len(rule) != 1:
        raise ValueError("a multisig rule must have exactly one constructor")
    kind, value = next(iter(rule.items()))
    if kind == "signature":
        if not isinstance(value, str) or len(value) != 56:
            raise ValueError("signature key hash must be 28 bytes")
        return constr(0, [b(value)])
    if kind in {"allOf", "anyOf"}:
        if not isinstance(value, list):
            raise ValueError(f"{kind} must contain a list")
        return constr(1 if kind == "allOf" else 2, [listed([multisig_rule(child) for child in value])])
    if kind == "atLeast":
        if not isinstance(value, dict) or set(value) != {"required", "rules"}:
            raise ValueError("atLeast needs required and rules")
        required, rules = value["required"], value["rules"]
        if not isinstance(required, int) or isinstance(required, bool) or required < 0 or not isinstance(rules, list):
            raise ValueError("invalid atLeast threshold")
        return constr(3, [i(required), listed([multisig_rule(child) for child in rules])])
    if kind in {"before", "after"}:
        if not isinstance(value, int) or isinstance(value, bool):
            raise ValueError("time bound must be POSIX milliseconds")
        return constr(4 if kind == "before" else 5, [i(value)])
    if kind == "script":
        if not isinstance(value, str) or len(value) != 56:
            raise ValueError("withdrawal script hash must be 28 bytes")
        return constr(6, [b(value)])
    raise ValueError(f"unsupported multisig constructor: {kind}")


def create_governance(manifest: dict, rule: dict, directory: Path) -> None:
    currency = manifest["governancePolicyId"]
    token = manifest["governanceTokenName"]
    if not isinstance(currency, str) or not isinstance(token, str) or len(currency) != 56 or len(token) > 64 or len(token) % 2:
        raise ValueError("invalid governance NFT identity")
    datum = listed([b(currency), b(token), multisig_rule(rule)])
    directory.mkdir(parents=True, exist_ok=False)
    write(directory, "governance.datum.json", datum)
    write(directory, "spend.redeemer.json", i(0))
    write(directory, "mint.redeemer.json", i(0))


def create_uploads(upload: dict, directory: Path) -> None:
    verify_plan(upload)
    directory.mkdir(parents=True, exist_ok=False)
    write(directory, "manifest.datum.json", manifest_datum(upload))
    for part in upload["preimages"]:
        payload = base64.b64decode(part["bytesBase64"], validate=True)
        write(directory, f"preimage-{part['index']:03d}.datum.json",
              preimage_datum(upload["subject"], part["index"], part["hash"], payload))
    write(directory, "spend.redeemer.json", i(0))


def operation_files(result: dict, commitment: dict) -> dict[str, dict]:
    action = result["action"]
    kind = action["kind"]
    ref = {key: commitment[key] for key in ("subject", "contentHash", "contentBytes", "segmentHashes")}
    validate_ref(ref)
    old_node = action["oldNode"]
    new_nodes = action["newNodes"]
    validate_nodes(result["successorNodes"])
    if not any(result["successorNodes"][position:position + len(new_nodes)] == new_nodes
               for position in range(len(result["successorNodes"]))):
        raise ValueError("action successor nodes are absent from the planned list")
    if action["oldNodeToken"] != node_token(old_node["lowerBound"]):
        raise ValueError("old node token does not match its lower bound")
    index = action["index"]
    old_entries = old_node["entries"]
    if not isinstance(index, int) or isinstance(index, bool) or index < 0:
        raise ValueError("invalid insertion index")
    if kind == "insert":
        expected = old_entries[:index] + [ref] + old_entries[index:]
        valid = (index <= len(old_entries) and len(new_nodes) == 1
                 and new_nodes[0] == {**old_node, "entries": expected})
        redeemer = constr(0, [content_ref(ref), i(index)])
    elif kind == "update":
        expected = old_entries[:index] + [ref] + old_entries[index + 1:]
        valid = (index < len(old_entries) and old_entries[index]["subject"] == ref["subject"]
                 and len(new_nodes) == 1 and new_nodes[0] == {**old_node, "entries": expected})
        redeemer = constr(1, [content_ref(ref), i(index)])
    elif kind == "split":
        expected = old_entries[:index] + [ref] + old_entries[index:]
        valid = (len(old_entries) == 8 and index <= 8 and len(new_nodes) == 2
                 and bool(new_nodes[0]["entries"]) and bool(new_nodes[1]["entries"])
                 and new_nodes[0]["entries"] + new_nodes[1]["entries"] == expected
                 and new_nodes[0]["lowerBound"] == old_node["lowerBound"]
                 and new_nodes[0]["nextBound"] == new_nodes[1]["lowerBound"]
                 and new_nodes[1]["nextBound"] == old_node["nextBound"]
                 and new_nodes[1]["lowerBound"] == new_nodes[1]["entries"][0]["subject"])
        boundary = action["rightLowerBound"]
        valid = (valid and boundary == new_nodes[1]["lowerBound"]
                 and action["rightNodeToken"] == node_token(boundary))
        redeemer = constr(2, [content_ref(ref), i(index), b(boundary)])
    else:
        raise ValueError("unsupported list action")
    if not valid:
        raise ValueError("operation does not reconstruct the supplied nodes")
    files = {"old-node.datum.json": list_datum(old_node),
             "left-node.datum.json": list_datum(new_nodes[0]),
             "spend.redeemer.json": redeemer,
             "treasury.redeemer.json": i(0)}
    if kind == "split":
        files["right-node.datum.json"] = list_datum(new_nodes[1])
        files["mint.redeemer.json"] = constr(1, [content_ref(ref), i(index),
                                                b(old_node["lowerBound"]), b(action["rightLowerBound"])])
    return files


def create_operation(result: dict, commitment: dict, directory: Path) -> None:
    files = operation_files(result, commitment)
    directory.mkdir(parents=True, exist_ok=False)
    for name, value in files.items():
        write(directory, name, value)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    root_cmd = sub.add_parser("root", help="empty root datum and bootstrap mint redeemer")
    root_cmd.add_argument("output", type=Path)
    upload_cmd = sub.add_parser("uploads", help="one datum per preimage upload")
    upload_cmd.add_argument("upload_plan", type=Path)
    upload_cmd.add_argument("output", type=Path)
    governance_cmd = sub.add_parser("governance", help="governance NFT datum from a semantic multisig rule")
    governance_cmd.add_argument("deployment_manifest", type=Path)
    governance_cmd.add_argument("rule", type=Path)
    governance_cmd.add_argument("output", type=Path)
    operation_cmd = sub.add_parser("operation", help="datums and redeemers for an insert, update, or split")
    operation_cmd.add_argument("list_plan", type=Path)
    operation_cmd.add_argument("commitment", type=Path)
    operation_cmd.add_argument("output", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "root":
            create_root(args.output)
        elif args.command == "uploads":
            create_uploads(load_json(args.upload_plan.read_text()), args.output)
        elif args.command == "governance":
            create_governance(load_json(args.deployment_manifest.read_text()), load_json(args.rule.read_text()), args.output)
        else:
            create_operation(load_json(args.list_plan.read_text()), load_json(args.commitment.read_text()), args.output)
    except (ValueError, KeyError, IndexError, FileExistsError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
