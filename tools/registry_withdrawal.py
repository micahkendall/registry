"""Optional zero-withdrawal Plutus V3 witnesses for multisig Script rules."""

from __future__ import annotations

import re
from pathlib import Path

from registry_address import script_reward_address
from registry_content import load_json
from registry_script_hash import script_hash


def script_rule_hashes(rule: dict) -> set[str]:
    if not isinstance(rule, dict) or set(rule) != {"constructor", "fields"}:
        raise ValueError("invalid governance rule datum")
    tag, fields = rule["constructor"], rule["fields"]
    if type(tag) is not int or not isinstance(fields, list):
        raise ValueError("invalid governance rule constructor")
    if tag == 6:
        if len(fields) != 1 or not isinstance(fields[0], dict) or set(fields[0]) != {"bytes"}:
            raise ValueError("invalid script withdrawal rule")
        return {fields[0]["bytes"]}
    if tag in (1, 2, 3):
        index = 0 if tag in (1, 2) else 1
        if len(fields) != index + 1 or not isinstance(fields[index], dict) or set(fields[index]) != {"list"}:
            raise ValueError("invalid multisig child rules")
        children = fields[index]["list"]
        if not isinstance(children, list):
            raise ValueError("invalid multisig child list")
        return set().union(*(script_rule_hashes(child) for child in children))
    if tag in (0, 4, 5):
        return set()
    raise ValueError("unknown governance rule constructor")


def withdrawal_args(
    specs: list[dict] | None, governance_datum: dict, network: str,
    used_refs: list[str],
) -> list[str]:
    if not specs:
        return []
    if not isinstance(governance_datum, dict) or not isinstance(governance_datum.get("list"), list) or len(governance_datum["list"]) != 3:
        raise ValueError("invalid governance datum for withdrawal authority")
    allowed_hashes = script_rule_hashes(governance_datum["list"][2])
    used = set(used_refs)
    hashes = set()
    command = []
    for spec in specs:
        if not isinstance(spec, dict) or set(spec) != {"scriptFile", "reference", "redeemerFile"}:
            raise ValueError("withdrawal spec needs scriptFile, reference, and redeemerFile")
        script_file = Path(spec["scriptFile"])
        redeemer_file = Path(spec["redeemerFile"])
        reference = spec["reference"]
        if not isinstance(reference, str) or not re.fullmatch(r"[0-9a-f]{64}#[0-9]+", reference) or reference in used:
            raise ValueError("withdrawal script reference must be valid and distinct")
        used.add(reference)
        hash_value = script_hash(load_json(script_file.read_text()))
        if hash_value not in allowed_hashes:
            raise ValueError("withdrawal script hash is absent from the current governance rule")
        if hash_value in hashes:
            raise ValueError("duplicate withdrawal script hash")
        hashes.add(hash_value)
        if not isinstance(load_json(redeemer_file.read_text()), dict):
            raise ValueError("withdrawal redeemer must be detailed-schema JSON")
        address = script_reward_address(hash_value, network)
        command += ["--withdrawal", f"{address}+0",
                    "--withdrawal-tx-in-reference", reference,
                    "--withdrawal-plutus-script-v3",
                    "--withdrawal-reference-tx-in-redeemer-file", str(redeemer_file)]
    return command
