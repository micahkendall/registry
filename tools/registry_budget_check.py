#!/usr/bin/env python3
"""Evaluate the three maximum packed-split scripts under a supplied V3 cost model.

The contexts are synthetic but shared across all three scripts. This still
does not replace evaluating a real transaction against a node's ledger state.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path


TEST_LABELS = (
    "maximum packed registry split budget",
    "maximum packed node mint budget",
    "maximum packed split governance budget",
)
LEDGER_LABELS = (
    "maximum packed registry spend ledger budget",
    "maximum packed node mint ledger budget",
    "maximum packed governance spend ledger budget",
)


def check(protocol_params: Path, test_output: str) -> dict:
    parameters = json.loads(protocol_params.read_text())
    limits = parameters["maxTxExecutionUnits"]
    if (type(limits.get("steps")) is not int or limits["steps"] <= 0
            or type(limits.get("memory")) is not int or limits["memory"] <= 0):
        raise ValueError("protocol parameters lack positive transaction execution limits")
    labels = LEDGER_LABELS if all(label + ":" in test_output for label in LEDGER_LABELS) else TEST_LABELS
    totals = {"steps": 0, "memory": 0}
    for label in labels:
        pattern = re.escape(label) + r": ExBudget \{exBudgetCPU = ExCPU (\d+), exBudgetMemory = ExMemory (\d+)\}"
        matches = re.findall(pattern, test_output)
        if len(matches) != 1:
            raise ValueError(f"expected exactly one {label} in the test log")
        steps, memory = map(int, matches[0])
        totals["steps"] += steps
        totals["memory"] += memory
    if any(totals[key] > limits[key] for key in totals):
        raise ValueError("combined maximum packed-split test budget exceeds transaction limits")
    model = "ledger-v3" if labels == LEDGER_LABELS else "plutarch-test"
    return {"scriptContexts": len(labels), "costModel": model, "combinedBudget": totals,
            "protocolTransactionLimit": {key: limits[key] for key in totals},
            "withinProtocolLimits": True}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("protocol_params", type=Path)
    parser.add_argument("--test-output", type=Path,
                        help="captured onchain-compile stdout; defaults to rerunning the built test executable")
    args = parser.parse_args()
    try:
        if args.test_output is not None:
            output = args.test_output.read_text()
        else:
            candidates = [path for path in Path("dist-newstyle").rglob("onchain-compile") if path.is_file()]
            if not candidates:
                parser.error("run cabal test all first, or supply --test-output")
            executable = max(candidates, key=lambda path: path.stat().st_mtime)
            params = json.loads(args.protocol_params.read_text())
            model = params.get("costModels", {}).get("PlutusV3")
            major = params.get("protocolVersion", {}).get("major")
            if (not isinstance(model, list) or not model
                    or any(type(value) is not int for value in model)
                    or type(major) is not int or major < 9):
                raise ValueError("protocol parameters lack a valid PlutusV3 model and protocol major version")
            with tempfile.TemporaryDirectory(prefix="registry-ledger-budget-") as directory:
                model_file = Path(directory) / "cost-model.txt"
                model_file.write_text("\n".join(map(str, model)) + "\n")
                environment = {**os.environ, "REGISTRY_V3_COST_MODEL": str(model_file),
                               "REGISTRY_PROTOCOL_MAJOR": str(major)}
                output = subprocess.check_output([str(executable.resolve())], text=True, env=environment)
            if not all(label + ":" in output for label in LEDGER_LABELS):
                raise ValueError("test executable did not report V3 ledger budgets")
        print(json.dumps(check(args.protocol_params, output), indent=2))
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
