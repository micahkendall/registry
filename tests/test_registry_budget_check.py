import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from registry_budget_check import LEDGER_LABELS, TEST_LABELS, check


class LedgerBudgetCheckTests(unittest.TestCase):
    def test_ledger_cost_model_takes_precedence_over_test_model(self):
        with tempfile.TemporaryDirectory() as temporary:
            parameters = Path(temporary) / "params.json"
            parameters.write_text(json.dumps({"maxTxExecutionUnits": {"steps": 1000, "memory": 100}}))
            test_lines = [f"{label}: ExBudget {{exBudgetCPU = ExCPU 900, exBudgetMemory = ExMemory 90}}"
                          for label in TEST_LABELS]
            ledger_lines = [f"{label}: ExBudget {{exBudgetCPU = ExCPU 100, exBudgetMemory = ExMemory 10}}"
                            for label in LEDGER_LABELS]
            result = check(parameters, "\n".join(test_lines + ledger_lines))
            self.assertEqual(result["costModel"], "ledger-v3")
            self.assertEqual(result["combinedBudget"], {"steps": 300, "memory": 30})
            with self.assertRaisesRegex(ValueError, "exceeds transaction limits"):
                check(parameters, "\n".join(test_lines + [
                    f"{label}: ExBudget {{exBudgetCPU = ExCPU 400, exBudgetMemory = ExMemory 40}}"
                    for label in LEDGER_LABELS]))


if __name__ == "__main__":
    unittest.main()
