import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from registry_deployment import prepare


SEED1 = "11" * 32 + "#0"
SEED2 = "22" * 32 + "#1"
HASHES = ["a1" * 28, "b2" * 28, "c3" * 28, "d4" * 28]


class DeploymentTests(unittest.TestCase):
    def test_script_dependencies_are_applied_in_order(self):
        with tempfile.TemporaryDirectory() as temp, patch("registry_deployment.export", side_effect=HASHES) as exporter:
            target = Path(temp) / "release"
            manifest = prepare(SEED1, SEED2, "474f56", target)
            self.assertEqual(exporter.call_args_list[0].args[:2], ("governance", []))
            self.assertEqual(exporter.call_args_list[1].args[:2],
                             ("governance-policy", [SEED1, "474f56", HASHES[0]]))
            self.assertEqual(exporter.call_args_list[2].args[:2],
                             ("node-policy", [SEED2, HASHES[1], "474f56", HASHES[0]]))
            self.assertEqual(exporter.call_args_list[3].args[:2],
                             ("registry", [HASHES[1], "474f56", HASHES[0], HASHES[2]]))
            self.assertEqual(manifest["registryScriptHash"], HASHES[3])
            self.assertTrue(manifest["registryAddresses"]["mainnet"].startswith("addr1w"))
            self.assertTrue(manifest["registryAddresses"]["testnet"].startswith("addr_test1w"))
            self.assertNotEqual(manifest["registryAddresses"]["mainnet"], manifest["governanceAddresses"]["mainnet"])
            self.assertTrue((target / "manifest.json").exists())

    def test_duplicate_or_bad_seeds_fail_before_creating_output(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "release"
            for seed1, seed2, token in ((SEED1, SEED1, "474f56"), ("bad", SEED2, "474f56"),
                                         (SEED1, SEED2, "XYZ")):
                with self.assertRaises(ValueError):
                    prepare(seed1, seed2, token, target)
                self.assertFalse(target.exists())


if __name__ == "__main__":
    unittest.main()
