import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from registry_address import script_address, script_reward_address


class ScriptAddressTests(unittest.TestCase):
    def test_cip19_type07_mainnet_and_testnet_vectors(self):
        # CIP-19's script1cda3... reference hash and type-07 addresses.
        script_hash = "c37b1b5dc0669f1d3c61a6fddb2e8fde96be87b881c60bce8e8d542f"
        self.assertEqual(script_address(script_hash, "mainnet"),
                         "addr1w8phkx6acpnf78fuvxn0mkew3l0fd058hzquvz7w36x4gtcyjy7wx")
        self.assertEqual(script_address(script_hash, "testnet"),
                         "addr_test1wrphkx6acpnf78fuvxn0mkew3l0fd058hzquvz7w36x4gtcl6szpr")

    def test_invalid_hash_and_network(self):
        for script_hash, network in (("00", "mainnet"), ("AB" * 28, "testnet"), ("ab" * 28, "preview")):
            with self.assertRaises(ValueError):
                script_address(script_hash, network)

    def test_cip19_type15_reward_script_vectors(self):
        script_hash = "c37b1b5dc0669f1d3c61a6fddb2e8fde96be87b881c60bce8e8d542f"
        self.assertEqual(script_reward_address(script_hash, "mainnet"),
                         "stake178phkx6acpnf78fuvxn0mkew3l0fd058hzquvz7w36x4gtcccycj5")
        self.assertEqual(script_reward_address(script_hash, "testnet"),
                         "stake_test17rphkx6acpnf78fuvxn0mkew3l0fd058hzquvz7w36x4gtcljw6kf")


if __name__ == "__main__":
    unittest.main()
