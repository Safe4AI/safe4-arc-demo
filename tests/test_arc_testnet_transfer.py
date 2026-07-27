from __future__ import annotations

import unittest

from scripts.arc_testnet_transfer import (
    ArcTransferError,
    encode_balance_of,
    encode_transfer,
    matching_transfer_log,
    usdc_units,
)


class ArcTestnetTransferScriptTests(unittest.TestCase):
    def test_usdc_units_preserves_six_decimals(self) -> None:
        self.assertEqual(usdc_units("0.01"), 10_000)
        self.assertEqual(usdc_units("1.000001"), 1_000_001)

    def test_usdc_units_rejects_sub_unit_precision(self) -> None:
        with self.assertRaises(ArcTransferError):
            usdc_units("0.0000001")

    def test_encode_transfer_uses_erc20_abi_layout(self) -> None:
        recipient = "0x1111111111111111111111111111111111111111"
        encoded = encode_transfer(recipient, 10_000)
        self.assertEqual(encoded[:10], "0xa9059cbb")
        self.assertEqual(encoded[10:74], ("1" * 40).rjust(64, "0"))
        self.assertEqual(encoded[74:], f"{10_000:064x}")

    def test_encode_balance_of_uses_erc20_abi_layout(self) -> None:
        wallet = "0x2222222222222222222222222222222222222222"
        self.assertEqual(
            encode_balance_of(wallet),
            "0x70a08231" + ("2" * 40).rjust(64, "0"),
        )

    def test_matching_transfer_log_requires_usdc_contract_and_topic(self) -> None:
        receipt = {
            "logs": [
                {
                    "address": "0x3600000000000000000000000000000000000000",
                    "topics": [
                        "0xddf252ad1be2c89b69c2b068fc378daa"
                        "952ba7f163c4a11628f55a4df523b3ef"
                    ],
                }
            ]
        }
        self.assertTrue(matching_transfer_log(receipt))


if __name__ == "__main__":
    unittest.main()
