from __future__ import annotations

from copy import deepcopy
import unittest

from scripts.verify_arc_settlement import (
    ArcSettlementError,
    TRANSFER_TOPIC,
    address_topic,
    encode_transfer,
    verify_settlement_payloads,
)


TX_HASH = "0x" + ("a" * 64)
USDC = "0x3600000000000000000000000000000000000000"
SENDER = "0x1111111111111111111111111111111111111111"
RECIPIENT = "0x2222222222222222222222222222222222222222"
AMOUNT_UNITS = 10_000


def valid_payloads() -> tuple[dict[str, object], dict[str, object]]:
    transaction: dict[str, object] = {
        "hash": TX_HASH,
        "from": SENDER,
        "to": USDC,
        "value": "0x0",
        "input": encode_transfer(RECIPIENT, AMOUNT_UNITS),
    }
    receipt: dict[str, object] = {
        "transactionHash": TX_HASH,
        "status": "0x1",
        "blockNumber": "0x2a",
        "logs": [
            {
                "address": USDC,
                "topics": [
                    TRANSFER_TOPIC,
                    address_topic(SENDER),
                    address_topic(RECIPIENT),
                ],
                "data": hex(AMOUNT_UNITS),
            }
        ],
    }
    return transaction, receipt


class ArcSettlementVerifierTests(unittest.TestCase):
    def verify(
        self,
        transaction: dict[str, object] | None,
        receipt: dict[str, object] | None,
    ) -> int:
        return verify_settlement_payloads(
            transaction,
            receipt,
            transaction_hash=TX_HASH,
            usdc_address=USDC,
            sender=SENDER,
            recipient=RECIPIENT,
            amount_units=AMOUNT_UNITS,
        )

    def test_accepts_exact_successful_usdc_transfer(self) -> None:
        transaction, receipt = valid_payloads()
        self.assertEqual(self.verify(transaction, receipt), 42)

    def test_rejects_unrelated_usdc_transaction(self) -> None:
        transaction, receipt = valid_payloads()
        transaction["input"] = encode_transfer(
            "0x3333333333333333333333333333333333333333",
            AMOUNT_UNITS,
        )
        with self.assertRaisesRegex(ArcSettlementError, "calldata"):
            self.verify(transaction, receipt)

    def test_rejects_wrong_sender(self) -> None:
        transaction, receipt = valid_payloads()
        transaction["from"] = "0x3333333333333333333333333333333333333333"
        with self.assertRaisesRegex(ArcSettlementError, "sender"):
            self.verify(transaction, receipt)

    def test_rejects_reverted_transaction(self) -> None:
        transaction, receipt = valid_payloads()
        receipt["status"] = "0x0"
        with self.assertRaisesRegex(ArcSettlementError, "not successful"):
            self.verify(transaction, receipt)

    def test_rejects_transfer_event_with_wrong_amount(self) -> None:
        transaction, receipt = valid_payloads()
        mutated_receipt = deepcopy(receipt)
        mutated_receipt["logs"][0]["data"] = hex(AMOUNT_UNITS + 1)  # type: ignore[index]
        with self.assertRaisesRegex(ArcSettlementError, "no matching"):
            self.verify(transaction, mutated_receipt)

    def test_rejects_missing_transaction_or_receipt(self) -> None:
        transaction, receipt = valid_payloads()
        with self.assertRaisesRegex(ArcSettlementError, "transaction not found"):
            self.verify(None, receipt)
        with self.assertRaisesRegex(ArcSettlementError, "receipt not found"):
            self.verify(transaction, None)


if __name__ == "__main__":
    unittest.main()
