"""Tests for the additive browser-wallet-signing lane (app/api/demo_wallet.py).

None of these tests broadcast a transaction -- there is no private key
anywhere in this lane, so nothing here could. They prove: the recipient is
always server configuration and never request-supplied, the amount cap is
enforced, a DENY is reported without ever exposing a recipient/amount to
sign, and /demo/wallet/status reports only what an independent RPC call
actually observed.
"""

from __future__ import annotations

from decimal import Decimal
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from app import main
from app.api import demo_wallet


TASK = "Research competitor pricing using a paid company data service."
MATCHING_PURPOSE = "Generate a competitor pricing research brief from company data."
MISMATCHED_PURPOSE = "Purchase a gift card for an unrelated entertainment giveaway."
RECIPIENT = "0x530271DA8CC4e44375f22ad9632bC61A55382f88"


def _body(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "task": TASK,
        "purpose": MATCHING_PURPOSE,
        "amount": "0.001",
        "service_category": "company-research",
    }
    payload.update(overrides)
    return payload


class WalletConfigTests(unittest.TestCase):
    def test_inert_without_a_configured_recipient(self) -> None:
        with patch.object(demo_wallet, "_recipient", return_value=None):
            with TestClient(main.app) as client:
                response = client.get("/demo/wallet/config")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(
            response.json()["detail"]["code"], "WALLET_RECIPIENT_NOT_CONFIGURED"
        )

    def test_reports_chain_and_recipient_but_never_a_private_key(self) -> None:
        with patch.object(demo_wallet, "_recipient", return_value=RECIPIENT):
            with TestClient(main.app) as client:
                response = client.get("/demo/wallet/config")
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["recipient"], RECIPIENT)
        self.assertEqual(body["chain_id"], 5_042_002)
        self.assertEqual(body["chain_id_hex"], "0x4cef52")
        self.assertNotIn("private_key", body)
        self.assertNotIn("key", str(body).lower().replace("chain_id_hex", ""))


class WalletEvaluateTests(unittest.TestCase):
    def test_inert_without_a_configured_recipient(self) -> None:
        with patch.object(demo_wallet, "_recipient", return_value=None):
            with TestClient(main.app) as client:
                response = client.post("/demo/wallet/evaluate", json=_body())
        self.assertEqual(response.status_code, 503)

    def test_amount_above_the_per_transaction_cap_is_refused(self) -> None:
        with patch.object(demo_wallet, "_recipient", return_value=RECIPIENT):
            with TestClient(main.app) as client:
                response = client.post(
                    "/demo/wallet/evaluate", json=_body(amount="5.00")
                )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            response.json()["detail"]["code"], "WALLET_AMOUNT_CAP_EXCEEDED"
        )

    def test_matching_purpose_is_allowed_and_carries_signing_instructions(self) -> None:
        with patch.object(demo_wallet, "_recipient", return_value=RECIPIENT):
            with TestClient(main.app) as client:
                response = client.post("/demo/wallet/evaluate", json=_body())
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertTrue(body["allowed"])
        self.assertEqual(body["decision"]["reason_code"], "TASK_PURCHASE_MATCH")
        self.assertEqual(body["recipient"], RECIPIENT)
        self.assertEqual(body["amount_usdc"], "0.001")

    def test_mismatched_purpose_is_denied_without_signing_instructions(self) -> None:
        """A DENY never hands the caller a recipient/amount to sign."""
        with patch.object(demo_wallet, "_recipient", return_value=RECIPIENT):
            with TestClient(main.app) as client:
                response = client.post(
                    "/demo/wallet/evaluate", json=_body(purpose=MISMATCHED_PURPOSE)
                )
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertFalse(body["allowed"])
        self.assertEqual(body["decision"]["reason_code"], "PURCHASE_PURPOSE_MISMATCH")
        self.assertNotIn("recipient", body)
        self.assertNotIn("amount_usdc", body)

    def test_recipient_is_configuration_only(self) -> None:
        """A request cannot redirect funds; the body has no recipient field."""
        self.assertNotIn("recipient", demo_wallet.WalletEvaluateRequest.model_fields)
        self.assertNotIn("to", demo_wallet.WalletEvaluateRequest.model_fields)


class WalletStatusTests(unittest.TestCase):
    def test_inert_without_a_configured_recipient(self) -> None:
        with patch.object(demo_wallet, "_recipient", return_value=None):
            with TestClient(main.app) as client:
                response = client.get(
                    "/demo/wallet/status", params={"tx": "0x" + "ab" * 32}
                )
        self.assertEqual(response.status_code, 503)

    def test_reports_pending_before_a_receipt_exists(self) -> None:
        with patch.object(demo_wallet, "_recipient", return_value=RECIPIENT):
            with patch.object(demo_wallet, "_rpc", return_value=None):
                with TestClient(main.app) as client:
                    response = client.get(
                        "/demo/wallet/status", params={"tx": "0x" + "ab" * 32}
                    )
        body = response.json()
        self.assertEqual(response.status_code, 200)
        self.assertTrue(body["pending"])
        self.assertFalse(body["confirmed"])

    def test_verifies_a_genuine_transfer_to_the_configured_recipient(self) -> None:
        units = 1_000  # 0.001 USDC at 6 decimals
        receipt = {
            "status": "0x1",
            "blockNumber": "0x1",
            "logs": [
                {
                    "topics": [
                        demo_wallet.TRANSFER_TOPIC,
                        "0x" + "11" * 32,
                        "0x" + RECIPIENT[2:].lower().rjust(64, "0"),
                    ],
                    "data": hex(units),
                }
            ],
        }
        with patch.object(demo_wallet, "_recipient", return_value=RECIPIENT):
            with patch.object(demo_wallet, "_rpc", return_value=receipt):
                with TestClient(main.app) as client:
                    response = client.get(
                        "/demo/wallet/status", params={"tx": "0x" + "cd" * 32}
                    )
        body = response.json()
        self.assertEqual(response.status_code, 200)
        self.assertTrue(body["confirmed"])
        self.assertTrue(body["succeeded"])
        self.assertTrue(body["rpc_verified_transfer_to_configured_recipient"])
        self.assertEqual(body["amount_usdc"], "0.001")

    def test_does_not_verify_a_transfer_to_a_different_recipient(self) -> None:
        """A visitor cannot get this lane to vouch for a payment to someone else."""
        units = 1_000
        other_recipient = "0x" + "99" * 20
        receipt = {
            "status": "0x1",
            "blockNumber": "0x1",
            "logs": [
                {
                    "topics": [
                        demo_wallet.TRANSFER_TOPIC,
                        "0x" + "11" * 32,
                        "0x" + other_recipient[2:].lower().rjust(64, "0"),
                    ],
                    "data": hex(units),
                }
            ],
        }
        with patch.object(demo_wallet, "_recipient", return_value=RECIPIENT):
            with patch.object(demo_wallet, "_rpc", return_value=receipt):
                with TestClient(main.app) as client:
                    response = client.get(
                        "/demo/wallet/status", params={"tx": "0x" + "cd" * 32}
                    )
        body = response.json()
        self.assertFalse(body["rpc_verified_transfer_to_configured_recipient"])
        self.assertIsNone(body["amount_usdc"])


if __name__ == "__main__":
    unittest.main()
