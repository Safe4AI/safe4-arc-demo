"""Fail-closed tests for the admin-gated live settlement lane.

None of these tests broadcast a transaction. The ALLOW path is exercised only
far enough to prove the guards, and every test asserts that no RPC call is made
unless the request has passed every gate.
"""

from __future__ import annotations

from decimal import Decimal
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from app import main
from app.api import demo_live


ADMIN = "live-admin-secret-for-tests"
TASK = "Research competitor pricing using a paid company data service."
MATCHING_PURPOSE = "Generate a competitor pricing research brief from company data."
MISMATCHED_PURPOSE = "Purchase a gift card for an unrelated entertainment giveaway."


def _body(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "task": TASK,
        "purpose": MATCHING_PURPOSE,
        "amount": "0.001",
        "service_category": "company-research",
    }
    payload.update(overrides)
    return payload


class LiveSettleGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        demo_live._spend_day = None
        demo_live._spend_total = Decimal("0")

    def test_lane_is_inert_without_a_private_key(self) -> None:
        env = {"PAYMENT_FIREWALL_LIVE_ADMIN_SECRET": ADMIN}
        with patch.dict(demo_live.os.environ, env, clear=False):
            demo_live.os.environ.pop("ARC_PRIVATE_KEY", None)
            with TestClient(main.app) as client:
                response = client.post(
                    "/demo/live/settle", json=_body(), headers={"X-Live-Admin": ADMIN}
                )
        self.assertEqual(response.status_code, 503)
        self.assertEqual(
            response.json()["detail"]["code"], "LIVE_SETTLEMENT_NOT_CONFIGURED"
        )

    def test_admin_header_is_required(self) -> None:
        env = {
            "ARC_PRIVATE_KEY": "0x" + "11" * 32,
            "PAYMENT_FIREWALL_LIVE_ADMIN_SECRET": ADMIN,
        }
        with patch.dict(demo_live.os.environ, env, clear=False):
            with TestClient(main.app) as client:
                missing = client.post("/demo/live/settle", json=_body())
                wrong = client.post(
                    "/demo/live/settle",
                    json=_body(),
                    headers={"X-Live-Admin": "not-the-secret"},
                )
        self.assertEqual(missing.status_code, 403)
        self.assertEqual(wrong.status_code, 403)
        self.assertEqual(wrong.json()["detail"]["code"], "LIVE_ADMIN_REQUIRED")

    def test_amount_above_the_per_transaction_cap_is_refused(self) -> None:
        env = {
            "ARC_PRIVATE_KEY": "0x" + "11" * 32,
            "PAYMENT_FIREWALL_LIVE_ADMIN_SECRET": ADMIN,
            "PAYMENT_FIREWALL_PAY_TO": "0x530271DA8CC4e44375f22ad9632bC61A55382f88",
        }
        with patch.dict(demo_live.os.environ, env, clear=False):
            with patch.object(demo_live, "_rpc") as rpc:
                with TestClient(main.app) as client:
                    response = client.post(
                        "/demo/live/settle",
                        json=_body(amount="5.00"),
                        headers={"X-Live-Admin": ADMIN},
                    )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            response.json()["detail"]["code"], "LIVE_AMOUNT_CAP_EXCEEDED"
        )
        rpc.assert_not_called()

    def test_denied_intent_never_reaches_the_executor(self) -> None:
        """The core claim: a DENY builds, signs, and sends nothing."""
        env = {
            "ARC_PRIVATE_KEY": "0x" + "11" * 32,
            "PAYMENT_FIREWALL_LIVE_ADMIN_SECRET": ADMIN,
            "PAYMENT_FIREWALL_PAY_TO": "0x530271DA8CC4e44375f22ad9632bC61A55382f88",
        }
        with patch.dict(demo_live.os.environ, env, clear=False):
            with patch.object(demo_live, "_rpc") as rpc:
                with TestClient(main.app) as client:
                    response = client.post(
                        "/demo/live/settle",
                        json=_body(purpose=MISMATCHED_PURPOSE),
                        headers={"X-Live-Admin": ADMIN},
                    )
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertFalse(body["settled"])
        self.assertFalse(body["executor_invoked"])
        self.assertEqual(
            body["decision"]["reason_code"], "PURCHASE_PURPOSE_MISMATCH"
        )
        rpc.assert_not_called()
        self.assertEqual(demo_live._spend_total, Decimal("0"))

    def test_recipient_is_configuration_only(self) -> None:
        """A request cannot redirect funds; the body has no recipient field."""
        self.assertNotIn("recipient", demo_live.LiveSettleRequest.model_fields)
        self.assertNotIn("to", demo_live.LiveSettleRequest.model_fields)

    def test_daily_cap_blocks_further_settlement(self) -> None:
        demo_live._spend_day = demo_live.date.today()
        demo_live._spend_total = demo_live.MAX_PER_DAY
        env = {
            "ARC_PRIVATE_KEY": "0x" + "11" * 32,
            "PAYMENT_FIREWALL_LIVE_ADMIN_SECRET": ADMIN,
            "PAYMENT_FIREWALL_PAY_TO": "0x530271DA8CC4e44375f22ad9632bC61A55382f88",
        }
        with patch.dict(demo_live.os.environ, env, clear=False):
            with patch.object(demo_live, "_rpc") as rpc:
                with TestClient(main.app) as client:
                    response = client.post(
                        "/demo/live/settle",
                        json=_body(),
                        headers={"X-Live-Admin": ADMIN},
                    )
        self.assertEqual(response.status_code, 429)
        self.assertEqual(
            response.json()["detail"]["code"], "LIVE_DAILY_CAP_EXCEEDED"
        )
        rpc.assert_not_called()

    def test_caps_are_bounded(self) -> None:
        self.assertEqual(demo_live.MAX_PER_TRANSACTION, Decimal("0.01"))
        self.assertEqual(demo_live.MAX_PER_DAY, Decimal("0.10"))


if __name__ == "__main__":
    unittest.main()
