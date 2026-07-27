from __future__ import annotations

import unittest
from uuid import uuid4

from fastapi.testclient import TestClient
import pytest

from app import main, webhooks_api


pytestmark = pytest.mark.slow


class Phase2IntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        main.reset_runtime_state()
        webhooks_api.reset_webhook_sender_for_tests()
        self.client = TestClient(main.app)
        self.client_id = "dev-public-client"
        self.valid_payload = {
            "agent_id": "agent_alpha",
            "user_id": "user_123",
            "vendor": "acme_travel",
            "amount": 9.99,
            "currency": "USD",
            "description": "Book the approved train ticket for tomorrow client meeting with the sales team.",
            "context": {"trip_id": "trip_789"},
        }
        self.oauth = self.issue_oauth_tokens(
            scopes="payment:read payment:authorize budget:manage audit:read admin:all",
            subject="operator_1",
            agent_id="agent_alpha",
        )

    def auth_headers(self, **extra_headers: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.oauth['access_token']}"} | extra_headers

    def issue_oauth_tokens(self, scopes: str, subject: str, agent_id: str | None = None) -> dict[str, str]:
        verifier = "a" * 43
        authorize = self.client.post(
            "/oauth/authorize",
            json={
                "client_id": self.client_id,
                "redirect_uri": "https://localhost/callback",
                "scope": scopes,
                "code_challenge": main.compute_code_challenge(verifier),
                "code_challenge_method": "S256",
                "subject": subject,
                "agent_id": agent_id,
            },
        )
        self.assertEqual(authorize.status_code, 200)
        token = self.client.post(
            "/oauth/token",
            json={
                "grant_type": "authorization_code",
                "client_id": self.client_id,
                "code": authorize.json()["code"],
                "redirect_uri": "https://localhost/callback",
                "code_verifier": verifier,
            },
        )
        self.assertEqual(token.status_code, 200)
        return token.json()

    def issue_receipt_for(self, payload: dict) -> str:
        first = self.client.post("/pay", json=payload, headers=self.auth_headers())
        self.assertEqual(first.status_code, 402)
        detail = first.json()["details"]
        issue = self.client.post(
            "/receipts/issue",
            json={
                "amount_due": float(detail["amount_due"]),
                "currency": detail["currency"],
                "expires_in_seconds": 300,
            },
            headers=self.auth_headers(**{"X-Admin-Secret": main.RECEIPT_ADMIN_SECRET}),
        )
        self.assertEqual(issue.status_code, 200)
        return issue.json()["receipt_token"]

    def setup_trusted_mcp_tool(self, tool_name: str = "checkout_tool") -> str:
        self.client.post(
            "/mcp/servers",
            json={
                "server_id": "srv_payments",
                "server_name": "Payments Server",
                "server_url": "https://payments.example",
                "transport_type": "streamable_http",
                "description": "MCP server for approved checkout and billing operations.",
            },
            headers=self.auth_headers(),
        )
        self.client.post(
            "/mcp/servers/srv_payments/trust",
            json={"trust_level": "trusted", "reason": "Approved for testing."},
            headers=self.auth_headers(),
        )
        tool = self.client.post(
            "/mcp/servers/srv_payments/tools",
            json={
                "tool_name": tool_name,
                "description": "Approved checkout tool for purchase actions.",
                "input_schema": {"type": "object"},
            },
            headers=self.auth_headers(),
        )
        self.assertEqual(tool.status_code, 200)
        return tool.json()["tool_id"]

    def test_mcp_hitl_roundtrip_produces_authorization_and_forensics(self) -> None:
        delivered_payloads: list[dict[str, object]] = []

        def fake_sender(*, url: str, payload: dict[str, object], shared_secret: str | None, timeout_seconds: int) -> dict[str, object]:
            delivered_payloads.append(payload)
            return {"status_code": 200, "body": "ok"}

        webhooks_api.set_webhook_sender_for_tests(fake_sender)

        endpoint = self.client.post(
            "/webhooks/endpoints",
            json={
                "endpoint_id": "phase2_approval_sink",
                "target_url": "https://hooks.example/approvals",
                "subscribed_events": ["hitl_approval_requested", "hitl_approval_approved"],
                "is_active": True,
            },
            headers=self.auth_headers(),
        )
        self.assertEqual(endpoint.status_code, 200)

        tool_id = self.setup_trusted_mcp_tool("phase2_checkout")
        permission = self.client.post(
            "/mcp/permissions",
            json={
                "tool_id": tool_id,
                "user_id": "user_123",
                "allowed_actions": ["purchase"],
                "transaction_cap": 15.00,
                "daily_cap": 30.00,
                "requires_hitl": True,
            },
            headers=self.auth_headers(),
        )
        self.assertEqual(permission.status_code, 200)

        payload = self.valid_payload | {"mcp_tool_id": tool_id, "mcp_action": "purchase"}
        receipt_token = self.issue_receipt_for(payload)
        pending = self.client.post(
            "/pay",
            json=payload,
            headers=self.auth_headers(**{"X-Payment-Receipt": receipt_token, "Idempotency-Key": str(uuid4())}),
        )
        self.assertEqual(pending.status_code, 202)
        approval_id = pending.json()["approval_id"]

        decide = self.client.post(
            f"/approvals/{approval_id}/decide",
            json={"decision": "approved", "reason": "Approved in Phase 2 integration scenario."},
            headers=self.auth_headers(),
        )
        self.assertEqual(decide.status_code, 200)
        spend_token = decide.json()["spend_token"]

        approved = self.client.post(
            "/pay",
            json=payload,
            headers=self.auth_headers(**{"X-Payment-Receipt": receipt_token, "X-Spend-Token": spend_token}),
        )
        self.assertEqual(approved.status_code, 200)
        transaction_id = approved.json()["transaction_id"]

        dispatch = self.client.post("/webhooks/dispatch", headers=self.auth_headers())
        self.assertEqual(dispatch.status_code, 200)
        self.assertTrue(delivered_payloads)

        approval_trace = self.client.get(f"/audit/trace/approval/{approval_id}", headers=self.auth_headers())
        self.assertEqual(approval_trace.status_code, 200)
        self.assertTrue(any(entry["action"] == "approval_decide" for entry in approval_trace.json()["entries"]))

        timeline = self.client.get(
            "/audit/timeline",
            params={"transaction_id": transaction_id},
            headers=self.auth_headers(),
        )
        self.assertEqual(timeline.status_code, 200)
        source_types = {entry["source_type"] for entry in timeline.json()["entries"]}
        self.assertIn("audit", source_types)
        self.assertIn("log", source_types)


if __name__ == "__main__":
    unittest.main()
