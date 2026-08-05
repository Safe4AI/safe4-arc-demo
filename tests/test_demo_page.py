from __future__ import annotations

import unittest
from typing import Any

from fastapi.testclient import TestClient

from app import main, webhooks_api
from app.api import demo
from app.api.demo import setup_demo_api
from app.integrations.range import reset_range_requester_for_tests


class DemoPageTests(unittest.TestCase):
    def setUp(self) -> None:
        main.reset_runtime_state()
        webhooks_api.reset_webhook_sender_for_tests()
        reset_range_requester_for_tests()
        setup_demo_api(
            demo_access_token="demo-team-token",
            demo_x402_receipt_enabled=True,
            issue_receipt=main.issue_receipt,
            append_audit_entry=main.append_audit_entry,
            pay_to_address=main.PAY_TO_ADDRESS,
            get_current_identity=main.get_current_identity,
            ensure_scope=main.ensure_scope,
        )

    def issue_oauth_token(
        self,
        client: TestClient,
        *,
        scopes: str = "payment:authorize audit:read",
        agent_id: str = "agent_alpha",
    ) -> str:
        verifier = "d" * 43
        authorization = client.post(
            "/oauth/authorize",
            json={
                "client_id": "dev-public-client",
                "redirect_uri": "https://localhost/callback",
                "scope": scopes,
                "code_challenge": main.compute_code_challenge(verifier),
                "code_challenge_method": "S256",
                "subject": "safe4_demo_test",
                "agent_id": agent_id,
            },
        )
        self.assertEqual(authorization.status_code, 200)
        token = client.post(
            "/oauth/token",
            json={
                "grant_type": "authorization_code",
                "client_id": "dev-public-client",
                "code": authorization.json()["code"],
                "redirect_uri": "https://localhost/callback",
                "code_verifier": verifier,
            },
        )
        self.assertEqual(token.status_code, 200)
        return str(token.json()["access_token"])

    def test_demo_module_exports_router(self) -> None:
        self.assertTrue(hasattr(demo, "router"))

    def test_demo_page_is_served(self) -> None:
        with TestClient(main.app) as client:
            response = client.get("/demo/agent-security?access_token=demo-team-token")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Safe4 Agent Security Gateway", response.text)
        self.assertIn("/pay", response.text)
        self.assertIn("Range Risk", response.text)

    def test_console_mock_page_is_served(self) -> None:
        with TestClient(main.app) as client:
            response = client.get("/demo/console?access_token=demo-team-token")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Safe4 Console Mockup", response.text)
        self.assertIn("Authorized Travel Purchase", response.text)
        self.assertIn("Blocked High-Risk Transfer", response.text)
        self.assertIn("Live Safe4 Signals", response.text)

    def test_x402_demo_page_is_served_with_judge_facing_scenario_contract(self) -> None:
        with TestClient(main.app) as client:
            response = client.get("/demo/x402?access_token=demo-team-token")

        self.assertEqual(response.status_code, 200)
        self.assertIn("See every payment decision.", response.text)
        self.assertIn("Connect demo agent", response.text)
        for scenario_label in (
            "Task-matched purchase",
            "3-call agent batch",
            "Wrong purchase purpose",
            "Scope cap exceeded",
            "Used receipt replay",
            "Idempotent duplicate",
        ):
            with self.subTest(scenario_label=scenario_label):
                self.assertIn(scenario_label, response.text)

        for boundary_text in (
            "Local /pay live",
            "Guarded receipt fixture",
            "Browser broadcasts 0",
            "Separate live Arc Testnet evidence",
            "Running the browser lab never creates another transaction.",
            "Batch means independent requests, not atomic settlement.",
        ):
            with self.subTest(boundary_text=boundary_text):
                self.assertIn(boundary_text, response.text)

        for endpoint in (
            'fetch("/oauth/authorize"',
            'fetch("/oauth/token"',
            'fetch("/x402/capabilities"',
            'fetch("/pay"',
            'fetch("/demo/x402/receipt"',
        ):
            with self.subTest(endpoint=endpoint):
                self.assertIn(endpoint, response.text)

        self.assertIn("JSON.stringify(canonicalJson(first.body))", response.text)
        self.assertIn("JSON.stringify(canonicalJson(second.body))", response.text)

        for forbidden_text in (
            "Circle Marketplace",
            "circle_marketplace_company_research",
            "X-Admin-Secret",
            "ARC_PRIVATE_KEY",
            "CIRCLE_API_KEY",
            "demo-local-receipt-only",
            "demo-team-token",
        ):
            with self.subTest(forbidden_text=forbidden_text):
                self.assertNotIn(forbidden_text, response.text)

        self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertEqual(response.headers["referrer-policy"], "no-referrer")
        content_security_policy = response.headers["content-security-policy"]
        self.assertIn("connect-src 'self'", content_security_policy)
        self.assertIn("form-action 'none'", content_security_policy)
        self.assertIn("frame-ancestors 'none'", content_security_policy)

    def test_demo_pages_are_hidden_without_access_token(self) -> None:
        with TestClient(main.app) as client:
            landing_response = client.get("/demo/agent-security")
            console_response = client.get("/demo/console")
            x402_response = client.get("/demo/x402")
        self.assertEqual(landing_response.status_code, 404)
        self.assertEqual(console_response.status_code, 404)
        self.assertEqual(x402_response.status_code, 404)

    def test_demo_receipt_requires_gate_and_limited_payment_scope(self) -> None:
        pay_to = "0x530271DA8CC4e44375f22ad9632bC61A55382f88"
        issued: dict[str, Any] = {}

        def fake_issue_receipt(**kwargs: Any) -> dict[str, Any]:
            issued.update(kwargs)
            return {
                "token": "opaque-demo-receipt",
                "expires_at": "2026-07-28T12:00:00+00:00",
            }

        setup_demo_api(
            demo_access_token="demo-team-token",
            demo_x402_receipt_enabled=True,
            issue_receipt=fake_issue_receipt,
            append_audit_entry=main.append_audit_entry,
            pay_to_address=pay_to,
            get_current_identity=main.get_current_identity,
            ensure_scope=main.ensure_scope,
        )

        with TestClient(main.app) as client:
            payment_token = self.issue_oauth_token(client)
            audit_token = self.issue_oauth_token(client, scopes="audit:read")
            wrong_agent_token = self.issue_oauth_token(client, agent_id="agent_beta")
            payload = {
                "amount_due": "0.000025",
                "currency": "USDC",
                "pay_to": pay_to,
            }

            hidden = client.post(
                "/demo/x402/receipt",
                json=payload,
                headers={"Authorization": f"Bearer {payment_token}"},
            )
            unauthenticated = client.post(
                "/demo/x402/receipt",
                json=payload,
                headers={"X-Demo-Access": "demo-team-token"},
            )
            insufficient = client.post(
                "/demo/x402/receipt",
                json=payload,
                headers={
                    "X-Demo-Access": "demo-team-token",
                    "Authorization": f"Bearer {audit_token}",
                },
            )
            wrong_agent = client.post(
                "/demo/x402/receipt",
                json=payload,
                headers={
                    "X-Demo-Access": "demo-team-token",
                    "Authorization": f"Bearer {wrong_agent_token}",
                },
            )
            allowed = client.post(
                "/demo/x402/receipt",
                json=payload,
                headers={
                    "X-Demo-Access": "demo-team-token",
                    "Authorization": f"Bearer {payment_token}",
                },
            )

        self.assertEqual(hidden.status_code, 404)
        self.assertEqual(unauthenticated.status_code, 401)
        self.assertEqual(insufficient.status_code, 403)
        self.assertEqual(wrong_agent.status_code, 403)
        self.assertEqual(allowed.status_code, 200)
        self.assertEqual(allowed.headers["cache-control"], "no-store")
        self.assertEqual(
            allowed.json(),
            {
                "status": "scaffolded",
                "receipt_mode": "signed_receipt_fallback",
                "broadcast": False,
                "rpc_verified": False,
                "receipt_token": "opaque-demo-receipt",
                "expires_at": "2026-07-28T12:00:00+00:00",
            },
        )
        self.assertEqual(str(issued["amount_due"]), "0.000025")
        self.assertEqual(issued["currency"], "USDC")
        self.assertEqual(issued["pay_to"], pay_to)
        self.assertEqual(issued["expires_in_seconds"], 120)
        audit_entry = main.store.list_audit_entries()[-1]
        self.assertEqual(audit_entry["action"], "demo_x402_receipt_issue")
        self.assertEqual(audit_entry["decision_details"]["broadcast"], False)
        self.assertNotIn("receipt_token", audit_entry["request_payload_summary"])

    def test_demo_receipt_rejects_broad_or_malformed_requests(self) -> None:
        pay_to = "0x530271DA8CC4e44375f22ad9632bC61A55382f88"
        setup_demo_api(
            demo_access_token="demo-team-token",
            demo_x402_receipt_enabled=True,
            issue_receipt=lambda **_kwargs: {
                "token": "unused",
                "expires_at": "2026-07-28T12:00:00+00:00",
            },
            append_audit_entry=main.append_audit_entry,
            pay_to_address=pay_to,
            get_current_identity=main.get_current_identity,
            ensure_scope=main.ensure_scope,
        )

        with TestClient(main.app) as client:
            token = self.issue_oauth_token(client)
            headers = {
                "X-Demo-Access": "demo-team-token",
                "Authorization": f"Bearer {token}",
            }
            invalid_payloads = [
                {"amount_due": "0.001001", "currency": "USDC", "pay_to": pay_to},
                {"amount_due": "0.000025", "currency": "USD", "pay_to": pay_to},
                {
                    "amount_due": "0.000025",
                    "currency": "USDC",
                    "pay_to": "0x0000000000000000000000000000000000000000",
                },
                {
                    "amount_due": "0.000025",
                    "currency": "USDC",
                    "pay_to": pay_to,
                    "expires_in_seconds": 3600,
                },
                {"amount_due": "0.0000001", "currency": "USDC", "pay_to": pay_to},
                {"amount_due": "0.000026", "currency": "USDC", "pay_to": pay_to},
            ]
            responses = [
                client.post("/demo/x402/receipt", json=payload, headers=headers)
                for payload in invalid_payloads
            ]

        self.assertTrue(all(response.status_code == 422 for response in responses))

    def test_x402_demo_requires_explicit_receipt_enable_flag(self) -> None:
        setup_demo_api(
            demo_access_token="demo-team-token",
            demo_x402_receipt_enabled=False,
            issue_receipt=None,
            append_audit_entry=None,
            pay_to_address=None,
            get_current_identity=main.get_current_identity,
            ensure_scope=main.ensure_scope,
        )

        with TestClient(main.app) as client:
            page = client.get("/demo/x402?access_token=demo-team-token")
            receipt = client.post(
                "/demo/x402/receipt",
                json={
                    "amount_due": "0.000025",
                    "currency": "USDC",
                    "pay_to": "0x530271DA8CC4e44375f22ad9632bC61A55382f88",
                },
                headers={"X-Demo-Access": "demo-team-token"},
            )
            informational_page = client.get(
                "/demo/agent-security?access_token=demo-team-token"
            )

        self.assertEqual(page.status_code, 404)
        self.assertEqual(receipt.status_code, 404)
        self.assertEqual(informational_page.status_code, 200)

    def test_demo_receipt_is_rate_limited(self) -> None:
        pay_to = "0x530271DA8CC4e44375f22ad9632bC61A55382f88"
        setup_demo_api(
            demo_access_token="demo-team-token",
            demo_x402_receipt_enabled=True,
            issue_receipt=lambda **_kwargs: {
                "token": "rate-limited-demo-receipt",
                "expires_at": "2026-07-28T12:00:00+00:00",
            },
            append_audit_entry=main.append_audit_entry,
            pay_to_address=pay_to,
            get_current_identity=main.get_current_identity,
            ensure_scope=main.ensure_scope,
        )
        original_limit = main.rate_limiter.limit
        main.rate_limiter.limit = 1
        main.rate_limiter.reset()
        try:
            with TestClient(main.app) as client:
                token = self.issue_oauth_token(client)
                headers = {
                    "X-Demo-Access": "demo-team-token",
                    "Authorization": f"Bearer {token}",
                }
                payload = {
                    "amount_due": "0.000025",
                    "currency": "USDC",
                    "pay_to": pay_to,
                }
                first = client.post("/demo/x402/receipt", json=payload, headers=headers)
                second = client.post("/demo/x402/receipt", json=payload, headers=headers)
        finally:
            main.rate_limiter.limit = original_limit
            main.rate_limiter.reset()

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 429)


if __name__ == "__main__":
    unittest.main()
