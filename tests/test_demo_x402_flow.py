from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap


ROOT = Path(__file__).resolve().parents[1]
PAY_TO = "0x530271DA8CC4e44375f22ad9632bC61A55382f88"


def test_browser_demo_contract_runs_real_allow_and_deny_paths() -> None:
    """Exercise a clean import with the exact local-demo environment contract."""

    script = textwrap.dedent(
        """
        from fastapi.testclient import TestClient
        from app import main

        verifier = "d" * 43
        with TestClient(main.app) as client:
            authorization = client.post(
                "/oauth/authorize",
                json={
                    "client_id": "dev-public-client",
                    "redirect_uri": "https://localhost/callback",
                    "scope": "payment:authorize audit:read",
                    "code_challenge": main.compute_code_challenge(verifier),
                    "code_challenge_method": "S256",
                    "subject": "safe4_demo_integration",
                    "agent_id": "agent_alpha",
                },
            )
            assert authorization.status_code == 200, authorization.text
            token_response = client.post(
                "/oauth/token",
                json={
                    "grant_type": "authorization_code",
                    "client_id": "dev-public-client",
                    "code": authorization.json()["code"],
                    "redirect_uri": "https://localhost/callback",
                    "code_verifier": verifier,
                },
            )
            assert token_response.status_code == 200, token_response.text
            auth_headers = {
                "Authorization": f"Bearer {token_response.json()['access_token']}"
            }

            capabilities = client.get("/x402/capabilities", headers=auth_headers)
            assert capabilities.status_code == 200, capabilities.text
            assert capabilities.json()["enabled"] is True
            assert capabilities.json()["supported_networks"] == ["arc-testnet"]

            scenarios = (
                (
                    "Generate a competitor pricing research brief from company data.",
                    200,
                    "TASK_PURCHASE_MATCH",
                ),
                (
                    "Purchase a gift card for an unrelated entertainment giveaway.",
                    403,
                    "PURCHASE_PURPOSE_MISMATCH",
                ),
            )
            for purpose, expected_status, expected_reason in scenarios:
                payload = {
                    "agent_id": "agent_alpha",
                    "user_id": "user_123",
                    "vendor": "circle_marketplace_company_research",
                    "amount": 0.01,
                    "currency": "USDC",
                    "description": purpose,
                    "context": {
                        "payment_intent": {
                            "task_id": "task_competitor_pricing_001",
                            "task": (
                                "Research competitor pricing using a paid "
                                "company data service."
                            ),
                            "allowed_service_categories": ["company-research"],
                            "service_category": "company-research",
                            "purchase_purpose": purpose,
                        }
                    },
                }
                first = client.post("/pay", json=payload, headers=auth_headers)
                assert first.status_code == 402, first.text
                details = first.json()["details"]
                challenge = details["x402_challenge"]
                assert challenge["status"] == "scaffolded"
                assert challenge["builder_name"] == "stub"
                assert challenge["settlement_method"] == "signed_receipt_fallback"
                assert challenge["amount"] == "0.000025"

                receipt = client.post(
                    "/demo/x402/receipt",
                    json={
                        "amount_due": challenge["amount"],
                        "currency": challenge["currency"],
                        "pay_to": details["pay_to"],
                    },
                    headers=auth_headers | {"X-Demo-Access": "safe4-local-demo"},
                )
                assert receipt.status_code == 200, receipt.text
                receipt_body = receipt.json()
                assert receipt_body["status"] == "scaffolded"
                assert receipt_body["receipt_mode"] == "signed_receipt_fallback"
                assert receipt_body["broadcast"] is False
                assert receipt_body["rpc_verified"] is False

                final = client.post(
                    "/pay",
                    json=payload,
                    headers=auth_headers
                    | {"X-Payment-Receipt": receipt_body["receipt_token"]},
                )
                assert final.status_code == expected_status, final.text
                if expected_status == 200:
                    decision = final.json()["intent_decision"]
                else:
                    decision = final.json()["details"]["intent_decision"]
                assert decision["reason_code"] == expected_reason

            demo_audits = [
                entry
                for entry in main.store.list_audit_entries()
                if entry["action"] == "demo_x402_receipt_issue"
            ]
            assert len(demo_audits) == 2
            assert all(
                entry["decision_details"]["broadcast"] is False
                and entry["decision_details"]["rpc_verified"] is False
                for entry in demo_audits
            )
        """
    )

    with tempfile.TemporaryDirectory(prefix="safe4-demo-flow-test-") as temp_dir:
        environment = os.environ.copy()
        environment.pop("PAYMENT_FIREWALL_POSTGRES_DSN", None)
        environment.update(
            {
                "PAYMENT_FIREWALL_ENV": "development",
                "PAYMENT_FIREWALL_DB_PATH": str(
                    Path(temp_dir) / "safe4-demo-flow.db"
                ),
                "PAYMENT_FIREWALL_ADMIN_SECRET": "demo-test-admin-only",
                "PAYMENT_FIREWALL_RECEIPT_SECRET": "demo-test-receipt-only",
                "PAYMENT_FIREWALL_DEMO_ACCESS_TOKEN": "safe4-local-demo",
                "PAYMENT_FIREWALL_DEMO_X402_RECEIPT_ENABLED": "true",
                "PAYMENT_FIREWALL_PAY_TO": PAY_TO,
                "PAYMENT_FIREWALL_FEE_RATE": "0.0025",
                "PAYMENT_FIREWALL_PHASE3_X402_ADVANCED_ENABLED": "true",
                "PAYMENT_FIREWALL_X402_SUPPORTED_NETWORKS": "arc-testnet",
                "PAYMENT_FIREWALL_X402_NETWORK_RECIPIENTS": (
                    f"arc-testnet:{PAY_TO}"
                ),
                "PAYMENT_FIREWALL_RATE_LIMIT_REQUESTS": "120",
            }
        )
        result = subprocess.run(
            [sys.executable, "-c", script],
            cwd=ROOT,
            env=environment,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

    assert result.returncode == 0, (
        f"browser demo integration subprocess failed\n"
        f"stdout:\n{result.stdout}\n"
        f"stderr:\n{result.stderr}"
    )
