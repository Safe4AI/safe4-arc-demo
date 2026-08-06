from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap

import pytest


ROOT = Path(__file__).resolve().parents[1]
PAY_TO = "0x530271DA8CC4e44375f22ad9632bC61A55382f88"
SCENARIOS = (
    "single_allow",
    "three_sequential_allows",
    "intent_mismatch_deny",
    "scope_cap_deny",
    "receipt_replay",
    "identical_idempotent_retry",
)


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_local_judge_demo_scenario_matrix(scenario: str) -> None:
    """Exercise judge-facing scenarios through the real local ``/pay`` path."""

    script = textwrap.dedent(
        """
        import os
        from pathlib import Path

        from fastapi.testclient import TestClient

        from app import main


        scenario = os.environ["SAFE4_JUDGE_SCENARIO"]
        expected_db = Path(os.environ["PAYMENT_FIREWALL_DB_PATH"]).resolve()
        assert not main.POSTGRES_DSN
        assert Path(main.DB_URL).resolve() == expected_db

        matching_task = (
            "Research competitor pricing using a paid company data service."
        )


        def payment_payload(
            purpose: str,
            *,
            task_id: str,
            scope_max_cost: float | None = None,
            task: str = matching_task,
            vendor: str = "demo_company_research_api",
            service_category: str = "company-research",
        ) -> dict[str, object]:
            payload: dict[str, object] = {
                "agent_id": "agent_alpha",
                "user_id": "user_123",
                "vendor": vendor,
                "amount": 0.01,
                "currency": "USDC",
                "description": purpose,
                "context": {
                    "payment_intent": {
                        "task_id": task_id,
                        "task": task,
                        "allowed_service_categories": [service_category],
                        "service_category": service_category,
                        "purchase_purpose": purpose,
                    }
                },
            }
            if scope_max_cost is not None:
                payload["scope_of_autonomy"] = {"max_cost": scope_max_cost}
            return payload


        def issue_demo_receipt(
            client: TestClient,
            auth_headers: dict[str, str],
            payload: dict[str, object],
        ) -> str:
            challenge_response = client.post(
                "/pay", json=payload, headers=auth_headers
            )
            assert challenge_response.status_code == 402, challenge_response.text
            details = challenge_response.json()["details"]
            challenge = details["x402_challenge"]
            assert challenge["status"] == "scaffolded"
            assert challenge["builder_name"] == "stub"
            assert challenge["settlement_method"] == "signed_receipt_fallback"
            assert challenge["amount"] == "0.000025"

            receipt_response = client.post(
                "/demo/x402/receipt",
                json={
                    "amount_due": challenge["amount"],
                    "currency": challenge["currency"],
                    "pay_to": details["pay_to"],
                },
                headers=auth_headers | {"X-Demo-Access": "safe4-local-demo"},
            )
            assert receipt_response.status_code == 200, receipt_response.text
            receipt = receipt_response.json()
            assert receipt["status"] == "scaffolded"
            assert receipt["receipt_mode"] == "signed_receipt_fallback"
            assert receipt["broadcast"] is False
            assert receipt["rpc_verified"] is False
            return str(receipt["receipt_token"])


        def authorize(
            client: TestClient,
            auth_headers: dict[str, str],
            payload: dict[str, object],
            *,
            idempotency_key: str | None = None,
        ):
            receipt_token = issue_demo_receipt(client, auth_headers, payload)
            headers = auth_headers | {"X-Payment-Receipt": receipt_token}
            if idempotency_key is not None:
                headers["Idempotency-Key"] = idempotency_key
            return client.post("/pay", json=payload, headers=headers), receipt_token


        def user_spend() -> str:
            return format(main.store.get_budget("user_123")["spent_today"], "f")


        def agent_spend() -> str:
            return format(
                main.store.get_agent_budget("agent_alpha")["spent_today"], "f"
            )


        def authorized_log_count() -> int:
            return sum(
                entry["result"] == "AUTHORIZED"
                for entry in main.store.list_logs()
            )


        verifier = "j" * 43
        with TestClient(main.app) as client:
            authorization = client.post(
                "/oauth/authorize",
                json={
                    "client_id": "dev-public-client",
                    "redirect_uri": "https://localhost/callback",
                    "scope": "payment:authorize audit:read",
                    "code_challenge": main.compute_code_challenge(verifier),
                    "code_challenge_method": "S256",
                    "subject": "safe4_judge_scenario_test",
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

            if scenario == "single_allow":
                payload = payment_payload(
                    "Generate a competitor pricing research brief from company data.",
                    task_id="judge_single_allow",
                )
                response, _ = authorize(client, auth_headers, payload)

                assert response.status_code == 200, response.text
                assert response.json()["status"] == "AUTHORIZED"
                assert (
                    response.json()["intent_decision"]["reason_code"]
                    == "TASK_PURCHASE_MATCH"
                )
                assert user_spend() == "0.010000"
                assert agent_spend() == "0.010000"
                assert authorized_log_count() == 1

            elif scenario == "three_sequential_allows":
                service_requests = (
                    {
                        "vendor": "demo_market_data_api",
                        "service_category": "market-data",
                        "task": (
                            "Monitor crypto market data and prices for the daily "
                            "risk report."
                        ),
                        "purpose": (
                            "Purchase current crypto market data and prices for "
                            "the daily risk report."
                        ),
                    },
                    {
                        "vendor": "demo_compute_api",
                        "service_category": "compute",
                        "task": (
                            "Run hosted compute inference for the portfolio risk "
                            "analysis."
                        ),
                        "purpose": (
                            "Purchase hosted compute inference for the portfolio "
                            "risk analysis."
                        ),
                    },
                    {
                        "vendor": "demo_agent_memory",
                        "service_category": "agent-memory",
                        "task": (
                            "Store agent memory records for the customer support "
                            "task."
                        ),
                        "purpose": (
                            "Purchase agent memory storage for the customer support "
                            "task."
                        ),
                    },
                )
                idempotency_keys = (
                    "10000000-0000-4000-8000-000000000001",
                    "10000000-0000-4000-8000-000000000002",
                    "10000000-0000-4000-8000-000000000003",
                )
                transaction_ids: set[str] = set()
                for index, (service_request, idempotency_key) in enumerate(
                    zip(service_requests, idempotency_keys, strict=True), start=1
                ):
                    payload = payment_payload(
                        service_request["purpose"],
                        task_id=f"judge_sequential_{index}",
                        task=service_request["task"],
                        vendor=service_request["vendor"],
                        service_category=service_request["service_category"],
                    )
                    response, _ = authorize(
                        client,
                        auth_headers,
                        payload,
                        idempotency_key=idempotency_key,
                    )
                    assert response.status_code == 200, response.text
                    assert response.json()["status"] == "AUTHORIZED"
                    assert (
                        response.json()["intent_decision"]["reason_code"]
                        == "TASK_PURCHASE_MATCH"
                    )
                    transaction_ids.add(response.json()["transaction_id"])

                assert len(transaction_ids) == 3
                assert user_spend() == "0.030000"
                assert agent_spend() == "0.030000"
                assert authorized_log_count() == 3

            elif scenario == "intent_mismatch_deny":
                payload = payment_payload(
                    "Purchase a gift card for an unrelated entertainment giveaway.",
                    task_id="judge_intent_mismatch",
                )
                response, _ = authorize(client, auth_headers, payload)

                assert response.status_code == 403, response.text
                assert response.json()["code"] == "INTENT_VERIFICATION_FAILED"
                assert (
                    response.json()["details"]["intent_decision"]["reason_code"]
                    == "PURCHASE_PURPOSE_MISMATCH"
                )
                assert response.json().get("status") != "AUTHORIZED"
                assert user_spend() == "0.000000"
                assert agent_spend() == "0.000000"
                assert authorized_log_count() == 0

            elif scenario == "scope_cap_deny":
                payload = payment_payload(
                    "Generate a competitor pricing research brief from company data.",
                    task_id="judge_scope_cap",
                    scope_max_cost=0.005,
                )
                response, _ = authorize(client, auth_headers, payload)

                assert response.status_code == 403, response.text
                assert (
                    response.json()["code"]
                    == "SCOPE_OF_AUTONOMY_MAX_COST_EXCEEDED"
                )
                assert response.json().get("status") != "AUTHORIZED"
                assert user_spend() == "0.000000"
                assert agent_spend() == "0.000000"
                assert authorized_log_count() == 0

            elif scenario == "receipt_replay":
                first_payload = payment_payload(
                    "Generate a competitor pricing research brief from company data.",
                    task_id="judge_receipt_first",
                )
                first, used_receipt = authorize(
                    client, auth_headers, first_payload
                )
                assert first.status_code == 200, first.text

                replay_payload = payment_payload(
                    "Analyze competitor pricing using paid company data research.",
                    task_id="judge_receipt_replay",
                )
                replay = client.post(
                    "/pay",
                    json=replay_payload,
                    headers=auth_headers | {"X-Payment-Receipt": used_receipt},
                )

                assert replay.status_code == 402, replay.text
                assert replay.json()["code"] == "PAYMENT_RECEIPT_ALREADY_USED"
                assert replay.json().get("status") != "AUTHORIZED"
                assert user_spend() == "0.010000"
                assert agent_spend() == "0.010000"
                assert authorized_log_count() == 1

            elif scenario == "identical_idempotent_retry":
                payload = payment_payload(
                    "Build another competitor pricing research brief from company data.",
                    task_id="judge_idempotent_retry",
                )
                receipt_token = issue_demo_receipt(client, auth_headers, payload)
                headers = auth_headers | {
                    "X-Payment-Receipt": receipt_token,
                    "Idempotency-Key": "20000000-0000-4000-8000-000000000001",
                }
                log_count_before = len(main.store.list_logs())

                first = client.post("/pay", json=payload, headers=headers)
                spend_after_first = user_spend()
                second = client.post("/pay", json=payload, headers=headers)

                assert first.status_code == 200, first.text
                assert second.status_code == 200, second.text
                assert first.json() == second.json()
                assert spend_after_first == "0.010000"
                assert user_spend() == "0.010000"
                assert agent_spend() == "0.010000"
                assert len(main.store.list_logs()) - log_count_before == 1
                assert authorized_log_count() == 1

            else:
                raise AssertionError(f"Unknown scenario: {scenario}")

            expected_receipts = 3 if scenario == "three_sequential_allows" else 1
            demo_receipt_audits = [
                entry
                for entry in main.store.list_audit_entries()
                if entry["action"] == "demo_x402_receipt_issue"
            ]
            assert len(demo_receipt_audits) == expected_receipts
            assert all(
                entry["decision_details"]["broadcast"] is False
                and entry["decision_details"]["rpc_verified"] is False
                for entry in demo_receipt_audits
            )
        """
    )

    with tempfile.TemporaryDirectory(
        prefix=f"safe4-judge-{scenario}-"
    ) as temp_dir:
        database_path = Path(temp_dir) / "safe4-judge-scenario.db"
        environment = os.environ.copy()
        environment.pop("PAYMENT_FIREWALL_POSTGRES_DSN", None)
        environment.update(
            {
                "SAFE4_JUDGE_SCENARIO": scenario,
                "PAYMENT_FIREWALL_ENV": "development",
                "PAYMENT_FIREWALL_DB_PATH": str(database_path),
                "PAYMENT_FIREWALL_ADMIN_SECRET": "judge-test-admin-only",
                "PAYMENT_FIREWALL_RECEIPT_SECRET": "judge-test-receipt-only",
                "PAYMENT_FIREWALL_DEMO_ACCESS_TOKEN": "safe4-local-demo",
                "PAYMENT_FIREWALL_DEMO_X402_RECEIPT_ENABLED": "true",
                "PAYMENT_FIREWALL_PAY_TO": PAY_TO,
                "PAYMENT_FIREWALL_FEE_RATE": "0.0025",
                "PAYMENT_FIREWALL_PHASE3_X402_ADVANCED_ENABLED": "true",
                "PAYMENT_FIREWALL_PHASE3_AP2_ENABLED": "false",
                "PAYMENT_FIREWALL_PHASE3_INFRASTRUCTURE_IDENTITY_ENABLED": (
                    "false"
                ),
                "PAYMENT_FIREWALL_X402_SUPPORTED_NETWORKS": "arc-testnet",
                "PAYMENT_FIREWALL_X402_NETWORK_RECIPIENTS": (
                    f"arc-testnet:{PAY_TO}"
                ),
                "PAYMENT_FIREWALL_RATE_LIMIT_REQUESTS": "240",
                "PAYMENT_FIREWALL_VELOCITY_LIMIT": "20",
                "PAYMENT_FIREWALL_WEBHOOK_DISPATCH_ENABLED": "false",
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
        f"judge scenario {scenario!r} subprocess failed\n"
        f"stdout:\n{result.stdout}\n"
        f"stderr:\n{result.stderr}"
    )
