from __future__ import annotations

import unittest

from fastapi.testclient import TestClient

from app import main, webhooks_api
from app.api import integrations
from app.integrations.range import RangeHttpResponse, reset_range_requester_for_tests, set_range_requester_for_tests


class IntegrationsApiTests(unittest.TestCase):
    def setUp(self) -> None:
        main.reset_runtime_state()
        webhooks_api.reset_webhook_sender_for_tests()
        reset_range_requester_for_tests()
        self.client = TestClient(main.app)
        self.client_id = "dev-public-client"
        self.oauth = self.issue_oauth_tokens("admin:all audit:read", "operator_integrations")

    def tearDown(self) -> None:
        reset_range_requester_for_tests()

    def issue_oauth_tokens(self, scopes: str, subject: str) -> dict[str, str]:
        verifier = "b" * 43
        authorize = self.client.post(
            "/oauth/authorize",
            json={
                "client_id": self.client_id,
                "redirect_uri": "https://localhost/callback",
                "scope": scopes,
                "code_challenge": main.compute_code_challenge(verifier),
                "code_challenge_method": "S256",
                "subject": subject,
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

    def auth_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.oauth['access_token']}"}

    def test_router_module_exports_router(self) -> None:
        self.assertTrue(hasattr(integrations, "router"))

    def test_list_integrations_providers_includes_range(self) -> None:
        response = self.client.get("/integrations/providers", headers=self.auth_headers())
        self.assertEqual(response.status_code, 200)
        provider_slugs = {item["provider_slug"] for item in response.json()["providers"]}
        self.assertIn("range_risk", provider_slugs)

    def test_range_address_risk_endpoint_returns_provider_result(self) -> None:
        original_get_range_api_key = main.get_range_api_key
        main.get_range_api_key = lambda: "range_test_key"
        try:
            main.setup_integrations_api(
                get_current_identity=main.get_current_identity,
                ensure_scope=main.ensure_scope,
                registry=main.INTEGRATION_ADAPTER_REGISTRY,
                range_provider_config=main.RANGE_PROVIDER_CONFIG,
                get_range_api_key=main.get_range_api_key,
            )
            set_range_requester_for_tests(
                lambda **_: RangeHttpResponse(
                    status_code=200,
                    payload={
                        "riskScore": 74,
                        "riskLevel": "medium",
                        "numHops": 1,
                        "maliciousAddressesFound": [],
                        "reasoning": "indirect exposure",
                        "attribution": {"vendor": "range"},
                    },
                )
            )
            response = self.client.post(
                "/integrations/range/address-risk",
                json={"address": "0xabc", "network": "ethereum"},
                headers=self.auth_headers(),
            )
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()["result"]["risk_score"], 74)
        finally:
            main.get_range_api_key = original_get_range_api_key
            main.setup_integrations_api(
                get_current_identity=main.get_current_identity,
                ensure_scope=main.ensure_scope,
                registry=main.INTEGRATION_ADAPTER_REGISTRY,
                range_provider_config=main.RANGE_PROVIDER_CONFIG,
                get_range_api_key=main.get_range_api_key,
            )

    def test_range_sanctions_endpoint_returns_provider_result(self) -> None:
        original_get_range_api_key = main.get_range_api_key
        main.get_range_api_key = lambda: "range_test_key"
        try:
            main.setup_integrations_api(
                get_current_identity=main.get_current_identity,
                ensure_scope=main.ensure_scope,
                registry=main.INTEGRATION_ADAPTER_REGISTRY,
                range_provider_config=main.RANGE_PROVIDER_CONFIG,
                get_range_api_key=main.get_range_api_key,
            )
            set_range_requester_for_tests(
                lambda **_: RangeHttpResponse(
                    status_code=200,
                    payload={
                        "address": "0xabc",
                        "network": "ethereum",
                        "is_token_blacklisted": True,
                        "is_ofac_sanctioned": False,
                        "checked_at": "2026-03-22T00:00:00+00:00",
                        "token_status_summary": [{"source": "ofac", "status": "clear"}],
                        "attribution": {"vendor": "range"},
                    },
                )
            )
            response = self.client.post(
                "/integrations/range/sanctions",
                json={"address": "0xabc", "network": "ethereum", "include_details": True},
                headers=self.auth_headers(),
            )
            self.assertEqual(response.status_code, 200)
            self.assertTrue(response.json()["result"]["is_token_blacklisted"])
        finally:
            main.get_range_api_key = original_get_range_api_key
            main.setup_integrations_api(
                get_current_identity=main.get_current_identity,
                ensure_scope=main.ensure_scope,
                registry=main.INTEGRATION_ADAPTER_REGISTRY,
                range_provider_config=main.RANGE_PROVIDER_CONFIG,
                get_range_api_key=main.get_range_api_key,
            )


if __name__ == "__main__":
    unittest.main()
