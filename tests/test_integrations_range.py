from __future__ import annotations

import unittest

from app.integrations.config import ProviderEndpointConfig, ProviderEnvironment, ProviderRuntimeConfig
from app.integrations.errors import ProviderIntegrationError
from app.integrations.range import (
    RangeAddressRiskRequest,
    RangeHttpResponse,
    RangeRiskApiAdapter,
    RangeSanctionsRequest,
    register_default_range_adapters,
)
from app.integrations.registry import IntegrationAdapterRegistry


class RangeIntegrationTests(unittest.TestCase):
    def test_default_range_adapter_registers(self) -> None:
        registry = IntegrationAdapterRegistry()
        register_default_range_adapters(registry)
        adapter = registry.get("range_risk_api")
        self.assertIsNotNone(adapter)
        assert adapter is not None
        self.assertEqual(adapter.describe()["provider_slug"], "range_risk")

    def test_address_risk_normalizes_provider_payload(self) -> None:
        adapter = RangeRiskApiAdapter(
            requester=lambda **_: RangeHttpResponse(
                status_code=200,
                payload={
                    "riskScore": 91,
                    "riskLevel": "high",
                    "numHops": 2,
                    "maliciousAddressesFound": [{"address": "0xbad"}],
                    "reasoning": "linked to sanctioned funds",
                    "attribution": {"vendor": "range"},
                },
            )
        )
        result = adapter.get_address_risk(
            RangeAddressRiskRequest(address="0xabc", network="ethereum"),
            config=ProviderRuntimeConfig(
                provider_slug="range_risk",
                environment=ProviderEnvironment.PRODUCTION,
                endpoint=ProviderEndpointConfig(base_url="https://api.range.org"),
            ),
            api_key="test_key",
        )
        self.assertEqual(result.risk_score, 91)
        self.assertEqual(result.risk_level, "high")

    def test_sanctions_check_normalizes_provider_payload(self) -> None:
        adapter = RangeRiskApiAdapter(
            requester=lambda **_: RangeHttpResponse(
                status_code=200,
                payload={
                    "address": "0xabc",
                    "network": "ethereum",
                    "is_token_blacklisted": True,
                    "is_ofac_sanctioned": False,
                    "checked_at": "2026-03-21T00:00:00+00:00",
                    "token_status_summary": [{"source": "ofac", "status": "clear"}],
                    "attribution": {"vendor": "range"},
                },
            )
        )
        result = adapter.get_sanctions_check(
            RangeSanctionsRequest(address="0xabc", network="ethereum", include_details=True),
            config=ProviderRuntimeConfig(
                provider_slug="range_risk",
                environment=ProviderEnvironment.PRODUCTION,
                endpoint=ProviderEndpointConfig(base_url="https://api.range.org"),
            ),
            api_key="test_key",
        )
        self.assertTrue(result.is_token_blacklisted)
        self.assertFalse(result.is_ofac_sanctioned)

    def test_missing_api_key_raises_provider_error(self) -> None:
        adapter = RangeRiskApiAdapter(requester=lambda **_: RangeHttpResponse(status_code=200, payload={}))
        with self.assertRaises(ProviderIntegrationError) as ctx:
            adapter.get_address_risk(
                RangeAddressRiskRequest(address="0xabc", network="ethereum"),
                config=ProviderRuntimeConfig(
                    provider_slug="range_risk",
                    environment=ProviderEnvironment.PRODUCTION,
                    endpoint=ProviderEndpointConfig(base_url="https://api.range.org"),
                ),
                api_key="",
            )
        self.assertEqual(ctx.exception.code, "RANGE_NOT_CONFIGURED")


if __name__ == "__main__":
    unittest.main()
