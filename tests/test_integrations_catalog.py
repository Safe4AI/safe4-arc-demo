from __future__ import annotations

import unittest

from app.integrations.catalog import (
    ProviderDomain,
    get_integration_candidate,
    list_integration_candidates,
)
from app.integrations.registry import IntegrationAdapterRegistry


class _FakeAdapter:
    adapter_name = "fake_stripe_identity"
    provider_slug = "stripe_identity"
    domain = "kyc_individual"

    def describe(self) -> dict[str, str]:
        return {
            "adapter_name": self.adapter_name,
            "provider_slug": self.provider_slug,
            "domain": self.domain,
        }


class IntegrationCatalogTests(unittest.TestCase):
    def test_candidate_lookup_by_slug(self) -> None:
        candidate = get_integration_candidate("stripe_identity")
        self.assertIsNotNone(candidate)
        assert candidate is not None
        self.assertEqual(candidate.provider_name, "Stripe Identity")

    def test_range_candidate_is_listed_for_crypto_screening(self) -> None:
        candidate = get_integration_candidate("range_risk")
        self.assertIsNotNone(candidate)
        assert candidate is not None
        self.assertEqual(candidate.domain, ProviderDomain.CRYPTO_SCREENING)

    def test_candidate_filter_by_domain(self) -> None:
        candidates = list_integration_candidates(domain=ProviderDomain.KYC_INDIVIDUAL)
        self.assertTrue(any(candidate.provider_slug == "stripe_identity" for candidate in candidates))
        self.assertTrue(any(candidate.provider_slug == "veriff" for candidate in candidates))

    def test_registry_registers_and_describes_adapters(self) -> None:
        registry = IntegrationAdapterRegistry()
        registry.register(_FakeAdapter())
        self.assertIsNotNone(registry.get("fake_stripe_identity"))
        described = registry.describe_all()
        self.assertEqual(described[0]["provider_slug"], "stripe_identity")


if __name__ == "__main__":
    unittest.main()
