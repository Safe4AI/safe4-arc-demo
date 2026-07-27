from __future__ import annotations

import unittest

from app.integrations.config import ProviderEndpointConfig, ProviderEnvironment, ProviderRuntimeConfig
from app.integrations.kyc import (
    KycVerificationRequest,
    StripeIdentitySandboxAdapter,
    VeriffSandboxAdapter,
    VerificationStatus,
    register_default_kyc_sandbox_adapters,
)
from app.integrations.registry import IntegrationAdapterRegistry


class KycIntegrationTests(unittest.TestCase):
    def test_default_kyc_adapters_register(self) -> None:
        registry = IntegrationAdapterRegistry()
        register_default_kyc_sandbox_adapters(registry)
        adapter_names = {item["adapter_name"] for item in registry.describe_all()}
        self.assertIn("stripe_identity_sandbox", adapter_names)
        self.assertIn("veriff_sandbox", adapter_names)

    def test_stripe_identity_sandbox_review_path(self) -> None:
        adapter = StripeIdentitySandboxAdapter()
        result = adapter.verify_identity(
            KycVerificationRequest(
                verification_id="verify_1",
                full_name="Jane Example",
                country_code="US",
                document_type="passport",
                document_number="ABC-REVIEW",
            ),
            config=ProviderRuntimeConfig(
                provider_slug="stripe_identity",
                environment=ProviderEnvironment.SANDBOX,
                endpoint=ProviderEndpointConfig(base_url="https://sandbox.stripe.example"),
            ),
        )
        self.assertEqual(result.status, VerificationStatus.REVIEW)

    def test_veriff_sandbox_reject_path(self) -> None:
        adapter = VeriffSandboxAdapter()
        result = adapter.verify_identity(
            KycVerificationRequest(
                verification_id="verify_2",
                full_name="Jane Example",
                country_code="ZZ",
                document_type="id_card",
                document_number="12345",
            ),
            config=ProviderRuntimeConfig(
                provider_slug="veriff",
                environment=ProviderEnvironment.SANDBOX,
                endpoint=ProviderEndpointConfig(base_url="https://sandbox.veriff.example"),
            ),
        )
        self.assertEqual(result.status, VerificationStatus.REJECTED)

    def test_veriff_sandbox_approve_path(self) -> None:
        adapter = VeriffSandboxAdapter()
        result = adapter.verify_identity(
            KycVerificationRequest(
                verification_id="verify_3",
                full_name="Jane Example",
                country_code="GB",
                document_type="id_card",
                document_number="12345",
            ),
            config=ProviderRuntimeConfig(
                provider_slug="veriff",
                environment=ProviderEnvironment.SANDBOX,
                endpoint=ProviderEndpointConfig(base_url="https://sandbox.veriff.example"),
            ),
        )
        self.assertEqual(result.status, VerificationStatus.APPROVED)


if __name__ == "__main__":
    unittest.main()
