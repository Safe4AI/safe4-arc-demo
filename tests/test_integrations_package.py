from __future__ import annotations

import unittest

from app.integrations.errors import ProviderIntegrationError
from app.integrations.health import ProviderHealthStatus
from app.integrations.models import ProviderCredentials
from app.integrations.catalog import PAYPERUSE_INTEGRATION_CANDIDATES
from app.integrations.config import (
    CredentialSourceKind,
    ProviderCredentialRef,
    ProviderEndpointConfig,
    ProviderEnvironment,
    ProviderRuntimeConfig,
    build_provider_env_var_name,
    default_api_key_ref,
)


class IntegrationsPackageTests(unittest.TestCase):
    def test_provider_health_status_shape(self) -> None:
        status = ProviderHealthStatus(provider_name="demo", healthy=True, detail="ok")
        self.assertEqual(status.provider_name, "demo")
        self.assertTrue(status.healthy)

    def test_provider_error_normalization_shape(self) -> None:
        error = ProviderIntegrationError("demo", "BAD_REQUEST", "failure")
        self.assertEqual(error.provider_name, "demo")
        self.assertEqual(error.code, "BAD_REQUEST")

    def test_provider_credentials_shape(self) -> None:
        credentials = ProviderCredentials("demo", "api_key", key_id="v1", secret_ref="env:DEMO")
        self.assertEqual(credentials.key_id, "v1")

    def test_payperuse_catalog_is_present(self) -> None:
        self.assertTrue(PAYPERUSE_INTEGRATION_CANDIDATES)

    def test_provider_env_var_naming_convention(self) -> None:
        self.assertEqual(
            build_provider_env_var_name("stripe_identity", "api_key"),
            "SAFE4_PROVIDER_STRIPE_IDENTITY_API_KEY",
        )

    def test_default_api_key_ref_uses_env_source(self) -> None:
        ref = default_api_key_ref("veriff")
        self.assertEqual(ref.source_kind, CredentialSourceKind.ENV)
        self.assertEqual(ref.source_value, "SAFE4_PROVIDER_VERIFF_API_KEY")

    def test_provider_runtime_config_shape(self) -> None:
        config = ProviderRuntimeConfig(
            provider_slug="stripe_identity",
            environment=ProviderEnvironment.SANDBOX,
            endpoint=ProviderEndpointConfig(base_url="https://sandbox.example", timeout_seconds=10.0),
            credential_refs=(
                ProviderCredentialRef(
                    field_name="api_key",
                    source_kind=CredentialSourceKind.ENV,
                    source_value="SAFE4_PROVIDER_STRIPE_IDENTITY_API_KEY",
                ),
            ),
        )
        self.assertEqual(config.environment, ProviderEnvironment.SANDBOX)
        self.assertEqual(config.endpoint.timeout_seconds, 10.0)


if __name__ == "__main__":
    unittest.main()
