from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from .catalog import ProviderDomain
from .config import ProviderRuntimeConfig
from .errors import ProviderIntegrationError
from .registry import IntegrationAdapterRegistry


class VerificationStatus(StrEnum):
    APPROVED = "approved"
    REVIEW = "review"
    REJECTED = "rejected"


@dataclass(frozen=True)
class KycVerificationRequest:
    verification_id: str
    full_name: str
    country_code: str
    document_type: str
    document_number: str
    email: str | None = None


@dataclass(frozen=True)
class KycVerificationResult:
    provider_slug: str
    status: VerificationStatus
    reference_id: str
    matched_name: str
    reason_code: str | None = None
    sandbox: bool = True


class KycProviderAdapter(Protocol):
    adapter_name: str
    provider_slug: str
    domain: str

    def describe(self) -> dict[str, str]:
        ...

    def verify_identity(
        self,
        request: KycVerificationRequest,
        *,
        config: ProviderRuntimeConfig,
    ) -> KycVerificationResult:
        ...


def _build_reference_id(provider_slug: str, verification_id: str) -> str:
    return f"{provider_slug}:{verification_id}"


class StripeIdentitySandboxAdapter:
    adapter_name = "stripe_identity_sandbox"
    provider_slug = "stripe_identity"
    domain = ProviderDomain.KYC_INDIVIDUAL.value

    def describe(self) -> dict[str, str]:
        return {
            "adapter_name": self.adapter_name,
            "provider_slug": self.provider_slug,
            "domain": self.domain,
            "mode": "sandbox",
        }

    def verify_identity(
        self,
        request: KycVerificationRequest,
        *,
        config: ProviderRuntimeConfig,
    ) -> KycVerificationResult:
        if config.provider_slug != self.provider_slug:
            raise ProviderIntegrationError(self.provider_slug, "CONFIG_PROVIDER_MISMATCH", "provider slug mismatch")
        normalized_document = request.document_number.strip().upper()
        if normalized_document.endswith("REVIEW"):
            return KycVerificationResult(
                provider_slug=self.provider_slug,
                status=VerificationStatus.REVIEW,
                reference_id=_build_reference_id(self.provider_slug, request.verification_id),
                matched_name=request.full_name,
                reason_code="DOCUMENT_REVIEW_REQUIRED",
            )
        if normalized_document.endswith("FAIL"):
            return KycVerificationResult(
                provider_slug=self.provider_slug,
                status=VerificationStatus.REJECTED,
                reference_id=_build_reference_id(self.provider_slug, request.verification_id),
                matched_name=request.full_name,
                reason_code="DOCUMENT_REJECTED",
            )
        return KycVerificationResult(
            provider_slug=self.provider_slug,
            status=VerificationStatus.APPROVED,
            reference_id=_build_reference_id(self.provider_slug, request.verification_id),
            matched_name=request.full_name,
        )


class VeriffSandboxAdapter:
    adapter_name = "veriff_sandbox"
    provider_slug = "veriff"
    domain = ProviderDomain.KYC_INDIVIDUAL.value

    def describe(self) -> dict[str, str]:
        return {
            "adapter_name": self.adapter_name,
            "provider_slug": self.provider_slug,
            "domain": self.domain,
            "mode": "sandbox",
        }

    def verify_identity(
        self,
        request: KycVerificationRequest,
        *,
        config: ProviderRuntimeConfig,
    ) -> KycVerificationResult:
        if config.provider_slug != self.provider_slug:
            raise ProviderIntegrationError(self.provider_slug, "CONFIG_PROVIDER_MISMATCH", "provider slug mismatch")
        normalized_name = request.full_name.strip().lower()
        if "manual review" in normalized_name:
            return KycVerificationResult(
                provider_slug=self.provider_slug,
                status=VerificationStatus.REVIEW,
                reference_id=_build_reference_id(self.provider_slug, request.verification_id),
                matched_name=request.full_name,
                reason_code="NAME_REVIEW_REQUIRED",
            )
        if request.country_code.upper() == "ZZ":
            return KycVerificationResult(
                provider_slug=self.provider_slug,
                status=VerificationStatus.REJECTED,
                reference_id=_build_reference_id(self.provider_slug, request.verification_id),
                matched_name=request.full_name,
                reason_code="UNSUPPORTED_COUNTRY",
            )
        return KycVerificationResult(
            provider_slug=self.provider_slug,
            status=VerificationStatus.APPROVED,
            reference_id=_build_reference_id(self.provider_slug, request.verification_id),
            matched_name=request.full_name,
        )


def register_default_kyc_sandbox_adapters(registry: IntegrationAdapterRegistry) -> None:
    registry.register(StripeIdentitySandboxAdapter())
    registry.register(VeriffSandboxAdapter())
