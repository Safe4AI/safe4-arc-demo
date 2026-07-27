from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class ProviderDomain(StrEnum):
    KYC_INDIVIDUAL = "kyc_individual"
    KYB_BUSINESS = "kyb_business"
    BANK_IDENTITY = "bank_identity"
    CRYPTO_SCREENING = "crypto_screening"
    CRYPTO_PROTECTION = "crypto_protection"
    FIAT_FRAUD = "fiat_fraud"
    UNIFIED_COMPLIANCE = "unified_compliance"


@dataclass(frozen=True)
class IntegrationCandidate:
    provider_name: str
    provider_slug: str
    domain: ProviderDomain
    startup_fit: str
    pricing_clarity: str
    notes: str


PAYPERUSE_INTEGRATION_CANDIDATES: tuple[IntegrationCandidate, ...] = (
    IntegrationCandidate("Stripe Identity", "stripe_identity", ProviderDomain.KYC_INDIVIDUAL, "high", "high", "clear per-verification pricing"),
    IntegrationCandidate("Veriff", "veriff", ProviderDomain.KYC_INDIVIDUAL, "high", "high", "clear self-serve pricing"),
    IntegrationCandidate("Plaid", "plaid", ProviderDomain.BANK_IDENTITY, "high", "medium_high", "pay-as-you-go bank and identity coverage"),
    IntegrationCandidate("Middesk", "middesk", ProviderDomain.KYB_BUSINESS, "medium_high", "medium", "KYB-focused startup path"),
    IntegrationCandidate("GoPlus Security", "goplus_security", ProviderDomain.CRYPTO_SCREENING, "high", "medium", "crypto screening with accessible entry point"),
    IntegrationCandidate("Range Risk API", "range_risk", ProviderDomain.CRYPTO_SCREENING, "high", "medium_high", "address risk scoring and sanctions screening with self-serve API key"),
    IntegrationCandidate("Harpie", "harpie", ProviderDomain.CRYPTO_PROTECTION, "high", "medium", "broad wallet protection orientation"),
    IntegrationCandidate("Blockmate", "blockmate", ProviderDomain.CRYPTO_SCREENING, "medium_high", "low", "free API key path but limited public pricing detail"),
    IntegrationCandidate("Sardine", "sardine", ProviderDomain.FIAT_FRAUD, "medium", "low", "custom pricing and broader fraud/compliance platform"),
    IntegrationCandidate("Alloy", "alloy", ProviderDomain.FIAT_FRAUD, "medium", "low", "orchestration-heavy fraud and identity platform"),
    IntegrationCandidate("Sift", "sift", ProviderDomain.FIAT_FRAUD, "low", "medium", "powerful but often too expensive for MVP"),
    IntegrationCandidate("Sumsub", "sumsub", ProviderDomain.UNIFIED_COMPLIANCE, "medium", "high", "transparent unified compliance platform"),
    IntegrationCandidate("Flagright", "flagright", ProviderDomain.UNIFIED_COMPLIANCE, "medium", "low", "unified compliance direction with custom pricing"),
)


def list_integration_candidates(*, domain: ProviderDomain | None = None) -> list[IntegrationCandidate]:
    if domain is None:
        return list(PAYPERUSE_INTEGRATION_CANDIDATES)
    return [candidate for candidate in PAYPERUSE_INTEGRATION_CANDIDATES if candidate.domain == domain]


def get_integration_candidate(provider_slug: str) -> IntegrationCandidate | None:
    for candidate in PAYPERUSE_INTEGRATION_CANDIDATES:
        if candidate.provider_slug == provider_slug:
            return candidate
    return None
