from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any, Callable, Protocol

from fastapi import APIRouter, Header, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field


router = APIRouter()

_get_current_identity = None
_ensure_scope: Callable[[Any, list[str]], Any] | None = None
_get_runtime_phase3_features: Callable[[], dict[str, bool]] | None = None
_store = None
_append_audit_entry: Callable[..., None] | None = None
_pay_to_address = ""
_network_recipient_addresses: dict[str, str] = {}
_challenge_ttl_seconds = 0
_supported_networks: list[str] = []
_challenge_builder = None
_receipt_verifier = None
_parse_and_validate_receipt_token: Callable[[str | None], tuple[str | None, dict[str, Any] | None]] | None = None
_normalize_money: Callable[[Decimal], Decimal] | None = None
_provider_shared_secret = ""
_provider_keys: dict[str, str] = {}
_provider_jwks: dict[str, dict[str, Any]] = {}
_provider_adapters: dict[str, Any] = {}
_provider_discovery: dict[str, dict[str, Any]] = {}
_provider_discovery_max_age_seconds = 0
_provider_trust_anchors: dict[str, dict[str, Any]] = {}

PROVIDER_RECEIPT_PREFIX = "x402p1"
PROVIDER_RECEIPT_JWT_PREFIX = "x402j1"
PROVIDER_RECEIPT_VERSION = "x402-provider-receipt-v1"
PROVIDER_RECEIPT_MAX_AGE_SECONDS = 3600
PROVIDER_RECEIPT_FUTURE_SKEW_SECONDS = 60
RS256_SHA256_DIGESTINFO_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")


@dataclass(slots=True)
class X402Challenge:
    amount: str
    currency: str
    recipient_address: str
    recipient_addresses: dict[str, str]
    supported_networks: list[str]
    expiry_seconds: int
    settlement_method: str
    receipt_header: str
    status: str


@dataclass(slots=True)
class X402ReceiptVerificationResult:
    status: str
    receipt_id: str | None
    receipt: dict[str, Any] | None
    reason_code: str | None = None
    verifier_name: str = "unknown"
    receipt_source: str = "signed_receipt_fallback"


class X402ChallengeBuilder(Protocol):
    builder_name: str

    def build(self, *, payment: Any, amount_due: Decimal) -> X402Challenge:
        ...


class X402ReceiptVerifier(Protocol):
    verifier_name: str

    def verify(self, *, payment: Any, amount_due: Decimal, receipt_token: str | None) -> X402ReceiptVerificationResult:
        ...


class X402ProviderAdapter(Protocol):
    adapter_name: str
    verification_mode: str

    def verify_payload(
        self,
        *,
        payment: Any,
        amount_due: Decimal,
        payload: dict[str, Any],
        signature: str,
        signing_input: str | None = None,
        header: dict[str, Any] | None = None,
    ) -> X402ReceiptVerificationResult:
        ...

    def capabilities(self) -> dict[str, Any]:
        ...


class X402ProviderConfigRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    provider_name: str = Field(..., min_length=1)
    adapter_name: str = Field(..., min_length=1)
    issuer_url: str | None = None
    issuer_urls: list[str] = Field(default_factory=list)
    verifier_key_id: str | None = None
    verifier_key_ids: list[str] = Field(default_factory=list)
    trust_anchor_ids: list[str] = Field(default_factory=list)
    required_settlement_proof_type: str | None = None
    minimum_confirmations: int | None = Field(default=None, ge=0)
    supported_networks: list[str] = Field(default_factory=list)
    is_enabled: bool = True
    notes: str | None = None


def _bootstrap_provider_configs() -> None:
    for adapter_name in _provider_adapters:
        if _store.get_x402_provider_config(adapter_name) is None:
            _store.upsert_x402_provider_config(
                provider_name=adapter_name,
                adapter_name=adapter_name,
                issuer_url=None,
                issuer_urls=[],
                verifier_key_id="default",
                verifier_key_ids=["default"],
                trust_anchor_ids=[],
                required_settlement_proof_type="transaction_hash",
                minimum_confirmations=1,
                supported_networks=list(_supported_networks),
                is_enabled=True,
                notes="Auto-bootstrapped from registered x402 provider adapter.",
            )


def _network_recipient_address(network: str | None) -> str:
    if network and network in _network_recipient_addresses:
        return _network_recipient_addresses[network]
    return _pay_to_address


class StubX402ChallengeBuilder:
    builder_name = "stub"

    def build(self, *, payment: Any, amount_due: Decimal) -> X402Challenge:
        recipient_addresses = {network: _network_recipient_address(network) for network in _supported_networks}
        return X402Challenge(
            amount=f"{amount_due:.6f}",
            currency=payment.currency,
            recipient_address=recipient_addresses.get(_supported_networks[0], _pay_to_address) if _supported_networks else _pay_to_address,
            recipient_addresses=recipient_addresses,
            supported_networks=list(_supported_networks),
            expiry_seconds=_challenge_ttl_seconds,
            settlement_method="signed_receipt_fallback",
            receipt_header="X-Payment-Receipt",
            status="scaffolded",
        )


class SignedReceiptFallbackVerifier:
    verifier_name = "signed_receipt_fallback"

    def verify(self, *, payment: Any, amount_due: Decimal, receipt_token: str | None) -> X402ReceiptVerificationResult:
        receipt_id, receipt = _parse_and_validate_receipt_token(receipt_token)
        if receipt is None or receipt.get("status") != "paid" or receipt.get("pay_to") != _pay_to_address:
            return X402ReceiptVerificationResult(
                status="payment_required",
                receipt_id=receipt_id,
                receipt=receipt,
                reason_code="PAYMENT_REQUIRED",
                verifier_name=self.verifier_name,
                receipt_source="signed_receipt_fallback",
            )

        receipt_amount = _normalize_money(Decimal(str(receipt["amount_due"])))
        if receipt.get("used_at"):
            return X402ReceiptVerificationResult(
                status="already_used",
                receipt_id=receipt_id,
                receipt=receipt,
                reason_code="PAYMENT_RECEIPT_ALREADY_USED",
                verifier_name=self.verifier_name,
                receipt_source="signed_receipt_fallback",
            )
        if receipt["expires_at"]:
            from datetime import datetime, timezone

            if datetime.fromisoformat(receipt["expires_at"]) <= datetime.now(timezone.utc):
                return X402ReceiptVerificationResult(
                    status="expired",
                    receipt_id=receipt_id,
                    receipt=receipt,
                    reason_code="PAYMENT_RECEIPT_EXPIRED",
                    verifier_name=self.verifier_name,
                    receipt_source="signed_receipt_fallback",
                )
        if receipt_amount != amount_due or receipt["currency"] != payment.currency:
            return X402ReceiptVerificationResult(
                status="mismatch",
                receipt_id=receipt_id,
                receipt=receipt,
                reason_code="PAYMENT_RECEIPT_MISMATCH",
                verifier_name=self.verifier_name,
                receipt_source="signed_receipt_fallback",
            )
        return X402ReceiptVerificationResult(
            status="accepted",
            receipt_id=receipt_id,
            receipt=receipt,
            verifier_name=self.verifier_name,
            receipt_source="signed_receipt_fallback",
        )


def _base64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")


def _base64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _canonical_provider_payload_segment(payload: dict[str, Any]) -> str:
    return _base64url_encode(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def _verify_rs256_signature(*, signing_input: str, signature_segment: str, signing_key: dict[str, Any]) -> bool:
    try:
        signature = _base64url_decode(signature_segment)
    except Exception:
        return False
    modulus = signing_key.get("modulus")
    exponent = signing_key.get("exponent")
    if not isinstance(modulus, int) or not isinstance(exponent, int) or modulus <= 0 or exponent <= 0:
        return False

    modulus_size = (modulus.bit_length() + 7) // 8
    if len(signature) != modulus_size:
        return False

    signature_int = int.from_bytes(signature, "big")
    if signature_int >= modulus:
        return False

    digest = hashlib.sha256(signing_input.encode("utf-8")).digest()
    padding_length = modulus_size - len(RS256_SHA256_DIGESTINFO_PREFIX) - len(digest) - 3
    if padding_length < 8:
        return False

    expected_message = (
        b"\x00\x01"
        + (b"\xff" * padding_length)
        + b"\x00"
        + RS256_SHA256_DIGESTINFO_PREFIX
        + digest
    )
    actual_message = pow(signature_int, exponent, modulus).to_bytes(modulus_size, "big")
    return secrets.compare_digest(actual_message, expected_message)


def _coerce_utc_datetime(value: Any) -> datetime:
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _provider_key_metadata(signing_key: dict[str, Any]) -> dict[str, Any]:
    return {
        "key_id": signing_key.get("kid"),
        "status": str(signing_key.get("status") or "active").strip().lower(),
        "not_before": signing_key.get("not_before"),
        "not_after": signing_key.get("not_after"),
        "provider_names": list(signing_key.get("provider_names") or []),
        "issuer_url": signing_key.get("issuer_url"),
        "discovery_url": signing_key.get("discovery_url"),
        "trust_anchor_id": signing_key.get("trust_anchor_id"),
    }


def _provider_key_disabled_reason(signing_key: dict[str, Any]) -> str | None:
    status_value = str(signing_key.get("status") or "active").strip().lower()
    if status_value == "disabled":
        return "PAYMENT_PROVIDER_KEY_ID_DISABLED"
    return None


def _provider_key_rotation_window_reason(*, signing_key: dict[str, Any], issued_at_raw: Any) -> str | None:
    status_value = str(signing_key.get("status") or "active").strip().lower()
    if issued_at_raw in (None, ""):
        return None
    try:
        issued_at = _coerce_utc_datetime(issued_at_raw)
    except ValueError:
        return None

    not_before_raw = signing_key.get("not_before")
    if not_before_raw:
        not_before = _coerce_utc_datetime(not_before_raw)
        if issued_at < not_before:
            return "PAYMENT_PROVIDER_KEY_NOT_YET_ACTIVE"

    not_after_raw = signing_key.get("not_after")
    if not_after_raw:
        not_after = _coerce_utc_datetime(not_after_raw)
        if issued_at > not_after:
            return "PAYMENT_PROVIDER_KEY_ROTATED_OUT"

    if status_value == "retired" and not_after_raw is None:
        return "PAYMENT_PROVIDER_KEY_ROTATED_OUT"
    return None


def _provider_key_trust_reason(*, signing_key: dict[str, Any], provider_name: str) -> str | None:
    provider_names = signing_key.get("provider_names") or []
    if provider_names and provider_name not in provider_names:
        return "PAYMENT_PROVIDER_KEY_TRUST_MISMATCH"
    trust_anchor_id = signing_key.get("trust_anchor_id")
    if trust_anchor_id:
        trust_anchor = _provider_trust_anchors.get(trust_anchor_id)
        if trust_anchor is None:
            return "PAYMENT_PROVIDER_TRUST_ANCHOR_MISSING"
        if str(trust_anchor.get("status") or "active").lower() != "active":
            return "PAYMENT_PROVIDER_TRUST_ANCHOR_INACTIVE"
        provider_names = trust_anchor.get("provider_names") or []
        if provider_names and provider_name not in provider_names:
            return "PAYMENT_PROVIDER_KEY_TRUST_MISMATCH"
    return None


def _provider_discovery_reason(
    *,
    provider_name: str,
    key_id: str,
    payload_issuer_url: Any,
    signing_key: dict[str, Any] | None = None,
) -> str | None:
    discovery_document = _provider_discovery.get(provider_name)
    if discovery_document is None:
        return None
    refreshed_at_raw = discovery_document.get("refreshed_at")
    if not refreshed_at_raw:
        return "PAYMENT_PROVIDER_DISCOVERY_STALE"
    try:
        refreshed_at = _coerce_utc_datetime(refreshed_at_raw)
    except ValueError:
        return "PAYMENT_PROVIDER_DISCOVERY_STALE"
    if (datetime.now(timezone.utc) - refreshed_at).total_seconds() > _provider_discovery_max_age_seconds:
        return "PAYMENT_PROVIDER_DISCOVERY_STALE"
    key_ids = discovery_document.get("jwks_key_ids") or []
    if key_ids and key_id not in key_ids:
        return "PAYMENT_PROVIDER_SOURCE_MISMATCH"
    issuer_url = discovery_document.get("issuer_url")
    if issuer_url and payload_issuer_url and payload_issuer_url != issuer_url:
        return "PAYMENT_PROVIDER_DISCOVERY_ISSUER_MISMATCH"
    if signing_key is not None:
        trust_anchor_id = signing_key.get("trust_anchor_id")
        trust_anchor = _provider_trust_anchors.get(trust_anchor_id) if trust_anchor_id else None
        key_issuer_url = signing_key.get("issuer_url")
        anchor_issuer_url = trust_anchor.get("issuer_url") if trust_anchor else None
        if issuer_url and key_issuer_url and key_issuer_url != issuer_url:
            return "PAYMENT_PROVIDER_SOURCE_MISMATCH"
        if issuer_url and anchor_issuer_url and anchor_issuer_url != issuer_url:
            return "PAYMENT_PROVIDER_SOURCE_MISMATCH"
        discovery_url = discovery_document.get("discovery_url")
        key_discovery_url = signing_key.get("discovery_url")
        if discovery_url and key_discovery_url and key_discovery_url != discovery_url:
            return "PAYMENT_PROVIDER_SOURCE_MISMATCH"
        anchor_discovery_url = trust_anchor.get("discovery_url") if trust_anchor else None
        if discovery_url and anchor_discovery_url and anchor_discovery_url != discovery_url:
            return "PAYMENT_PROVIDER_SOURCE_MISMATCH"
    return None


def build_provider_receipt_token(
    *,
    receipt_id: str,
    pay_to: str,
    amount_paid: Decimal,
    currency: str,
    network: str,
    shared_secret: str,
    settled_at: str,
    expires_at: str | None = None,
    provider_name: str = "mock_x402_provider",
    receipt_version: str = PROVIDER_RECEIPT_VERSION,
    issuer_url: str | None = None,
    key_id: str | None = "default",
    issued_at: str | None = None,
    settlement_reference: str | None = None,
    settlement_proof_type: str | None = "transaction_hash",
    settlement_proof_value: str | None = None,
    confirmation_count: int | None = 6,
    confirmed_at: str | None = None,
    status: str = "settled",
) -> str:
    payload = {
        "receipt_id": receipt_id,
        "provider_name": provider_name,
        "receipt_version": receipt_version,
        "issuer_url": issuer_url,
        "key_id": key_id,
        "issued_at": issued_at if issued_at is not None else datetime.now(timezone.utc).isoformat(),
        "settlement_reference": settlement_reference,
        "settlement_proof_type": settlement_proof_type,
        "settlement_proof_value": settlement_proof_value or (f"proof_{receipt_id}" if settlement_proof_type else None),
        "confirmation_count": confirmation_count,
        "confirmed_at": confirmed_at if confirmed_at is not None else settled_at,
        "pay_to": pay_to,
        "amount_paid": f"{amount_paid:.6f}",
        "currency": currency,
        "network": network,
        "status": status,
        "settled_at": settled_at,
        "expires_at": expires_at,
    }
    payload_segment = _canonical_provider_payload_segment(payload)
    signature = hmac.new(
        shared_secret.encode("utf-8"),
        payload_segment.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"{PROVIDER_RECEIPT_PREFIX}.{payload_segment}.{signature}"


class SharedSecretMockX402ProviderAdapter:
    adapter_name = "mock_x402_provider"
    verification_mode = "shared_secret_hmac"

    def verify_payload(
        self,
        *,
        payment: Any,
        amount_due: Decimal,
        payload: dict[str, Any],
        signature: str,
        signing_input: str | None = None,
        header: dict[str, Any] | None = None,
    ) -> X402ReceiptVerificationResult:
        payload_segment = _canonical_provider_payload_segment(payload)
        key_id = str(payload.get("key_id") or "default")
        shared_secret = _provider_keys.get(key_id)
        if shared_secret is None:
            return X402ReceiptVerificationResult(
                status="invalid",
                receipt_id=payload.get("receipt_id"),
                receipt=payload,
                reason_code="PAYMENT_PROVIDER_KEY_ID_UNKNOWN",
                verifier_name=self.adapter_name,
                receipt_source="provider_receipt",
            )
        expected_signature = hmac.new(
            shared_secret.encode("utf-8"),
            payload_segment.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        if not secrets.compare_digest(signature, expected_signature):
            return X402ReceiptVerificationResult(
                status="invalid",
                receipt_id=payload.get("receipt_id"),
                receipt=payload,
                reason_code="PAYMENT_PROVIDER_RECEIPT_INVALID_SIGNATURE",
                verifier_name=self.adapter_name,
                receipt_source="provider_receipt",
            )
        return X402ReceiptVerificationResult(
            status="accepted",
            receipt_id=payload.get("receipt_id"),
            receipt=payload,
            verifier_name=self.adapter_name,
            receipt_source="provider_receipt",
        )

    def capabilities(self) -> dict[str, Any]:
        return {
            "adapter_name": self.adapter_name,
            "verification_mode": self.verification_mode,
            "supports_signature_verification": True,
            "supports_replay_protection": True,
            "supports_query_api": True,
            "supports_issuer_binding": True,
            "supports_key_routing": True,
            "supports_key_rotation_windows": False,
            "supports_settlement_reference": True,
            "supports_settlement_proof": True,
            "supports_confirmation_counts": True,
            "supports_receipt_versioning": True,
            "receipt_version": PROVIDER_RECEIPT_VERSION,
            "available_key_ids": sorted(_provider_keys.keys()),
            "status": "development",
        }


class Rs256MockX402ProviderAdapter:
    adapter_name = "mock_x402_provider_rs256"
    verification_mode = "rs256_public_key"

    def __init__(self, signing_keys: dict[str, dict[str, Any]]) -> None:
        self.signing_keys = signing_keys

    def verify_payload(
        self,
        *,
        payment: Any,
        amount_due: Decimal,
        payload: dict[str, Any],
        signature: str,
        signing_input: str | None = None,
        header: dict[str, Any] | None = None,
    ) -> X402ReceiptVerificationResult:
        payload_segment = _canonical_provider_payload_segment(payload)
        effective_signing_input = signing_input or payload_segment
        key_id = str(payload.get("key_id") or "default")
        signing_key = self.signing_keys.get(key_id)
        if signing_key is None:
            return X402ReceiptVerificationResult(
                status="invalid",
                receipt_id=payload.get("receipt_id"),
                receipt=payload,
                reason_code="PAYMENT_PROVIDER_KEY_ID_UNKNOWN",
                verifier_name=self.adapter_name,
                receipt_source="provider_receipt",
            )
        trust_reason = _provider_key_trust_reason(signing_key=signing_key, provider_name=str(payload.get("provider_name") or ""))
        if trust_reason is not None:
            return X402ReceiptVerificationResult(
                status="invalid",
                receipt_id=payload.get("receipt_id"),
                receipt=payload,
                reason_code=trust_reason,
                verifier_name=self.adapter_name,
                receipt_source="provider_receipt",
            )
        rotation_reason = _provider_key_disabled_reason(signing_key)
        if rotation_reason is not None:
            return X402ReceiptVerificationResult(
                status="invalid",
                receipt_id=payload.get("receipt_id"),
                receipt=payload,
                reason_code=rotation_reason,
                verifier_name=self.adapter_name,
                receipt_source="provider_receipt",
            )
        if not _verify_rs256_signature(signing_input=effective_signing_input, signature_segment=signature, signing_key=signing_key):
            return X402ReceiptVerificationResult(
                status="invalid",
                receipt_id=payload.get("receipt_id"),
                receipt=payload,
                reason_code="PAYMENT_PROVIDER_RECEIPT_INVALID_SIGNATURE",
                verifier_name=self.adapter_name,
                receipt_source="provider_receipt",
            )
        rotation_reason = _provider_key_rotation_window_reason(
            signing_key=signing_key,
            issued_at_raw=payload.get("issued_at"),
        )
        if rotation_reason is not None:
            return X402ReceiptVerificationResult(
                status="invalid",
                receipt_id=payload.get("receipt_id"),
                receipt=payload,
                reason_code=rotation_reason,
                verifier_name=self.adapter_name,
                receipt_source="provider_receipt",
            )
        discovery_reason = _provider_discovery_reason(
            provider_name=str(payload.get("provider_name") or ""),
            key_id=key_id,
            payload_issuer_url=payload.get("issuer_url"),
            signing_key=signing_key,
        )
        if discovery_reason is not None:
            return X402ReceiptVerificationResult(
                status="invalid",
                receipt_id=payload.get("receipt_id"),
                receipt=payload,
                reason_code=discovery_reason,
                verifier_name=self.adapter_name,
                receipt_source="provider_receipt",
            )
        return X402ReceiptVerificationResult(
            status="accepted",
            receipt_id=payload.get("receipt_id"),
            receipt=payload,
            verifier_name=self.adapter_name,
            receipt_source="provider_receipt",
        )

    def capabilities(self) -> dict[str, Any]:
        return {
            "adapter_name": self.adapter_name,
            "verification_mode": self.verification_mode,
            "supports_signature_verification": True,
            "supports_replay_protection": True,
            "supports_query_api": True,
            "supports_issuer_binding": True,
            "supports_key_routing": True,
            "supports_key_rotation_windows": True,
            "supports_provider_trust_binding": True,
            "supports_provider_discovery_refresh": True,
            "supports_jwks_source_reconciliation": True,
            "supports_federated_trust_anchors": True,
            "supports_settlement_reference": True,
            "supports_settlement_proof": True,
            "supports_confirmation_counts": True,
            "supports_receipt_versioning": True,
            "receipt_version": PROVIDER_RECEIPT_VERSION,
            "available_key_ids": sorted(self.signing_keys.keys()),
            "key_metadata": [_provider_key_metadata(self.signing_keys[key_id]) for key_id in sorted(self.signing_keys.keys())],
            "status": "integration_ready",
        }


class JwtRs256X402ProviderAdapter:
    adapter_name = "mock_x402_provider_jwt_rs256"
    verification_mode = "rs256_compact_jwt"

    def __init__(self, signing_keys: dict[str, dict[str, Any]]) -> None:
        self.signing_keys = signing_keys

    def verify_payload(
        self,
        *,
        payment: Any,
        amount_due: Decimal,
        payload: dict[str, Any],
        signature: str,
        signing_input: str | None = None,
        header: dict[str, Any] | None = None,
    ) -> X402ReceiptVerificationResult:
        jwt_header = header or {}
        if str(jwt_header.get("alg") or "").upper() != "RS256":
            return X402ReceiptVerificationResult(
                status="invalid",
                receipt_id=payload.get("receipt_id"),
                receipt=payload,
                reason_code="PAYMENT_PROVIDER_RECEIPT_INVALID_SIGNATURE",
                verifier_name=self.adapter_name,
                receipt_source="provider_receipt",
            )
        key_id = str(jwt_header.get("kid") or payload.get("key_id") or "default")
        signing_key = self.signing_keys.get(key_id)
        if signing_key is None:
            return X402ReceiptVerificationResult(
                status="invalid",
                receipt_id=payload.get("receipt_id"),
                receipt=payload,
                reason_code="PAYMENT_PROVIDER_KEY_ID_UNKNOWN",
                verifier_name=self.adapter_name,
                receipt_source="provider_receipt",
            )
        trust_reason = _provider_key_trust_reason(signing_key=signing_key, provider_name=str(payload.get("provider_name") or ""))
        if trust_reason is not None:
            return X402ReceiptVerificationResult(
                status="invalid",
                receipt_id=payload.get("receipt_id"),
                receipt=payload,
                reason_code=trust_reason,
                verifier_name=self.adapter_name,
                receipt_source="provider_receipt",
            )
        rotation_reason = _provider_key_disabled_reason(signing_key)
        if rotation_reason is not None:
            return X402ReceiptVerificationResult(
                status="invalid",
                receipt_id=payload.get("receipt_id"),
                receipt=payload,
                reason_code=rotation_reason,
                verifier_name=self.adapter_name,
                receipt_source="provider_receipt",
            )
        if not signing_input or not _verify_rs256_signature(signing_input=signing_input, signature_segment=signature, signing_key=signing_key):
            return X402ReceiptVerificationResult(
                status="invalid",
                receipt_id=payload.get("receipt_id"),
                receipt=payload,
                reason_code="PAYMENT_PROVIDER_RECEIPT_INVALID_SIGNATURE",
                verifier_name=self.adapter_name,
                receipt_source="provider_receipt",
            )
        rotation_reason = _provider_key_rotation_window_reason(
            signing_key=signing_key,
            issued_at_raw=payload.get("issued_at"),
        )
        if rotation_reason is not None:
            return X402ReceiptVerificationResult(
                status="invalid",
                receipt_id=payload.get("receipt_id"),
                receipt=payload,
                reason_code=rotation_reason,
                verifier_name=self.adapter_name,
                receipt_source="provider_receipt",
            )
        discovery_reason = _provider_discovery_reason(
            provider_name=str(payload.get("provider_name") or ""),
            key_id=key_id,
            payload_issuer_url=payload.get("issuer_url"),
            signing_key=signing_key,
        )
        if discovery_reason is not None:
            return X402ReceiptVerificationResult(
                status="invalid",
                receipt_id=payload.get("receipt_id"),
                receipt=payload,
                reason_code=discovery_reason,
                verifier_name=self.adapter_name,
                receipt_source="provider_receipt",
            )
        return X402ReceiptVerificationResult(
            status="accepted",
            receipt_id=payload.get("receipt_id"),
            receipt=payload,
            verifier_name=self.adapter_name,
            receipt_source="provider_receipt",
        )

    def capabilities(self) -> dict[str, Any]:
        return {
            "adapter_name": self.adapter_name,
            "verification_mode": self.verification_mode,
            "supports_signature_verification": True,
            "supports_replay_protection": True,
            "supports_query_api": True,
            "supports_issuer_binding": True,
            "supports_key_routing": True,
            "supports_key_rotation_windows": True,
            "supports_provider_trust_binding": True,
            "supports_provider_discovery_refresh": True,
            "supports_jwks_source_reconciliation": True,
            "supports_federated_trust_anchors": True,
            "supports_settlement_reference": True,
            "supports_settlement_proof": True,
            "supports_confirmation_counts": True,
            "supports_receipt_versioning": True,
            "receipt_version": PROVIDER_RECEIPT_VERSION,
            "receipt_format": PROVIDER_RECEIPT_JWT_PREFIX,
            "available_key_ids": sorted(self.signing_keys.keys()),
            "key_metadata": [_provider_key_metadata(self.signing_keys[key_id]) for key_id in sorted(self.signing_keys.keys())],
            "status": "integration_ready",
        }


class DevelopmentProviderReceiptVerifier:
    verifier_name = "provider_adapter_registry"

    def verify(self, *, payment: Any, amount_due: Decimal, receipt_token: str | None) -> X402ReceiptVerificationResult:
        _bootstrap_provider_configs()
        if not receipt_token or (
            not receipt_token.startswith(f"{PROVIDER_RECEIPT_PREFIX}.")
            and not receipt_token.startswith(f"{PROVIDER_RECEIPT_JWT_PREFIX}.")
        ):
            return X402ReceiptVerificationResult(
                status="invalid",
                receipt_id=None,
                receipt=None,
                reason_code="PAYMENT_PROVIDER_RECEIPT_INVALID",
                verifier_name=self.verifier_name,
                receipt_source="provider_receipt",
            )
        if not x402_enabled():
            return X402ReceiptVerificationResult(
                status="provider_disabled",
                receipt_id=None,
                receipt=None,
                reason_code="ADVANCED_X402_DISABLED",
                verifier_name=self.verifier_name,
                receipt_source="provider_receipt",
            )
        header: dict[str, Any] | None = None
        signing_input: str | None = None
        try:
            if receipt_token.startswith(f"{PROVIDER_RECEIPT_JWT_PREFIX}."):
                _, header_segment, payload_segment, provided_signature = receipt_token.split(".", 3)
                header = json.loads(_base64url_decode(header_segment).decode("utf-8"))
                payload = json.loads(_base64url_decode(payload_segment).decode("utf-8"))
                signing_input = f"{header_segment}.{payload_segment}"
            else:
                _, payload_segment, provided_signature = receipt_token.split(".", 2)
                payload = json.loads(_base64url_decode(payload_segment).decode("utf-8"))
                signing_input = payload_segment
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
            return X402ReceiptVerificationResult(
                status="invalid",
                receipt_id=None,
                receipt=None,
                reason_code="PAYMENT_PROVIDER_RECEIPT_INVALID",
                verifier_name=self.verifier_name,
                receipt_source="provider_receipt",
            )

        receipt_id = payload.get("receipt_id")
        if not receipt_id:
            return X402ReceiptVerificationResult(
                status="invalid",
                receipt_id=None,
                receipt=None,
                reason_code="PAYMENT_PROVIDER_RECEIPT_INVALID",
                verifier_name=self.verifier_name,
                receipt_source="provider_receipt",
            )
        provider_name = str(payload.get("provider_name") or "")
        provider_config = _store.get_x402_provider_config(provider_name)
        if provider_config is None:
            _store.upsert_x402_provider_receipt(
                receipt_id=receipt_id,
                provider_name=provider_name or "unknown",
                receipt_version=payload.get("receipt_version"),
                issuer_url=payload.get("issuer_url"),
                key_id=payload.get("key_id"),
                issued_at=payload.get("issued_at"),
                settlement_reference=payload.get("settlement_reference"),
                settlement_proof_type=payload.get("settlement_proof_type"),
                settlement_proof_value=payload.get("settlement_proof_value"),
                confirmation_count=payload.get("confirmation_count"),
                confirmed_at=payload.get("confirmed_at"),
                network=str(payload.get("network") or ""),
                pay_to=str(payload.get("pay_to") or ""),
                amount_paid=Decimal("0"),
                currency=str(payload.get("currency") or payment.currency),
                status=str(payload.get("status") or "invalid"),
                settled_at=str(payload.get("settled_at") or ""),
                expires_at=payload.get("expires_at"),
                verification_status="rejected",
                verification_reason_code="PAYMENT_PROVIDER_UNKNOWN",
                payload=payload,
            )
            return X402ReceiptVerificationResult(
                status="invalid",
                receipt_id=receipt_id,
                receipt=payload,
                reason_code="PAYMENT_PROVIDER_UNKNOWN",
                verifier_name=self.verifier_name,
                receipt_source="provider_receipt",
            )
        adapter_name = str(provider_config.get("adapter_name") or provider_name)
        provider_adapter = _provider_adapters.get(adapter_name)
        if provider_adapter is None:
            _store.upsert_x402_provider_receipt(
                receipt_id=receipt_id,
                provider_name=provider_name or "unknown",
                receipt_version=payload.get("receipt_version"),
                issuer_url=payload.get("issuer_url"),
                key_id=payload.get("key_id"),
                issued_at=payload.get("issued_at"),
                settlement_reference=payload.get("settlement_reference"),
                settlement_proof_type=payload.get("settlement_proof_type"),
                settlement_proof_value=payload.get("settlement_proof_value"),
                confirmation_count=payload.get("confirmation_count"),
                confirmed_at=payload.get("confirmed_at"),
                network=str(payload.get("network") or ""),
                pay_to=str(payload.get("pay_to") or ""),
                amount_paid=Decimal("0"),
                currency=str(payload.get("currency") or payment.currency),
                status=str(payload.get("status") or "invalid"),
                settled_at=str(payload.get("settled_at") or ""),
                expires_at=payload.get("expires_at"),
                verification_status="rejected",
                verification_reason_code="PAYMENT_PROVIDER_UNKNOWN",
                payload=payload,
            )
            return X402ReceiptVerificationResult(
                status="invalid",
                receipt_id=receipt_id,
                receipt=payload,
                reason_code="PAYMENT_PROVIDER_UNKNOWN",
                verifier_name=self.verifier_name,
                receipt_source="provider_receipt",
            )
        if not provider_config["is_enabled"]:
            _store.upsert_x402_provider_receipt(
                receipt_id=receipt_id,
                provider_name=provider_name or "unknown",
                receipt_version=payload.get("receipt_version"),
                issuer_url=payload.get("issuer_url"),
                key_id=payload.get("key_id"),
                issued_at=payload.get("issued_at"),
                settlement_reference=payload.get("settlement_reference"),
                settlement_proof_type=payload.get("settlement_proof_type"),
                settlement_proof_value=payload.get("settlement_proof_value"),
                confirmation_count=payload.get("confirmation_count"),
                confirmed_at=payload.get("confirmed_at"),
                network=str(payload.get("network") or ""),
                pay_to=str(payload.get("pay_to") or ""),
                amount_paid=Decimal("0"),
                currency=str(payload.get("currency") or payment.currency),
                status=str(payload.get("status") or "invalid"),
                settled_at=str(payload.get("settled_at") or ""),
                expires_at=payload.get("expires_at"),
                verification_status="rejected",
                verification_reason_code="PAYMENT_PROVIDER_NOT_ENABLED",
                payload=payload,
            )
            return X402ReceiptVerificationResult(
                status="invalid",
                receipt_id=receipt_id,
                receipt=payload,
                reason_code="PAYMENT_PROVIDER_NOT_ENABLED",
                verifier_name=self.verifier_name,
                receipt_source="provider_receipt",
            )

        try:
            amount_paid = _normalize_money(Decimal(str(payload["amount_paid"])))
        except Exception:
            _store.upsert_x402_provider_receipt(
                receipt_id=receipt_id,
                provider_name=provider_name or "unknown",
                receipt_version=payload.get("receipt_version"),
                issuer_url=payload.get("issuer_url"),
                key_id=payload.get("key_id"),
                issued_at=payload.get("issued_at"),
                settlement_reference=payload.get("settlement_reference"),
                settlement_proof_type=payload.get("settlement_proof_type"),
                settlement_proof_value=payload.get("settlement_proof_value"),
                confirmation_count=payload.get("confirmation_count"),
                confirmed_at=payload.get("confirmed_at"),
                network=str(payload.get("network") or ""),
                pay_to=str(payload.get("pay_to") or ""),
                amount_paid=Decimal("0"),
                currency=str(payload.get("currency") or payment.currency),
                status=str(payload.get("status") or "invalid"),
                settled_at=str(payload.get("settled_at") or ""),
                expires_at=payload.get("expires_at"),
                verification_status="rejected",
                verification_reason_code="PAYMENT_PROVIDER_RECEIPT_INVALID",
                payload=payload,
            )
            return X402ReceiptVerificationResult(
                status="invalid",
                receipt_id=receipt_id,
                receipt=payload,
                reason_code="PAYMENT_PROVIDER_RECEIPT_INVALID",
                verifier_name=self.verifier_name,
                receipt_source="provider_receipt",
            )

        receipt = _store.upsert_x402_provider_receipt(
            receipt_id=receipt_id,
            provider_name=provider_name,
            receipt_version=payload.get("receipt_version"),
            issuer_url=payload.get("issuer_url"),
            key_id=payload.get("key_id"),
            issued_at=payload.get("issued_at"),
            settlement_reference=payload.get("settlement_reference"),
            settlement_proof_type=payload.get("settlement_proof_type"),
            settlement_proof_value=payload.get("settlement_proof_value"),
            confirmation_count=payload.get("confirmation_count"),
            confirmed_at=payload.get("confirmed_at"),
            network=str(payload.get("network") or ""),
            pay_to=str(payload.get("pay_to") or ""),
            amount_paid=amount_paid,
            currency=str(payload.get("currency") or payment.currency),
            status=str(payload.get("status") or "unknown"),
            settled_at=str(payload.get("settled_at") or ""),
            expires_at=payload.get("expires_at"),
            verification_status="pending",
            verification_reason_code="PAYMENT_PROVIDER_RECEIPT_PENDING",
            payload=payload,
        )
        adapter_verification = provider_adapter.verify_payload(
            payment=payment,
            amount_due=amount_due,
            payload=payload,
            signature=provided_signature,
            signing_input=signing_input,
            header=header,
        )
        if adapter_verification.status != "accepted":
            _store.upsert_x402_provider_receipt_verification(
                receipt_id=receipt_id,
                verification_status="rejected",
                verification_reason_code=adapter_verification.reason_code or "PAYMENT_PROVIDER_RECEIPT_INVALID",
            )
            return adapter_verification
        if payload.get("receipt_version") != PROVIDER_RECEIPT_VERSION:
            _store.upsert_x402_provider_receipt_verification(
                receipt_id=receipt_id,
                verification_status="rejected",
                verification_reason_code="PAYMENT_PROVIDER_RECEIPT_VERSION_UNSUPPORTED",
            )
            return X402ReceiptVerificationResult(
                status="invalid",
                receipt_id=receipt_id,
                receipt=receipt,
                reason_code="PAYMENT_PROVIDER_RECEIPT_VERSION_UNSUPPORTED",
                verifier_name=provider_name,
                receipt_source="provider_receipt",
            )
        issued_at_raw = payload.get("issued_at")
        if not issued_at_raw:
            _store.upsert_x402_provider_receipt_verification(
                receipt_id=receipt_id,
                verification_status="rejected",
                verification_reason_code="PAYMENT_PROVIDER_ISSUED_AT_MISSING",
            )
            return X402ReceiptVerificationResult(
                status="invalid",
                receipt_id=receipt_id,
                receipt=receipt,
                reason_code="PAYMENT_PROVIDER_ISSUED_AT_MISSING",
                verifier_name=provider_name,
                receipt_source="provider_receipt",
            )
        try:
            issued_at = _coerce_utc_datetime(issued_at_raw)
        except ValueError:
            _store.upsert_x402_provider_receipt_verification(
                receipt_id=receipt_id,
                verification_status="rejected",
                verification_reason_code="PAYMENT_PROVIDER_ISSUED_AT_INVALID",
            )
            return X402ReceiptVerificationResult(
                status="invalid",
                receipt_id=receipt_id,
                receipt=receipt,
                reason_code="PAYMENT_PROVIDER_ISSUED_AT_INVALID",
                verifier_name=provider_name,
                receipt_source="provider_receipt",
            )
        now = datetime.now(timezone.utc)
        if issued_at > now + timedelta(seconds=PROVIDER_RECEIPT_FUTURE_SKEW_SECONDS):
            _store.upsert_x402_provider_receipt_verification(
                receipt_id=receipt_id,
                verification_status="rejected",
                verification_reason_code="PAYMENT_PROVIDER_ISSUED_AT_IN_FUTURE",
            )
            return X402ReceiptVerificationResult(
                status="invalid",
                receipt_id=receipt_id,
                receipt=receipt,
                reason_code="PAYMENT_PROVIDER_ISSUED_AT_IN_FUTURE",
                verifier_name=provider_name,
                receipt_source="provider_receipt",
            )
        if (now - issued_at).total_seconds() > PROVIDER_RECEIPT_MAX_AGE_SECONDS:
            _store.upsert_x402_provider_receipt_verification(
                receipt_id=receipt_id,
                verification_status="rejected",
                verification_reason_code="PAYMENT_PROVIDER_ISSUED_AT_TOO_OLD",
            )
            return X402ReceiptVerificationResult(
                status="expired",
                receipt_id=receipt_id,
                receipt=receipt,
                reason_code="PAYMENT_PROVIDER_ISSUED_AT_TOO_OLD",
                verifier_name=provider_name,
                receipt_source="provider_receipt",
            )
        if not payload.get("settlement_reference"):
            _store.upsert_x402_provider_receipt_verification(
                receipt_id=receipt_id,
                verification_status="rejected",
                verification_reason_code="PAYMENT_PROVIDER_SETTLEMENT_REFERENCE_MISSING",
            )
            return X402ReceiptVerificationResult(
                status="invalid",
                receipt_id=receipt_id,
                receipt=receipt,
                reason_code="PAYMENT_PROVIDER_SETTLEMENT_REFERENCE_MISSING",
                verifier_name=provider_name,
                receipt_source="provider_receipt",
            )
        settlement_proof_type = payload.get("settlement_proof_type")
        settlement_proof_value = payload.get("settlement_proof_value")
        if not settlement_proof_type or not settlement_proof_value:
            _store.upsert_x402_provider_receipt_verification(
                receipt_id=receipt_id,
                verification_status="rejected",
                verification_reason_code="PAYMENT_PROVIDER_SETTLEMENT_PROOF_MISSING",
            )
            return X402ReceiptVerificationResult(
                status="invalid",
                receipt_id=receipt_id,
                receipt=receipt,
                reason_code="PAYMENT_PROVIDER_SETTLEMENT_PROOF_MISSING",
                verifier_name=provider_name,
                receipt_source="provider_receipt",
            )
        required_settlement_proof_type = provider_config.get("required_settlement_proof_type")
        if required_settlement_proof_type and settlement_proof_type != required_settlement_proof_type:
            _store.upsert_x402_provider_receipt_verification(
                receipt_id=receipt_id,
                verification_status="rejected",
                verification_reason_code="PAYMENT_PROVIDER_SETTLEMENT_PROOF_TYPE_MISMATCH",
            )
            return X402ReceiptVerificationResult(
                status="mismatch",
                receipt_id=receipt_id,
                receipt=receipt,
                reason_code="PAYMENT_PROVIDER_SETTLEMENT_PROOF_TYPE_MISMATCH",
                verifier_name=provider_name,
                receipt_source="provider_receipt",
            )
        try:
            confirmation_count = int(payload.get("confirmation_count"))
        except (TypeError, ValueError):
            _store.upsert_x402_provider_receipt_verification(
                receipt_id=receipt_id,
                verification_status="rejected",
                verification_reason_code="PAYMENT_PROVIDER_CONFIRMATION_COUNT_INVALID",
            )
            return X402ReceiptVerificationResult(
                status="invalid",
                receipt_id=receipt_id,
                receipt=receipt,
                reason_code="PAYMENT_PROVIDER_CONFIRMATION_COUNT_INVALID",
                verifier_name=provider_name,
                receipt_source="provider_receipt",
            )
        if confirmation_count < 0:
            _store.upsert_x402_provider_receipt_verification(
                receipt_id=receipt_id,
                verification_status="rejected",
                verification_reason_code="PAYMENT_PROVIDER_CONFIRMATION_COUNT_INVALID",
            )
            return X402ReceiptVerificationResult(
                status="invalid",
                receipt_id=receipt_id,
                receipt=receipt,
                reason_code="PAYMENT_PROVIDER_CONFIRMATION_COUNT_INVALID",
                verifier_name=provider_name,
                receipt_source="provider_receipt",
            )
        confirmed_at_raw = payload.get("confirmed_at")
        if confirmation_count > 0 and not confirmed_at_raw:
            _store.upsert_x402_provider_receipt_verification(
                receipt_id=receipt_id,
                verification_status="rejected",
                verification_reason_code="PAYMENT_PROVIDER_CONFIRMED_AT_MISSING",
            )
            return X402ReceiptVerificationResult(
                status="invalid",
                receipt_id=receipt_id,
                receipt=receipt,
                reason_code="PAYMENT_PROVIDER_CONFIRMED_AT_MISSING",
                verifier_name=provider_name,
                receipt_source="provider_receipt",
            )
        if confirmed_at_raw:
            try:
                confirmed_at = _coerce_utc_datetime(confirmed_at_raw)
            except ValueError:
                _store.upsert_x402_provider_receipt_verification(
                    receipt_id=receipt_id,
                    verification_status="rejected",
                    verification_reason_code="PAYMENT_PROVIDER_CONFIRMED_AT_INVALID",
                )
                return X402ReceiptVerificationResult(
                    status="invalid",
                    receipt_id=receipt_id,
                    receipt=receipt,
                    reason_code="PAYMENT_PROVIDER_CONFIRMED_AT_INVALID",
                    verifier_name=provider_name,
                    receipt_source="provider_receipt",
                )
            if confirmed_at > now + timedelta(seconds=PROVIDER_RECEIPT_FUTURE_SKEW_SECONDS):
                _store.upsert_x402_provider_receipt_verification(
                    receipt_id=receipt_id,
                    verification_status="rejected",
                    verification_reason_code="PAYMENT_PROVIDER_CONFIRMED_AT_IN_FUTURE",
                )
                return X402ReceiptVerificationResult(
                    status="invalid",
                    receipt_id=receipt_id,
                    receipt=receipt,
                    reason_code="PAYMENT_PROVIDER_CONFIRMED_AT_IN_FUTURE",
                    verifier_name=provider_name,
                    receipt_source="provider_receipt",
                )
        minimum_confirmations = provider_config.get("minimum_confirmations")
        if minimum_confirmations is not None and confirmation_count < int(minimum_confirmations):
            _store.upsert_x402_provider_receipt_verification(
                receipt_id=receipt_id,
                verification_status="rejected",
                verification_reason_code="PAYMENT_PROVIDER_SETTLEMENT_NOT_CONFIRMED",
            )
            return X402ReceiptVerificationResult(
                status="invalid",
                receipt_id=receipt_id,
                receipt=receipt,
                reason_code="PAYMENT_PROVIDER_SETTLEMENT_NOT_CONFIRMED",
                verifier_name=provider_name,
                receipt_source="provider_receipt",
            )
        if receipt["used_at"]:
            _store.upsert_x402_provider_receipt_verification(
                receipt_id=receipt_id,
                verification_status="rejected",
                verification_reason_code="PAYMENT_PROVIDER_RECEIPT_ALREADY_USED",
            )
            return X402ReceiptVerificationResult(
                status="already_used",
                receipt_id=receipt_id,
                receipt=receipt,
                reason_code="PAYMENT_PROVIDER_RECEIPT_ALREADY_USED",
                verifier_name=provider_name,
                receipt_source="provider_receipt",
            )
        expires_at = receipt.get("expires_at")
        if expires_at and datetime.fromisoformat(expires_at) <= datetime.now(timezone.utc):
            _store.upsert_x402_provider_receipt_verification(
                receipt_id=receipt_id,
                verification_status="rejected",
                verification_reason_code="PAYMENT_PROVIDER_RECEIPT_EXPIRED",
            )
            return X402ReceiptVerificationResult(
                status="expired",
                receipt_id=receipt_id,
                receipt=receipt,
                reason_code="PAYMENT_PROVIDER_RECEIPT_EXPIRED",
                verifier_name=provider_name,
                receipt_source="provider_receipt",
            )
        if receipt["status"] != "settled":
            _store.upsert_x402_provider_receipt_verification(
                receipt_id=receipt_id,
                verification_status="rejected",
                verification_reason_code="PAYMENT_PROVIDER_RECEIPT_UNSETTLED",
            )
            return X402ReceiptVerificationResult(
                status="invalid",
                receipt_id=receipt_id,
                receipt=receipt,
                reason_code="PAYMENT_PROVIDER_RECEIPT_UNSETTLED",
                verifier_name=provider_name,
                receipt_source="provider_receipt",
            )
        expected_pay_to = _network_recipient_address(receipt["network"])
        if receipt["pay_to"] != expected_pay_to or receipt["network"] not in _supported_networks:
            _store.upsert_x402_provider_receipt_verification(
                receipt_id=receipt_id,
                verification_status="rejected",
                verification_reason_code="PAYMENT_PROVIDER_RECEIPT_MISMATCH",
            )
            return X402ReceiptVerificationResult(
                status="mismatch",
                receipt_id=receipt_id,
                receipt=receipt,
                reason_code="PAYMENT_PROVIDER_RECEIPT_MISMATCH",
                verifier_name=provider_name,
                receipt_source="provider_receipt",
            )
        configured_issuer = provider_config.get("issuer_url")
        configured_issuers = list(provider_config.get("issuer_urls") or [])
        if configured_issuer and configured_issuer not in configured_issuers:
            configured_issuers.append(configured_issuer)
        configured_trust_anchor_ids = list(provider_config.get("trust_anchor_ids") or [])
        receipt_issuer = payload.get("issuer_url")
        receipt_key_id = payload.get("key_id")
        receipt_signing_key = _provider_jwks.get(str(receipt_key_id or ""))
        receipt_trust_anchor_id = receipt_signing_key.get("trust_anchor_id") if receipt_signing_key else None
        issuer_allowed_via_anchor = False
        if configured_trust_anchor_ids and receipt_trust_anchor_id in configured_trust_anchor_ids:
            trust_anchor = _provider_trust_anchors.get(receipt_trust_anchor_id)
            if trust_anchor and receipt_issuer == trust_anchor.get("issuer_url"):
                issuer_allowed_via_anchor = True
        if configured_issuers and receipt_issuer not in configured_issuers and not issuer_allowed_via_anchor:
            _store.upsert_x402_provider_receipt_verification(
                receipt_id=receipt_id,
                verification_status="rejected",
                verification_reason_code="PAYMENT_PROVIDER_ISSUER_MISMATCH",
            )
            return X402ReceiptVerificationResult(
                status="mismatch",
                receipt_id=receipt_id,
                receipt=receipt,
                reason_code="PAYMENT_PROVIDER_ISSUER_MISMATCH",
                verifier_name=provider_name,
                receipt_source="provider_receipt",
            )
        configured_key_id = provider_config.get("verifier_key_id")
        configured_key_ids = list(provider_config.get("verifier_key_ids") or [])
        if configured_key_id and configured_key_id not in configured_key_ids:
            configured_key_ids.append(configured_key_id)
        key_allowed_via_anchor = bool(configured_trust_anchor_ids and receipt_trust_anchor_id in configured_trust_anchor_ids)
        if configured_key_ids and receipt_key_id not in configured_key_ids and not key_allowed_via_anchor:
            _store.upsert_x402_provider_receipt_verification(
                receipt_id=receipt_id,
                verification_status="rejected",
                verification_reason_code="PAYMENT_PROVIDER_KEY_ID_MISMATCH",
            )
            return X402ReceiptVerificationResult(
                status="mismatch",
                receipt_id=receipt_id,
                receipt=receipt,
                reason_code="PAYMENT_PROVIDER_KEY_ID_MISMATCH",
                verifier_name=provider_name,
                receipt_source="provider_receipt",
            )
        if receipt["network"] not in provider_config["supported_networks"]:
            _store.upsert_x402_provider_receipt_verification(
                receipt_id=receipt_id,
                verification_status="rejected",
                verification_reason_code="PAYMENT_PROVIDER_NETWORK_NOT_ALLOWED",
            )
            return X402ReceiptVerificationResult(
                status="mismatch",
                receipt_id=receipt_id,
                receipt=receipt,
                reason_code="PAYMENT_PROVIDER_NETWORK_NOT_ALLOWED",
                verifier_name=provider_name,
                receipt_source="provider_receipt",
            )
        if amount_paid != amount_due or receipt["currency"] != payment.currency:
            _store.upsert_x402_provider_receipt_verification(
                receipt_id=receipt_id,
                verification_status="rejected",
                verification_reason_code="PAYMENT_PROVIDER_RECEIPT_MISMATCH",
            )
            return X402ReceiptVerificationResult(
                status="mismatch",
                receipt_id=receipt_id,
                receipt=receipt,
                reason_code="PAYMENT_PROVIDER_RECEIPT_MISMATCH",
                verifier_name=provider_name,
                receipt_source="provider_receipt",
            )

        accepted = _store.upsert_x402_provider_receipt_verification(
            receipt_id=receipt_id,
            verification_status="accepted",
            verification_reason_code="PAYMENT_PROVIDER_RECEIPT_ACCEPTED",
        )
        return X402ReceiptVerificationResult(
            status="accepted",
            receipt_id=receipt_id,
            receipt=accepted,
            verifier_name=provider_name,
            receipt_source="provider_receipt",
        )


class CompositeX402ReceiptVerifier:
    verifier_name = "provider_plus_signed_receipt"

    def __init__(self, provider_verifier: X402ReceiptVerifier, fallback_verifier: X402ReceiptVerifier) -> None:
        self.provider_verifier = provider_verifier
        self.fallback_verifier = fallback_verifier

    def verify(self, *, payment: Any, amount_due: Decimal, receipt_token: str | None) -> X402ReceiptVerificationResult:
        if receipt_token and (
            receipt_token.startswith(f"{PROVIDER_RECEIPT_PREFIX}.")
            or receipt_token.startswith(f"{PROVIDER_RECEIPT_JWT_PREFIX}.")
        ):
            return self.provider_verifier.verify(payment=payment, amount_due=amount_due, receipt_token=receipt_token)
        return self.fallback_verifier.verify(payment=payment, amount_due=amount_due, receipt_token=receipt_token)


def setup_x402_api(
    *,
    store: Any,
    append_audit_entry: Callable[..., None],
    get_current_identity: Callable[..., Any],
    ensure_scope: Callable[[Any, list[str]], Any],
    get_runtime_phase3_features: Callable[[], dict[str, bool]],
    parse_and_validate_receipt_token: Callable[[str | None], tuple[str | None, dict[str, Any] | None]],
    normalize_money: Callable[[Decimal], Decimal],
    pay_to_address: str,
    challenge_ttl_seconds: int,
    supported_networks: list[str],
    network_recipient_addresses: dict[str, str] | None = None,
    provider_shared_secret: str,
    provider_keys: dict[str, str] | None = None,
    provider_jwks: dict[str, dict[str, Any]] | None = None,
    provider_discovery: dict[str, dict[str, Any]] | None = None,
    provider_discovery_max_age_seconds: int = 3600,
    provider_trust_anchors: dict[str, dict[str, Any]] | None = None,
    provider_adapters: dict[str, X402ProviderAdapter] | None = None,
    challenge_builder: X402ChallengeBuilder | None = None,
    receipt_verifier: X402ReceiptVerifier | None = None,
) -> None:
    global _get_current_identity, _ensure_scope, _get_runtime_phase3_features
    global _store, _pay_to_address, _network_recipient_addresses, _challenge_ttl_seconds, _supported_networks, _challenge_builder
    global _receipt_verifier, _parse_and_validate_receipt_token, _normalize_money
    global _provider_shared_secret, _provider_keys, _provider_jwks, _provider_adapters, _append_audit_entry
    global _provider_discovery, _provider_discovery_max_age_seconds, _provider_trust_anchors
    _store = store
    _append_audit_entry = append_audit_entry
    _get_current_identity = get_current_identity
    _ensure_scope = ensure_scope
    _get_runtime_phase3_features = get_runtime_phase3_features
    _parse_and_validate_receipt_token = parse_and_validate_receipt_token
    _normalize_money = normalize_money
    _pay_to_address = pay_to_address
    _challenge_ttl_seconds = challenge_ttl_seconds
    _supported_networks = supported_networks
    _network_recipient_addresses = dict(network_recipient_addresses or {network: pay_to_address for network in supported_networks})
    _provider_shared_secret = provider_shared_secret
    _provider_keys = provider_keys or {"default": provider_shared_secret}
    _provider_jwks = provider_jwks or {}
    _provider_discovery = dict(provider_discovery or {})
    _provider_discovery_max_age_seconds = provider_discovery_max_age_seconds
    _provider_trust_anchors = dict(provider_trust_anchors or {})
    _provider_adapters = provider_adapters or {
        SharedSecretMockX402ProviderAdapter.adapter_name: SharedSecretMockX402ProviderAdapter(),
        Rs256MockX402ProviderAdapter.adapter_name: Rs256MockX402ProviderAdapter(_provider_jwks),
        JwtRs256X402ProviderAdapter.adapter_name: JwtRs256X402ProviderAdapter(_provider_jwks),
    }
    _bootstrap_provider_configs()
    _challenge_builder = challenge_builder or StubX402ChallengeBuilder()
    if receipt_verifier is None:
        _receipt_verifier = CompositeX402ReceiptVerifier(
            DevelopmentProviderReceiptVerifier(),
            SignedReceiptFallbackVerifier(),
        )
    else:
        _receipt_verifier = receipt_verifier


def _require_x402_identity(authorization: str | None) -> Any:
    identity = _get_current_identity(authorization)
    return _ensure_scope(identity, ["audit:read"])


def x402_enabled() -> bool:
    if _get_runtime_phase3_features is None:
        return False
    return bool(_get_runtime_phase3_features().get("advanced_x402_enabled", False))


def build_x402_challenge(*, payment: Any, amount_due: Decimal) -> dict[str, Any] | None:
    if not x402_enabled():
        return None
    challenge = _challenge_builder.build(payment=payment, amount_due=amount_due)
    return {
        "amount": challenge.amount,
        "currency": challenge.currency,
        "recipient_address": challenge.recipient_address,
        "recipient_addresses": challenge.recipient_addresses,
        "supported_networks": challenge.supported_networks,
        "expiry_seconds": challenge.expiry_seconds,
        "settlement_method": challenge.settlement_method,
        "receipt_header": challenge.receipt_header,
        "status": challenge.status,
        "builder_name": getattr(_challenge_builder, "builder_name", "unknown"),
    }


def verify_x402_receipt(*, payment: Any, amount_due: Decimal, receipt_token: str | None) -> X402ReceiptVerificationResult:
    return _receipt_verifier.verify(payment=payment, amount_due=amount_due, receipt_token=receipt_token)


@router.get("/x402/capabilities")
def get_x402_capabilities(
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> dict[str, Any]:
    _require_x402_identity(authorization)
    _bootstrap_provider_configs()
    provider_capabilities = [adapter.capabilities() for adapter in _provider_adapters.values()]
    return {
        "enabled": x402_enabled(),
        "builder_name": getattr(_challenge_builder, "builder_name", "unknown"),
        "verifier_name": getattr(_receipt_verifier, "verifier_name", "unknown"),
        "provider_verifier_name": "provider_adapter_registry",
        "fallback_verifier_name": "signed_receipt_fallback",
        "provider_adapters": provider_capabilities,
        "configured_providers": _store.list_x402_provider_configs(),
        "supports_multi_chain_verification": len(_supported_networks) > 1,
        "supports_machine_readable_challenges": x402_enabled(),
        "supports_receipt_verification": True,
        "supports_provider_receipts": True,
        "supports_provider_receipt_queries": True,
        "supports_provider_key_rotation_windows": any(
            bool(item.get("supports_key_rotation_windows")) for item in provider_capabilities
        ),
        "supports_provider_discovery_refresh": any(
            bool(item.get("supports_provider_discovery_refresh")) for item in provider_capabilities
        ),
        "supports_jwks_source_reconciliation": any(
            bool(item.get("supports_jwks_source_reconciliation")) for item in provider_capabilities
        ),
        "supports_federated_trust_anchors": any(
            bool(item.get("supports_federated_trust_anchors")) for item in provider_capabilities
        ),
        "supports_settlement_proof": any(bool(item.get("supports_settlement_proof")) for item in provider_capabilities),
        "supports_confirmation_counts": any(bool(item.get("supports_confirmation_counts")) for item in provider_capabilities),
        "supports_multi_issuer_provider_config": True,
        "supports_multi_key_provider_config": True,
        "provider_receipt_format": PROVIDER_RECEIPT_PREFIX,
        "provider_receipt_version": PROVIDER_RECEIPT_VERSION,
        "fallback_receipt_flow_enabled": True,
        "status": "development_provider_plus_fallback",
        "supported_networks": list(_supported_networks),
        "network_recipient_addresses": {network: _network_recipient_address(network) for network in _supported_networks},
    }


@router.get("/x402/providers")
def list_x402_providers(
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> dict[str, Any]:
    _require_x402_identity(authorization)
    _bootstrap_provider_configs()
    return {
        "providers": [adapter.capabilities() for adapter in _provider_adapters.values()],
        "active_provider_count": len(_provider_adapters),
        "configured_providers": _store.list_x402_provider_configs(),
    }


@router.get("/x402/provider-configs")
def list_x402_provider_configs(
    is_enabled: bool | None = None,
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> list[dict[str, Any]]:
    _require_x402_identity(authorization)
    _bootstrap_provider_configs()
    return _store.list_x402_provider_configs(is_enabled=is_enabled)


@router.post("/x402/provider-configs")
def upsert_x402_provider_config(
    payload: X402ProviderConfigRequest,
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> dict[str, Any]:
    identity = _get_current_identity(authorization)
    _ensure_scope(identity, ["admin:all"])
    if payload.adapter_name not in _provider_adapters:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Unknown x402 adapter_name")
    config = _store.upsert_x402_provider_config(
        provider_name=payload.provider_name,
        adapter_name=payload.adapter_name,
        issuer_url=payload.issuer_url,
        verifier_key_id=payload.verifier_key_id,
        required_settlement_proof_type=payload.required_settlement_proof_type,
        minimum_confirmations=payload.minimum_confirmations,
        issuer_urls=payload.issuer_urls,
        verifier_key_ids=payload.verifier_key_ids,
        trust_anchor_ids=payload.trust_anchor_ids,
        supported_networks=payload.supported_networks,
        is_enabled=payload.is_enabled,
        notes=payload.notes,
    )
    _append_audit_entry(
        actor_type="operator",
        actor_id=getattr(identity, "subject", None) or getattr(identity, "user_id", None) or "unknown",
        action="x402_provider_config_upsert",
        request_path="/x402/provider-configs",
        request_payload_hash=payload.provider_name,
        request_payload_summary={
            "provider_name": payload.provider_name,
            "adapter_name": payload.adapter_name,
            "is_enabled": payload.is_enabled,
        },
        decision="updated",
        decision_reason=None,
        decision_details={
            "supported_networks": payload.supported_networks,
            "verifier_key_id": payload.verifier_key_id,
            "verifier_key_ids": payload.verifier_key_ids,
            "trust_anchor_ids": payload.trust_anchor_ids,
            "issuer_urls": payload.issuer_urls,
            "required_settlement_proof_type": payload.required_settlement_proof_type,
            "minimum_confirmations": payload.minimum_confirmations,
        },
    )
    return {"provider_config": config}


@router.get("/x402/provider-receipts")
def list_x402_provider_receipts(
    verification_status: str | None = None,
    provider_name: str | None = None,
    network: str | None = None,
    status: str | None = None,
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> list[dict[str, Any]]:
    _require_x402_identity(authorization)
    return _store.list_x402_provider_receipts(
        verification_status=verification_status,
        provider_name=provider_name,
        network=network,
        status=status,
    )


@router.get("/x402/provider-receipts/{receipt_id}")
def get_x402_provider_receipt(
    receipt_id: str,
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> dict[str, Any]:
    _require_x402_identity(authorization)
    receipt = _store.get_x402_provider_receipt(receipt_id)
    if receipt is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="X402 provider receipt not found")
    return receipt
