from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import hmac
import json
import secrets
import time
from decimal import Decimal, InvalidOperation
from typing import Any, Callable, Protocol
from urllib.parse import urlsplit, urlunsplit

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Header
from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..auth import (
    audit_infrastructure_identity_fields,
    capture_infrastructure_identity_profile,
    require_trusted_infrastructure_identity_for_admin,
)


router = APIRouter()

_store = None
_append_audit_entry: Callable[..., None] | None = None
_error_payload: Callable[..., dict[str, Any]] | None = None
_hash_token: Callable[[str], str] | None = None
_sanitize_text: Callable[[str, int], str] | None = None
_get_current_identity = None
_ensure_scope: Callable[[Any, list[str]], Any] | None = None
_get_runtime_phase3_features: Callable[[], dict[str, bool]] | None = None
_get_runtime_ap2_lifecycle_policy: Callable[[], dict[str, int]] | None = None
_get_federation_discovery: Callable[[], dict[str, dict[str, Any]]] | None = None
_deny_payment: Callable[..., Any] | None = None
_verifier = None
_shared_secret = ""
_signer_keys: dict[str, str] = {}
_signer_jwks: dict[str, dict[str, Any]] = {}
_trust_anchors: dict[str, dict[str, Any]] = {}
AP2_FEDERATION_DISCOVERY_MAX_AGE = timedelta(days=1)
RS256_SHA256_DIGESTINFO_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")
AP2_SIGNER_VERIFICATION_ERRORS = {
    "AP2_SIGNER_UNKNOWN",
    "AP2_SIGNER_DISABLED",
    "AP2_SIGNER_KEY_MISMATCH",
    "AP2_SIGNER_KEY_UNKNOWN",
    "AP2_SIGNER_KEY_INACTIVE",
    "AP2_SIGNER_ISSUER_MISMATCH",
    "AP2_SIGNER_DISCOVERY_MISMATCH",
    "AP2_SIGNER_DISCOVERY_STALE",
    "AP2_SIGNER_SOURCE_MISMATCH",
    "AP2_SIGNER_TRUST_MISMATCH",
    "AP2_SIGNER_TRUST_ANCHOR_UNKNOWN",
    "AP2_SIGNER_TRUST_ANCHOR_INACTIVE",
}
AP2_TERMINAL_LIFECYCLE_STATUSES = {"archived", "consumed", "consumed_by_child"}


def _request_infrastructure_identity_fields(request: Any) -> dict[str, Any]:
    identity = getattr(request.state, "current_identity", None)
    infra = None if identity is None else getattr(identity, "infrastructure_identity", None)
    return {
        "infrastructure_provider_name": None if infra is None else infra.provider_name,
        "infrastructure_subject": None if infra is None else infra.subject,
        "infrastructure_trust_tier": None if infra is None else infra.trust_tier,
    }


def _accepted_ap2_lifecycle_status(mandate_type: str) -> str:
    return "consumed" if mandate_type == "cart" else "active"


def _base64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("utf-8"))


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


def _parse_signing_key_timestamp(value: Any) -> datetime | None:
    if value is None:
        return None
    candidate = str(value).strip()
    if not candidate:
        return None
    parsed = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _normalize_signer_metadata_url(value: Any) -> str | None:
    if value is None:
        return None
    candidate = str(value).strip()
    if not candidate:
        return None
    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return None
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc or parsed.fragment:
        return None
    normalized_path = parsed.path or "/"
    return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), normalized_path, parsed.query, ""))


def _validate_rs256_signing_key_trust(*, signing_key: dict[str, Any], signer_id: str) -> str | None:
    status = str(signing_key.get("status") or "active").strip().lower()
    if status != "active":
        return "AP2_SIGNER_KEY_INACTIVE"
    try:
        not_before = _parse_signing_key_timestamp(signing_key.get("not_before"))
        not_after = _parse_signing_key_timestamp(signing_key.get("not_after"))
    except ValueError:
        return "AP2_SIGNER_KEY_INACTIVE"
    now = datetime.now(timezone.utc)
    if not_before and now < not_before:
        return "AP2_SIGNER_KEY_INACTIVE"
    if not_after and now >= not_after:
        return "AP2_SIGNER_KEY_INACTIVE"
    allowed_signer_ids = signing_key.get("ap2_signer_ids") or []
    if allowed_signer_ids and signer_id not in {str(item).strip() for item in allowed_signer_ids if str(item).strip()}:
        return "AP2_SIGNER_TRUST_MISMATCH"
    trust_anchor_error = _validate_rs256_signing_key_trust_anchor(signing_key=signing_key, signer_id=signer_id)
    if trust_anchor_error is not None:
        return trust_anchor_error
    return None


def _extract_ap2_signer_issuer_url(payload: dict[str, Any]) -> str | None:
    for field_name in ("issuer_url", "issuer", "iss"):
        if field_name in payload:
            return _normalize_signer_metadata_url(payload.get(field_name))
    return None


def _extract_ap2_signer_discovery_url(payload: dict[str, Any]) -> str | None:
    for field_name in ("discovery_url", "signer_discovery_url"):
        if field_name in payload:
            return _normalize_signer_metadata_url(payload.get(field_name))
    return None


def _validate_rs256_signing_key_discovery_binding(
    *,
    signing_key: dict[str, Any],
    mandate: "AP2MandateReference",
) -> str | None:
    configured_issuer_url, configured_discovery_url, _ = _effective_rs256_signing_key_binding(signing_key)
    if configured_issuer_url is not None:
        presented_issuer_url = _extract_ap2_signer_issuer_url(mandate.payload)
        if presented_issuer_url != configured_issuer_url:
            return "AP2_SIGNER_ISSUER_MISMATCH"

    if configured_discovery_url is not None:
        presented_discovery_url = _extract_ap2_signer_discovery_url(mandate.payload)
        if presented_discovery_url != configured_discovery_url:
            return "AP2_SIGNER_DISCOVERY_MISMATCH"
    return None


def _current_ap2_federation_discovery() -> dict[str, dict[str, Any]]:
    if _get_federation_discovery is None:
        return {}
    try:
        configured = _get_federation_discovery()
    except Exception:
        return {}
    return configured if isinstance(configured, dict) else {}


def _signing_key_trust_anchor_id(signing_key: dict[str, Any] | None) -> str | None:
    if signing_key is None:
        return None
    candidate = str(signing_key.get("trust_anchor_id") or "").strip()
    return candidate or None


def _resolve_signing_key_trust_anchor(signing_key: dict[str, Any]) -> tuple[str | None, dict[str, Any] | None]:
    trust_anchor_id = _signing_key_trust_anchor_id(signing_key)
    if trust_anchor_id is None:
        return None, None
    return trust_anchor_id, _trust_anchors.get(trust_anchor_id)


def _validate_rs256_signing_key_trust_anchor(*, signing_key: dict[str, Any], signer_id: str) -> str | None:
    trust_anchor_id, trust_anchor = _resolve_signing_key_trust_anchor(signing_key)
    if trust_anchor_id is None:
        return None
    if trust_anchor is None:
        return "AP2_SIGNER_TRUST_ANCHOR_UNKNOWN"

    trust_anchor_status = str(trust_anchor.get("status") or "active").strip().lower()
    if trust_anchor_status != "active":
        return "AP2_SIGNER_TRUST_ANCHOR_INACTIVE"

    allowed_signer_ids = trust_anchor.get("ap2_signer_ids") or []
    if allowed_signer_ids and signer_id not in {str(item).strip() for item in allowed_signer_ids if str(item).strip()}:
        return "AP2_SIGNER_TRUST_MISMATCH"

    trust_anchor_issuer_url = _normalize_signer_metadata_url(trust_anchor.get("issuer_url"))
    trust_anchor_discovery_url = _normalize_signer_metadata_url(trust_anchor.get("discovery_url"))
    key_issuer_url = _normalize_signer_metadata_url(signing_key.get("issuer_url"))
    key_discovery_url = _normalize_signer_metadata_url(signing_key.get("discovery_url"))
    if key_issuer_url is not None and key_issuer_url != trust_anchor_issuer_url:
        return "AP2_SIGNER_TRUST_MISMATCH"
    if key_discovery_url is not None and key_discovery_url != trust_anchor_discovery_url:
        return "AP2_SIGNER_TRUST_MISMATCH"
    return None


def _effective_rs256_signing_key_binding(
    signing_key: dict[str, Any],
) -> tuple[str | None, str | None, str | None]:
    trust_anchor_id, trust_anchor = _resolve_signing_key_trust_anchor(signing_key)
    metadata_source = trust_anchor or signing_key
    return (
        _normalize_signer_metadata_url(metadata_source.get("issuer_url")),
        _normalize_signer_metadata_url(metadata_source.get("discovery_url")),
        trust_anchor_id,
    )


def _resolve_rs256_federation_discovery_document(signing_key: dict[str, Any]) -> dict[str, Any] | None:
    _, discovery_url, _ = _effective_rs256_signing_key_binding(signing_key)
    if discovery_url is None:
        return None
    discovery_document = _current_ap2_federation_discovery().get(discovery_url)
    return discovery_document if isinstance(discovery_document, dict) else None


def _validate_rs256_signing_key_federation_source(*, signing_key: dict[str, Any], key_id: str) -> str | None:
    discovery_document = _resolve_rs256_federation_discovery_document(signing_key)
    if discovery_document is None:
        return None
    if str(discovery_document.get("status") or "active").strip().lower() != "active":
        return "AP2_SIGNER_SOURCE_MISMATCH"
    issuer_url, discovery_url, trust_anchor_id = _effective_rs256_signing_key_binding(signing_key)
    if _normalize_signer_metadata_url(discovery_document.get("issuer_url")) != issuer_url:
        return "AP2_SIGNER_SOURCE_MISMATCH"
    if _normalize_signer_metadata_url(discovery_document.get("discovery_url")) != discovery_url:
        return "AP2_SIGNER_SOURCE_MISMATCH"
    discovery_trust_anchor_id = str(discovery_document.get("trust_anchor_id") or "").strip() or None
    if trust_anchor_id is not None and discovery_trust_anchor_id is not None and discovery_trust_anchor_id != trust_anchor_id:
        return "AP2_SIGNER_SOURCE_MISMATCH"
    try:
        cache_expires_at = _parse_signing_key_timestamp(discovery_document.get("cache_expires_at"))
    except ValueError:
        return "AP2_SIGNER_DISCOVERY_STALE"
    if cache_expires_at is not None and datetime.now(timezone.utc) >= cache_expires_at:
        return "AP2_SIGNER_DISCOVERY_STALE"
    try:
        refreshed_at = _parse_signing_key_timestamp(discovery_document.get("refreshed_at"))
    except ValueError:
        return "AP2_SIGNER_DISCOVERY_STALE"
    if refreshed_at is None or datetime.now(timezone.utc) - refreshed_at > AP2_FEDERATION_DISCOVERY_MAX_AGE:
        return "AP2_SIGNER_DISCOVERY_STALE"
    discovered_keys = discovery_document.get("keys")
    if not isinstance(discovered_keys, dict):
        return "AP2_SIGNER_SOURCE_MISMATCH"
    discovered_key = discovered_keys.get(key_id)
    if not isinstance(discovered_key, dict):
        return "AP2_SIGNER_SOURCE_MISMATCH"
    if signing_key.get("modulus") != discovered_key.get("modulus"):
        return "AP2_SIGNER_SOURCE_MISMATCH"
    if signing_key.get("exponent") != discovered_key.get("exponent"):
        return "AP2_SIGNER_SOURCE_MISMATCH"
    return None


def _rs256_signing_key_federation_evidence(signing_key: dict[str, Any]) -> dict[str, Any] | None:
    discovery_document = _resolve_rs256_federation_discovery_document(signing_key)
    if discovery_document is None:
        return None
    jwks_uri = _normalize_signer_metadata_url(discovery_document.get("jwks_uri"))
    refreshed_at = discovery_document.get("refreshed_at")
    if jwks_uri is None or not isinstance(refreshed_at, str) or not refreshed_at.strip():
        return None
    return {
        "federation_jwks_uri": jwks_uri,
        "federation_refreshed_at": refreshed_at,
    }


def _rs256_key_ids_share_trust_anchor(*, configured_key_id: str, presented_key_id: str) -> bool:
    if configured_key_id == presented_key_id:
        return True
    configured_key = _signer_jwks.get(configured_key_id)
    presented_key = _signer_jwks.get(presented_key_id)
    configured_anchor_id = _signing_key_trust_anchor_id(configured_key)
    presented_anchor_id = _signing_key_trust_anchor_id(presented_key)
    if configured_anchor_id is None or configured_anchor_id != presented_anchor_id:
        return False
    trust_anchor = _trust_anchors.get(configured_anchor_id)
    return trust_anchor is not None and str(trust_anchor.get("status") or "active").strip().lower() == "active"


class AP2MandatePayload(BaseModel):
    model_config = ConfigDict(extra="allow", strict=True)


class AP2MandateReference(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    mandate_id: str = Field(..., min_length=1)
    mandate_type: str = Field(..., min_length=1)
    signer_id: str | None = Field(default=None)
    key_id: str | None = Field(default=None)
    reference: str | None = Field(default=None)
    signature: str | None = Field(default=None)
    payload: dict[str, Any] = Field(default_factory=dict)

    @field_validator("mandate_id", "mandate_type", "signer_id", "key_id", "reference", "signature")
    @classmethod
    def sanitize_optional_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        sanitized = _sanitize_text(value, max_length=500)
        if not sanitized:
            raise ValueError("value cannot be empty")
        return sanitized


@dataclass(slots=True)
class AP2VerificationResult:
    accepted: bool
    reason_code: str
    message: str
    parsed_mandate: dict[str, Any] | None = None
    discrepancies: list[str] | None = None
    verifier_name: str = "stub"


class AP2CanonicalPayloadError(ValueError):
    def __init__(self, field_name: str, message: str) -> None:
        super().__init__(message)
        self.field_name = field_name


class AP2SignerConfigRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    signer_id: str = Field(..., min_length=1)
    verifier_name: str | None = Field(default=None)
    verifier_key_id: str | None = Field(default=None)
    is_enabled: bool = Field(default=True)
    notes: str | None = Field(default=None)

    @field_validator("signer_id", "verifier_name", "verifier_key_id", "notes")
    @classmethod
    def sanitize_text_fields(cls, value: str | None) -> str | None:
        if value is None:
            return None
        sanitized = _sanitize_text(value, max_length=500)
        if not sanitized:
            raise ValueError("value cannot be empty")
        return sanitized


class AP2MandateRetentionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    retained_until: str = Field(..., min_length=1)

    @field_validator("retained_until")
    @classmethod
    def validate_timestamp(cls, value: str) -> str:
        sanitized = _sanitize_text(value, max_length=100)
        if not sanitized:
            raise ValueError("value cannot be empty")
        try:
            datetime.fromisoformat(sanitized.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("retained_until must be a valid ISO-8601 timestamp") from exc
        return sanitized


class AP2Verifier(Protocol):
    verifier_name: str

    def verify(self, *, payment: Any, mandate: AP2MandateReference) -> AP2VerificationResult:
        ...


class StubAP2Verifier:
    verifier_name = "stub"

    def verify(self, *, payment: Any, mandate: AP2MandateReference) -> AP2VerificationResult:
        return AP2VerificationResult(
            accepted=False,
            reason_code="AP2_NOT_IMPLEMENTED",
            message="AP2 verification is enabled but no concrete mandate verifier is installed yet.",
            parsed_mandate={
                "mandate_id": mandate.mandate_id,
                "mandate_type": mandate.mandate_type,
                "reference": mandate.reference,
                "payload_keys": sorted(mandate.payload.keys()),
            },
            discrepancies=None,
            verifier_name=self.verifier_name,
        )


class SharedSecretAP2Verifier:
    verifier_name = "shared_secret_hmac"
    _PACKAGE_CONTAINER_KEYS = ("package", "payment_package")
    _VENDOR_IDENTIFIER_KEYS = ("vendor_id", "merchant_id", "id", "identifier", "code")
    _USER_IDENTIFIER_KEYS = ("user_id", "subject", "sub", "id", "identifier")

    @staticmethod
    def _resolve_signer_config(mandate: AP2MandateReference) -> tuple[str, str]:
        signer_id = mandate.signer_id or "default"
        config = _store.get_ap2_signer_config(signer_id)
        if config is None:
            if signer_id != "default":
                raise ValueError("AP2_SIGNER_UNKNOWN")
            return signer_id, mandate.key_id or "default"
        if not config["is_enabled"]:
            raise ValueError("AP2_SIGNER_DISABLED")
        configured_key_id = config.get("verifier_key_id") or "default"
        if mandate.key_id and mandate.key_id != configured_key_id:
            raise ValueError("AP2_SIGNER_KEY_MISMATCH")
        return signer_id, configured_key_id

    @staticmethod
    def _extract_parent_mandate_id(mandate: AP2MandateReference) -> str | None:
        for key in ("intent_mandate_id", "parent_mandate_id"):
            value = mandate.payload.get(key)
            if value is None:
                continue
            parent_id = str(value).strip()
            if parent_id:
                return parent_id
        return None

    @classmethod
    def _package_payload_sources(cls, payload: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
        sources = [("payload", payload)]
        package_sources: list[tuple[str, dict[str, Any]]] = []
        for field_name in cls._PACKAGE_CONTAINER_KEYS:
            if field_name not in payload:
                continue
            candidate = payload.get(field_name)
            if not isinstance(candidate, dict):
                raise AP2CanonicalPayloadError(field_name, f"AP2 mandate {field_name} must be an object.")
            if any(nested_field in candidate for nested_field in cls._PACKAGE_CONTAINER_KEYS):
                raise AP2CanonicalPayloadError(
                    field_name,
                    f"AP2 mandate {field_name} must not contain nested package envelopes.",
                )
            package_sources.append((field_name, candidate))
        if len(package_sources) > 1:
            raise AP2CanonicalPayloadError(
                "package",
                "AP2 mandate must not contain both package and payment_package envelopes.",
            )
        sources.extend(package_sources)
        return sources

    @staticmethod
    def _normalize_finite_decimal(value: Any, *, field_name: str) -> Decimal:
        try:
            candidate = Decimal(str(value))
        except (InvalidOperation, TypeError, ValueError) as exc:
            raise ValueError(f"invalid {field_name}") from exc
        if not candidate.is_finite():
            raise ValueError(f"invalid {field_name}")
        return candidate

    @staticmethod
    def _normalize_package_amount(value: Any) -> Decimal:
        return SharedSecretAP2Verifier._normalize_finite_decimal(value, field_name="amount")

    @classmethod
    def _normalize_package_currency(cls, value: Any) -> str:
        candidate = cls._normalize_leaf_text(value, field_name="currency").upper()
        if not candidate:
            raise ValueError("invalid currency")
        return candidate

    @staticmethod
    def _normalize_leaf_text(value: Any, *, field_name: str, allow_empty: bool = False) -> str:
        if isinstance(value, dict) or isinstance(value, (list, tuple, set)):
            raise ValueError(f"invalid {field_name}")
        candidate = str(value).strip()
        if not candidate and not allow_empty:
            raise ValueError(f"invalid {field_name}")
        return candidate

    @classmethod
    def _normalize_identifier_value(
        cls,
        value: Any,
        *,
        field_name: str,
        object_keys: tuple[str, ...],
    ) -> str:
        if isinstance(value, dict):
            resolved = None
            for key in object_keys:
                if key not in value:
                    continue
                candidate = cls._normalize_leaf_text(value.get(key), field_name=field_name, allow_empty=True)
                if not candidate:
                    continue
                if resolved is None:
                    resolved = candidate
                    continue
                if resolved != candidate:
                    raise AP2CanonicalPayloadError(
                        field_name,
                        f"AP2 mandate {field_name} has conflicting canonical identifier/package values.",
                    )
            if resolved is None:
                raise ValueError("invalid identifier")
            return resolved
        candidate = cls._normalize_leaf_text(value, field_name=field_name)
        if not candidate:
            raise ValueError("invalid identifier")
        return candidate

    @classmethod
    def _resolve_canonical_package_scalar(
        cls,
        payload: dict[str, Any],
        *,
        field_name: str,
        aliases: tuple[str, ...],
        normalizer: Callable[[Any], Any],
    ) -> tuple[Any | None, list[str]]:
        resolved = None
        sources: list[str] = []
        for source_name, source_payload in cls._package_payload_sources(payload):
            source_resolved = None
            for candidate_field in (field_name, *aliases):
                if candidate_field not in source_payload:
                    continue
                try:
                    normalized = normalizer(source_payload.get(candidate_field))
                except AP2CanonicalPayloadError:
                    raise
                except ValueError as exc:
                    raise AP2CanonicalPayloadError(
                        field_name,
                        f"AP2 mandate {field_name} is invalid.",
                    ) from exc
                if source_resolved is None:
                    source_resolved = normalized
                    continue
                if source_resolved != normalized:
                    raise AP2CanonicalPayloadError(
                        field_name,
                        f"AP2 mandate {field_name} has conflicting canonical identifier/package values.",
                    )
            if source_resolved is None:
                continue
            if resolved is None:
                resolved = source_resolved
            elif resolved != source_resolved:
                raise AP2CanonicalPayloadError(
                    field_name,
                    f"AP2 mandate {field_name} has conflicting canonical identifier/package values.",
                )
            sources.append(source_name)
        return resolved, sorted(set(sources))

    @classmethod
    def _resolve_canonical_package(cls, payload: dict[str, Any]) -> dict[str, Any]:
        amount, amount_sources = cls._resolve_canonical_package_scalar(
            payload,
            field_name="amount",
            aliases=("total_amount",),
            normalizer=cls._normalize_package_amount,
        )
        currency, currency_sources = cls._resolve_canonical_package_scalar(
            payload,
            field_name="currency",
            aliases=(),
            normalizer=cls._normalize_package_currency,
        )
        vendor, vendor_sources = cls._resolve_canonical_package_scalar(
            payload,
            field_name="vendor",
            aliases=("vendor_id", "merchant", "merchant_id"),
            normalizer=lambda value: cls._normalize_identifier_value(
                value,
                field_name="vendor",
                object_keys=cls._VENDOR_IDENTIFIER_KEYS,
            ),
        )
        user_id, user_sources = cls._resolve_canonical_package_scalar(
            payload,
            field_name="user_id",
            aliases=("user", "subject"),
            normalizer=lambda value: cls._normalize_identifier_value(
                value,
                field_name="user_id",
                object_keys=cls._USER_IDENTIFIER_KEYS,
            ),
        )
        items, item_sources = cls._resolve_canonical_package_items(payload)
        return {
            "amount": amount,
            "currency": currency,
            "vendor": vendor,
            "user_id": user_id,
            "items": items,
            "item_sources": item_sources,
            "missing_fields": [
                field_name
                for field_name, value in (
                    ("amount", amount),
                    ("currency", currency),
                    ("vendor", vendor),
                    ("user_id", user_id),
                )
                if value is None
            ],
            "package_sources": sorted(
                set(amount_sources + currency_sources + vendor_sources + user_sources + item_sources)
            ),
        }

    @staticmethod
    def _canonical_message(mandate: AP2MandateReference) -> str:
        return json.dumps(
            {
                "mandate_id": mandate.mandate_id,
                "mandate_type": mandate.mandate_type,
                "signer_id": mandate.signer_id,
                "key_id": mandate.key_id,
                "reference": mandate.reference,
                "payload": mandate.payload,
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    def _verify_signature(self, mandate: AP2MandateReference) -> tuple[bool, str, str]:
        if not mandate.signature:
            return False, mandate.signer_id or "default", mandate.key_id or "default"
        try:
            signer_id, key_id = self._resolve_signer_config(mandate)
        except ValueError as exc:
            return False, mandate.signer_id or "default", str(exc)
        secret = _signer_keys.get(key_id, _shared_secret if key_id == "default" else None)
        if secret is None:
            return False, signer_id, "AP2_SIGNER_KEY_UNKNOWN"
        digest = hmac.new(
            secret.encode("utf-8"),
            self._canonical_message(mandate).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(digest, mandate.signature), signer_id, key_id

    @classmethod
    def _normalize_item(cls, item: Any, *, index: int) -> dict[str, Any]:
        if not isinstance(item, dict):
            raise ValueError(f"items[{index}] must be an object")
        item_id = ""
        for key in ("item_id", "sku", "name", "description"):
            value = item.get(key)
            if value is None:
                continue
            try:
                item_id = cls._normalize_leaf_text(
                    value,
                    field_name=f"items[{index}].{key}",
                    allow_empty=True,
                )
            except ValueError as exc:
                raise ValueError(f"items[{index}].item_id is invalid") from exc
            if item_id:
                break
        if not item_id:
            raise ValueError(f"items[{index}] must include item_id, sku, name, or description")
        quantity_raw = item.get("quantity", "1")
        try:
            quantity = cls._normalize_finite_decimal(quantity_raw, field_name=f"items[{index}].quantity")
        except ValueError as exc:
            raise ValueError(f"items[{index}].quantity is invalid") from exc
        if quantity <= 0:
            raise ValueError(f"items[{index}].quantity must be positive")
        unit_amount_raw = item.get("unit_amount")
        unit_amount = None
        if unit_amount_raw is not None:
            try:
                unit_amount = cls._normalize_finite_decimal(unit_amount_raw, field_name=f"items[{index}].unit_amount")
            except ValueError as exc:
                raise ValueError(f"items[{index}].unit_amount is invalid") from exc
            if unit_amount < 0:
                raise ValueError(f"items[{index}].unit_amount must be non-negative")
        line_amount = None
        for key in ("line_amount", "line_total", "total_amount", "amount"):
            raw_value = item.get(key)
            if raw_value is None:
                continue
            try:
                line_amount = cls._normalize_finite_decimal(raw_value, field_name=f"items[{index}].line_amount")
            except ValueError as exc:
                raise ValueError(f"items[{index}].line_amount is invalid") from exc
            if line_amount < 0:
                raise ValueError(f"items[{index}].line_amount must be non-negative")
            break
        computed_line_amount = None if unit_amount is None else unit_amount * quantity
        if line_amount is not None and computed_line_amount is not None and line_amount != computed_line_amount:
            raise ValueError(f"items[{index}].line_amount must equal quantity * unit_amount")
        canonical_line_amount = line_amount if line_amount is not None else computed_line_amount
        canonical_unit_amount = unit_amount
        if canonical_unit_amount is None and canonical_line_amount is not None:
            canonical_unit_amount = canonical_line_amount / quantity
        currency = item.get("currency")
        currency_text = None
        if currency is not None:
            try:
                normalized_currency = cls._normalize_leaf_text(
                    currency,
                    field_name=f"items[{index}].currency",
                    allow_empty=True,
                )
            except ValueError as exc:
                raise ValueError(f"items[{index}].currency is invalid") from exc
            currency_text = normalized_currency.upper() if normalized_currency else None
        return {
            "item_id": item_id,
            "quantity": quantity,
            "unit_amount": unit_amount,
            "canonical_unit_amount": canonical_unit_amount,
            "line_amount": canonical_line_amount,
            "currency": currency_text,
        }

    @classmethod
    def _normalize_items(cls, raw_items: Any) -> list[dict[str, Any]]:
        if not isinstance(raw_items, list) or not raw_items:
            raise ValueError("items must be a non-empty list")
        return [cls._normalize_item(item, index=index) for index, item in enumerate(raw_items)]

    @classmethod
    def _resolve_canonical_package_items(
        cls,
        payload: dict[str, Any],
    ) -> tuple[list[dict[str, Any]] | None, list[str]]:
        resolved = None
        sources: list[str] = []
        for source_name, source_payload in cls._package_payload_sources(payload):
            if "items" not in source_payload:
                continue
            try:
                normalized = cls._normalize_items(source_payload.get("items"))
            except ValueError as exc:
                raise AP2CanonicalPayloadError("items", "AP2 mandate items are invalid.") from exc
            if resolved is None:
                resolved = normalized
            elif cls._aggregate_items(resolved) != cls._aggregate_items(normalized):
                raise AP2CanonicalPayloadError(
                    "items",
                    "AP2 mandate items have conflicting canonical package values.",
                )
            sources.append(source_name)
        return resolved, sorted(set(sources))

    @staticmethod
    def _item_key(item: dict[str, Any]) -> tuple[str, Decimal | None, str | None]:
        unit_amount = item["canonical_unit_amount"]
        return (
            item["item_id"],
            unit_amount,
            item["currency"],
        )

    @classmethod
    def _aggregate_items(cls, items: list[dict[str, Any]]) -> dict[tuple[str, Decimal | None, str | None], Decimal]:
        aggregated: dict[tuple[str, Decimal | None, str | None], Decimal] = {}
        for item in items:
            key = cls._item_key(item)
            aggregated[key] = aggregated.get(key, Decimal("0")) + item["quantity"]
        return aggregated

    @classmethod
    def _compare_exact_items(
        cls,
        *,
        expected_items: list[dict[str, Any]],
        actual_items: list[dict[str, Any]],
        discrepancies: list[str],
        prefix: str,
    ) -> None:
        if cls._aggregate_items(expected_items) != cls._aggregate_items(actual_items):
            discrepancies.append(prefix)

    @classmethod
    def _compare_parent_item_limits(
        cls,
        *,
        parent_items: list[dict[str, Any]],
        child_items: list[dict[str, Any]],
        discrepancies: list[str],
    ) -> None:
        parent_agg = cls._aggregate_items(parent_items)
        child_agg = cls._aggregate_items(child_items)
        for key, child_quantity in child_agg.items():
            if key not in parent_agg:
                discrepancies.append("parent_items_missing")
                continue
            if child_quantity > parent_agg[key]:
                discrepancies.append("parent_item_quantity_limit")

    def _lifecycle_invalid_result(
        self,
        *,
        parsed_mandate: dict[str, Any],
        message: str,
        discrepancies: list[str],
        lifecycle_status: str | None = None,
        family_id: str | None = None,
        chain_status: str | None = None,
        chain_depth: int | None = None,
        superseded_by_mandate_id: str | None = None,
        extra_fields: dict[str, Any] | None = None,
    ) -> AP2VerificationResult:
        enriched_parsed_mandate = dict(parsed_mandate)
        if lifecycle_status is not None:
            enriched_parsed_mandate["lifecycle_status"] = lifecycle_status
        if family_id is not None:
            enriched_parsed_mandate["family_id"] = family_id
        if chain_status is not None:
            enriched_parsed_mandate["chain_status"] = chain_status
        if chain_depth is not None:
            enriched_parsed_mandate["chain_depth"] = chain_depth
        if superseded_by_mandate_id is not None:
            enriched_parsed_mandate["superseded_by_mandate_id"] = superseded_by_mandate_id
        if extra_fields:
            enriched_parsed_mandate.update(extra_fields)
        return AP2VerificationResult(
            accepted=False,
            reason_code="AP2_MANDATE_LIFECYCLE_INVALID",
            message=message,
            parsed_mandate=enriched_parsed_mandate,
            discrepancies=discrepancies,
            verifier_name=self.verifier_name,
        )

    def _validate_existing_mandate_lifecycle(
        self,
        *,
        mandate: AP2MandateReference,
        parsed_mandate: dict[str, Any],
    ) -> AP2VerificationResult | None:
        existing_mandate = _store.get_ap2_mandate(mandate.mandate_id)
        if existing_mandate is None:
            return None
        lifecycle_status = str(existing_mandate.get("lifecycle_status") or "").strip()
        if lifecycle_status not in AP2_TERMINAL_LIFECYCLE_STATUSES:
            return None
        return self._lifecycle_invalid_result(
            parsed_mandate=parsed_mandate,
            message="AP2 mandate lifecycle state no longer permits payment authorization.",
            discrepancies=["lifecycle_status"],
            lifecycle_status=lifecycle_status,
            family_id=str(existing_mandate.get("family_id") or existing_mandate["mandate_id"]),
            chain_status=str(existing_mandate.get("chain_status") or "standalone"),
            chain_depth=int(existing_mandate.get("chain_depth", 1)),
            superseded_by_mandate_id=existing_mandate.get("superseded_by_mandate_id"),
            extra_fields={
                "existing_verification_status": existing_mandate.get("verification_status"),
                "existing_mandate_id": existing_mandate["mandate_id"],
            },
        )

    def _validate_parent_mandate_lifecycle(
        self,
        *,
        mandate: AP2MandateReference,
        parsed_mandate: dict[str, Any],
        parent: dict[str, Any],
    ) -> AP2VerificationResult | None:
        lifecycle_status = str(parent.get("lifecycle_status") or "").strip()
        family_id = str(parent.get("family_id") or parent["mandate_id"])
        chain_depth = int(parent.get("chain_depth", 1)) + 1
        if lifecycle_status == "archived":
            return self._lifecycle_invalid_result(
                parsed_mandate=parsed_mandate,
                message="AP2 cart mandate cannot attach to an archived mandate family.",
                discrepancies=["parent_mandate_id"],
                lifecycle_status=lifecycle_status,
                family_id=family_id,
                chain_status="parent_archived",
                chain_depth=chain_depth,
                superseded_by_mandate_id=parent.get("superseded_by_mandate_id"),
                extra_fields={
                    "parent_lifecycle_status": lifecycle_status,
                    "parent_verification_status": parent.get("verification_status"),
                },
            )
        superseded_by_mandate_id = parent.get("superseded_by_mandate_id")
        if lifecycle_status == "consumed_by_child" and superseded_by_mandate_id not in {None, mandate.mandate_id}:
            return self._lifecycle_invalid_result(
                parsed_mandate=parsed_mandate,
                message="AP2 cart mandate cannot reuse an intent mandate that has already been consumed by another child.",
                discrepancies=["parent_mandate_id"],
                lifecycle_status=lifecycle_status,
                family_id=family_id,
                chain_status="parent_consumed",
                chain_depth=chain_depth,
                superseded_by_mandate_id=superseded_by_mandate_id,
                extra_fields={
                    "parent_lifecycle_status": lifecycle_status,
                    "parent_verification_status": parent.get("verification_status"),
                    "parent_current_child_mandate_id": superseded_by_mandate_id,
                },
            )
        return None

    def _validate_parent_family_retirement(
        self,
        *,
        parsed_mandate: dict[str, Any],
        parent: dict[str, Any],
    ) -> AP2VerificationResult | None:
        lifecycle_status = str(parent.get("lifecycle_status") or "").strip()
        if lifecycle_status == "archived":
            return None
        family_id = str(parent.get("family_id") or parent["mandate_id"])
        archived_family_mandate_ids = _list_archived_ap2_family_mandate_ids(family_id)
        if not archived_family_mandate_ids:
            return None
        return self._lifecycle_invalid_result(
            parsed_mandate=parsed_mandate,
            message="AP2 cart mandate cannot attach to a mandate family that has already started retirement.",
            discrepancies=["parent_mandate_id"],
            lifecycle_status=lifecycle_status or None,
            family_id=family_id,
            chain_status="family_retiring",
            chain_depth=int(parent.get("chain_depth", 1)) + 1,
            superseded_by_mandate_id=parent.get("superseded_by_mandate_id"),
            extra_fields={
                "parent_lifecycle_status": lifecycle_status,
                "parent_verification_status": parent.get("verification_status"),
                "archived_family_mandate_ids": archived_family_mandate_ids,
            },
        )

    def verify(self, *, payment: Any, mandate: AP2MandateReference) -> AP2VerificationResult:
        parent_mandate_id = self._extract_parent_mandate_id(mandate)
        signer_id = mandate.signer_id or "default"
        key_id = mandate.key_id or "default"
        parsed_mandate = {
            "mandate_id": mandate.mandate_id,
            "mandate_type": mandate.mandate_type,
            "signer_id": signer_id,
            "key_id": key_id,
            "reference": mandate.reference,
            "payload_keys": sorted(mandate.payload.keys()),
            "parent_mandate_id": parent_mandate_id,
        }
        issuer_url = _extract_ap2_signer_issuer_url(mandate.payload)
        discovery_url = _extract_ap2_signer_discovery_url(mandate.payload)
        if issuer_url is not None:
            parsed_mandate["issuer_url"] = issuer_url
        if discovery_url is not None:
            parsed_mandate["discovery_url"] = discovery_url
        if mandate.mandate_type == "cart" and parent_mandate_id is None:
            return AP2VerificationResult(
                accepted=False,
                reason_code="AP2_MANDATE_CHAIN_INVALID",
                message="AP2 cart mandate must reference a parent intent mandate.",
                parsed_mandate={**parsed_mandate, "chain_status": "missing_parent", "chain_depth": 1},
                discrepancies=["intent_mandate_id"],
                verifier_name=self.verifier_name,
            )
        existing_mandate_lifecycle_error = self._validate_existing_mandate_lifecycle(
            mandate=mandate,
            parsed_mandate=parsed_mandate,
        )
        if existing_mandate_lifecycle_error is not None:
            return existing_mandate_lifecycle_error
        try:
            canonical_package = self._resolve_canonical_package(mandate.payload)
        except AP2CanonicalPayloadError as exc:
            return AP2VerificationResult(
                accepted=False,
                reason_code="AP2_MANDATE_INVALID",
                message=str(exc),
                parsed_mandate=parsed_mandate,
                discrepancies=[exc.field_name],
                verifier_name=self.verifier_name,
            )
        parsed_mandate["canonical_package_sources"] = canonical_package["package_sources"]
        parsed_mandate["canonical_vendor_id"] = canonical_package["vendor"]
        parsed_mandate["canonical_user_id"] = canonical_package["user_id"]
        parsed_mandate["canonical_item_sources"] = canonical_package["item_sources"]
        missing = canonical_package["missing_fields"]
        if missing:
            return AP2VerificationResult(
                accepted=False,
                reason_code="AP2_MANDATE_INVALID",
                message="AP2 mandate payload is missing required fields.",
                parsed_mandate=parsed_mandate,
                discrepancies=missing,
                verifier_name=self.verifier_name,
            )
        parent: dict[str, Any] | None = None
        if mandate.mandate_type == "cart":
            parent = _store.get_ap2_mandate(parent_mandate_id)
            if parent is not None and parent["mandate_type"] == "intent" and parent["verification_status"] == "accepted":
                parent_family_retirement_error = self._validate_parent_family_retirement(
                    parsed_mandate=parsed_mandate,
                    parent=parent,
                )
                if parent_family_retirement_error is not None:
                    return parent_family_retirement_error
        signature_valid, signer_id, resolved_key = self._verify_signature(mandate)
        parsed_mandate["signer_id"] = signer_id
        parsed_mandate["key_id"] = resolved_key
        resolved_signing_key = _signer_jwks.get(resolved_key)
        resolved_trust_anchor_id = _signing_key_trust_anchor_id(resolved_signing_key)
        if resolved_trust_anchor_id is not None:
            parsed_mandate["trust_anchor_id"] = resolved_trust_anchor_id
        if isinstance(resolved_signing_key, dict):
            federation_evidence = _rs256_signing_key_federation_evidence(resolved_signing_key)
            if federation_evidence is not None:
                parsed_mandate.update(federation_evidence)
        if not signature_valid:
            if resolved_key in AP2_SIGNER_VERIFICATION_ERRORS:
                return AP2VerificationResult(
                    accepted=False,
                    reason_code=resolved_key,
                    message="AP2 mandate signer verification failed.",
                    parsed_mandate=parsed_mandate,
                    discrepancies=["signature"],
                    verifier_name=self.verifier_name,
                )
            return AP2VerificationResult(
                accepted=False,
                reason_code="AP2_INVALID_SIGNATURE",
                message="AP2 mandate signature verification failed.",
                parsed_mandate=parsed_mandate,
                discrepancies=["signature"],
                verifier_name=self.verifier_name,
            )

        discrepancies: list[str] = []
        mandate_amount = canonical_package["amount"]
        if mandate_amount != payment.amount:
            discrepancies.append("amount")
        if canonical_package["currency"] != payment.currency:
            discrepancies.append("currency")
        if canonical_package["vendor"] != payment.vendor:
            discrepancies.append("vendor")
        if canonical_package["user_id"] != payment.user_id:
            discrepancies.append("user_id")

        mandate_items = canonical_package["items"]
        mandate_item_count = 0 if mandate_items is None else len(mandate_items)
        if mandate_items is not None:
            context_items_raw = payment.context.get("items")
            if context_items_raw is None:
                discrepancies.append("context_items_missing")
            else:
                try:
                    context_items = self._normalize_items(context_items_raw)
                except ValueError:
                    discrepancies.append("context_items_invalid")
                else:
                    self._compare_exact_items(
                        expected_items=mandate_items,
                        actual_items=context_items,
                        discrepancies=discrepancies,
                        prefix="items",
                    )

        chain_status = "root_intent" if mandate.mandate_type == "intent" else "standalone"
        chain_depth = 1
        family_id = mandate.mandate_id
        if mandate.mandate_type == "cart":
            if parent is None:
                return AP2VerificationResult(
                    accepted=False,
                    reason_code="AP2_MANDATE_CHAIN_INVALID",
                    message="AP2 cart mandate references an unknown parent intent mandate.",
                    parsed_mandate={**parsed_mandate, "chain_status": "parent_missing", "chain_depth": 1},
                    discrepancies=["parent_mandate_id"],
                    verifier_name=self.verifier_name,
                )
            if parent["mandate_type"] != "intent" or parent["verification_status"] != "accepted":
                return AP2VerificationResult(
                    accepted=False,
                    reason_code="AP2_MANDATE_CHAIN_INVALID",
                    message="AP2 cart mandate must reference an accepted intent mandate.",
                    parsed_mandate={
                        **parsed_mandate,
                        "chain_status": "parent_invalid",
                        "chain_depth": 1,
                        "parent_verification_status": parent["verification_status"],
                    },
                    discrepancies=["parent_mandate_id"],
                    verifier_name=self.verifier_name,
                )
            parent_lifecycle_error = self._validate_parent_mandate_lifecycle(
                mandate=mandate,
                parsed_mandate=parsed_mandate,
                parent=parent,
            )
            if parent_lifecycle_error is not None:
                return parent_lifecycle_error
            family_id = parent.get("family_id") or parent["mandate_id"]
            if parent["vendor"] != payment.vendor:
                discrepancies.append("parent_vendor")
            if parent["currency"] != payment.currency:
                discrepancies.append("parent_currency")
            if parent["requestor_user_id"] != payment.user_id:
                discrepancies.append("parent_user_id")
            parent_amount = Decimal(str(parent["amount"]))
            if mandate_amount > parent_amount:
                discrepancies.append("parent_amount_limit")
            if mandate_items is not None:
                try:
                    parent_items, _ = self._resolve_canonical_package_items(parent.get("payload", {}))
                except AP2CanonicalPayloadError:
                    discrepancies.append("parent_items_invalid")
                else:
                    if parent_items is not None:
                        self._compare_parent_item_limits(
                            parent_items=parent_items,
                            child_items=mandate_items,
                            discrepancies=discrepancies,
                        )
            chain_status = "verified_chain"
            chain_depth = int(parent.get("chain_depth", 1)) + 1

        if discrepancies:
            return AP2VerificationResult(
                accepted=False,
                reason_code="AP2_MANDATE_MISMATCH",
                message="AP2 mandate does not match the payment request.",
                parsed_mandate={
                    **parsed_mandate,
                    "family_id": family_id,
                    "chain_status": chain_status,
                    "chain_depth": chain_depth,
                    "item_count": mandate_item_count,
                },
                discrepancies=discrepancies,
                verifier_name=self.verifier_name,
            )
        return AP2VerificationResult(
            accepted=True,
            reason_code="AP2_ACCEPTED",
            message="AP2 mandate verified and matched against the payment request.",
            parsed_mandate={
                **parsed_mandate,
                "family_id": family_id,
                "chain_status": chain_status,
                "chain_depth": chain_depth,
                "item_count": mandate_item_count,
            },
            discrepancies=[],
            verifier_name=self.verifier_name,
        )


class Rs256PublicKeyAP2Verifier(SharedSecretAP2Verifier):
    verifier_name = "rs256_public_key"

    def _verify_signature(self, mandate: AP2MandateReference) -> tuple[bool, str, str]:
        if not mandate.signature:
            return False, mandate.signer_id or "default", mandate.key_id or "default"
        signer_id = mandate.signer_id or "default"
        config = _store.get_ap2_signer_config(signer_id)
        if config is None:
            if signer_id != "default":
                return False, signer_id, "AP2_SIGNER_UNKNOWN"
            configured_key_id = mandate.key_id or "default"
        else:
            if not config["is_enabled"]:
                return False, signer_id, "AP2_SIGNER_DISABLED"
            configured_key_id = config.get("verifier_key_id") or "default"
        presented_key_id = mandate.key_id or configured_key_id
        if mandate.key_id and not _rs256_key_ids_share_trust_anchor(
            configured_key_id=configured_key_id,
            presented_key_id=presented_key_id,
        ):
            return False, signer_id, "AP2_SIGNER_KEY_MISMATCH"
        signing_key = _signer_jwks.get(presented_key_id)
        if signing_key is None:
            return False, signer_id, "AP2_SIGNER_KEY_UNKNOWN"
        trust_error = _validate_rs256_signing_key_trust(signing_key=signing_key, signer_id=signer_id)
        if trust_error is not None:
            return False, signer_id, trust_error
        federation_source_error = _validate_rs256_signing_key_federation_source(
            signing_key=signing_key,
            key_id=presented_key_id,
        )
        if federation_source_error is not None:
            return False, signer_id, federation_source_error
        signature_valid = _verify_rs256_signature(
            signing_input=self._canonical_message(mandate),
            signature_segment=mandate.signature,
            signing_key=signing_key,
        )
        if not signature_valid:
            return False, signer_id, presented_key_id
        binding_error = _validate_rs256_signing_key_discovery_binding(signing_key=signing_key, mandate=mandate)
        if binding_error is not None:
            return False, signer_id, binding_error
        return True, signer_id, presented_key_id


class AsymmetricStubAP2Verifier(Rs256PublicKeyAP2Verifier):
    verifier_name = "asymmetric_stub"


class CompositeAP2Verifier:
    verifier_name = "composite"

    def __init__(self, verifiers: dict[str, AP2Verifier]) -> None:
        self._verifiers = verifiers

    def verifier_names(self) -> list[str]:
        return sorted(self._verifiers.keys())

    def verify(self, *, payment: Any, mandate: AP2MandateReference) -> AP2VerificationResult:
        signer_id = mandate.signer_id or "default"
        config = _store.get_ap2_signer_config(signer_id)
        if config is None:
            if signer_id != "default":
                return AP2VerificationResult(
                    accepted=False,
                    reason_code="AP2_SIGNER_UNKNOWN",
                    message="AP2 mandate signer is not registered.",
                    parsed_mandate={
                        "mandate_id": mandate.mandate_id,
                        "mandate_type": mandate.mandate_type,
                        "signer_id": signer_id,
                        "key_id": mandate.key_id or "default",
                    },
                    discrepancies=["signature"],
                    verifier_name=self.verifier_name,
                )
            verifier_name = SharedSecretAP2Verifier.verifier_name
        else:
            if not config["is_enabled"]:
                return AP2VerificationResult(
                    accepted=False,
                    reason_code="AP2_SIGNER_DISABLED",
                    message="AP2 mandate signer is disabled.",
                    parsed_mandate={
                        "mandate_id": mandate.mandate_id,
                        "mandate_type": mandate.mandate_type,
                        "signer_id": signer_id,
                        "key_id": mandate.key_id or "default",
                    },
                    discrepancies=["signature"],
                    verifier_name=self.verifier_name,
                )
            verifier_name = config.get("verifier_name") or SharedSecretAP2Verifier.verifier_name

        verifier = self._verifiers.get(verifier_name)
        if verifier is None:
            return AP2VerificationResult(
                accepted=False,
                reason_code="AP2_VERIFIER_UNKNOWN",
                message="AP2 signer references an unknown verifier adapter.",
                parsed_mandate={
                    "mandate_id": mandate.mandate_id,
                    "mandate_type": mandate.mandate_type,
                    "signer_id": signer_id,
                    "key_id": mandate.key_id or "default",
                    "verifier_name": verifier_name,
                },
                discrepancies=["signature"],
                verifier_name=self.verifier_name,
            )
        return verifier.verify(payment=payment, mandate=mandate)


def setup_ap2_api(
    *,
    store: Any,
    append_audit_entry: Callable[..., None],
    error_payload: Callable[..., dict[str, Any]],
    hash_token: Callable[[str], str],
    sanitize_text: Callable[[str, int], str],
    get_current_identity: Callable[..., Any],
    ensure_scope: Callable[[Any, list[str]], Any],
    get_runtime_phase3_features: Callable[[], dict[str, bool]],
    get_runtime_ap2_lifecycle_policy: Callable[[], dict[str, int]] | None = None,
    get_federation_discovery: Callable[[], dict[str, dict[str, Any]]] | None = None,
    deny_payment: Callable[..., Any],
    shared_secret: str,
    signer_keys: dict[str, str] | None = None,
    signer_jwks: dict[str, dict[str, Any]] | None = None,
    trust_anchors: dict[str, dict[str, Any]] | None = None,
    verifier: AP2Verifier | None = None,
) -> None:
    global _store, _append_audit_entry, _error_payload, _hash_token, _sanitize_text, _get_current_identity
    global _ensure_scope, _get_runtime_phase3_features, _get_runtime_ap2_lifecycle_policy, _get_federation_discovery
    global _deny_payment
    global _verifier, _shared_secret, _signer_keys
    global _signer_jwks, _trust_anchors
    _store = store
    _append_audit_entry = append_audit_entry
    _error_payload = error_payload
    _hash_token = hash_token
    _sanitize_text = sanitize_text
    _get_current_identity = get_current_identity
    _ensure_scope = ensure_scope
    _get_runtime_phase3_features = get_runtime_phase3_features
    _get_runtime_ap2_lifecycle_policy = get_runtime_ap2_lifecycle_policy
    _get_federation_discovery = get_federation_discovery
    _deny_payment = deny_payment
    _shared_secret = shared_secret
    _signer_keys = signer_keys or {"default": shared_secret}
    _signer_jwks = signer_jwks or {}
    _trust_anchors = trust_anchors or {}
    _verifier = verifier or CompositeAP2Verifier(
        {
            SharedSecretAP2Verifier.verifier_name: SharedSecretAP2Verifier(),
            Rs256PublicKeyAP2Verifier.verifier_name: Rs256PublicKeyAP2Verifier(),
            AsymmetricStubAP2Verifier.verifier_name: AsymmetricStubAP2Verifier(),
        }
    )


def _require_ap2_identity(authorization: str | None) -> Any:
    identity = _get_current_identity(authorization)
    return _ensure_scope(identity, ["audit:read"])


def _phase3_ap2_enabled() -> bool:
    if _get_runtime_phase3_features is None:
        return False
    return bool(_get_runtime_phase3_features().get("ap2_enabled", False))


def _ap2_lifecycle_policy() -> dict[str, int]:
    defaults = {
        "intent_retention_days": 30,
        "cart_retention_days": 30,
        "archived_redaction_delay_days": 30,
    }
    if _get_runtime_ap2_lifecycle_policy is None:
        return defaults
    try:
        configured = _get_runtime_ap2_lifecycle_policy()
    except Exception:
        return defaults
    if not isinstance(configured, dict):
        return defaults
    resolved = defaults.copy()
    for key, minimum in (
        ("intent_retention_days", 1),
        ("cart_retention_days", 1),
        ("archived_redaction_delay_days", 0),
    ):
        try:
            resolved[key] = max(minimum, int(configured.get(key, defaults[key])))
        except (TypeError, ValueError):
            resolved[key] = defaults[key]
    return resolved


def _policy_managed_retained_until(*, mandate_type: str) -> str:
    lifecycle_policy = _ap2_lifecycle_policy()
    retention_days = lifecycle_policy["cart_retention_days"] if mandate_type == "cart" else lifecycle_policy["intent_retention_days"]
    return (datetime.now(timezone.utc) + timedelta(days=retention_days)).isoformat()


def _list_ap2_descendants(mandates: list[dict[str, Any]], mandate_id: str) -> list[dict[str, Any]]:
    children_by_parent: dict[str, list[dict[str, Any]]] = {}
    for item in mandates:
        parent_id = item.get("parent_mandate_id")
        if not parent_id:
            continue
        children_by_parent.setdefault(str(parent_id), []).append(item)

    descendants: list[dict[str, Any]] = []
    seen: set[str] = set()
    stack = list(children_by_parent.get(mandate_id, []))
    while stack:
        current = stack.pop()
        current_id = str(current["mandate_id"])
        if current_id in seen:
            continue
        seen.add(current_id)
        descendants.append(current)
        stack.extend(children_by_parent.get(current_id, []))
    return descendants


def _list_archived_ap2_family_mandate_ids(family_id: str) -> list[str]:
    return sorted(
        str(item["mandate_id"])
        for item in _store.list_ap2_mandate_family(family_id)
        if item.get("archived_at") is not None
    )


def _assert_ap2_mandate_can_archive(mandate: dict[str, Any]) -> None:
    family_id = str(mandate.get("family_id") or mandate["mandate_id"])
    family = _store.list_ap2_mandate_family(family_id)
    descendant_ids = sorted(
        item["mandate_id"]
        for item in _list_ap2_descendants(family, str(mandate["mandate_id"]))
        if item.get("archived_at") is None
    )
    if not descendant_ids:
        return

    from fastapi import HTTPException, status

    raise HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail={
            "code": "AP2_MANDATE_ARCHIVE_BLOCKED_ACTIVE_DESCENDANTS",
            "family_id": family_id,
            "descendant_mandate_ids": descendant_ids,
        },
    )


def _should_preserve_ap2_family_retirement_snapshot(
    *,
    result: AP2VerificationResult,
    existing_mandate: dict[str, Any] | None,
) -> bool:
    if existing_mandate is not None or result.accepted or result.reason_code != "AP2_MANDATE_LIFECYCLE_INVALID":
        return False
    family_id = str((result.parsed_mandate or {}).get("family_id") or "").strip()
    if not family_id:
        return False
    return bool(_list_archived_ap2_family_mandate_ids(family_id))


def enforce_ap2_policy(
    *,
    request: Any,
    payment: Any,
    request_hash: str,
    amount_due: Any,
    started_at: float,
    idempotency_key: str | None,
    mcp_server_id: str | None,
    mcp_tool_id: str | None,
    mcp_tool_name: str | None,
) -> Any | None:
    if getattr(payment, "ap2_mandate", None) is None:
        return None

    if not _phase3_ap2_enabled():
        return _deny_payment(
            request=request,
            payment=payment,
            request_hash=request_hash,
            amount_due=amount_due,
            started_at=started_at,
            idempotency_key=idempotency_key,
            status_code=403,
            error_code="AP2_DISABLED",
            message="AP2 mandate support is currently disabled by policy.",
            details={"phase3_feature": "ap2"},
            audit_reason="AP2 mandate support is currently disabled by policy.",
            audit_reason_code="AP2_DISABLED",
            mcp_server_id=mcp_server_id,
            mcp_tool_id=mcp_tool_id,
            mcp_tool_name=mcp_tool_name,
        )

    verification_started_at = time.perf_counter()
    result = _verifier.verify(payment=payment, mandate=payment.ap2_mandate)
    verification_latency_ms = int((time.perf_counter() - verification_started_at) * 1000)
    existing_mandate = _store.get_ap2_mandate(payment.ap2_mandate.mandate_id)
    preserve_existing_mandate = (
        existing_mandate is not None
        and str(existing_mandate.get("lifecycle_status") or "").strip() in AP2_TERMINAL_LIFECYCLE_STATUSES
    )
    preserve_retiring_family_snapshot = _should_preserve_ap2_family_retirement_snapshot(
        result=result,
        existing_mandate=existing_mandate,
    )
    mandate_record = existing_mandate
    if not preserve_existing_mandate and not preserve_retiring_family_snapshot:
        mandate_record = _store.upsert_ap2_mandate(
            mandate_id=payment.ap2_mandate.mandate_id,
            mandate_type=payment.ap2_mandate.mandate_type,
            signer_id=(result.parsed_mandate or {}).get("signer_id"),
            key_id=(result.parsed_mandate or {}).get("key_id"),
            family_id=str((result.parsed_mandate or {}).get("family_id") or payment.ap2_mandate.mandate_id),
            parent_mandate_id=(result.parsed_mandate or {}).get("parent_mandate_id"),
            chain_status=str((result.parsed_mandate or {}).get("chain_status", "standalone")),
            chain_depth=int((result.parsed_mandate or {}).get("chain_depth", 1)),
            lifecycle_status=(
                _accepted_ap2_lifecycle_status(payment.ap2_mandate.mandate_type)
                if result.accepted
                else "rejected"
            ),
            request_hash=request_hash,
            requestor_agent_id=payment.agent_id,
            requestor_user_id=payment.user_id,
            vendor=payment.vendor,
            amount=payment.amount,
            currency=payment.currency,
            reference=payment.ap2_mandate.reference,
            signature=payment.ap2_mandate.signature,
            payload=payment.ap2_mandate.payload,
            parsed_mandate=result.parsed_mandate,
            verifier_name=result.verifier_name,
            verification_status="accepted" if result.accepted else "rejected",
            verification_reason_code=result.reason_code,
            discrepancies=result.discrepancies or [],
        )
    if mandate_record is not None and (existing_mandate is None or existing_mandate.get("retained_until") is None):
        mandate_record = _store.update_ap2_mandate_lifecycle(
            mandate_id=payment.ap2_mandate.mandate_id,
            lifecycle_status=mandate_record["lifecycle_status"],
            retained_until=_policy_managed_retained_until(mandate_type=payment.ap2_mandate.mandate_type),
            superseded_by_mandate_id=mandate_record.get("superseded_by_mandate_id"),
            archived_at=mandate_record.get("archived_at"),
        )
    parent_mandate_id = (result.parsed_mandate or {}).get("parent_mandate_id")
    if result.accepted and payment.ap2_mandate.mandate_type == "cart" and parent_mandate_id:
        parent_mandate = _store.get_ap2_mandate(str(parent_mandate_id))
        _store.update_ap2_mandate_lifecycle(
            mandate_id=str(parent_mandate_id),
            lifecycle_status="consumed_by_child",
            retained_until=None if parent_mandate is None else parent_mandate.get("retained_until"),
            superseded_by_mandate_id=payment.ap2_mandate.mandate_id,
            archived_at=None if parent_mandate is None else parent_mandate.get("archived_at"),
        )
    _append_audit_entry(
        actor_type="agent",
        actor_id=payment.agent_id,
        action="ap2_verify",
        request_path="/pay",
        request_payload_hash=request_hash,
        request_payload_summary={
            "user_id": payment.user_id,
            "vendor": payment.vendor,
            "mandate_id": payment.ap2_mandate.mandate_id,
            "mandate_type": payment.ap2_mandate.mandate_type,
        },
        decision="accepted" if result.accepted else "rejected",
        decision_reason=result.message,
        decision_details={
            "reason_code": result.reason_code,
            "verifier_name": result.verifier_name,
            "verification_latency_ms": verification_latency_ms,
            "retained_until": None if mandate_record is None else mandate_record.get("retained_until"),
            "parsed_mandate": result.parsed_mandate,
            "discrepancies": result.discrepancies or [],
        },
        transaction_amount=payment.amount,
        transaction_currency=payment.currency,
        mcp_server_id=mcp_server_id,
        mcp_tool_id=mcp_tool_id,
        mcp_tool_name=mcp_tool_name,
        **_request_infrastructure_identity_fields(request),
    )
    if result.accepted:
        return None
    return _deny_payment(
        request=request,
        payment=payment,
        request_hash=request_hash,
        amount_due=amount_due,
        started_at=started_at,
        idempotency_key=idempotency_key,
        status_code=501 if result.reason_code in {"AP2_NOT_IMPLEMENTED", "AP2_VERIFIER_NOT_IMPLEMENTED"} else 403,
        error_code=result.reason_code,
        message=result.message,
        details={
            "mandate_id": payment.ap2_mandate.mandate_id,
            "mandate_type": payment.ap2_mandate.mandate_type,
            "verifier_name": result.verifier_name,
            "discrepancies": result.discrepancies or [],
        },
        audit_reason=None,
        mcp_server_id=mcp_server_id,
        mcp_tool_id=mcp_tool_id,
        mcp_tool_name=mcp_tool_name,
    )


@router.get("/ap2/capabilities")
def get_ap2_capabilities(
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> dict[str, Any]:
    _require_ap2_identity(authorization)
    supported_verifiers = (
        _verifier.verifier_names()
        if hasattr(_verifier, "verifier_names")
        else [getattr(_verifier, "verifier_name", "unknown")]
    )
    return {
        "enabled": _phase3_ap2_enabled(),
        "verifier_name": getattr(_verifier, "verifier_name", "unknown"),
        "supports_parse": True,
        "supports_signature_verification": True,
        "supports_intent_matching": True,
        "supports_chain_verification": True,
        "supports_item_matching": True,
        "supports_signer_registry": True,
        "supports_key_routing": True,
        "supports_verifier_selection": True,
        "supports_signer_trust_binding": True,
        "supports_key_rotation_windows": True,
        "supports_multi_key_trust_anchors": True,
        "supports_federated_trust_anchors": True,
        "supports_issuer_binding": True,
        "supports_discovery_binding": True,
        "supports_federation_discovery_refresh": True,
        "supports_jwks_source_reconciliation": True,
        "supports_lifecycle_controls": True,
        "supports_retention_controls": True,
        "supports_policy_managed_retention_windows": True,
        "supports_archive_redaction_automation": True,
        "supported_verifiers": supported_verifiers,
        "available_key_ids": sorted(set(_signer_keys.keys()) | set(_signer_jwks.keys())),
        "available_trust_anchor_ids": sorted(_trust_anchors.keys()),
        "status": "development_signer_registry",
    }


@router.get("/ap2/verifiers")
def list_ap2_verifiers(
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> list[dict[str, Any]]:
    _require_ap2_identity(authorization)
    return [
        {
            "verifier_name": SharedSecretAP2Verifier.verifier_name,
            "status": "development_ready",
            "supports_signature_verification": True,
            "supports_key_routing": True,
            "supports_signer_trust_binding": False,
            "supports_key_rotation_windows": False,
            "supports_multi_key_trust_anchors": False,
            "supports_federated_trust_anchors": False,
            "supports_issuer_binding": False,
            "supports_discovery_binding": False,
            "supports_federation_discovery_refresh": False,
            "supports_jwks_source_reconciliation": False,
        },
        {
            "verifier_name": Rs256PublicKeyAP2Verifier.verifier_name,
            "status": "integration_ready",
            "supports_signature_verification": True,
            "supports_key_routing": True,
            "supports_signer_trust_binding": True,
            "supports_key_rotation_windows": True,
            "supports_multi_key_trust_anchors": True,
            "supports_federated_trust_anchors": True,
            "supports_issuer_binding": True,
            "supports_discovery_binding": True,
            "supports_federation_discovery_refresh": True,
            "supports_jwks_source_reconciliation": True,
        },
        {
            "verifier_name": AsymmetricStubAP2Verifier.verifier_name,
            "status": "compatibility_alias",
            "supports_signature_verification": True,
            "supports_key_routing": True,
            "supports_signer_trust_binding": True,
            "supports_key_rotation_windows": True,
            "supports_multi_key_trust_anchors": True,
            "supports_federated_trust_anchors": True,
            "supports_issuer_binding": True,
            "supports_discovery_binding": True,
            "supports_federation_discovery_refresh": True,
            "supports_jwks_source_reconciliation": True,
        },
    ]


@router.get("/ap2/signers")
def list_ap2_signers(
    is_enabled: bool | None = None,
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> list[dict[str, Any]]:
    _require_ap2_identity(authorization)
    signers = _store.list_ap2_signer_configs(is_enabled=is_enabled)
    if not any(item["signer_id"] == "default" for item in signers):
        signers.insert(
            0,
            {
                "signer_id": "default",
                "verifier_name": SharedSecretAP2Verifier.verifier_name,
                "verifier_key_id": "default",
                "is_enabled": True,
                "notes": "Implicit default signer backed by development AP2 key material.",
                "created_at": None,
                "updated_at": None,
            },
        )
    return signers


@router.post("/ap2/signers")
def upsert_ap2_signer(
    payload: AP2SignerConfigRequest,
    authorization: str | None = Header(default=None, alias="Authorization"),
    infrastructure_assertion: str | None = Header(default=None, alias="X-Infrastructure-Assertion"),
    infrastructure_signature: str | None = Header(default=None, alias="X-Infrastructure-Signature"),
) -> dict[str, Any]:
    identity = _get_current_identity(authorization, infrastructure_assertion, infrastructure_signature)
    _ensure_scope(identity, ["admin:all"])
    require_trusted_infrastructure_identity_for_admin(identity)
    supported_verifiers = (
        _verifier.verifier_names()
        if hasattr(_verifier, "verifier_names")
        else [getattr(_verifier, "verifier_name", "unknown")]
    )
    verifier_name = payload.verifier_name or SharedSecretAP2Verifier.verifier_name
    if verifier_name not in supported_verifiers:
        from fastapi import HTTPException, status

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "AP2_VERIFIER_UNKNOWN", "supported_verifiers": supported_verifiers},
        )
    signer = _store.upsert_ap2_signer_config(
        signer_id=payload.signer_id,
        verifier_name=verifier_name,
        verifier_key_id=payload.verifier_key_id,
        is_enabled=payload.is_enabled,
        notes=payload.notes,
    )
    _append_audit_entry(
        actor_type="user",
        actor_id=identity.oauth_subject,
        action="ap2_signer_upsert",
        request_path="/ap2/signers",
        request_payload_hash=_hash_token(json.dumps(payload.model_dump(mode="json"), sort_keys=True)),
        request_payload_summary={
            "signer_id": payload.signer_id,
            "verifier_name": verifier_name,
            "verifier_key_id": payload.verifier_key_id,
            "is_enabled": payload.is_enabled,
        },
        decision="accepted",
        decision_reason="AP2 signer configuration updated.",
        decision_details={"signer_id": payload.signer_id},
        **audit_infrastructure_identity_fields(identity),
    )
    capture_infrastructure_identity_profile(
        store=_store,
        identity=identity,
        actor_type="admin",
        actor_id=identity.oauth_subject,
        event_type="admin_mutation",
        action="ap2_signer_upsert",
        request_path="/ap2/signers",
    )
    return signer


@router.get("/ap2/mandates")
def list_ap2_mandates(
    verification_status: str | None = None,
    lifecycle_status: str | None = None,
    requestor_user_id: str | None = None,
    requestor_agent_id: str | None = None,
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> list[dict[str, Any]]:
    _require_ap2_identity(authorization)
    return _store.list_ap2_mandates(
        verification_status=verification_status,
        lifecycle_status=lifecycle_status,
        requestor_user_id=requestor_user_id,
        requestor_agent_id=requestor_agent_id,
    )


@router.get("/ap2/mandates/{mandate_id}")
def get_ap2_mandate(
    mandate_id: str,
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> dict[str, Any]:
    _require_ap2_identity(authorization)
    mandate = _store.get_ap2_mandate(mandate_id)
    if mandate is None:
        from fastapi import HTTPException, status

        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"code": "AP2_MANDATE_NOT_FOUND"})
    return mandate


@router.get("/ap2/families/{family_id}")
def get_ap2_mandate_family(
    family_id: str,
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> dict[str, Any]:
    _require_ap2_identity(authorization)
    mandates = _store.list_ap2_mandate_family(family_id)
    if not mandates:
        from fastapi import HTTPException, status

        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"code": "AP2_FAMILY_NOT_FOUND"})
    return {
        "family_id": family_id,
        "mandates": mandates,
        "root_mandate_id": mandates[0]["family_id"],
        "active_mandate_ids": [item["mandate_id"] for item in mandates if item["lifecycle_status"] == "active"],
    }


@router.post("/ap2/mandates/{mandate_id}/retention")
def set_ap2_mandate_retention(
    mandate_id: str,
    payload: AP2MandateRetentionRequest,
    authorization: str | None = Header(default=None, alias="Authorization"),
    infrastructure_assertion: str | None = Header(default=None, alias="X-Infrastructure-Assertion"),
    infrastructure_signature: str | None = Header(default=None, alias="X-Infrastructure-Signature"),
) -> dict[str, Any]:
    identity = _get_current_identity(authorization, infrastructure_assertion, infrastructure_signature)
    _ensure_scope(identity, ["admin:all"])
    require_trusted_infrastructure_identity_for_admin(identity)
    mandate = _store.get_ap2_mandate(mandate_id)
    if mandate is None:
        from fastapi import HTTPException, status

        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"code": "AP2_MANDATE_NOT_FOUND"})
    updated = _store.update_ap2_mandate_lifecycle(
        mandate_id=mandate_id,
        lifecycle_status=mandate["lifecycle_status"],
        retained_until=payload.retained_until,
        superseded_by_mandate_id=mandate.get("superseded_by_mandate_id"),
        archived_at=mandate.get("archived_at"),
    )
    _append_audit_entry(
        actor_type="user",
        actor_id=identity.oauth_subject,
        action="ap2_mandate_retention_set",
        request_path=f"/ap2/mandates/{mandate_id}/retention",
        request_payload_hash=_hash_token(json.dumps(payload.model_dump(mode="json"), sort_keys=True)),
        request_payload_summary={"mandate_id": mandate_id, "retained_until": payload.retained_until},
        decision="accepted",
        decision_reason="AP2 mandate retention updated.",
        decision_details={"mandate_id": mandate_id, "retained_until": payload.retained_until},
        **audit_infrastructure_identity_fields(identity),
    )
    capture_infrastructure_identity_profile(
        store=_store,
        identity=identity,
        actor_type="admin",
        actor_id=identity.oauth_subject,
        event_type="admin_mutation",
        action="ap2_mandate_retention_set",
        request_path=f"/ap2/mandates/{mandate_id}/retention",
    )
    return updated


@router.post("/ap2/mandates/{mandate_id}/archive")
def archive_ap2_mandate(
    mandate_id: str,
    authorization: str | None = Header(default=None, alias="Authorization"),
    infrastructure_assertion: str | None = Header(default=None, alias="X-Infrastructure-Assertion"),
    infrastructure_signature: str | None = Header(default=None, alias="X-Infrastructure-Signature"),
) -> dict[str, Any]:
    identity = _get_current_identity(authorization, infrastructure_assertion, infrastructure_signature)
    _ensure_scope(identity, ["admin:all"])
    require_trusted_infrastructure_identity_for_admin(identity)
    mandate = _store.get_ap2_mandate(mandate_id)
    if mandate is None:
        from fastapi import HTTPException, status

        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"code": "AP2_MANDATE_NOT_FOUND"})
    _assert_ap2_mandate_can_archive(mandate)
    archived_at = datetime.now(timezone.utc).isoformat()
    updated = _store.update_ap2_mandate_lifecycle(
        mandate_id=mandate_id,
        lifecycle_status="archived",
        retained_until=mandate.get("retained_until"),
        superseded_by_mandate_id=mandate.get("superseded_by_mandate_id"),
        archived_at=archived_at,
    )
    _append_audit_entry(
        actor_type="user",
        actor_id=identity.oauth_subject,
        action="ap2_mandate_archive",
        request_path=f"/ap2/mandates/{mandate_id}/archive",
        request_payload_hash=_hash_token(mandate_id),
        request_payload_summary={"mandate_id": mandate_id},
        decision="accepted",
        decision_reason="AP2 mandate archived.",
        decision_details={"mandate_id": mandate_id, "archived_at": archived_at},
        **audit_infrastructure_identity_fields(identity),
    )
    capture_infrastructure_identity_profile(
        store=_store,
        identity=identity,
        actor_type="admin",
        actor_id=identity.oauth_subject,
        event_type="admin_mutation",
        action="ap2_mandate_archive",
        request_path=f"/ap2/mandates/{mandate_id}/archive",
    )
    return updated


@router.post("/ap2/mandates/archive-expired")
def archive_expired_ap2_mandates(
    authorization: str | None = Header(default=None, alias="Authorization"),
    infrastructure_assertion: str | None = Header(default=None, alias="X-Infrastructure-Assertion"),
    infrastructure_signature: str | None = Header(default=None, alias="X-Infrastructure-Signature"),
) -> dict[str, Any]:
    identity = _get_current_identity(authorization, infrastructure_assertion, infrastructure_signature)
    _ensure_scope(identity, ["admin:all"])
    require_trusted_infrastructure_identity_for_admin(identity)
    lifecycle_policy = _ap2_lifecycle_policy()
    archived = _store.archive_expired_ap2_mandates()
    redacted = _store.redact_archived_ap2_mandates(
        redaction_delay_days=lifecycle_policy["archived_redaction_delay_days"]
    )
    _append_audit_entry(
        actor_type="user",
        actor_id=identity.oauth_subject,
        action="ap2_mandate_archive_expired",
        request_path="/ap2/mandates/archive-expired",
        request_payload_hash=_hash_token("archive-expired"),
        request_payload_summary={},
        decision="accepted",
        decision_reason="Expired AP2 mandate retention sweep completed.",
        decision_details={"archived": archived, "redacted": redacted},
        **audit_infrastructure_identity_fields(identity),
    )
    capture_infrastructure_identity_profile(
        store=_store,
        identity=identity,
        actor_type="admin",
        actor_id=identity.oauth_subject,
        event_type="admin_mutation",
        action="ap2_mandate_archive_expired",
        request_path="/ap2/mandates/archive-expired",
    )
    return {"archived": archived, "redacted": redacted}
