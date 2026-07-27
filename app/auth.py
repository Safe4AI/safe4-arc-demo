from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
from datetime import datetime, timezone
from typing import Any, Callable, Protocol

from fastapi import Depends, Header, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field

from .oauth_api import compute_code_challenge


JWT_ASSERTION_PATTERN = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")
RS256_SHA256_DIGESTINFO_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")

_store = None
_allowed_scopes: set[str] = set()
_get_runtime_phase3_features: Callable[[], dict[str, bool]] | None = None
_get_runtime_infrastructure_identity_policy: Callable[[], dict[str, Any]] | None = None
_infra_identity_verifiers: list["InfrastructureIdentityVerifier"] = []


class InfrastructureIdentity(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider_name: str
    subject: str
    agent_id: str | None = None
    environment: str | None = None
    namespace: str | None = None
    service_account: str | None = None
    trust_tier: str | None = None
    claims: dict[str, Any] = Field(default_factory=dict)
    verification_status: str = "accepted"
    verification_reason_code: str = "INFRA_IDENTITY_ACCEPTED"


class AgentIdentity(BaseModel):
    model_config = ConfigDict(extra="forbid")

    oauth_subject: str
    oauth_scopes: list[str]
    agent_id: str | None = None
    client_id: str
    infrastructure_identity: InfrastructureIdentity | None = None


class InfrastructureIdentityVerifier(Protocol):
    verifier_name: str
    verifier_status: str
    supported_assertion_type: str
    requires_detached_signature: bool

    def can_verify(self, *, assertion: str, signature: str | None) -> bool:
        ...

    def verify(self, *, assertion: str, signature: str | None, client_id: str) -> InfrastructureIdentity:
        ...


def _raise_infra_identity_error(code: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={"code": code},
    )


def _base64url_decode(segment: str, *, error_code: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode((segment + padding).encode("utf-8"))
    except Exception as exc:  # pragma: no cover - defensive parse guard
        raise _raise_infra_identity_error(error_code) from exc


def _base64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")


def _decode_json_segment(segment: str, *, error_code: str) -> dict[str, Any]:
    try:
        payload = json.loads(_base64url_decode(segment, error_code=error_code).decode("utf-8"))
    except Exception as exc:  # pragma: no cover - defensive parse guard
        raise _raise_infra_identity_error(error_code) from exc
    if not isinstance(payload, dict):
        raise _raise_infra_identity_error(error_code)
    return payload


def _coerce_timestamp(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        raise _raise_infra_identity_error("INFRA_IDENTITY_INVALID_ASSERTION")
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise _raise_infra_identity_error("INFRA_IDENTITY_INVALID_ASSERTION") from exc


def _audiences(claim_value: Any) -> list[str]:
    if isinstance(claim_value, str):
        return [claim_value]
    if isinstance(claim_value, list):
        return [str(item).strip() for item in claim_value if str(item).strip()]
    raise _raise_infra_identity_error("INFRA_IDENTITY_INVALID_ASSERTION")


def _read_unverified_jwt_payload(assertion: str) -> dict[str, Any] | None:
    if JWT_ASSERTION_PATTERN.fullmatch(assertion) is None:
        return None
    try:
        _, payload_segment, _ = assertion.split(".")
        return _decode_json_segment(payload_segment, error_code="INFRA_IDENTITY_INVALID_ASSERTION")
    except Exception:
        return None


def _read_string_claim(payload: dict[str, Any], *path: str) -> str | None:
    current: Any = payload
    for part in path:
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    if current is None:
        return None
    value = str(current).strip()
    return value or None


def _verify_rs256_signature(*, signing_input: str, signature_segment: str, signing_key: dict[str, Any]) -> None:
    signature = _base64url_decode(signature_segment, error_code="INFRA_IDENTITY_INVALID_SIGNATURE")
    modulus = signing_key.get("modulus")
    exponent = signing_key.get("exponent")
    if not isinstance(modulus, int) or not isinstance(exponent, int) or modulus <= 0 or exponent <= 0:
        raise _raise_infra_identity_error("INFRA_IDENTITY_INVALID_SIGNATURE")

    modulus_size = (modulus.bit_length() + 7) // 8
    if len(signature) != modulus_size:
        raise _raise_infra_identity_error("INFRA_IDENTITY_INVALID_SIGNATURE")

    signature_int = int.from_bytes(signature, "big")
    if signature_int >= modulus:
        raise _raise_infra_identity_error("INFRA_IDENTITY_INVALID_SIGNATURE")

    digest = hashlib.sha256(signing_input.encode("utf-8")).digest()
    padding_length = modulus_size - len(RS256_SHA256_DIGESTINFO_PREFIX) - len(digest) - 3
    if padding_length < 8:
        raise _raise_infra_identity_error("INFRA_IDENTITY_INVALID_SIGNATURE")

    expected_message = (
        b"\x00\x01"
        + (b"\xff" * padding_length)
        + b"\x00"
        + RS256_SHA256_DIGESTINFO_PREFIX
        + digest
    )
    actual_message = pow(signature_int, exponent, modulus).to_bytes(modulus_size, "big")
    if not secrets.compare_digest(actual_message, expected_message):
        raise _raise_infra_identity_error("INFRA_IDENTITY_INVALID_SIGNATURE")


class WorkloadHmacInfrastructureIdentityVerifier:
    verifier_name = "workload_hmac_stub"
    verifier_status = "development_ready"
    supported_assertion_type = "hmac_signed_workload_claim"
    requires_detached_signature = True

    def __init__(self, shared_secret: str) -> None:
        self.shared_secret = shared_secret

    def can_verify(self, *, assertion: str, signature: str | None) -> bool:
        return bool(signature) and JWT_ASSERTION_PATTERN.fullmatch(assertion) is None

    @staticmethod
    def _decode_assertion(assertion: str) -> dict[str, Any]:
        try:
            decoded = _base64url_decode(assertion, error_code="INFRA_IDENTITY_INVALID_ASSERTION").decode("utf-8")
            payload = json.loads(decoded)
        except Exception as exc:  # pragma: no cover - defensive parse guard
            raise _raise_infra_identity_error("INFRA_IDENTITY_INVALID_ASSERTION") from exc
        if not isinstance(payload, dict):
            raise _raise_infra_identity_error("INFRA_IDENTITY_INVALID_ASSERTION")
        return payload

    @staticmethod
    def _canonical_payload(payload: dict[str, Any]) -> str:
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))

    def verify(self, *, assertion: str, signature: str | None, client_id: str) -> InfrastructureIdentity:
        if not signature:
            raise _raise_infra_identity_error("INFRA_IDENTITY_MISSING_HEADERS")
        payload = self._decode_assertion(assertion)
        provider_name = str(payload.get("provider_name") or "").strip()
        subject = str(payload.get("subject") or "").strip()
        if not provider_name or not subject:
            raise _raise_infra_identity_error("INFRA_IDENTITY_INVALID_ASSERTION")
        expected = hmac.new(
            self.shared_secret.encode("utf-8"),
            self._canonical_payload(payload).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        if not secrets.compare_digest(expected, signature):
            raise _raise_infra_identity_error("INFRA_IDENTITY_INVALID_SIGNATURE")
        payload_client_id = payload.get("client_id")
        if payload_client_id is not None and str(payload_client_id) != client_id:
            raise _raise_infra_identity_error("INFRA_IDENTITY_CLIENT_MISMATCH")
        return InfrastructureIdentity(
            provider_name=provider_name,
            subject=subject,
            agent_id=None if payload.get("agent_id") is None else str(payload.get("agent_id")),
            environment=None if payload.get("environment") is None else str(payload.get("environment")),
            namespace=None if payload.get("namespace") is None else str(payload.get("namespace")),
            service_account=None if payload.get("service_account") is None else str(payload.get("service_account")),
            trust_tier=None if payload.get("trust_tier") is None else str(payload.get("trust_tier")),
            claims=payload,
            verification_status="accepted",
            verification_reason_code="INFRA_IDENTITY_ACCEPTED",
        )


class KubernetesServiceAccountJwtInfrastructureIdentityVerifier:
    verifier_name = "kubernetes_service_account_jwt"
    verifier_status = "integration_ready"
    supported_assertion_type = "kubernetes_service_account_token"
    requires_detached_signature = False

    def __init__(
        self,
        *,
        issuer: str,
        environment: str | None,
        signing_keys: dict[str, str],
        clock_skew_seconds: int = 60,
    ) -> None:
        self.issuer = issuer
        self.environment = environment
        self.signing_keys = signing_keys
        self.clock_skew_seconds = clock_skew_seconds

    def can_verify(self, *, assertion: str, signature: str | None) -> bool:
        payload = _read_unverified_jwt_payload(assertion)
        if payload is None:
            return False
        issuer = str(payload.get("iss") or "").strip()
        subject = str(payload.get("sub") or "").strip()
        return issuer == self.issuer and (
            subject.startswith("system:serviceaccount:") or isinstance(payload.get("kubernetes.io"), dict)
        )

    def verify(self, *, assertion: str, signature: str | None, client_id: str) -> InfrastructureIdentity:
        try:
            header_segment, payload_segment, signature_segment = assertion.split(".")
        except ValueError as exc:
            raise _raise_infra_identity_error("INFRA_IDENTITY_INVALID_ASSERTION") from exc

        header = _decode_json_segment(header_segment, error_code="INFRA_IDENTITY_INVALID_ASSERTION")
        payload = _decode_json_segment(payload_segment, error_code="INFRA_IDENTITY_INVALID_ASSERTION")

        algorithm = str(header.get("alg") or "").strip()
        token_type = str(header.get("typ") or "JWT").strip()
        if algorithm != "HS256" or token_type not in {"JWT", ""}:
            raise _raise_infra_identity_error("INFRA_IDENTITY_UNSUPPORTED_ASSERTION")

        key_id = str(header.get("kid") or "default").strip() or "default"
        signing_secret = self.signing_keys.get(key_id) or self.signing_keys.get("default")
        if not signing_secret:
            raise _raise_infra_identity_error("INFRA_IDENTITY_INVALID_SIGNATURE")

        expected_signature = _base64url_encode(
            hmac.new(
                signing_secret.encode("utf-8"),
                f"{header_segment}.{payload_segment}".encode("utf-8"),
                hashlib.sha256,
            ).digest()
        )
        if not secrets.compare_digest(expected_signature, signature_segment):
            raise _raise_infra_identity_error("INFRA_IDENTITY_INVALID_SIGNATURE")

        issuer = str(payload.get("iss") or "").strip()
        subject = str(payload.get("sub") or "").strip()
        if issuer != self.issuer or not subject:
            raise _raise_infra_identity_error("INFRA_IDENTITY_INVALID_ASSERTION")

        audiences = _audiences(payload.get("aud"))
        if client_id not in audiences:
            raise _raise_infra_identity_error("INFRA_IDENTITY_CLIENT_MISMATCH")

        now = int(datetime.now(timezone.utc).timestamp())
        expires_at = _coerce_timestamp(payload.get("exp"))
        if expires_at is None or expires_at <= now - self.clock_skew_seconds:
            raise _raise_infra_identity_error("INFRA_IDENTITY_ASSERTION_EXPIRED")

        not_before = _coerce_timestamp(payload.get("nbf"))
        if not_before is not None and not_before > now + self.clock_skew_seconds:
            raise _raise_infra_identity_error("INFRA_IDENTITY_ASSERTION_NOT_YET_VALID")

        issued_at = _coerce_timestamp(payload.get("iat"))
        if issued_at is not None and issued_at > now + self.clock_skew_seconds:
            raise _raise_infra_identity_error("INFRA_IDENTITY_ASSERTION_NOT_YET_VALID")

        subject_parts = subject.split(":")
        if len(subject_parts) != 4 or subject_parts[0] != "system" or subject_parts[1] != "serviceaccount":
            raise _raise_infra_identity_error("INFRA_IDENTITY_INVALID_ASSERTION")

        kubernetes_claims = payload.get("kubernetes.io")
        if not isinstance(kubernetes_claims, dict):
            raise _raise_infra_identity_error("INFRA_IDENTITY_INVALID_ASSERTION")

        namespace = str(kubernetes_claims.get("namespace") or subject_parts[2]).strip()
        service_account_claims = kubernetes_claims.get("serviceaccount")
        service_account = None
        if isinstance(service_account_claims, dict):
            service_account = str(service_account_claims.get("name") or "").strip() or None
        if not namespace or not service_account:
            service_account = service_account or subject_parts[3]
        if namespace != subject_parts[2] or service_account != subject_parts[3]:
            raise _raise_infra_identity_error("INFRA_IDENTITY_INVALID_ASSERTION")

        pod_claims = kubernetes_claims.get("pod")
        agent_id = None
        if isinstance(pod_claims, dict):
            pod_name = str(pod_claims.get("name") or "").strip()
            if pod_name:
                agent_id = pod_name

        return InfrastructureIdentity(
            provider_name="kubernetes_service_account",
            subject=subject,
            agent_id=agent_id,
            environment=self.environment,
            namespace=namespace,
            service_account=service_account,
            trust_tier="verified_workload",
            claims=payload,
            verification_status="accepted",
            verification_reason_code="INFRA_IDENTITY_K8S_JWT_ACCEPTED",
        )


class OidcWorkloadJwtInfrastructureIdentityVerifier:
    verifier_name = "oidc_workload_identity_jwt"
    verifier_status = "integration_ready"
    supported_assertion_type = "oidc_workload_identity_token"
    requires_detached_signature = False

    def __init__(
        self,
        *,
        issuer: str,
        signing_keys: dict[str, dict[str, Any]],
        allowed_subject_prefixes: list[str] | None = None,
        clock_skew_seconds: int = 60,
    ) -> None:
        self.issuer = issuer
        self.signing_keys = signing_keys
        self.allowed_subject_prefixes = [item for item in (allowed_subject_prefixes or []) if item]
        self.clock_skew_seconds = clock_skew_seconds

    def can_verify(self, *, assertion: str, signature: str | None) -> bool:
        payload = _read_unverified_jwt_payload(assertion)
        if payload is None:
            return False
        return str(payload.get("iss") or "").strip() == self.issuer

    def verify(self, *, assertion: str, signature: str | None, client_id: str) -> InfrastructureIdentity:
        try:
            header_segment, payload_segment, signature_segment = assertion.split(".")
        except ValueError as exc:
            raise _raise_infra_identity_error("INFRA_IDENTITY_INVALID_ASSERTION") from exc

        header = _decode_json_segment(header_segment, error_code="INFRA_IDENTITY_INVALID_ASSERTION")
        payload = _decode_json_segment(payload_segment, error_code="INFRA_IDENTITY_INVALID_ASSERTION")

        algorithm = str(header.get("alg") or "").strip()
        token_type = str(header.get("typ") or "JWT").strip()
        if algorithm != "RS256" or token_type not in {"JWT", ""}:
            raise _raise_infra_identity_error("INFRA_IDENTITY_UNSUPPORTED_ASSERTION")

        key_id = str(header.get("kid") or "default").strip() or "default"
        signing_key = self.signing_keys.get(key_id) or self.signing_keys.get("default")
        if signing_key is None:
            raise _raise_infra_identity_error("INFRA_IDENTITY_INVALID_SIGNATURE")
        _verify_rs256_signature(
            signing_input=f"{header_segment}.{payload_segment}",
            signature_segment=signature_segment,
            signing_key=signing_key,
        )

        issuer = str(payload.get("iss") or "").strip()
        subject = str(payload.get("sub") or "").strip()
        if issuer != self.issuer or not subject:
            raise _raise_infra_identity_error("INFRA_IDENTITY_INVALID_ASSERTION")
        if self.allowed_subject_prefixes and not any(subject.startswith(prefix) for prefix in self.allowed_subject_prefixes):
            raise _raise_infra_identity_error("INFRA_IDENTITY_SUBJECT_NOT_ALLOWED")

        audiences = _audiences(payload.get("aud"))
        if client_id not in audiences:
            raise _raise_infra_identity_error("INFRA_IDENTITY_CLIENT_MISMATCH")

        now = int(datetime.now(timezone.utc).timestamp())
        expires_at = _coerce_timestamp(payload.get("exp"))
        if expires_at is None or expires_at <= now - self.clock_skew_seconds:
            raise _raise_infra_identity_error("INFRA_IDENTITY_ASSERTION_EXPIRED")

        not_before = _coerce_timestamp(payload.get("nbf"))
        if not_before is not None and not_before > now + self.clock_skew_seconds:
            raise _raise_infra_identity_error("INFRA_IDENTITY_ASSERTION_NOT_YET_VALID")

        issued_at = _coerce_timestamp(payload.get("iat"))
        if issued_at is not None and issued_at > now + self.clock_skew_seconds:
            raise _raise_infra_identity_error("INFRA_IDENTITY_ASSERTION_NOT_YET_VALID")

        workload_claims = payload.get("workload")
        if workload_claims is None:
            workload_claims = {}
        if not isinstance(workload_claims, dict):
            raise _raise_infra_identity_error("INFRA_IDENTITY_INVALID_ASSERTION")

        agent_id = _read_string_claim(workload_claims, "agent_id") or _read_string_claim(payload, "agent_id")
        environment = _read_string_claim(workload_claims, "environment") or _read_string_claim(payload, "environment")
        namespace = _read_string_claim(workload_claims, "namespace") or _read_string_claim(payload, "namespace")
        service_account = _read_string_claim(workload_claims, "service_account") or _read_string_claim(
            payload, "service_account"
        )
        trust_tier = _read_string_claim(workload_claims, "trust_tier") or _read_string_claim(payload, "trust_tier")

        return InfrastructureIdentity(
            provider_name="oidc_workload_identity",
            subject=subject,
            agent_id=agent_id,
            environment=environment,
            namespace=namespace,
            service_account=service_account,
            trust_tier=trust_tier or "verified_workload",
            claims=payload,
            verification_status="accepted",
            verification_reason_code="INFRA_IDENTITY_OIDC_JWT_ACCEPTED",
        )


def _select_infrastructure_identity_verifier(
    *,
    assertion: str,
    signature: str | None,
) -> InfrastructureIdentityVerifier | None:
    for verifier in _infra_identity_verifiers:
        if verifier.can_verify(assertion=assertion, signature=signature):
            return verifier
    return None


def setup_auth(
    *,
    store: Any,
    allowed_scopes: set[str],
    get_runtime_phase3_features: Callable[[], dict[str, bool]],
    get_runtime_infrastructure_identity_policy: Callable[[], dict[str, Any]],
    infra_identity_shared_secret: str,
    infra_identity_kubernetes_issuer: str,
    infra_identity_kubernetes_environment: str | None,
    infra_identity_kubernetes_signing_keys: dict[str, str],
    infra_identity_oidc_issuer: str,
    infra_identity_oidc_signing_keys: dict[str, dict[str, Any]],
    infra_identity_oidc_allowed_subject_prefixes: list[str],
) -> None:
    global _store, _allowed_scopes, _get_runtime_phase3_features, _get_runtime_infrastructure_identity_policy, _infra_identity_verifiers
    _store = store
    _allowed_scopes = allowed_scopes
    _get_runtime_phase3_features = get_runtime_phase3_features
    _get_runtime_infrastructure_identity_policy = get_runtime_infrastructure_identity_policy
    _infra_identity_verifiers = [
        WorkloadHmacInfrastructureIdentityVerifier(infra_identity_shared_secret),
        KubernetesServiceAccountJwtInfrastructureIdentityVerifier(
            issuer=infra_identity_kubernetes_issuer,
            environment=infra_identity_kubernetes_environment,
            signing_keys=infra_identity_kubernetes_signing_keys,
        ),
        OidcWorkloadJwtInfrastructureIdentityVerifier(
            issuer=infra_identity_oidc_issuer,
            signing_keys=infra_identity_oidc_signing_keys,
            allowed_subject_prefixes=infra_identity_oidc_allowed_subject_prefixes,
        ),
    ]


def normalize_scope_string(scope: str) -> list[str]:
    scopes = sorted({item for item in scope.split() if item})
    if not scopes:
        raise ValueError("at least one scope is required")
    unknown = [item for item in scopes if item not in _allowed_scopes]
    if unknown:
        raise ValueError(f"unsupported scopes requested: {', '.join(unknown)}")
    return scopes


def hash_token(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def issue_secret_token(prefix: str) -> tuple[str, str]:
    token = f"{prefix}_{secrets.token_urlsafe(32)}"
    return token, hash_token(token)


def verify_pkce(code_verifier: str, stored_code_challenge: str) -> bool:
    if not re.fullmatch(r"[A-Za-z0-9\-._~]{43,128}", code_verifier):
        return False
    return secrets.compare_digest(compute_code_challenge(code_verifier), stored_code_challenge)


def ensure_scope(identity: AgentIdentity, required_scopes: list[str]) -> AgentIdentity:
    missing = [scope for scope in required_scopes if scope not in identity.oauth_scopes]
    if missing:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "INSUFFICIENT_SCOPE", "missing_scopes": missing},
        )
    return identity


def _phase3_infrastructure_identity_enabled() -> bool:
    if _get_runtime_phase3_features is None:
        return False
    return bool(_get_runtime_phase3_features().get("infrastructure_identity_enabled", False))


def _normalize_header_value(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def list_infrastructure_identity_verifiers() -> list[dict[str, Any]]:
    return [
        {
            "verifier_name": verifier.verifier_name,
            "status": verifier.verifier_status,
            "supported_assertion_type": verifier.supported_assertion_type,
            "requires_detached_signature": verifier.requires_detached_signature,
        }
        for verifier in _infra_identity_verifiers
    ]


def audit_infrastructure_identity_fields(identity: AgentIdentity | None) -> dict[str, str | None]:
    infra = None if identity is None else identity.infrastructure_identity
    return {
        "infrastructure_provider_name": None if infra is None else infra.provider_name,
        "infrastructure_subject": None if infra is None else infra.subject,
        "infrastructure_trust_tier": None if infra is None else infra.trust_tier,
    }


def assess_infrastructure_identity_posture(identity: AgentIdentity | None) -> dict[str, Any]:
    policy = {} if _get_runtime_infrastructure_identity_policy is None else _get_runtime_infrastructure_identity_policy()
    infra = None if identity is None else identity.infrastructure_identity
    if not policy or not policy.get("enabled", False):
        return {
            "posture": "disabled",
            "is_trusted_workload": False,
            "environment": None if infra is None else infra.environment,
            "namespace": None if infra is None else infra.namespace,
            "service_account": None if infra is None else infra.service_account,
            "trust_tier": None if infra is None else infra.trust_tier,
        }

    if infra is None:
        return {
            "posture": "oauth_only",
            "is_trusted_workload": False,
            "environment": None,
            "namespace": None,
            "service_account": None,
            "trust_tier": None,
        }

    trusted_environments = set(policy.get("trusted_environments") or [])
    trusted_namespaces = set(policy.get("trusted_namespaces") or [])
    trusted_service_accounts = set(policy.get("trusted_service_accounts") or [])
    trusted_trust_tiers = set(policy.get("trusted_trust_tiers") or [])
    trusted_provider_names = set(policy.get("trusted_provider_names") or [])

    is_trusted_workload = True
    if trusted_provider_names and infra.provider_name not in trusted_provider_names:
        is_trusted_workload = False
    if trusted_environments and infra.environment not in trusted_environments:
        is_trusted_workload = False
    if trusted_namespaces and infra.namespace not in trusted_namespaces:
        is_trusted_workload = False
    if trusted_service_accounts and infra.service_account not in trusted_service_accounts:
        is_trusted_workload = False
    if trusted_trust_tiers and infra.trust_tier not in trusted_trust_tiers:
        is_trusted_workload = False

    return {
        "posture": "trusted_workload" if is_trusted_workload else "untrusted_workload",
        "is_trusted_workload": is_trusted_workload,
        "environment": infra.environment,
        "namespace": infra.namespace,
        "service_account": infra.service_account,
        "trust_tier": infra.trust_tier,
    }


def require_trusted_infrastructure_identity_for_admin(identity: AgentIdentity | None) -> AgentIdentity | None:
    policy = {} if _get_runtime_infrastructure_identity_policy is None else _get_runtime_infrastructure_identity_policy()
    if not policy or not policy.get("enabled", False):
        return identity
    if not policy.get("require_trusted_workload_for_admin_mutations", False):
        return identity
    posture = assess_infrastructure_identity_posture(identity)
    if posture["is_trusted_workload"]:
        return identity
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail={
            "code": "TRUSTED_INFRASTRUCTURE_IDENTITY_REQUIRED",
            "posture": posture["posture"],
        },
    )


def capture_infrastructure_identity_profile(
    *,
    store: Any,
    identity: AgentIdentity | None,
    actor_type: str,
    actor_id: str,
    event_type: str,
    action: str,
    transaction_amount: Any = None,
    transaction_currency: str | None = None,
    transaction_id: str | None = None,
    request_path: str | None = None,
) -> dict[str, Any] | None:
    posture = assess_infrastructure_identity_posture(identity)
    infra = None if identity is None else identity.infrastructure_identity
    if posture["posture"] == "disabled" and infra is None:
        return None
    return store.upsert_infrastructure_identity_profile(
        actor_type=actor_type,
        actor_id=actor_id,
        event_type=event_type,
        action=action,
        provider_name=None if infra is None else infra.provider_name,
        subject=None if infra is None else infra.subject,
        posture=posture["posture"],
        environment=posture["environment"],
        namespace=posture["namespace"],
        service_account=posture["service_account"],
        trust_tier=posture["trust_tier"],
        transaction_currency=transaction_currency,
        amount=transaction_amount,
        transaction_id=transaction_id,
        request_path=request_path,
    )


def get_current_identity(
    authorization: str | None = Header(default=None, alias="Authorization"),
    infrastructure_assertion: str | None = Header(default=None, alias="X-Infrastructure-Assertion"),
    infrastructure_signature: str | None = Header(default=None, alias="X-Infrastructure-Signature"),
    allow_disabled_infrastructure_identity: bool = False,
) -> AgentIdentity:
    authorization = _normalize_header_value(authorization)
    infrastructure_assertion = _normalize_header_value(infrastructure_assertion)
    infrastructure_signature = _normalize_header_value(infrastructure_signature)
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"code": "AUTH_REQUIRED"})
    token = authorization.removeprefix("Bearer ").strip()
    record = _store.get_oauth_access_token(hash_token(token))
    if record is None or record["revoked"]:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"code": "INVALID_ACCESS_TOKEN"})
    if datetime.fromisoformat(record["expires_at"]) <= datetime.now(timezone.utc):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"code": "ACCESS_TOKEN_EXPIRED"})
    infrastructure_identity = None
    if infrastructure_assertion or infrastructure_signature:
        if not _phase3_infrastructure_identity_enabled() and not allow_disabled_infrastructure_identity:
            raise _raise_infra_identity_error("INFRA_IDENTITY_DISABLED")
        if not infrastructure_assertion:
            raise _raise_infra_identity_error("INFRA_IDENTITY_MISSING_HEADERS")
        verifier = _select_infrastructure_identity_verifier(
            assertion=infrastructure_assertion,
            signature=infrastructure_signature,
        )
        if verifier is None:
            if not infrastructure_signature and JWT_ASSERTION_PATTERN.fullmatch(infrastructure_assertion) is None:
                raise _raise_infra_identity_error("INFRA_IDENTITY_MISSING_HEADERS")
            raise _raise_infra_identity_error("INFRA_IDENTITY_UNSUPPORTED_ASSERTION")
        infrastructure_identity = verifier.verify(
            assertion=infrastructure_assertion,
            signature=infrastructure_signature,
            client_id=record["client_id"],
        )
        _store.upsert_agent_identity_assertion(
            assertion_hash=hash_token(infrastructure_assertion),
            provider_name=infrastructure_identity.provider_name,
            subject=infrastructure_identity.subject,
            agent_id=infrastructure_identity.agent_id,
            client_id=record["client_id"],
            environment=infrastructure_identity.environment,
            namespace=infrastructure_identity.namespace,
            service_account=infrastructure_identity.service_account,
            trust_tier=infrastructure_identity.trust_tier,
            claims=infrastructure_identity.claims,
            verification_status=infrastructure_identity.verification_status,
            verification_reason_code=infrastructure_identity.verification_reason_code,
        )
    return AgentIdentity(
        oauth_subject=record["subject"],
        oauth_scopes=record["scopes"],
        agent_id=record["agent_id"],
        client_id=record["client_id"],
        infrastructure_identity=infrastructure_identity,
    )


def require_scopes(*scopes: str):
    def dependency(identity: AgentIdentity = Depends(get_current_identity)) -> AgentIdentity:
        return ensure_scope(identity, list(scopes))

    return dependency
