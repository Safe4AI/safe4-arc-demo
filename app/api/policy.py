from __future__ import annotations

from decimal import Decimal, InvalidOperation
from typing import Any, Callable

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from ..anomaly_api import anomaly_severity_is_stricter
from ..auth import audit_infrastructure_identity_fields, capture_infrastructure_identity_profile


router = APIRouter()

_store = None
_append_audit_entry: Callable[..., None] | None = None
_hash_token: Callable[[str], str] | None = None
_sanitize_text: Callable[[str, int], str] | None = None
_get_current_identity = None
_ensure_scope: Callable[[Any, list[str]], Any] | None = None


def _parse_decimal_text(value: Any, field_name: str) -> Decimal:
    if isinstance(value, Decimal):
        return value
    if isinstance(value, int | float):
        return Decimal(str(value))
    if isinstance(value, str):
        try:
            return Decimal(value)
        except InvalidOperation as exc:
            raise ValueError(f"{field_name} must be a decimal-compatible value") from exc
    raise ValueError(f"{field_name} must be a decimal-compatible value")


def setup_policy_api(
    *,
    store: Any,
    append_audit_entry: Callable[..., None],
    hash_token: Callable[[str], str],
    sanitize_text: Callable[[str, int], str],
    get_current_identity: Callable[..., Any],
    ensure_scope: Callable[[Any, list[str]], Any],
) -> None:
    global _store, _append_audit_entry, _hash_token, _sanitize_text, _get_current_identity, _ensure_scope
    _store = store
    _append_audit_entry = append_audit_entry
    _hash_token = hash_token
    _sanitize_text = sanitize_text
    _get_current_identity = get_current_identity
    _ensure_scope = ensure_scope


class PolicyActivationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    version: str = Field(..., min_length=1)
    document: dict[str, Any] = Field(default_factory=dict)
    notes: str | None = Field(default=None)

    @field_validator("version")
    @classmethod
    def sanitize_version(cls, value: str) -> str:
        sanitized = _sanitize_text(value, max_length=50)
        if not sanitized:
            raise ValueError("version cannot be empty")
        return sanitized

    @field_validator("notes")
    @classmethod
    def sanitize_notes(cls, value: str | None) -> str | None:
        if value is None:
            return None
        sanitized = _sanitize_text(value, max_length=500)
        return sanitized or None


class PolicyVelocityControl(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    requests: int = Field(..., ge=1)
    window_seconds: int = Field(..., ge=1)


class PolicyRateLimitControl(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    requests: int = Field(..., ge=1)
    window_seconds: int = Field(..., ge=1)


class PolicyPhase3Features(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    ap2_enabled: bool | None = None
    advanced_x402_enabled: bool | None = None
    infrastructure_identity_enabled: bool | None = None


class PolicyInfrastructureIdentityPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    require_trusted_workload_for_admin_mutations: bool | None = None
    oauth_only_max_amount: Decimal | None = None
    trusted_workload_max_amount: Decimal | None = None
    trusted_provider_names: list[str] | None = None
    trusted_environments: list[str] | None = None
    trusted_namespaces: list[str] | None = None
    trusted_service_accounts: list[str] | None = None
    trusted_trust_tiers: list[str] | None = None

    @field_validator("oauth_only_max_amount", "trusted_workload_max_amount", mode="before")
    @classmethod
    def parse_optional_policy_decimal(cls, value: Any, info) -> Decimal | None:
        if value is None:
            return None
        return _parse_decimal_text(value, info.field_name)

    @field_validator("oauth_only_max_amount", "trusted_workload_max_amount")
    @classmethod
    def validate_optional_policy_decimal(cls, value: Decimal | None) -> Decimal | None:
        if value is not None and value <= Decimal("0"):
            raise ValueError("threshold amounts must be greater than zero")
        return value

    @field_validator(
        "trusted_provider_names",
        "trusted_environments",
        "trusted_namespaces",
        "trusted_service_accounts",
        "trusted_trust_tiers",
        mode="before",
    )
    @classmethod
    def validate_optional_string_list(cls, value: Any, info) -> list[str] | None:
        if value is None:
            return None
        if not isinstance(value, list):
            raise ValueError("value must be a list")
        normalized = []
        for item in value:
            if not isinstance(item, str):
                raise ValueError("all entries must be strings")
            candidate = item.strip()
            if candidate:
                normalized.append(candidate)
        # An empty provider list intentionally means "no provider-name
        # restriction" in infrastructure identity evaluation. Other trust
        # dimensions must stay non-empty when explicitly configured.
        if not normalized and info.field_name != "trusted_provider_names":
            raise ValueError("list cannot be empty")
        return normalized


class PolicyAp2LifecyclePolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    intent_retention_days: int | None = Field(default=None, ge=1)
    cart_retention_days: int | None = Field(default=None, ge=1)
    archived_redaction_delay_days: int | None = Field(default=None, ge=0)


class PolicyControls(BaseModel):
    model_config = ConfigDict(extra="allow", strict=True)

    allowed_currencies: list[str] | None = None
    fee_rate: Decimal | None = None
    min_description_words: int | None = Field(default=None, ge=1)
    rate_limit: PolicyRateLimitControl | None = None
    payment_velocity_limit: PolicyVelocityControl | None = None
    budget_alert_thresholds: list[Decimal] | None = None
    hitl_approval_ttl_seconds: int | None = Field(default=None, ge=1)
    spend_token_ttl_seconds: int | None = Field(default=None, ge=1)
    mcp_unknown_server_hitl_threshold: Decimal | None = None
    webhook_timeout_seconds: int | None = Field(default=None, ge=1)
    webhook_max_attempts: int | None = Field(default=None, ge=1)
    infrastructure_identity_anomaly_alert_min_severity: str | None = None
    infrastructure_identity_anomaly_hitl_min_severity: str | None = None
    infrastructure_identity_anomaly_deny_min_severity: str | None = None
    phase3_features: PolicyPhase3Features | None = None
    infrastructure_identity_policy: PolicyInfrastructureIdentityPolicy | None = None
    ap2_lifecycle_policy: PolicyAp2LifecyclePolicy | None = None

    @field_validator("fee_rate", "mcp_unknown_server_hitl_threshold", mode="before")
    @classmethod
    def parse_optional_decimal(cls, value: Any, info) -> Decimal | None:
        if value is None:
            return None
        return _parse_decimal_text(value, info.field_name)

    @field_validator("budget_alert_thresholds", mode="before")
    @classmethod
    def parse_threshold_list(cls, value: Any) -> list[Decimal] | None:
        if value is None:
            return None
        if not isinstance(value, list):
            raise ValueError("budget_alert_thresholds must be a list")
        return [_parse_decimal_text(item, "budget_alert_thresholds") for item in value]

    @field_validator("budget_alert_thresholds")
    @classmethod
    def validate_threshold_list(cls, value: list[Decimal] | None) -> list[Decimal] | None:
        if value is None:
            return None
        if not value:
            raise ValueError("budget_alert_thresholds cannot be empty")
        for item in value:
            if item <= Decimal("0") or item > Decimal("1"):
                raise ValueError("budget_alert_thresholds values must be within (0, 1]")
        return value

    @field_validator("infrastructure_identity_anomaly_alert_min_severity")
    @classmethod
    def validate_anomaly_alert_min_severity(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = str(value).strip().lower()
        if normalized not in {"disabled", "informational", "low", "medium", "high"}:
            raise ValueError(
                "infrastructure_identity_anomaly_alert_min_severity must be one of disabled, informational, low, medium, or high"
            )
        return normalized

    @field_validator("infrastructure_identity_anomaly_hitl_min_severity")
    @classmethod
    def validate_anomaly_hitl_min_severity(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = str(value).strip().lower()
        if normalized not in {"disabled", "informational", "low", "medium", "high"}:
            raise ValueError(
                "infrastructure_identity_anomaly_hitl_min_severity must be one of disabled, informational, low, medium, or high"
            )
        return normalized

    @field_validator("infrastructure_identity_anomaly_deny_min_severity")
    @classmethod
    def validate_anomaly_deny_min_severity(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = str(value).strip().lower()
        if normalized not in {"disabled", "informational", "low", "medium", "high"}:
            raise ValueError(
                "infrastructure_identity_anomaly_deny_min_severity must be one of disabled, informational, low, medium, or high"
            )
        return normalized

    @model_validator(mode="after")
    def validate_anomaly_threshold_relationships(self) -> "PolicyControls":
        deny_threshold = self.infrastructure_identity_anomaly_deny_min_severity
        if deny_threshold in {None, "disabled"}:
            return self

        hitl_threshold = self.infrastructure_identity_anomaly_hitl_min_severity or "disabled"
        if hitl_threshold == "disabled":
            raise ValueError(
                "infrastructure_identity_anomaly_deny_min_severity requires an enabled infrastructure_identity_anomaly_hitl_min_severity"
            )
        if not anomaly_severity_is_stricter(severity=deny_threshold, baseline=hitl_threshold):
            raise ValueError(
                "infrastructure_identity_anomaly_deny_min_severity must be stricter than infrastructure_identity_anomaly_hitl_min_severity"
            )
        return self


class PolicyDocumentModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    version: str = Field(..., min_length=1)
    description: str | None = None
    controls: PolicyControls = Field(default_factory=PolicyControls)

    @field_validator("version")
    @classmethod
    def sanitize_document_version(cls, value: str) -> str:
        sanitized = _sanitize_text(value, max_length=50)
        if not sanitized:
            raise ValueError("version cannot be empty")
        return sanitized

    @field_validator("description")
    @classmethod
    def sanitize_description(cls, value: str | None) -> str | None:
        if value is None:
            return None
        sanitized = _sanitize_text(value, max_length=500)
        return sanitized or None


def _require_identity(
    authorization: str | None,
    scopes: list[str],
    infrastructure_assertion: str | None = None,
    infrastructure_signature: str | None = None,
    allow_disabled_infrastructure_identity: bool = False,
) -> Any:
    if _get_current_identity is None or _ensure_scope is None:
        raise RuntimeError("Policy API not configured")
    identity = _get_current_identity(
        authorization,
        infrastructure_assertion,
        infrastructure_signature,
        allow_disabled_infrastructure_identity,
    )
    return _ensure_scope(identity, scopes)


@router.get("/policies")
def list_policies(authorization: str | None = Header(default=None, alias="Authorization")) -> list[dict[str, Any]]:
    _require_identity(authorization, ["audit:read"])
    return _store.list_policy_documents()


@router.get("/policies/current")
def get_current_policy(authorization: str | None = Header(default=None, alias="Authorization")) -> dict[str, Any]:
    _require_identity(authorization, ["audit:read"])
    return _store.get_current_policy_document()


@router.post("/policies/current")
def activate_policy(
    payload: PolicyActivationRequest,
    authorization: str | None = Header(default=None, alias="Authorization"),
    infrastructure_assertion: str | None = Header(default=None, alias="X-Infrastructure-Assertion"),
    infrastructure_signature: str | None = Header(default=None, alias="X-Infrastructure-Signature"),
) -> dict[str, Any]:
    identity = _require_identity(
        authorization,
        ["admin:all"],
        infrastructure_assertion,
        infrastructure_signature,
        allow_disabled_infrastructure_identity=True,
    )
    try:
        document = PolicyDocumentModel.model_validate(payload.document)
    except ValidationError as exc:
        serialized_errors = []
        for item in exc.errors():
            ctx = item.get("ctx")
            if ctx:
                item = item.copy()
                item["ctx"] = {key: str(value) for key, value in ctx.items()}
            serialized_errors.append(item)
        raise HTTPException(status_code=422, detail={"code": "INVALID_POLICY_DOCUMENT", "errors": serialized_errors}) from exc
    if document.version != payload.version:
        raise HTTPException(status_code=422, detail={"code": "POLICY_VERSION_MISMATCH"})
    policy = _store.activate_policy_document(payload.version, document.model_dump(mode="json"), payload.notes)
    _append_audit_entry(
        actor_type="admin",
        actor_id=identity.oauth_subject,
        action="policy_activate",
        request_path="/policies/current",
        request_payload_hash=_hash_token(payload.model_dump_json()),
        request_payload_summary={"version": payload.version},
        decision="updated",
        decision_reason=payload.notes,
        decision_details={"status": "updated"},
        **audit_infrastructure_identity_fields(identity),
    )
    capture_infrastructure_identity_profile(
        store=_store,
        identity=identity,
        actor_type="admin",
        actor_id=identity.oauth_subject,
        event_type="admin_mutation",
        action="policy_activate",
        request_path="/policies/current",
    )
    return policy
