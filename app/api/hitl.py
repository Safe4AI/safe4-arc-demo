from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any, Callable

from fastapi import APIRouter, Header, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..auth import (
    audit_infrastructure_identity_fields,
    capture_infrastructure_identity_profile,
    require_trusted_infrastructure_identity_for_admin,
)


router = APIRouter()

_store = None
_append_audit_entry: Callable[..., None] | None = None
_hash_token: Callable[[str], str] | None = None
_issue_secret_token: Callable[[str], tuple[str, str]] | None = None
_normalize_money: Callable[[Decimal], Decimal] | None = None
_decimal_to_text: Callable[[Decimal], str] | None = None
_sanitize_text: Callable[[str, int], str] | None = None
_get_current_identity = None
_ensure_scope: Callable[[Any, list[str]], Any] | None = None
_get_spend_token_ttl_seconds: Callable[[], int] | None = None
_parse_decimal_input: Callable[[Any, str], Decimal] | None = None
_max_amount = None


def setup_hitl_api(
    *,
    store: Any,
    append_audit_entry: Callable[..., None],
    hash_token: Callable[[str], str],
    issue_secret_token: Callable[[str], tuple[str, str]],
    normalize_money: Callable[[Decimal], Decimal],
    decimal_to_text: Callable[[Decimal], str],
    sanitize_text: Callable[[str, int], str],
    parse_decimal_input: Callable[[Any, str], Decimal],
    get_current_identity: Callable[..., Any],
    ensure_scope: Callable[[Any, list[str]], Any],
    get_spend_token_ttl_seconds: Callable[[], int],
    max_amount: Any,
) -> None:
    global _store, _append_audit_entry, _hash_token, _issue_secret_token, _normalize_money
    global _decimal_to_text, _sanitize_text, _get_current_identity, _ensure_scope, _get_spend_token_ttl_seconds
    global _parse_decimal_input, _max_amount
    _store = store
    _append_audit_entry = append_audit_entry
    _hash_token = hash_token
    _issue_secret_token = issue_secret_token
    _normalize_money = normalize_money
    _decimal_to_text = decimal_to_text
    _sanitize_text = sanitize_text
    _parse_decimal_input = parse_decimal_input
    _get_current_identity = get_current_identity
    _ensure_scope = ensure_scope
    _get_spend_token_ttl_seconds = get_spend_token_ttl_seconds
    _max_amount = max_amount


class ApprovalDecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    decision: str = Field(..., min_length=1)
    reason: str | None = Field(default=None)

    @field_validator("decision")
    @classmethod
    def validate_decision(cls, value: str) -> str:
        if value not in {"approved", "denied"}:
            raise ValueError("decision must be approved or denied")
        return value

    @field_validator("reason")
    @classmethod
    def sanitize_reason(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _sanitize_text(value, max_length=500)


class SpendTokenRevokeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    token: str = Field(..., min_length=1)


class ApprovalAlertAckRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    reason: str | None = Field(default=None)

    @field_validator("reason")
    @classmethod
    def sanitize_reason(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _sanitize_text(value, max_length=500)


class HitlRuleRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    rule_id: str = Field(..., min_length=1)
    applies_to: str = Field(default="direct")
    trigger_type: str = Field(..., min_length=1)
    threshold_amount: Decimal | None = Field(default=None, ge=0)
    vendor_pattern: str | None = Field(default=None)
    currency: str | None = Field(default=None)
    mcp_tool_id: str | None = Field(default=None)
    mcp_action: str | None = Field(default=None)
    mcp_server_trust_level: str | None = Field(default=None)
    secondary_trigger_type: str | None = Field(default=None)
    secondary_threshold_amount: Decimal | None = Field(default=None, ge=0)
    secondary_vendor_pattern: str | None = Field(default=None)
    secondary_currency: str | None = Field(default=None)
    secondary_mcp_tool_id: str | None = Field(default=None)
    secondary_mcp_action: str | None = Field(default=None)
    secondary_mcp_server_trust_level: str | None = Field(default=None)
    is_active: bool = Field(default=True)

    @field_validator(
        "rule_id",
        "vendor_pattern",
        "currency",
        "mcp_tool_id",
        "mcp_action",
        "mcp_server_trust_level",
        "secondary_trigger_type",
        "secondary_vendor_pattern",
        "secondary_currency",
        "secondary_mcp_tool_id",
        "secondary_mcp_action",
        "secondary_mcp_server_trust_level",
    )
    @classmethod
    def sanitize_optional_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        sanitized = _sanitize_text(value, max_length=255)
        if not sanitized:
            raise ValueError("field cannot be empty")
        return sanitized

    @field_validator("applies_to")
    @classmethod
    def validate_applies_to(cls, value: str) -> str:
        if value not in {"direct", "mcp", "any"}:
            raise ValueError("applies_to must be direct, mcp, or any")
        return value

    @field_validator("trigger_type")
    @classmethod
    def validate_trigger_type(cls, value: str) -> str:
        allowed = {
            "amount_threshold",
            "first_time_vendor",
            "vendor_pattern",
            "first_time_agent_user",
            "currency_match",
            "mcp_tool_match",
            "mcp_action_match",
            "mcp_server_trust_level",
        }
        if value not in allowed:
            raise ValueError("unsupported trigger_type")
        return value

    @field_validator("secondary_trigger_type")
    @classmethod
    def validate_secondary_trigger_type(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return cls.validate_trigger_type(value)

    @field_validator("threshold_amount", mode="before")
    @classmethod
    def parse_threshold_amount(cls, value: Any) -> Decimal | None:
        if value is None:
            return None
        return _parse_decimal_input(value, "threshold_amount")

    @field_validator("threshold_amount")
    @classmethod
    def normalize_threshold_amount(cls, value: Decimal | None) -> Decimal | None:
        if value is None:
            return None
        normalized = _normalize_money(value)
        if normalized > _max_amount:
            raise ValueError("threshold_amount must be less than or equal to 1000000.000000")
        if normalized != value:
            raise ValueError("threshold_amount must have at most 6 decimal places")
        return normalized

    @field_validator("secondary_threshold_amount", mode="before")
    @classmethod
    def parse_secondary_threshold_amount(cls, value: Any) -> Decimal | None:
        if value is None:
            return None
        return _parse_decimal_input(value, "secondary_threshold_amount")

    @field_validator("secondary_threshold_amount")
    @classmethod
    def normalize_secondary_threshold_amount(cls, value: Decimal | None) -> Decimal | None:
        if value is None:
            return None
        normalized = _normalize_money(value)
        if normalized > _max_amount:
            raise ValueError("secondary_threshold_amount must be less than or equal to 1000000.000000")
        if normalized != value:
            raise ValueError("secondary_threshold_amount must have at most 6 decimal places")
        return normalized

    @field_validator("vendor_pattern")
    @classmethod
    def require_vendor_pattern_for_pattern_rule(cls, value: str | None, info) -> str | None:
        if info.data.get("trigger_type") == "vendor_pattern" and not value:
            raise ValueError("vendor_pattern is required for vendor_pattern rules")
        return value

    @field_validator("threshold_amount")
    @classmethod
    def require_threshold_for_amount_rule(cls, value: Decimal | None, info) -> Decimal | None:
        if info.data.get("trigger_type") == "amount_threshold" and value is None:
            raise ValueError("threshold_amount is required for amount_threshold rules")
        return value

    @field_validator("currency")
    @classmethod
    def require_currency_for_currency_rule(cls, value: str | None, info) -> str | None:
        if info.data.get("trigger_type") == "currency_match" and not value:
            raise ValueError("currency is required for currency_match rules")
        return value

    @field_validator("mcp_tool_id")
    @classmethod
    def require_mcp_tool_for_tool_match(cls, value: str | None, info) -> str | None:
        if info.data.get("trigger_type") == "mcp_tool_match" and not value:
            raise ValueError("mcp_tool_id is required for mcp_tool_match rules")
        return value

    @field_validator("mcp_action")
    @classmethod
    def require_mcp_action_for_action_match(cls, value: str | None, info) -> str | None:
        if info.data.get("trigger_type") == "mcp_action_match" and not value:
            raise ValueError("mcp_action is required for mcp_action_match rules")
        return value

    @field_validator("mcp_server_trust_level")
    @classmethod
    def require_server_trust_for_server_rule(cls, value: str | None, info) -> str | None:
        if info.data.get("trigger_type") == "mcp_server_trust_level" and not value:
            raise ValueError("mcp_server_trust_level is required for mcp_server_trust_level rules")
        if value is not None and value not in {"trusted", "verified", "unknown", "blocked"}:
            raise ValueError("unsupported mcp_server_trust_level")
        return value

    @field_validator("secondary_vendor_pattern")
    @classmethod
    def require_secondary_vendor_pattern(cls, value: str | None, info) -> str | None:
        if info.data.get("secondary_trigger_type") == "vendor_pattern" and not value:
            raise ValueError("secondary_vendor_pattern is required for vendor_pattern rules")
        return value

    @field_validator("secondary_threshold_amount")
    @classmethod
    def require_secondary_threshold(cls, value: Decimal | None, info) -> Decimal | None:
        if info.data.get("secondary_trigger_type") == "amount_threshold" and value is None:
            raise ValueError("secondary_threshold_amount is required for amount_threshold rules")
        return value

    @field_validator("secondary_currency")
    @classmethod
    def require_secondary_currency(cls, value: str | None, info) -> str | None:
        if info.data.get("secondary_trigger_type") == "currency_match" and not value:
            raise ValueError("secondary_currency is required for currency_match rules")
        return value

    @field_validator("secondary_mcp_tool_id")
    @classmethod
    def require_secondary_mcp_tool(cls, value: str | None, info) -> str | None:
        if info.data.get("secondary_trigger_type") == "mcp_tool_match" and not value:
            raise ValueError("secondary_mcp_tool_id is required for mcp_tool_match rules")
        return value

    @field_validator("secondary_mcp_action")
    @classmethod
    def require_secondary_mcp_action(cls, value: str | None, info) -> str | None:
        if info.data.get("secondary_trigger_type") == "mcp_action_match" and not value:
            raise ValueError("secondary_mcp_action is required for mcp_action_match rules")
        return value

    @field_validator("secondary_mcp_server_trust_level")
    @classmethod
    def require_secondary_server_trust(cls, value: str | None, info) -> str | None:
        if info.data.get("secondary_trigger_type") == "mcp_server_trust_level" and not value:
            raise ValueError("secondary_mcp_server_trust_level is required for mcp_server_trust_level rules")
        if value is not None and value not in {"trusted", "verified", "unknown", "blocked"}:
            raise ValueError("unsupported secondary_mcp_server_trust_level")
        return value

    @model_validator(mode="after")
    def validate_scope_for_trigger(self) -> "HitlRuleRequest":
        if self.trigger_type in {"mcp_tool_match", "mcp_action_match", "mcp_server_trust_level"} and self.applies_to == "direct":
            raise ValueError("MCP trigger types require applies_to of mcp or any")
        if self.secondary_trigger_type in {"mcp_tool_match", "mcp_action_match", "mcp_server_trust_level"} and self.applies_to == "direct":
            raise ValueError("Secondary MCP trigger types require applies_to of mcp or any")
        return self


def _require_admin_identity(
    authorization: str | None,
    infrastructure_assertion: str | None = None,
    infrastructure_signature: str | None = None,
) -> Any:
    if _get_current_identity is None or _ensure_scope is None:
        raise RuntimeError("HITL API not configured")
    identity = _get_current_identity(authorization, infrastructure_assertion, infrastructure_signature)
    return _ensure_scope(identity, ["admin:all"])


def _enqueue_approval_lifecycle_alert(*, approval: dict[str, Any], alert_type: str, summary: str, details: dict[str, Any] | None = None) -> None:
    _store.enqueue_approval_alert(
        alert_type=alert_type,
        approval_id=approval["approval_id"],
        request_hash=approval["request_hash"],
        triggered_by=approval["triggered_by"],
        requestor_agent_id=approval["requestor_agent_id"],
        requestor_user_id=approval["requestor_user_id"],
        mcp_tool_id=approval["mcp_tool_id"],
        summary=summary,
        details={
            "approval_id": approval["approval_id"],
            "status": approval["status"],
            "decided_by": approval["decided_by"],
            "decided_at": approval["decided_at"],
            "decision_reason": approval["decision_reason"],
            "expires_at": approval["expires_at"],
        }
        | (details or {}),
        event_key=f"{alert_type}:{approval['approval_id']}",
    )


def _current_spend_token_ttl_seconds() -> int:
    if _get_spend_token_ttl_seconds is None:
        return 300
    return max(1, int(_get_spend_token_ttl_seconds()))


def _expire_and_enqueue_approval_alerts() -> int:
    now_value = datetime.now(timezone.utc).isoformat()
    pending_to_expire = [
        item for item in _store.list_approval_requests(status="pending") if item["expires_at"] <= now_value
    ]
    expired = _store.expire_approval_requests(now_value)
    if expired:
        for approval in pending_to_expire:
            expired_record = _store.get_approval_request(approval["approval_id"])
            if expired_record is None or expired_record["status"] != "expired":
                continue
            _enqueue_approval_lifecycle_alert(
                approval=expired_record,
                alert_type="hitl_approval_expired",
                summary="HITL approval expired before review.",
                details={"reason_code": "APPROVAL_EXPIRED"},
            )
    return expired


@router.get("/approvals")
def list_approvals(
    status: str | None = None,
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> list[dict[str, Any]]:
    _require_admin_identity(authorization)
    return _store.list_approval_requests(status)


@router.get("/approval-alerts/outbox")
def list_approval_alerts(
    status: str | None = None,
    alert_type: str | None = None,
    approval_id: str | None = None,
    requestor_user_id: str | None = None,
    requestor_agent_id: str | None = None,
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> list[dict[str, Any]]:
    _require_admin_identity(authorization)
    return _store.list_approval_alerts(
        status=status,
        alert_type=alert_type,
        approval_id=approval_id,
        requestor_user_id=requestor_user_id,
        requestor_agent_id=requestor_agent_id,
    )


@router.post("/approval-alerts/outbox/{alert_id}/ack")
def acknowledge_approval_alert(
    alert_id: str,
    payload: ApprovalAlertAckRequest,
    authorization: str | None = Header(default=None, alias="Authorization"),
    infrastructure_assertion: str | None = Header(default=None, alias="X-Infrastructure-Assertion"),
    infrastructure_signature: str | None = Header(default=None, alias="X-Infrastructure-Signature"),
) -> dict[str, Any]:
    identity = _require_admin_identity(authorization, infrastructure_assertion, infrastructure_signature)
    require_trusted_infrastructure_identity_for_admin(identity)
    alert = _store.acknowledge_approval_alert(alert_id)
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"code": "APPROVAL_ALERT_NOT_FOUND"})
    _append_audit_entry(
        actor_type="admin",
        actor_id=identity.oauth_subject,
        action="approval_alert_acknowledge",
        request_path=f"/approval-alerts/outbox/{alert_id}/ack",
        request_payload_hash=_hash_token(payload.model_dump_json()),
        request_payload_summary={"alert_id": alert_id, "approval_id": alert["approval_id"]},
        decision="acknowledged",
        decision_reason=payload.reason,
        decision_details={},
        mcp_tool_id=alert["mcp_tool_id"],
        **audit_infrastructure_identity_fields(identity),
    )
    capture_infrastructure_identity_profile(
        store=_store,
        identity=identity,
        actor_type="admin",
        actor_id=identity.oauth_subject,
        event_type="admin_mutation",
        action="approval_alert_acknowledge",
        request_path=f"/approval-alerts/outbox/{alert_id}/ack",
    )
    return alert


@router.get("/hitl/rules")
def list_hitl_rules(authorization: str | None = Header(default=None, alias="Authorization")) -> list[dict[str, Any]]:
    _require_admin_identity(authorization)
    return _store.list_hitl_rules()


@router.post("/hitl/rules")
def upsert_hitl_rule(
    payload: HitlRuleRequest,
    authorization: str | None = Header(default=None, alias="Authorization"),
    infrastructure_assertion: str | None = Header(default=None, alias="X-Infrastructure-Assertion"),
    infrastructure_signature: str | None = Header(default=None, alias="X-Infrastructure-Signature"),
) -> dict[str, Any]:
    identity = _require_admin_identity(authorization, infrastructure_assertion, infrastructure_signature)
    require_trusted_infrastructure_identity_for_admin(identity)
    rule = _store.upsert_hitl_rule(
        rule_id=payload.rule_id,
        applies_to=payload.applies_to,
        trigger_type=payload.trigger_type,
        threshold_amount=payload.threshold_amount,
        vendor_pattern=payload.vendor_pattern,
        currency=payload.currency,
        mcp_tool_id=payload.mcp_tool_id,
        mcp_action=payload.mcp_action,
        mcp_server_trust_level=payload.mcp_server_trust_level,
        secondary_trigger_type=payload.secondary_trigger_type,
        secondary_threshold_amount=payload.secondary_threshold_amount,
        secondary_vendor_pattern=payload.secondary_vendor_pattern,
        secondary_currency=payload.secondary_currency,
        secondary_mcp_tool_id=payload.secondary_mcp_tool_id,
        secondary_mcp_action=payload.secondary_mcp_action,
        secondary_mcp_server_trust_level=payload.secondary_mcp_server_trust_level,
        is_active=payload.is_active,
    )
    _append_audit_entry(
        actor_type="admin",
        actor_id=identity.oauth_subject,
        action="hitl_rule_upsert",
        request_path="/hitl/rules",
        request_payload_hash=_hash_token(payload.model_dump_json()),
        request_payload_summary={"rule_id": payload.rule_id, "trigger_type": payload.trigger_type, "applies_to": payload.applies_to},
        decision="updated",
        decision_reason=None,
        decision_details={"is_active": payload.is_active},
        **audit_infrastructure_identity_fields(identity),
    )
    capture_infrastructure_identity_profile(
        store=_store,
        identity=identity,
        actor_type="admin",
        actor_id=identity.oauth_subject,
        event_type="admin_mutation",
        action="hitl_rule_upsert",
        request_path="/hitl/rules",
    )
    return rule


@router.get("/approvals/{approval_id}")
def get_approval(
    approval_id: str,
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> dict[str, Any]:
    _require_admin_identity(authorization)
    approval = _store.get_approval_request(approval_id)
    if approval is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"code": "APPROVAL_NOT_FOUND"})
    return approval


@router.post("/approvals/{approval_id}/decide")
def decide_approval(
    approval_id: str,
    request: Request,
    payload: ApprovalDecisionRequest,
    authorization: str | None = Header(default=None, alias="Authorization"),
    infrastructure_assertion: str | None = Header(default=None, alias="X-Infrastructure-Assertion"),
    infrastructure_signature: str | None = Header(default=None, alias="X-Infrastructure-Signature"),
) -> dict[str, Any]:
    decision_started_at = time.perf_counter()
    identity = _require_admin_identity(authorization, infrastructure_assertion, infrastructure_signature)
    require_trusted_infrastructure_identity_for_admin(identity)
    _expire_and_enqueue_approval_alerts()
    approval = _store.get_approval_request(approval_id)
    if approval is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"code": "APPROVAL_NOT_FOUND"})
    if approval["status"] == "expired" or datetime.fromisoformat(approval["expires_at"]) <= datetime.now(timezone.utc):
        raise HTTPException(status_code=status.HTTP_410_GONE, detail={"code": "APPROVAL_EXPIRED"})
    decided = _store.decide_approval_request(approval_id, payload.decision, identity.oauth_subject, payload.reason)
    if decided is None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail={"code": "APPROVAL_NOT_PENDING"})

    approval_wait_ms = max(0, int((datetime.now(timezone.utc) - datetime.fromisoformat(approval["created_at"])).total_seconds() * 1000))
    spend_token: str | None = None
    spend_token_ttl_seconds: int | None = None
    if payload.decision == "approved":
        raw_spend_token, spend_token_hash = _issue_secret_token("st")
        spend_token = raw_spend_token
        spend_token_ttl_seconds = _current_spend_token_ttl_seconds()
        expires_at = (datetime.now(timezone.utc) + timedelta(seconds=spend_token_ttl_seconds)).isoformat()
        stored_payload = decided["request_payload"]
        _store.create_spend_token(
            token_hash=spend_token_hash,
            token_id=raw_spend_token,
            request_hash=decided["request_hash"],
            user_id=decided["requestor_user_id"],
            agent_id=decided["requestor_agent_id"],
            mcp_tool_id=decided["mcp_tool_id"],
            authorized_amount=_normalize_money(Decimal(str(stored_payload["amount"]))),
            authorized_currency=stored_payload["currency"],
            authorized_action=stored_payload.get("mcp_action"),
            expires_at=expires_at,
        )

    _append_audit_entry(
        actor_type="admin",
        actor_id=identity.oauth_subject,
        action="approval_decide",
        request_path=f"/approvals/{approval_id}/decide",
        request_payload_hash=_hash_token(payload.model_dump_json()),
        request_payload_summary={"approval_id": approval_id, "decision": payload.decision},
        decision=payload.decision,
        decision_reason=payload.reason,
        decision_details={
            "approval_id": approval_id,
            "approval_wait_ms": approval_wait_ms,
            "decision_latency_ms": int((time.perf_counter() - decision_started_at) * 1000),
            "spend_token_ttl_seconds": spend_token_ttl_seconds,
        },
        mcp_tool_id=approval["mcp_tool_id"],
        **audit_infrastructure_identity_fields(identity),
    )
    capture_infrastructure_identity_profile(
        store=_store,
        identity=identity,
        actor_type="admin",
        actor_id=identity.oauth_subject,
        event_type="admin_mutation",
        action="approval_decide",
        request_path=f"/approvals/{approval_id}/decide",
    )
    _enqueue_approval_lifecycle_alert(
        approval=decided,
        alert_type="hitl_approval_approved" if payload.decision == "approved" else "hitl_approval_denied",
        summary="HITL approval approved by operator." if payload.decision == "approved" else "HITL approval denied by operator.",
        details={"reason_code": "APPROVAL_APPROVED" if payload.decision == "approved" else "APPROVAL_DENIED"},
    )
    return decided | {"spend_token": spend_token}


@router.post("/approvals/expire")
def expire_approvals(
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> dict[str, Any]:
    _require_admin_identity(authorization)
    expired = _expire_and_enqueue_approval_alerts()
    return {"expired": expired}


@router.get("/tokens/{token_id}")
def get_spend_token_status(
    token_id: str,
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> dict[str, Any]:
    _require_admin_identity(authorization)
    token = _store.get_spend_token(_hash_token(token_id))
    if token is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"code": "SPEND_TOKEN_NOT_FOUND"})
    return {
        "token_id": token["token_id"],
        "user_id": token["user_id"],
        "agent_id": token["agent_id"],
        "mcp_tool_id": token["mcp_tool_id"],
        "authorized_amount": _decimal_to_text(token["authorized_amount"]),
        "authorized_currency": token["authorized_currency"],
        "authorized_action": token["authorized_action"],
        "expires_at": token["expires_at"],
        "is_used": token["is_used"],
        "used_at": token["used_at"],
        "revoked": token["revoked"],
        "created_at": token["created_at"],
    }


@router.post("/tokens/revoke")
def revoke_spend_token(
    request: Request,
    payload: SpendTokenRevokeRequest,
    authorization: str | None = Header(default=None, alias="Authorization"),
    infrastructure_assertion: str | None = Header(default=None, alias="X-Infrastructure-Assertion"),
    infrastructure_signature: str | None = Header(default=None, alias="X-Infrastructure-Signature"),
) -> dict[str, Any]:
    identity = _require_admin_identity(authorization, infrastructure_assertion, infrastructure_signature)
    require_trusted_infrastructure_identity_for_admin(identity)
    revoked = _store.revoke_spend_token(_hash_token(payload.token))
    if not revoked:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"code": "SPEND_TOKEN_NOT_REVOCABLE"})
    _append_audit_entry(
        actor_type="admin",
        actor_id=identity.oauth_subject,
        action="spend_token_revoke",
        request_path="/tokens/revoke",
        request_payload_hash=_hash_token(payload.model_dump_json()),
        request_payload_summary={"token_id": payload.token},
        decision="revoked",
        decision_reason=None,
        decision_details={},
        **audit_infrastructure_identity_fields(identity),
    )
    capture_infrastructure_identity_profile(
        store=_store,
        identity=identity,
        actor_type="admin",
        actor_id=identity.oauth_subject,
        event_type="admin_mutation",
        action="spend_token_revoke",
        request_path="/tokens/revoke",
    )
    return {"revoked": True, "token_id": payload.token}
