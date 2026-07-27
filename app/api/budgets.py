from __future__ import annotations

import hashlib
import json
from decimal import Decimal
from typing import Any, Callable

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..auth import (
    audit_infrastructure_identity_fields,
    capture_infrastructure_identity_profile,
    require_trusted_infrastructure_identity_for_admin,
)


router = APIRouter()

_store = None
_append_audit_entry: Callable[..., None] | None = None
_decimal_to_text: Callable[[Any], str] | None = None
_serialize_budget: Callable[[dict[str, Any]], dict[str, str]] | None = None
_sanitize_text: Callable[[str, int], str] | None = None
_parse_decimal_input: Callable[[Any, str], Any] | None = None
_normalize_money: Callable[[Any], Any] | None = None
_get_current_identity = None
_ensure_scope: Callable[[Any, list[str]], Any] | None = None
_max_amount = None
_get_budget_alert_thresholds: Callable[[], list[Decimal]] | None = None


def setup_budgets_api(
    *,
    store: Any,
    append_audit_entry: Callable[..., None],
    decimal_to_text: Callable[[Any], str],
    serialize_budget: Callable[[dict[str, Any]], dict[str, str]],
    sanitize_text: Callable[[str, int], str],
    parse_decimal_input: Callable[[Any, str], Any],
    normalize_money: Callable[[Any], Any],
    get_current_identity: Callable[..., Any],
    ensure_scope: Callable[[Any, list[str]], Any],
    max_amount: Any,
    get_budget_alert_thresholds: Callable[[], list[Any]],
) -> None:
    global _store, _append_audit_entry, _decimal_to_text, _serialize_budget, _sanitize_text
    global _parse_decimal_input, _normalize_money, _get_current_identity, _ensure_scope, _max_amount
    global _get_budget_alert_thresholds
    _store = store
    _append_audit_entry = append_audit_entry
    _decimal_to_text = decimal_to_text
    _serialize_budget = serialize_budget
    _sanitize_text = sanitize_text
    _parse_decimal_input = parse_decimal_input
    _normalize_money = normalize_money
    _get_current_identity = get_current_identity
    _ensure_scope = ensure_scope
    _max_amount = max_amount
    _get_budget_alert_thresholds = get_budget_alert_thresholds


class BudgetConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    daily_cap: Any = Field(..., ge=0)
    transaction_cap: Any = Field(..., ge=0)
    spent_today: Any = Field(0, ge=0)

    @field_validator("daily_cap", "transaction_cap", "spent_today", mode="before")
    @classmethod
    def parse_money_field(cls, value: Any, info) -> Any:
        return _parse_decimal_input(value, info.field_name)

    @field_validator("daily_cap", "transaction_cap", "spent_today")
    @classmethod
    def normalize_money_field(cls, value: Any) -> Any:
        normalized = _normalize_money(value)
        if normalized > _max_amount:
            raise ValueError("budget values must be less than or equal to 1000000.000000")
        if value != normalized:
            raise ValueError("budget values must have at most 6 decimal places")
        return normalized


class BudgetUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    user_id: str = Field(..., min_length=1)
    daily_cap: Any = Field(..., ge=0)
    transaction_cap: Any = Field(..., ge=0)
    spent_today: Any = Field(0, ge=0)

    @field_validator("daily_cap", "transaction_cap", "spent_today", mode="before")
    @classmethod
    def parse_money_field(cls, value: Any, info) -> Any:
        return _parse_decimal_input(value, info.field_name)

    @field_validator("daily_cap", "transaction_cap", "spent_today")
    @classmethod
    def normalize_money_field(cls, value: Any) -> Any:
        normalized = _normalize_money(value)
        if normalized > _max_amount:
            raise ValueError("budget values must be less than or equal to 1000000.000000")
        if value != normalized:
            raise ValueError("budget values must have at most 6 decimal places")
        return normalized

    @field_validator("user_id")
    @classmethod
    def sanitize_user_id(cls, value: str) -> str:
        sanitized = _sanitize_text(value, max_length=255)
        if not sanitized:
            raise ValueError("user_id cannot be empty")
        return sanitized


class AgentBudgetUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    agent_id: str = Field(..., min_length=1)
    daily_cap: Any = Field(..., ge=0)
    transaction_cap: Any = Field(..., ge=0)
    spent_today: Any = Field(0, ge=0)

    @field_validator("daily_cap", "transaction_cap", "spent_today", mode="before")
    @classmethod
    def parse_money_field(cls, value: Any, info) -> Any:
        return _parse_decimal_input(value, info.field_name)

    @field_validator("daily_cap", "transaction_cap", "spent_today")
    @classmethod
    def normalize_money_field(cls, value: Any) -> Any:
        normalized = _normalize_money(value)
        if normalized > _max_amount:
            raise ValueError("budget values must be less than or equal to 1000000.000000")
        if value != normalized:
            raise ValueError("budget values must have at most 6 decimal places")
        return normalized

    @field_validator("agent_id")
    @classmethod
    def sanitize_agent_id(cls, value: str) -> str:
        sanitized = _sanitize_text(value, max_length=255)
        if not sanitized:
            raise ValueError("agent_id cannot be empty")
        return sanitized


class BudgetAlertAcknowledgeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    reason: str | None = Field(default=None, max_length=500)

    @field_validator("reason")
    @classmethod
    def sanitize_reason(cls, value: str | None) -> str | None:
        if value is None:
            return None
        sanitized = _sanitize_text(value, max_length=500)
        if not sanitized:
            raise ValueError("reason cannot be empty")
        return sanitized


def _require_identity(
    authorization: str | None,
    scopes: list[str],
    infrastructure_assertion: str | None = None,
    infrastructure_signature: str | None = None,
) -> Any:
    if _get_current_identity is None or _ensure_scope is None:
        raise RuntimeError("Budgets API not configured")
    identity = _get_current_identity(authorization, infrastructure_assertion, infrastructure_signature)
    return _ensure_scope(identity, scopes)


@router.get("/budgets")
def get_budgets(authorization: str | None = Header(default=None, alias="Authorization")) -> dict[str, dict[str, str]]:
    _require_identity(authorization, ["payment:read"])
    return _store.list_budgets()


@router.get("/budgets/agents")
def get_agent_budgets(authorization: str | None = Header(default=None, alias="Authorization")) -> dict[str, dict[str, str]]:
    _require_identity(authorization, ["payment:read"])
    return _store.list_agent_budgets()


@router.get("/budget-alerts/outbox")
def get_budget_alerts(
    status: str | None = None,
    entity_type: str | None = None,
    entity_id: str | None = None,
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> list[dict[str, Any]]:
    _require_identity(authorization, ["budget:manage"])
    return _store.list_budget_alerts(status=status, entity_type=entity_type, entity_id=entity_id)


@router.post("/budget-alerts/outbox/{alert_id}/ack")
def acknowledge_budget_alert(
    alert_id: str,
    request: BudgetAlertAcknowledgeRequest,
    authorization: str | None = Header(default=None, alias="Authorization"),
    infrastructure_assertion: str | None = Header(default=None, alias="X-Infrastructure-Assertion"),
    infrastructure_signature: str | None = Header(default=None, alias="X-Infrastructure-Signature"),
) -> dict[str, Any]:
    identity = _require_identity(authorization, ["budget:manage"], infrastructure_assertion, infrastructure_signature)
    require_trusted_infrastructure_identity_for_admin(identity)
    alert = _store.acknowledge_budget_alert(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Budget alert not found")
    _append_audit_entry(
        actor_type="admin",
        actor_id=identity.oauth_subject,
        action="budget_alert_acknowledge",
        request_path=f"/budget-alerts/outbox/{alert_id}/ack",
        request_payload_hash=hashlib.sha256(
            json.dumps(
                {
                    "alert_id": alert_id,
                    "reason": request.reason,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest(),
        request_payload_summary={"alert_id": alert_id},
        decision="acknowledged",
        decision_reason=request.reason,
        decision_details={"entity_type": alert["entity_type"], "entity_id": alert["entity_id"]},
        transaction_amount=None,
        transaction_currency=None,
        **audit_infrastructure_identity_fields(identity),
    )
    capture_infrastructure_identity_profile(
        store=_store,
        identity=identity,
        actor_type="admin",
        actor_id=identity.oauth_subject,
        event_type="admin_mutation",
        action="budget_alert_acknowledge",
        request_path=f"/budget-alerts/outbox/{alert_id}/ack",
    )
    return {"status": "acknowledged", "alert": alert}


@router.post("/budgets")
def upsert_budget(
    request: BudgetUpdateRequest,
    authorization: str | None = Header(default=None, alias="Authorization"),
    infrastructure_assertion: str | None = Header(default=None, alias="X-Infrastructure-Assertion"),
    infrastructure_signature: str | None = Header(default=None, alias="X-Infrastructure-Signature"),
) -> dict[str, Any]:
    identity = _require_identity(authorization, ["budget:manage"], infrastructure_assertion, infrastructure_signature)
    require_trusted_infrastructure_identity_for_admin(identity)
    budget_model = BudgetConfig(
        daily_cap=request.daily_cap,
        transaction_cap=request.transaction_cap,
        spent_today=request.spent_today,
    )
    budget = _store.upsert_budget(
        request.user_id,
        budget_model.daily_cap,
        budget_model.transaction_cap,
        budget_model.spent_today,
    )
    _append_audit_entry(
        actor_type="admin",
        actor_id=identity.oauth_subject,
        action="budget_upsert",
        request_path="/budgets",
        request_payload_hash=hashlib.sha256(
            json.dumps(
                {
                    "user_id": request.user_id,
                    "daily_cap": _decimal_to_text(budget_model.daily_cap),
                    "transaction_cap": _decimal_to_text(budget_model.transaction_cap),
                    "spent_today": _decimal_to_text(budget_model.spent_today),
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest(),
        request_payload_summary={"user_id": request.user_id},
        decision="updated",
        decision_reason=None,
        decision_details={"status": "updated"},
        transaction_amount=budget_model.transaction_cap,
        transaction_currency=None,
        **audit_infrastructure_identity_fields(identity),
    )
    capture_infrastructure_identity_profile(
        store=_store,
        identity=identity,
        actor_type="admin",
        actor_id=identity.oauth_subject,
        event_type="admin_mutation",
        action="budget_upsert",
        request_path="/budgets",
    )
    _store.enqueue_budget_alerts(
        entity_type="user",
        entity_id=request.user_id,
        budget=budget,
        thresholds=_get_budget_alert_thresholds() if _get_budget_alert_thresholds is not None else [],
        trigger_source="budget_upsert",
        trigger_details={
            "user_id": request.user_id,
            "daily_cap": _decimal_to_text(budget_model.daily_cap),
            "transaction_cap": _decimal_to_text(budget_model.transaction_cap),
            "spent_today": _decimal_to_text(budget_model.spent_today),
        },
    )
    return {"status": "updated", "user_id": request.user_id, "budget": _serialize_budget(budget)}


@router.post("/budgets/agents")
def upsert_agent_budget(
    request: AgentBudgetUpdateRequest,
    authorization: str | None = Header(default=None, alias="Authorization"),
    infrastructure_assertion: str | None = Header(default=None, alias="X-Infrastructure-Assertion"),
    infrastructure_signature: str | None = Header(default=None, alias="X-Infrastructure-Signature"),
) -> dict[str, Any]:
    identity = _require_identity(authorization, ["budget:manage"], infrastructure_assertion, infrastructure_signature)
    require_trusted_infrastructure_identity_for_admin(identity)
    budget_model = BudgetConfig(
        daily_cap=request.daily_cap,
        transaction_cap=request.transaction_cap,
        spent_today=request.spent_today,
    )
    budget = _store.upsert_agent_budget(
        request.agent_id,
        budget_model.daily_cap,
        budget_model.transaction_cap,
        budget_model.spent_today,
    )
    _append_audit_entry(
        actor_type="admin",
        actor_id=identity.oauth_subject,
        action="agent_budget_upsert",
        request_path="/budgets/agents",
        request_payload_hash=hashlib.sha256(
            json.dumps(
                {
                    "agent_id": request.agent_id,
                    "daily_cap": _decimal_to_text(budget_model.daily_cap),
                    "transaction_cap": _decimal_to_text(budget_model.transaction_cap),
                    "spent_today": _decimal_to_text(budget_model.spent_today),
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest(),
        request_payload_summary={"agent_id": request.agent_id},
        decision="updated",
        decision_reason=None,
        decision_details={"status": "updated"},
        transaction_amount=budget_model.transaction_cap,
        transaction_currency=None,
        **audit_infrastructure_identity_fields(identity),
    )
    capture_infrastructure_identity_profile(
        store=_store,
        identity=identity,
        actor_type="admin",
        actor_id=identity.oauth_subject,
        event_type="admin_mutation",
        action="agent_budget_upsert",
        request_path="/budgets/agents",
    )
    _store.enqueue_budget_alerts(
        entity_type="agent",
        entity_id=request.agent_id,
        budget=budget,
        thresholds=_get_budget_alert_thresholds() if _get_budget_alert_thresholds is not None else [],
        trigger_source="agent_budget_upsert",
        trigger_details={
            "agent_id": request.agent_id,
            "daily_cap": _decimal_to_text(budget_model.daily_cap),
            "transaction_cap": _decimal_to_text(budget_model.transaction_cap),
            "spent_today": _decimal_to_text(budget_model.spent_today),
        },
    )
    return {"status": "updated", "agent_id": request.agent_id, "budget": _serialize_budget(budget)}
