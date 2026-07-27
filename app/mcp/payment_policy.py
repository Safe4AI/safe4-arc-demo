from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any, Callable
from uuid import uuid4

from fastapi.responses import JSONResponse

from ..hitl_policy import enforce_mcp_hitl_policy


_store = None
_metrics = None
_append_audit_entry: Callable[..., None] | None = None
_error_payload: Callable[..., dict[str, Any]] | None = None
_hash_token: Callable[[str], str] | None = None
_normalize_money: Callable[[Decimal], Decimal] | None = None
_decimal_to_text: Callable[[Decimal], str] | None = None
_build_approval_payload: Callable[[Any], dict[str, Any]] | None = None
_payment_request_summary: Callable[..., dict[str, Any]] | None = None
_deny_payment: Callable[..., JSONResponse] | None = None
_hitl_approval_ttl_seconds = 0
_get_unknown_server_hitl_threshold: Callable[[], Decimal] | None = None


def _request_infrastructure_identity_fields(request: Any) -> dict[str, Any]:
    identity = getattr(request.state, "current_identity", None)
    infra = None if identity is None else getattr(identity, "infrastructure_identity", None)
    return {
        "infrastructure_provider_name": None if infra is None else infra.provider_name,
        "infrastructure_subject": None if infra is None else infra.subject,
        "infrastructure_trust_tier": None if infra is None else infra.trust_tier,
    }


def setup_mcp_payment_policy(
    *,
    store: Any,
    metrics: Any,
    append_audit_entry: Callable[..., None],
    error_payload: Callable[..., dict[str, Any]],
    hash_token: Callable[[str], str],
    normalize_money: Callable[[Decimal], Decimal],
    decimal_to_text: Callable[[Decimal], str],
    build_approval_payload: Callable[[Any], dict[str, Any]],
    payment_request_summary: Callable[..., dict[str, Any]],
    deny_payment: Callable[..., JSONResponse],
    hitl_approval_ttl_seconds: int,
    get_unknown_server_hitl_threshold: Callable[[], Decimal],
) -> None:
    global _store, _metrics, _append_audit_entry, _error_payload, _hash_token, _normalize_money
    global _decimal_to_text, _build_approval_payload, _payment_request_summary, _deny_payment
    global _hitl_approval_ttl_seconds, _get_unknown_server_hitl_threshold
    _store = store
    _metrics = metrics
    _append_audit_entry = append_audit_entry
    _error_payload = error_payload
    _hash_token = hash_token
    _normalize_money = normalize_money
    _decimal_to_text = decimal_to_text
    _build_approval_payload = build_approval_payload
    _payment_request_summary = payment_request_summary
    _deny_payment = deny_payment
    _hitl_approval_ttl_seconds = hitl_approval_ttl_seconds
    _get_unknown_server_hitl_threshold = get_unknown_server_hitl_threshold


def _create_hitl_approval(
    *,
    request: Any,
    payment: Any,
    request_hash: str,
    decision_reason: str,
    reason_code: str,
    triggered_by: str,
    mcp_server_id: str,
    mcp_tool_name: str | None,
) -> tuple[JSONResponse, str, str | None]:
    request_started_at = getattr(request.state, "started_at", None)
    approval_latency_ms = int((time.perf_counter() - request_started_at) * 1000) if isinstance(request_started_at, (int, float)) else None
    approval = _store.create_approval_request(
        approval_id=uuid4().hex,
        request_hash=request_hash,
        request_path="/pay",
        request_payload=_build_approval_payload(payment),
        triggered_by=triggered_by,
        requestor_agent_id=payment.agent_id,
        requestor_user_id=payment.user_id,
        mcp_tool_id=payment.mcp_tool_id,
        expires_at=(datetime.now(timezone.utc) + timedelta(seconds=_hitl_approval_ttl_seconds)).isoformat(),
    )
    _append_audit_entry(
        actor_type="agent",
        actor_id=payment.agent_id,
        action="approval_request",
        request_path="/pay",
        request_payload_hash=request_hash,
        request_payload_summary={"approval_id": approval["approval_id"], "mcp_tool_id": payment.mcp_tool_id},
        decision="pending",
        decision_reason=decision_reason,
        decision_details={
            "reason_code": reason_code,
            "approval_request_latency_ms": approval_latency_ms,
            "approval_ttl_seconds": _hitl_approval_ttl_seconds,
        },
        transaction_amount=payment.amount,
        transaction_currency=payment.currency,
        mcp_server_id=mcp_server_id,
        mcp_tool_id=payment.mcp_tool_id,
        mcp_tool_name=mcp_tool_name,
        **_request_infrastructure_identity_fields(request),
    )
    _metrics.increment("payment_hitl_required_total")
    return JSONResponse(
        status_code=202,
        content={
            "status": "PENDING_APPROVAL",
            "approval_id": approval["approval_id"],
            "message": "Human approval is required before this MCP payment can proceed.",
            "request_id": request.state.request_id,
        },
    ), mcp_server_id, mcp_tool_name


def enforce_mcp_payment_policy(
    *,
    request: Any,
    payment: Any,
    request_hash: str,
    amount_due: Decimal,
    started_at: float,
    idempotency_key: str | None,
    x_spend_token: str | None,
    receipt_id: str | None,
    receipt_source: str,
) -> tuple[JSONResponse | None, str | None, str | None]:
    if not payment.mcp_tool_id:
        return None, None, None

    tool = _store.get_mcp_tool(payment.mcp_tool_id)
    if tool is None:
        _metrics.increment("payment_denied_mcp_tool_missing_total")
        return JSONResponse(
            status_code=403,
            content=_error_payload(
                request,
                "MCP_TOOL_NOT_REGISTERED",
                "The referenced MCP tool is not registered.",
                {"tool_id": payment.mcp_tool_id},
            ),
        ), None, None

    mcp_server_id = tool["server_id"]
    mcp_tool_name = tool["tool_name"]

    if tool["quarantine_status"] != "clear":
        _metrics.increment("payment_denied_mcp_tool_quarantined_total")
        _append_audit_entry(
            actor_type="agent",
            actor_id=payment.agent_id,
            action="payment_authorize",
            request_path="/pay",
            request_payload_hash=request_hash,
            request_payload_summary=_payment_request_summary(payment, include_mcp=True),
            decision="denied",
            decision_reason="MCP tool is quarantined or blocked.",
            decision_details={"reason_code": "MCP_TOOL_QUARANTINED"},
            transaction_amount=payment.amount,
            transaction_currency=payment.currency,
            mcp_server_id=mcp_server_id,
            mcp_tool_id=payment.mcp_tool_id,
            mcp_tool_name=mcp_tool_name,
            **_request_infrastructure_identity_fields(request),
        )
        return JSONResponse(
            status_code=403,
            content=_error_payload(
                request,
                "MCP_TOOL_QUARANTINED",
                "The referenced MCP tool is quarantined or blocked.",
                {"tool_id": payment.mcp_tool_id, "quarantine_status": tool["quarantine_status"]},
            ),
        ), mcp_server_id, mcp_tool_name

    server = _store.get_mcp_server(tool["server_id"])
    if server is None:
        _metrics.increment("payment_denied_mcp_server_untrusted_total")
        return JSONResponse(
            status_code=403,
            content=_error_payload(
                request,
                "MCP_SERVER_NOT_TRUSTED",
                "The MCP server for this tool is not trusted for payment actions.",
                {"tool_id": payment.mcp_tool_id, "server_id": tool["server_id"]},
            ),
        ), mcp_server_id, mcp_tool_name
    if server["trust_level"] == "blocked":
        _metrics.increment("payment_denied_mcp_server_blocked_total")
        return JSONResponse(
            status_code=403,
            content=_error_payload(
                request,
                "MCP_SERVER_BLOCKED",
                "The MCP server for this tool is blocked for payment actions.",
                {"tool_id": payment.mcp_tool_id, "server_id": tool["server_id"]},
            ),
        ), mcp_server_id, mcp_tool_name

    permission = _store.get_mcp_tool_permission(payment.mcp_tool_id, payment.user_id)
    if permission is None or not permission["is_active"]:
        _metrics.increment("payment_denied_mcp_permission_missing_total")
        _append_audit_entry(
            actor_type="agent",
            actor_id=payment.agent_id,
            action="payment_authorize",
            request_path="/pay",
            request_payload_hash=request_hash,
            request_payload_summary=_payment_request_summary(payment, include_mcp=True),
            decision="denied",
            decision_reason="No MCP tool permission exists for this user and tool.",
            decision_details={"reason_code": "MCP_TOOL_PERMISSION_REQUIRED"},
            transaction_amount=payment.amount,
            transaction_currency=payment.currency,
            mcp_server_id=mcp_server_id,
            mcp_tool_id=payment.mcp_tool_id,
            mcp_tool_name=mcp_tool_name,
            **_request_infrastructure_identity_fields(request),
        )
        return JSONResponse(
            status_code=403,
            content=_error_payload(
                request,
                "MCP_TOOL_PERMISSION_REQUIRED",
                "This MCP tool is default-deny until a permission is granted.",
                {"tool_id": payment.mcp_tool_id, "user_id": payment.user_id},
            ),
        ), mcp_server_id, mcp_tool_name

    if payment.mcp_action not in permission["allowed_actions"]:
        _metrics.increment("payment_denied_mcp_action_not_allowed_total")
        return JSONResponse(
            status_code=403,
            content=_error_payload(
                request,
                "MCP_TOOL_ACTION_NOT_ALLOWED",
                "The requested MCP tool action is not allowed for this user.",
                {"tool_id": payment.mcp_tool_id, "mcp_action": payment.mcp_action},
            ),
        ), mcp_server_id, mcp_tool_name

    if permission["transaction_cap"] is not None and payment.amount > Decimal(permission["transaction_cap"]):
        _metrics.increment("payment_denied_mcp_permission_cap_total")
        return JSONResponse(
            status_code=403,
            content=_error_payload(
                request,
                "MCP_TOOL_TRANSACTION_CAP_EXCEEDED",
                "The requested amount exceeds the MCP tool permission transaction cap.",
                {"tool_id": payment.mcp_tool_id, "transaction_cap": permission["transaction_cap"]},
            ),
        ), mcp_server_id, mcp_tool_name

    if permission["daily_cap"] is not None:
        tool_spent_today = _store.get_mcp_tool_spent_today(payment.mcp_tool_id, payment.user_id, payment.currency)
        projected_tool_total = _normalize_money(tool_spent_today + payment.amount)
        if projected_tool_total > Decimal(permission["daily_cap"]):
            _metrics.increment("payment_denied_mcp_daily_cap_total")
            _append_audit_entry(
                actor_type="agent",
                actor_id=payment.agent_id,
                action="payment_authorize",
                request_path="/pay",
                request_payload_hash=request_hash,
                request_payload_summary=_payment_request_summary(payment, include_mcp=True),
                decision="denied",
                decision_reason="The requested amount exceeds the MCP tool permission daily cap.",
                decision_details={
                    "reason_code": "MCP_TOOL_DAILY_CAP_EXCEEDED",
                    "tool_spent_today": _decimal_to_text(tool_spent_today),
                    "projected_tool_total": _decimal_to_text(projected_tool_total),
                },
                transaction_amount=payment.amount,
                transaction_currency=payment.currency,
                mcp_server_id=mcp_server_id,
                mcp_tool_id=payment.mcp_tool_id,
                mcp_tool_name=mcp_tool_name,
                **_request_infrastructure_identity_fields(request),
            )
            return JSONResponse(
                status_code=403,
                content=_error_payload(
                    request,
                    "MCP_TOOL_DAILY_CAP_EXCEEDED",
                    "The requested amount exceeds the MCP tool permission daily cap.",
                    {
                        "tool_id": payment.mcp_tool_id,
                        "daily_cap": permission["daily_cap"],
                        "spent_today": _decimal_to_text(tool_spent_today),
                    },
                ),
            ), mcp_server_id, mcp_tool_name

    unknown_server_hitl_threshold = (
        _get_unknown_server_hitl_threshold() if _get_unknown_server_hitl_threshold is not None else Decimal("10.000000")
    )
    hitl_response = enforce_mcp_hitl_policy(
        request=request,
        payment=payment,
        request_hash=request_hash,
        amount_due=amount_due,
        started_at=started_at,
        idempotency_key=idempotency_key,
        x_spend_token=x_spend_token,
        receipt_id=receipt_id,
        receipt_source=receipt_source,
        mcp_server_id=mcp_server_id,
        mcp_tool_name=mcp_tool_name,
        mcp_server_trust_level=server["trust_level"],
        requires_permission_hitl=permission["requires_hitl"],
        requires_unknown_server_hitl=server["trust_level"] == "unknown" and payment.amount > unknown_server_hitl_threshold,
    )
    if hitl_response is not None:
        return hitl_response, mcp_server_id, mcp_tool_name

    return None, mcp_server_id, mcp_tool_name
