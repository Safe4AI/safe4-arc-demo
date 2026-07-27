from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Callable

from fastapi.responses import JSONResponse


_store = None
_metrics = None
_append_audit_entry: Callable[..., None] | None = None
_append_log: Callable[..., None] | None = None
_error_payload: Callable[..., dict[str, Any]] | None = None
_decimal_to_text: Callable[[Decimal], str] | None = None
_pay_to_address = ""
_fee_rate = None
_build_x402_challenge: Callable[..., dict[str, Any] | None] | None = None


def _request_infrastructure_identity_fields(request: Any) -> dict[str, Any]:
    identity = getattr(request.state, "current_identity", None)
    infra = None if identity is None else getattr(identity, "infrastructure_identity", None)
    return {
        "infrastructure_provider_name": None if infra is None else infra.provider_name,
        "infrastructure_subject": None if infra is None else infra.subject,
        "infrastructure_trust_tier": None if infra is None else infra.trust_tier,
    }


def setup_payment_flow(
    *,
    store: Any,
    metrics: Any,
    append_audit_entry: Callable[..., None],
    append_log: Callable[..., None],
    error_payload: Callable[..., dict[str, Any]],
    decimal_to_text: Callable[[Decimal], str],
    pay_to_address: str,
    fee_rate: Decimal,
    build_x402_challenge: Callable[..., dict[str, Any] | None],
) -> None:
    global _store, _metrics, _append_audit_entry, _append_log, _error_payload
    global _decimal_to_text, _pay_to_address, _fee_rate, _build_x402_challenge
    _store = store
    _metrics = metrics
    _append_audit_entry = append_audit_entry
    _append_log = append_log
    _error_payload = error_payload
    _decimal_to_text = decimal_to_text
    _pay_to_address = pay_to_address
    _fee_rate = fee_rate
    _build_x402_challenge = build_x402_challenge


def payment_request_summary(payment: Any, include_mcp: bool = False) -> dict[str, Any]:
    summary = {
        "user_id": payment.user_id,
        "vendor": payment.vendor,
        "currency": payment.currency,
    }
    if getattr(payment, "ap2_mandate", None) is not None:
        summary["ap2_mandate_id"] = payment.ap2_mandate.mandate_id
        summary["ap2_mandate_type"] = payment.ap2_mandate.mandate_type
    if include_mcp and payment.mcp_tool_id:
        summary["mcp_tool_id"] = payment.mcp_tool_id
    return summary


def save_idempotent_response(
    *,
    idempotency_key: str | None,
    request_hash: str,
    response: JSONResponse,
) -> JSONResponse:
    if idempotency_key:
        _store.save_idempotency(idempotency_key, request_hash, response.status_code, response.body.decode("utf-8"))
    return response


def deny_payment(
    *,
    request: Any,
    payment: Any,
    request_hash: str,
    amount_due: Decimal,
    started_at: float,
    idempotency_key: str | None,
    status_code: int,
    error_code: str,
    message: str,
    details: dict[str, Any] | None = None,
    metric_name: str | None = None,
    append_log_reason: str | None = None,
    mark_receipt_id: str | None = None,
    mark_receipt_source: str = "signed_receipt_fallback",
    audit_decision: str = "denied",
    audit_reason: str | None = None,
    audit_reason_code: str | None = None,
    mcp_server_id: str | None = None,
    mcp_tool_id: str | None = None,
    mcp_tool_name: str | None = None,
    include_mcp_in_summary: bool = False,
    transaction_id: str | None = None,
    extra_audit_details: dict[str, Any] | None = None,
) -> JSONResponse:
    if transaction_id is not None:
        request.state.transaction_id = transaction_id
    if metric_name:
        _metrics.increment(metric_name)
    if append_log_reason is not None:
        _append_log(request, payment, amount_due, "DENIED", append_log_reason, started_at, idempotency_key)
    if mark_receipt_id:
        if mark_receipt_source == "provider_receipt":
            _store.mark_x402_provider_receipt_used(mark_receipt_id)
        else:
            _store.mark_receipt_used(mark_receipt_id)
    if audit_reason is not None:
        decision_details = {"reason_code": audit_reason_code} if audit_reason_code else {}
        if extra_audit_details:
            decision_details.update(extra_audit_details)
        _append_audit_entry(
            actor_type="agent",
            actor_id=payment.agent_id,
            action="payment_authorize",
            request_path="/pay",
            request_payload_hash=request_hash,
            request_payload_summary=payment_request_summary(payment, include_mcp=include_mcp_in_summary),
            decision=audit_decision,
            decision_reason=audit_reason,
            decision_details=decision_details,
            transaction_id=transaction_id,
            transaction_amount=payment.amount,
            transaction_currency=payment.currency,
            mcp_server_id=mcp_server_id,
            mcp_tool_id=mcp_tool_id,
            mcp_tool_name=mcp_tool_name,
            **_request_infrastructure_identity_fields(request),
        )
    response = JSONResponse(
        status_code=status_code,
        content=_error_payload(request, error_code, message, details),
    )
    return save_idempotent_response(idempotency_key=idempotency_key, request_hash=request_hash, response=response)


def payment_required_response(
    *,
    request: Any,
    payment: Any,
    request_hash: str,
    amount_due: Decimal,
    idempotency_key: str | None,
) -> JSONResponse:
    _metrics.increment("payment_required_total")
    body = _error_payload(
        request,
        "PAYMENT_REQUIRED",
        "Micropayment required before authorization can proceed.",
        {
            "how_it_works": (
                "Retry the same request with a valid X-Payment-Receipt header "
                "after paying the firewall fee."
            ),
            "pay_to": _pay_to_address,
            "amount_due": _decimal_to_text(amount_due),
            "currency": payment.currency,
            "fee_rate": _decimal_to_text(_fee_rate),
            "receipt_issue_endpoint": "/receipts/issue",
        },
    )
    x402_challenge = _build_x402_challenge(payment=payment, amount_due=amount_due) if _build_x402_challenge is not None else None
    if x402_challenge is not None:
        body["details"]["x402_challenge"] = x402_challenge
    response = JSONResponse(
        status_code=402,
        content=body,
        headers={
            "X-Payment-Required": "true",
            "X-Pay-To": _pay_to_address,
            "X-Amount-Due": _decimal_to_text(amount_due),
        },
    )
    _append_audit_entry(
        actor_type="agent",
        actor_id=payment.agent_id,
        action="payment_authorize",
        request_path="/pay",
        request_payload_hash=request_hash,
        request_payload_summary=payment_request_summary(payment),
        decision="payment_required",
        decision_reason="Micropayment required before authorization can proceed.",
        decision_details={"amount_due": _decimal_to_text(amount_due)},
        transaction_amount=payment.amount,
        transaction_currency=payment.currency,
        **_request_infrastructure_identity_fields(request),
    )
    return save_idempotent_response(idempotency_key=idempotency_key, request_hash=request_hash, response=response)


def receipt_expired(expires_at: str) -> bool:
    return datetime.fromisoformat(expires_at) <= datetime.now(timezone.utc)
