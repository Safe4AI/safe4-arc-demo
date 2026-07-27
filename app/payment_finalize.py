from __future__ import annotations

import time
from uuid import uuid4
from typing import Any, Callable

from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse

from .anomaly_api import (
    anomaly_severity_meets_threshold,
    build_infrastructure_identity_anomaly_inputs,
    compute_infrastructure_identity_anomaly,
)
from .audit_api import build_siem_audit_anomaly_export
from .auth import assess_infrastructure_identity_posture, capture_infrastructure_identity_profile
from .payment_flow import payment_request_summary


_store = None
_metrics = None
_append_log: Callable[..., None] | None = None
_append_audit_entry: Callable[..., None] | None = None
_serialize_budget: Callable[[dict[str, Any]], dict[str, str]] | None = None
_get_budget_alert_thresholds: Callable[[], list[Any]] | None = None
_get_infrastructure_identity_anomaly_alert_min_severity: Callable[[], str] | None = None


def _request_infrastructure_identity_fields(request: Any) -> dict[str, Any]:
    identity = getattr(request.state, "current_identity", None)
    infra = None if identity is None else getattr(identity, "infrastructure_identity", None)
    return {
        "infrastructure_provider_name": None if infra is None else infra.provider_name,
        "infrastructure_subject": None if infra is None else infra.subject,
        "infrastructure_trust_tier": None if infra is None else infra.trust_tier,
    }


def _request_identity(request: Any) -> Any:
    return getattr(request.state, "current_identity", None)


def setup_payment_finalize(
    *,
    store: Any,
    metrics: Any,
    append_log: Callable[..., None],
    append_audit_entry: Callable[..., None],
    serialize_budget: Callable[[dict[str, Any]], dict[str, str]],
    get_budget_alert_thresholds: Callable[[], list[Any]],
    get_infrastructure_identity_anomaly_alert_min_severity: Callable[[], str],
) -> None:
    global _store, _metrics, _append_log, _append_audit_entry, _serialize_budget, _get_budget_alert_thresholds
    global _get_infrastructure_identity_anomaly_alert_min_severity
    _store = store
    _metrics = metrics
    _append_log = append_log
    _append_audit_entry = append_audit_entry
    _serialize_budget = serialize_budget
    _get_budget_alert_thresholds = get_budget_alert_thresholds
    _get_infrastructure_identity_anomaly_alert_min_severity = get_infrastructure_identity_anomaly_alert_min_severity


def _should_alert_on_anomaly(severity: str) -> bool:
    threshold = (
        "high"
        if _get_infrastructure_identity_anomaly_alert_min_severity is None
        else _get_infrastructure_identity_anomaly_alert_min_severity()
    )
    return anomaly_severity_meets_threshold(severity=severity, threshold=threshold)


def finalize_authorized_payment(
    *,
    request: Any,
    payment: Any,
    request_hash: str,
    amount_due: Any,
    started_at: float,
    idempotency_key: str | None,
    receipt_id: str | None,
    receipt_source: str,
    projected_total: Any,
    projected_agent_total: Any,
    mcp_server_id: str | None,
    mcp_tool_name: str | None,
) -> JSONResponse:
    finalize_started_at = time.perf_counter()
    transaction_id = uuid4().hex
    request.state.transaction_id = transaction_id
    identity = _request_identity(request)
    infra = None if identity is None else identity.infrastructure_identity
    posture = assess_infrastructure_identity_posture(identity)["posture"]
    anomaly_inputs = build_infrastructure_identity_anomaly_inputs(
        store=_store,
        actor_id=payment.agent_id,
        user_id=payment.user_id,
        vendor=payment.vendor,
        provider_name=None if infra is None else infra.provider_name,
        subject=None if infra is None else infra.subject,
        posture=posture,
        transaction_currency=payment.currency,
    )
    anomaly = compute_infrastructure_identity_anomaly(
        baseline_profile=anomaly_inputs["baseline_profile"],
        posture=posture,
        observed_amount=payment.amount,
        baseline_context_event_count=anomaly_inputs["baseline_context_event_count"],
        currency_history_count=anomaly_inputs["currency_history_count"],
        vendor_history_count=anomaly_inputs["vendor_history_count"],
        agent_user_history_count=anomaly_inputs["agent_user_history_count"],
    )
    budget = _store.update_spent_today(payment.user_id, projected_total)
    agent_budget = _store.update_agent_spent_today(payment.agent_id, projected_agent_total)
    budget_alert_thresholds = _get_budget_alert_thresholds() if _get_budget_alert_thresholds is not None else []
    _store.record_transaction_event(transaction_id, payment.agent_id, payment.user_id)
    if payment.mcp_tool_id:
        _store.record_mcp_tool_usage(payment.mcp_tool_id, payment.user_id, payment.amount, payment.currency)
    _store.enqueue_budget_alerts(
        entity_type="user",
        entity_id=payment.user_id,
        budget=budget,
        thresholds=budget_alert_thresholds,
        trigger_source="payment_authorized",
        trigger_details={
            "agent_id": payment.agent_id,
            "user_id": payment.user_id,
            "vendor": payment.vendor,
            "amount": str(payment.amount),
            "currency": payment.currency,
            "request_id": request.state.request_id,
            "transaction_id": transaction_id,
        },
    )
    _store.enqueue_budget_alerts(
        entity_type="agent",
        entity_id=payment.agent_id,
        budget=agent_budget,
        thresholds=budget_alert_thresholds,
        trigger_source="payment_authorized",
        trigger_details={
            "agent_id": payment.agent_id,
            "user_id": payment.user_id,
            "vendor": payment.vendor,
            "amount": str(payment.amount),
            "currency": payment.currency,
            "request_id": request.state.request_id,
            "transaction_id": transaction_id,
        },
    )
    if receipt_source == "provider_receipt":
        _store.mark_x402_provider_receipt_used(receipt_id or "")
    else:
        _store.mark_receipt_used(receipt_id or "")
    _append_log(request, payment, amount_due, "AUTHORIZED", None, started_at, idempotency_key)
    _append_audit_entry(
        actor_type="agent",
        actor_id=payment.agent_id,
        action="payment_authorize",
        request_path="/pay",
        request_payload_hash=request_hash,
        request_payload_summary=payment_request_summary(payment, include_mcp=bool(payment.mcp_tool_id)),
        decision="authorized",
        decision_reason=None,
        decision_details={
            "status": "AUTHORIZED",
            "receipt_id": receipt_id,
            "receipt_source": receipt_source,
            "total_decision_latency_ms": int((time.perf_counter() - started_at) * 1000),
            "finalization_latency_ms": int((time.perf_counter() - finalize_started_at) * 1000),
        },
        transaction_id=transaction_id,
        transaction_amount=payment.amount,
        transaction_currency=payment.currency,
        mcp_server_id=mcp_server_id,
        mcp_tool_id=payment.mcp_tool_id,
        mcp_tool_name=mcp_tool_name,
        **_request_infrastructure_identity_fields(request),
    )
    capture_infrastructure_identity_profile(
        store=_store,
        identity=identity,
        actor_type="agent",
        actor_id=payment.agent_id,
        event_type="payment",
        action="payment_authorize",
        transaction_amount=payment.amount,
        transaction_currency=payment.currency,
        transaction_id=transaction_id,
        request_path="/pay",
    )
    _store.record_infrastructure_identity_anomaly(
        anomaly_id=anomaly["anomaly_id"],
        transaction_id=transaction_id,
        actor_type="agent",
        actor_id=payment.agent_id,
        provider_name=None if infra is None else infra.provider_name,
        subject=None if infra is None else infra.subject,
        posture=posture,
        severity=anomaly["severity"],
        score=anomaly["score"],
        baseline_event_count=anomaly["baseline_event_count"],
        baseline_average_amount=anomaly["baseline_average_amount"],
        observed_amount=anomaly["observed_amount"],
        transaction_currency=payment.currency,
        reason_codes=anomaly["reason_codes"],
        feature_details=anomaly["feature_details"],
        request_path="/pay",
    )
    anomaly_alert = None
    if _should_alert_on_anomaly(anomaly["severity"]):
        anomaly_alert = _store.enqueue_infrastructure_identity_anomaly_alert(
            anomaly_id=anomaly["anomaly_id"],
            transaction_id=transaction_id,
            actor_id=payment.agent_id,
            provider_name=None if infra is None else infra.provider_name,
            subject=None if infra is None else infra.subject,
            posture=posture,
            severity=anomaly["severity"],
            score=anomaly["score"],
            summary=f"Infrastructure identity payment anomaly detected for agent {payment.agent_id}",
            details={
                "transaction_id": transaction_id,
                "user_id": payment.user_id,
                "vendor": payment.vendor,
                "currency": payment.currency,
                "reason_codes": anomaly["reason_codes"],
                "baseline_event_count": anomaly["baseline_event_count"],
                "baseline_average_amount": None
                if anomaly["baseline_average_amount"] is None
                else format(anomaly["baseline_average_amount"], "f"),
                "observed_amount": format(anomaly["observed_amount"], "f"),
                "feature_details": anomaly["feature_details"],
            },
            event_key=f"infrastructure_anomaly:{anomaly['anomaly_id']}",
        )
    _append_audit_entry(
        actor_type="agent",
        actor_id=payment.agent_id,
        action="payment_anomaly_score",
        request_path="/pay",
        request_payload_hash=request_hash,
        request_payload_summary=payment_request_summary(payment, include_mcp=bool(payment.mcp_tool_id))
        | {"transaction_id": transaction_id},
        decision=anomaly["severity"],
        decision_reason=", ".join(anomaly["reason_codes"]) if anomaly["reason_codes"] else None,
        decision_details={
            "anomaly_id": anomaly["anomaly_id"],
            "score": format(anomaly["score"], "f"),
            "baseline_event_count": anomaly["baseline_event_count"],
            "baseline_average_amount": None
            if anomaly["baseline_average_amount"] is None
            else format(anomaly["baseline_average_amount"], "f"),
            "observed_amount": format(anomaly["observed_amount"], "f"),
            "reason_codes": anomaly["reason_codes"],
            "feature_details": anomaly["feature_details"],
        },
        transaction_id=transaction_id,
        transaction_amount=payment.amount,
        transaction_currency=payment.currency,
        mcp_server_id=mcp_server_id,
        mcp_tool_id=payment.mcp_tool_id,
        mcp_tool_name=mcp_tool_name,
        **_request_infrastructure_identity_fields(request),
    )
    if anomaly_alert is not None:
        anomaly_record = _store.get_infrastructure_identity_anomaly(anomaly["anomaly_id"])
        audit_entries = [item for item in _store.list_audit_entries() if item.get("transaction_id") == transaction_id]
        if anomaly_record is not None:
            _store.enqueue_siem_export(
                export_type="audit_anomaly_bundle",
                transaction_id=transaction_id,
                anomaly_id=anomaly_record["anomaly_id"],
                anomaly_alert_id=anomaly_alert["alert_id"],
                actor_id=payment.agent_id,
                provider_name=None if infra is None else infra.provider_name,
                subject=None if infra is None else infra.subject,
                severity=anomaly_record["severity"],
                summary=f"SIEM export queued for anomalous payment transaction {transaction_id}",
                payload=build_siem_audit_anomaly_export(
                    audit_entries=audit_entries,
                    anomaly=anomaly_record,
                    anomaly_alert=anomaly_alert,
                ),
                event_key=f"siem_audit_anomaly_export:{anomaly_record['anomaly_id']}",
            )
    _metrics.increment("payment_authorized_total")
    body = jsonable_encoder(
        {
            "status": "AUTHORIZED",
            "transaction_id": transaction_id,
            "message": "Payment request approved by the firewall.",
            "request_id": request.state.request_id,
            "firewall_fee_charged": amount_due,
            "budget_snapshot": _serialize_budget(budget),
            "agent_budget_snapshot": _serialize_budget(agent_budget),
        }
    )
    response = JSONResponse(status_code=200, content=body)
    if idempotency_key:
        _store.save_idempotency(idempotency_key, request_hash, response.status_code, body)
    return response
