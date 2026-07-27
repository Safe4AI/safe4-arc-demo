from __future__ import annotations

import re
import time
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any, Callable
from uuid import uuid4

from fastapi.responses import JSONResponse

from .audit_api import build_siem_audit_anomaly_export
from .anomaly_api import (
    anomaly_severity_meets_threshold,
    build_infrastructure_identity_anomaly_inputs,
    compute_infrastructure_identity_anomaly,
)
from .auth import assess_infrastructure_identity_posture


_store = None
_metrics = None
_append_audit_entry: Callable[..., None] | None = None
_error_payload: Callable[..., dict[str, Any]] | None = None
_deny_payment: Callable[..., JSONResponse] | None = None
_hash_token: Callable[[str], str] | None = None
_build_approval_payload: Callable[[Any], dict[str, Any]] | None = None
_payment_request_summary: Callable[..., dict[str, Any]] | None = None
_get_hitl_approval_ttl_seconds: Callable[[], int] | None = None
_get_runtime_infrastructure_identity_policy: Callable[[], dict[str, Any]] | None = None
_get_runtime_infrastructure_identity_anomaly_hitl_min_severity: Callable[[], str] | None = None
_get_runtime_infrastructure_identity_anomaly_deny_min_severity: Callable[[], str] | None = None


def setup_hitl_policy(
    *,
    store: Any,
    metrics: Any,
    append_audit_entry: Callable[..., None],
    error_payload: Callable[..., dict[str, Any]],
    deny_payment: Callable[..., JSONResponse],
    hash_token: Callable[[str], str],
    build_approval_payload: Callable[[Any], dict[str, Any]],
    payment_request_summary: Callable[..., dict[str, Any]],
    get_hitl_approval_ttl_seconds: Callable[[], int],
    get_runtime_infrastructure_identity_policy: Callable[[], dict[str, Any]],
    get_runtime_infrastructure_identity_anomaly_hitl_min_severity: Callable[[], str],
    get_runtime_infrastructure_identity_anomaly_deny_min_severity: Callable[[], str],
) -> None:
    global _store, _metrics, _append_audit_entry, _error_payload, _deny_payment, _hash_token
    global _build_approval_payload, _payment_request_summary, _get_hitl_approval_ttl_seconds
    global _get_runtime_infrastructure_identity_policy, _get_runtime_infrastructure_identity_anomaly_hitl_min_severity
    global _get_runtime_infrastructure_identity_anomaly_deny_min_severity
    _store = store
    _metrics = metrics
    _append_audit_entry = append_audit_entry
    _error_payload = error_payload
    _deny_payment = deny_payment
    _hash_token = hash_token
    _build_approval_payload = build_approval_payload
    _payment_request_summary = payment_request_summary
    _get_hitl_approval_ttl_seconds = get_hitl_approval_ttl_seconds
    _get_runtime_infrastructure_identity_policy = get_runtime_infrastructure_identity_policy
    _get_runtime_infrastructure_identity_anomaly_hitl_min_severity = get_runtime_infrastructure_identity_anomaly_hitl_min_severity
    _get_runtime_infrastructure_identity_anomaly_deny_min_severity = get_runtime_infrastructure_identity_anomaly_deny_min_severity


def _request_infrastructure_identity_fields(request: Any) -> dict[str, Any]:
    identity = getattr(request.state, "current_identity", None)
    infra = None if identity is None else getattr(identity, "infrastructure_identity", None)
    return {
        "infrastructure_provider_name": None if infra is None else infra.provider_name,
        "infrastructure_subject": None if infra is None else infra.subject,
        "infrastructure_trust_tier": None if infra is None else infra.trust_tier,
    }


def _infrastructure_identity_trigger(request: Any, payment: Any) -> dict[str, Any] | None:
    identity = getattr(request.state, "current_identity", None)
    policy = {} if _get_runtime_infrastructure_identity_policy is None else _get_runtime_infrastructure_identity_policy()
    if not policy or not policy.get("enabled", False):
        return None
    posture = assess_infrastructure_identity_posture(identity)
    threshold = policy.get("trusted_workload_max_amount") if posture["is_trusted_workload"] else policy.get("oauth_only_max_amount")
    if threshold is None or payment.amount <= threshold:
        return None

    return {
        "reason_code": "INFRASTRUCTURE_IDENTITY_POLICY_HITL_REQUIRED",
        "triggered_by": "infrastructure_identity_policy",
        "decision_reason": "Human approval required by infrastructure identity policy.",
        "approval_message": "Human approval is required before this payment can proceed.",
        "posture": posture["posture"],
        "threshold_amount": str(threshold),
        "matched_environment": posture["environment"],
        "matched_namespace": posture["namespace"],
        "matched_service_account": posture["service_account"],
        "matched_trust_tier": posture["trust_tier"],
    }


def _format_anomaly_decimal(value: Decimal | None) -> str | None:
    if value is None:
        return None
    return format(value, "f")


def _current_anomaly_hitl_threshold() -> str:
    if _get_runtime_infrastructure_identity_anomaly_hitl_min_severity is None:
        return "disabled"
    return _get_runtime_infrastructure_identity_anomaly_hitl_min_severity()


def _current_anomaly_deny_threshold() -> str:
    if _get_runtime_infrastructure_identity_anomaly_deny_min_severity is None:
        return "disabled"
    return _get_runtime_infrastructure_identity_anomaly_deny_min_severity()


def _compute_infrastructure_identity_anomaly_context(request: Any, payment: Any) -> dict[str, Any] | None:
    if _current_anomaly_hitl_threshold() == "disabled" and _current_anomaly_deny_threshold() == "disabled":
        return None

    identity = getattr(request.state, "current_identity", None)
    posture = assess_infrastructure_identity_posture(identity)["posture"]
    if posture == "disabled":
        return None

    infra = None if identity is None else getattr(identity, "infrastructure_identity", None)
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

    return {
        "anomaly_id": anomaly["anomaly_id"],
        "severity": anomaly["severity"],
        "score": format(anomaly["score"], "f"),
        "score_value": anomaly["score"],
        "baseline_event_count": anomaly["baseline_event_count"],
        "baseline_average_amount": _format_anomaly_decimal(anomaly["baseline_average_amount"]),
        "baseline_average_amount_value": anomaly["baseline_average_amount"],
        "observed_amount": format(anomaly["observed_amount"], "f"),
        "observed_amount_value": anomaly["observed_amount"],
        "reason_codes": anomaly["reason_codes"],
        "feature_details": anomaly["feature_details"],
        "posture": posture,
        "provider_name": None if infra is None else infra.provider_name,
        "subject": None if infra is None else infra.subject,
    }


def _infrastructure_identity_anomaly_hitl_trigger(anomaly_context: dict[str, Any] | None) -> dict[str, Any] | None:
    threshold = _current_anomaly_hitl_threshold()
    if anomaly_context is None or not anomaly_severity_meets_threshold(severity=anomaly_context["severity"], threshold=threshold):
        return None

    return {
        "reason_code": "INFRASTRUCTURE_IDENTITY_ANOMALY_HITL_REQUIRED",
        "triggered_by": "infrastructure_identity_anomaly_policy",
        "decision_reason": "Human approval required by infrastructure identity anomaly policy.",
        "approval_message": "Human approval is required because this payment exceeded the configured anomaly threshold.",
        "severity": anomaly_context["severity"],
        "score": anomaly_context["score"],
        "baseline_event_count": anomaly_context["baseline_event_count"],
        "baseline_average_amount": anomaly_context["baseline_average_amount"],
        "observed_amount": anomaly_context["observed_amount"],
        "reason_codes": anomaly_context["reason_codes"],
        "feature_details": anomaly_context["feature_details"],
        "threshold_severity": threshold,
        "posture": anomaly_context["posture"],
    }


def _anomaly_decision_details(anomaly_context: dict[str, Any], *, threshold_severity: str) -> dict[str, Any]:
    return {
        "anomaly_id": anomaly_context["anomaly_id"],
        "anomaly_severity": anomaly_context["severity"],
        "anomaly_score": anomaly_context["score"],
        "anomaly_threshold_severity": threshold_severity,
        "baseline_event_count": anomaly_context["baseline_event_count"],
        "baseline_average_amount": anomaly_context["baseline_average_amount"],
        "observed_amount": anomaly_context["observed_amount"],
        "reason_codes": anomaly_context["reason_codes"],
        "feature_details": anomaly_context["feature_details"],
        "posture": anomaly_context["posture"],
    }


def _build_infrastructure_identity_trace_details(
    *,
    request: Any,
    payment: Any,
    anomaly_context: dict[str, Any] | None,
) -> dict[str, Any] | None:
    policy = {} if _get_runtime_infrastructure_identity_policy is None else _get_runtime_infrastructure_identity_policy()
    posture = assess_infrastructure_identity_posture(getattr(request.state, "current_identity", None))
    policy_enabled = bool(policy and policy.get("enabled", False))
    anomaly_hitl_threshold = _current_anomaly_hitl_threshold()
    anomaly_deny_threshold = _current_anomaly_deny_threshold()
    if (
        not policy_enabled
        and posture["posture"] == "disabled"
        and anomaly_context is None
        and anomaly_hitl_threshold == "disabled"
        and anomaly_deny_threshold == "disabled"
    ):
        return None

    threshold = policy.get("trusted_workload_max_amount") if posture["is_trusted_workload"] else policy.get("oauth_only_max_amount")
    details: dict[str, Any] = {
        "policy_enabled": policy_enabled,
        "posture": posture["posture"],
        "is_trusted_workload": posture["is_trusted_workload"],
        "threshold_amount": None if threshold is None else format(threshold, "f"),
        "environment": posture["environment"],
        "namespace": posture["namespace"],
        "service_account": posture["service_account"],
        "trust_tier": posture["trust_tier"],
        "anomaly_hitl_threshold": anomaly_hitl_threshold,
        "anomaly_deny_threshold": anomaly_deny_threshold,
    }
    if anomaly_context is not None:
        details.update(
            {
                "anomaly_id": anomaly_context["anomaly_id"],
                "anomaly_severity": anomaly_context["severity"],
                "anomaly_score": anomaly_context["score"],
                "baseline_event_count": anomaly_context["baseline_event_count"],
                "baseline_average_amount": anomaly_context["baseline_average_amount"],
                "observed_amount": anomaly_context["observed_amount"],
                "reason_codes": anomaly_context["reason_codes"],
                "feature_details": anomaly_context["feature_details"],
            }
        )
    return details


def _append_infrastructure_identity_evaluation_audit_entry(
    *,
    request: Any,
    payment: Any,
    request_hash: str,
    mcp_server_id: str | None,
    mcp_tool_name: str | None,
    decision: str,
    reason_code: str,
    decision_reason: str | None,
    anomaly_context: dict[str, Any] | None = None,
    transaction_id: str | None = None,
    extra_decision_details: dict[str, Any] | None = None,
) -> None:
    trace_details = _build_infrastructure_identity_trace_details(
        request=request,
        payment=payment,
        anomaly_context=anomaly_context,
    )
    if trace_details is None:
        return
    request_started_at = getattr(request.state, "started_at", None)
    if isinstance(request_started_at, (int, float)):
        trace_details["evaluation_latency_ms"] = int((time.perf_counter() - request_started_at) * 1000)
    trace_details["reason_code"] = reason_code
    if extra_decision_details:
        trace_details.update(extra_decision_details)
    _append_audit_entry(
        actor_type="agent",
        actor_id=payment.agent_id,
        action="infrastructure_identity_evaluate",
        request_path="/pay",
        request_payload_hash=request_hash,
        request_payload_summary=_payment_request_summary(payment, include_mcp=bool(payment.mcp_tool_id)),
        decision=decision,
        decision_reason=decision_reason,
        decision_details=trace_details,
        transaction_id=transaction_id,
        transaction_amount=payment.amount,
        transaction_currency=payment.currency,
        mcp_server_id=mcp_server_id,
        mcp_tool_id=payment.mcp_tool_id,
        mcp_tool_name=mcp_tool_name,
        **_request_infrastructure_identity_fields(request),
    )


def _append_anomaly_score_audit_entry(
    *,
    request: Any,
    payment: Any,
    request_hash: str,
    transaction_id: str,
    anomaly_context: dict[str, Any],
    mcp_server_id: str | None,
    mcp_tool_name: str | None,
    payment_decision: str,
    payment_reason_code: str,
) -> None:
    _append_audit_entry(
        actor_type="agent",
        actor_id=payment.agent_id,
        action="payment_anomaly_score",
        request_path="/pay",
        request_payload_hash=request_hash,
        request_payload_summary=_payment_request_summary(payment, include_mcp=bool(payment.mcp_tool_id))
        | {"transaction_id": transaction_id},
        decision=anomaly_context["severity"],
        decision_reason=", ".join(anomaly_context["reason_codes"]) if anomaly_context["reason_codes"] else None,
        decision_details={
            "anomaly_id": anomaly_context["anomaly_id"],
            "score": anomaly_context["score"],
            "baseline_event_count": anomaly_context["baseline_event_count"],
            "baseline_average_amount": anomaly_context["baseline_average_amount"],
            "observed_amount": anomaly_context["observed_amount"],
            "reason_codes": anomaly_context["reason_codes"],
            "feature_details": anomaly_context["feature_details"],
            "payment_decision": payment_decision,
            "payment_reason_code": payment_reason_code,
        },
        transaction_id=transaction_id,
        transaction_amount=payment.amount,
        transaction_currency=payment.currency,
        mcp_server_id=mcp_server_id,
        mcp_tool_id=payment.mcp_tool_id,
        mcp_tool_name=mcp_tool_name,
        **_request_infrastructure_identity_fields(request),
    )


def _enqueue_denied_anomaly_followups(
    *,
    transaction_id: str,
    payment: Any,
    anomaly_record: dict[str, Any],
) -> None:
    anomaly_alert = _store.enqueue_infrastructure_identity_anomaly_alert(
        anomaly_id=anomaly_record["anomaly_id"],
        transaction_id=transaction_id,
        actor_id=payment.agent_id,
        provider_name=anomaly_record["provider_name"],
        subject=anomaly_record["subject"],
        posture=anomaly_record["posture"],
        severity=anomaly_record["severity"],
        score=anomaly_record["score"],
        summary=f"Infrastructure identity anomalous payment denied for agent {payment.agent_id}",
        details={
            "transaction_id": transaction_id,
            "user_id": payment.user_id,
            "vendor": payment.vendor,
            "currency": payment.currency,
            "reason_codes": anomaly_record["reason_codes"],
            "baseline_event_count": anomaly_record["baseline_event_count"],
            "baseline_average_amount": _format_anomaly_decimal(anomaly_record["baseline_average_amount"]),
            "observed_amount": _format_anomaly_decimal(anomaly_record["observed_amount"]),
            "feature_details": anomaly_record["feature_details"],
            "payment_decision": "denied",
            "payment_reason_code": "INFRASTRUCTURE_IDENTITY_ANOMALY_DENIED",
        },
        event_key=f"infrastructure_anomaly:{anomaly_record['anomaly_id']}",
    )
    audit_entries = [item for item in _store.list_audit_entries() if item.get("transaction_id") == transaction_id]
    _store.enqueue_siem_export(
        export_type="audit_anomaly_bundle",
        transaction_id=transaction_id,
        anomaly_id=anomaly_record["anomaly_id"],
        anomaly_alert_id=None if anomaly_alert is None else anomaly_alert["alert_id"],
        actor_id=payment.agent_id,
        provider_name=anomaly_record["provider_name"],
        subject=anomaly_record["subject"],
        severity=anomaly_record["severity"],
        summary=f"SIEM export queued for anomaly-denied payment transaction {transaction_id}",
        payload=build_siem_audit_anomaly_export(
            audit_entries=audit_entries,
            anomaly=anomaly_record,
            anomaly_alert=anomaly_alert,
        ),
        event_key=f"siem_audit_anomaly_export:{anomaly_record['anomaly_id']}",
    )


def _deny_for_infrastructure_identity_anomaly(
    *,
    request: Any,
    payment: Any,
    request_hash: str,
    amount_due: Decimal,
    started_at: float,
    idempotency_key: str | None,
    receipt_id: str | None,
    receipt_source: str,
    mcp_server_id: str | None,
    mcp_tool_name: str | None,
    anomaly_context: dict[str, Any],
) -> JSONResponse:
    transaction_id = uuid4().hex
    _append_infrastructure_identity_evaluation_audit_entry(
        request=request,
        payment=payment,
        request_hash=request_hash,
        mcp_server_id=mcp_server_id,
        mcp_tool_name=mcp_tool_name,
        decision="denied",
        reason_code="INFRASTRUCTURE_IDENTITY_ANOMALY_DENIED",
        decision_reason="Payment denied by the infrastructure identity anomaly policy.",
        anomaly_context=anomaly_context,
        transaction_id=transaction_id,
        extra_decision_details={
            "anomaly_threshold_severity": _current_anomaly_deny_threshold(),
        },
    )
    anomaly_record = _store.record_infrastructure_identity_anomaly(
        anomaly_id=anomaly_context["anomaly_id"],
        transaction_id=transaction_id,
        actor_type="agent",
        actor_id=payment.agent_id,
        provider_name=anomaly_context["provider_name"],
        subject=anomaly_context["subject"],
        posture=anomaly_context["posture"],
        severity=anomaly_context["severity"],
        score=anomaly_context["score_value"],
        baseline_event_count=anomaly_context["baseline_event_count"],
        baseline_average_amount=anomaly_context["baseline_average_amount_value"],
        observed_amount=anomaly_context["observed_amount_value"],
        transaction_currency=payment.currency,
        reason_codes=anomaly_context["reason_codes"],
        feature_details=anomaly_context["feature_details"],
        request_path="/pay",
    )
    _append_anomaly_score_audit_entry(
        request=request,
        payment=payment,
        request_hash=request_hash,
        transaction_id=transaction_id,
        anomaly_context=anomaly_context,
        mcp_server_id=mcp_server_id,
        mcp_tool_name=mcp_tool_name,
        payment_decision="denied",
        payment_reason_code="INFRASTRUCTURE_IDENTITY_ANOMALY_DENIED",
    )
    response = _deny_payment(
        request=request,
        payment=payment,
        request_hash=request_hash,
        amount_due=amount_due,
        started_at=started_at,
        idempotency_key=idempotency_key,
        status_code=403,
        error_code="INFRASTRUCTURE_IDENTITY_ANOMALY_DENIED",
        message="Payment denied by the infrastructure identity anomaly policy.",
        details={
            "transaction_id": transaction_id,
            "anomaly_id": anomaly_context["anomaly_id"],
            "anomaly_severity": anomaly_context["severity"],
            "anomaly_threshold_severity": _current_anomaly_deny_threshold(),
            "anomaly_score": anomaly_context["score"],
            "reason_codes": anomaly_context["reason_codes"],
            "feature_details": anomaly_context["feature_details"],
            "posture": anomaly_context["posture"],
        },
        metric_name="payment_denied_infrastructure_identity_anomaly_total",
        append_log_reason="Payment denied by infrastructure identity anomaly policy.",
        mark_receipt_id=receipt_id or "",
        mark_receipt_source=receipt_source,
        audit_reason="Payment denied by infrastructure identity anomaly policy.",
        audit_reason_code="INFRASTRUCTURE_IDENTITY_ANOMALY_DENIED",
        mcp_server_id=mcp_server_id,
        mcp_tool_id=payment.mcp_tool_id,
        mcp_tool_name=mcp_tool_name,
        include_mcp_in_summary=bool(payment.mcp_tool_id),
        transaction_id=transaction_id,
        extra_audit_details=_anomaly_decision_details(
            anomaly_context,
            threshold_severity=_current_anomaly_deny_threshold(),
        ),
    )
    _enqueue_denied_anomaly_followups(
        transaction_id=transaction_id,
        payment=payment,
        anomaly_record=anomaly_record,
    )
    return response


def _rule_applies_to_payment(rule: dict[str, Any], payment: Any) -> bool:
    applies_to = rule.get("applies_to", "direct")
    if payment.mcp_tool_id:
        return applies_to in {"mcp", "any"}
    return applies_to in {"direct", "any"}


def _match_condition(
    payment: Any,
    *,
    trigger_type: str | None,
    threshold_amount: str | None = None,
    vendor_pattern: str | None = None,
    currency: str | None = None,
    mcp_tool_id: str | None = None,
    mcp_action: str | None = None,
    mcp_server_trust_level: str | None = None,
    observed_mcp_server_trust_level: str | None = None,
) -> bool:
    if not trigger_type:
        return True
    if trigger_type == "amount_threshold" and threshold_amount is not None:
        return payment.amount > Decimal(threshold_amount)
    if trigger_type == "first_time_vendor":
        return _store.count_user_vendor_authorized_transactions(payment.user_id, payment.vendor) == 0
    if trigger_type == "vendor_pattern" and vendor_pattern:
        return bool(re.search(vendor_pattern, payment.vendor, re.IGNORECASE))
    if trigger_type == "first_time_agent_user":
        return _store.count_agent_user_authorized_transactions(payment.agent_id, payment.user_id) == 0
    if trigger_type == "currency_match" and currency:
        return payment.currency == currency
    if trigger_type == "mcp_tool_match" and payment.mcp_tool_id and mcp_tool_id:
        return payment.mcp_tool_id == mcp_tool_id
    if trigger_type == "mcp_action_match" and payment.mcp_tool_id and mcp_action:
        return payment.mcp_action == mcp_action
    if trigger_type == "mcp_server_trust_level" and payment.mcp_tool_id and mcp_server_trust_level:
        return observed_mcp_server_trust_level == mcp_server_trust_level
    return False


def _matching_rule(payment: Any, *, mcp_server_trust_level: str | None = None) -> dict[str, Any] | None:
    for rule in _store.list_hitl_rules(active_only=True):
        if not _rule_applies_to_payment(rule, payment):
            continue
        primary_matches = _match_condition(
            payment,
            trigger_type=rule["trigger_type"],
            threshold_amount=rule["threshold_amount"],
            vendor_pattern=rule["vendor_pattern"],
            currency=rule["currency"],
            mcp_tool_id=rule["mcp_tool_id"],
            mcp_action=rule["mcp_action"],
            mcp_server_trust_level=rule["mcp_server_trust_level"],
            observed_mcp_server_trust_level=mcp_server_trust_level,
        )
        secondary_matches = _match_condition(
            payment,
            trigger_type=rule.get("secondary_trigger_type"),
            threshold_amount=rule.get("secondary_threshold_amount"),
            vendor_pattern=rule.get("secondary_vendor_pattern"),
            currency=rule.get("secondary_currency"),
            mcp_tool_id=rule.get("secondary_mcp_tool_id"),
            mcp_action=rule.get("secondary_mcp_action"),
            mcp_server_trust_level=rule.get("secondary_mcp_server_trust_level"),
            observed_mcp_server_trust_level=mcp_server_trust_level,
        )
        if primary_matches and secondary_matches:
            return rule
    return None


def _create_hitl_approval(
    *,
    request: Any,
    payment: Any,
    request_hash: str,
    triggered_by: str,
    decision_reason: str,
    reason_code: str,
    approval_message: str,
    mcp_server_id: str | None,
    mcp_tool_name: str | None,
    rule: dict[str, Any] | None = None,
    extra_decision_details: dict[str, Any] | None = None,
) -> JSONResponse:
    request_started_at = getattr(request.state, "started_at", None)
    approval_latency_ms = int((time.perf_counter() - request_started_at) * 1000) if isinstance(request_started_at, (int, float)) else None
    hitl_approval_ttl_seconds = _get_hitl_approval_ttl_seconds() if _get_hitl_approval_ttl_seconds is not None else 300
    approval = _store.create_approval_request(
        approval_id=uuid4().hex,
        request_hash=request_hash,
        request_path="/pay",
        request_payload=_build_approval_payload(payment),
        triggered_by=triggered_by,
        requestor_agent_id=payment.agent_id,
        requestor_user_id=payment.user_id,
        mcp_tool_id=payment.mcp_tool_id,
        expires_at=(datetime.now(timezone.utc) + timedelta(seconds=hitl_approval_ttl_seconds)).isoformat(),
    )
    alert_details = {
        "approval_id": approval["approval_id"],
        "triggered_by": triggered_by,
        "amount": str(payment.amount),
        "currency": payment.currency,
        "vendor": payment.vendor,
        "description": payment.description,
        "expires_at": approval["expires_at"],
        "mcp_tool_id": payment.mcp_tool_id,
        "mcp_action": getattr(payment, "mcp_action", None),
        "mcp_server_id": mcp_server_id,
        "mcp_tool_name": mcp_tool_name,
        "rule_id": rule["rule_id"] if rule is not None else None,
        "trigger_type": rule["trigger_type"] if rule is not None else None,
        "reason_code": reason_code,
    }
    if extra_decision_details:
        alert_details.update(extra_decision_details)
    _store.enqueue_approval_alert(
        alert_type="hitl_approval_requested",
        approval_id=approval["approval_id"],
        request_hash=request_hash,
        triggered_by=triggered_by,
        requestor_agent_id=payment.agent_id,
        requestor_user_id=payment.user_id,
        mcp_tool_id=payment.mcp_tool_id,
        summary=decision_reason,
        details=alert_details,
        event_key=f"approval_request:{approval['approval_id']}",
    )
    decision_details: dict[str, Any] = {"reason_code": reason_code}
    if rule is not None:
        decision_details["rule_id"] = rule["rule_id"]
        decision_details["trigger_type"] = rule["trigger_type"]
    if extra_decision_details:
        decision_details.update(extra_decision_details)
    decision_details["approval_request_latency_ms"] = approval_latency_ms
    decision_details["approval_ttl_seconds"] = hitl_approval_ttl_seconds
    _append_audit_entry(
        actor_type="agent",
        actor_id=payment.agent_id,
        action="approval_request",
        request_path="/pay",
        request_payload_hash=request_hash,
        request_payload_summary={
            "approval_id": approval["approval_id"],
            "rule_id": rule["rule_id"] if rule is not None else None,
            "mcp_tool_id": payment.mcp_tool_id,
        },
        decision="pending",
        decision_reason=decision_reason,
        decision_details=decision_details,
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
            "message": approval_message,
            "request_id": request.state.request_id,
        },
    )


def validate_and_consume_spend_token(
    *,
    request: Any,
    payment: Any,
    request_hash: str,
    x_spend_token: str | None,
    expected_mcp_tool_id: str | None,
    expected_action: str | None,
    mismatch_message: str,
) -> JSONResponse | None:
    spend_token_record = _store.get_spend_token(_hash_token(x_spend_token)) if x_spend_token else None
    if spend_token_record is None:
        return JSONResponse(
            status_code=403,
            content=_error_payload(
                request,
                "SPEND_TOKEN_REQUIRED",
                "A valid spend token is required to continue this approved payment request.",
            ),
        )
    if spend_token_record["revoked"] or spend_token_record["is_used"]:
        return JSONResponse(status_code=403, content=_error_payload(request, "SPEND_TOKEN_INVALID", "Spend token has already been used or revoked."))
    if datetime.fromisoformat(spend_token_record["expires_at"]) <= datetime.now(timezone.utc):
        return JSONResponse(status_code=403, content=_error_payload(request, "SPEND_TOKEN_EXPIRED", "Spend token has expired."))
    if (
        spend_token_record["request_hash"] != request_hash
        or spend_token_record["user_id"] != payment.user_id
        or spend_token_record["agent_id"] != payment.agent_id
        or spend_token_record["authorized_currency"] != payment.currency
        or spend_token_record["authorized_amount"] < payment.amount
        or spend_token_record["mcp_tool_id"] != expected_mcp_tool_id
        or spend_token_record["authorized_action"] != expected_action
    ):
        return JSONResponse(status_code=403, content=_error_payload(request, "SPEND_TOKEN_MISMATCH", mismatch_message))
    if not _store.consume_spend_token(_hash_token(x_spend_token)):
        return JSONResponse(status_code=403, content=_error_payload(request, "SPEND_TOKEN_ALREADY_USED", "Spend token has already been consumed."))
    return None


def enforce_direct_hitl_policy(
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
    mcp_server_id: str | None,
    mcp_tool_name: str | None,
) -> JSONResponse | None:
    if payment.mcp_tool_id:
        return None
    anomaly_context = _compute_infrastructure_identity_anomaly_context(request, payment)
    if anomaly_context is not None and anomaly_severity_meets_threshold(
        severity=anomaly_context["severity"],
        threshold=_current_anomaly_deny_threshold(),
    ):
        return _deny_for_infrastructure_identity_anomaly(
            request=request,
            payment=payment,
            request_hash=request_hash,
            amount_due=amount_due,
            started_at=started_at,
            idempotency_key=idempotency_key,
            receipt_id=receipt_id,
            receipt_source=receipt_source,
            mcp_server_id=mcp_server_id,
            mcp_tool_name=mcp_tool_name,
            anomaly_context=anomaly_context,
        )
    infrastructure_trigger = _infrastructure_identity_trigger(request, payment)
    if infrastructure_trigger is not None:
        if not x_spend_token:
            _append_infrastructure_identity_evaluation_audit_entry(
                request=request,
                payment=payment,
                request_hash=request_hash,
                mcp_server_id=mcp_server_id,
                mcp_tool_name=mcp_tool_name,
                decision="hitl_required",
                reason_code=infrastructure_trigger["reason_code"],
                decision_reason=infrastructure_trigger["decision_reason"],
                anomaly_context=anomaly_context,
                extra_decision_details={
                    "threshold_amount": infrastructure_trigger["threshold_amount"],
                    "environment": infrastructure_trigger["matched_environment"],
                    "namespace": infrastructure_trigger["matched_namespace"],
                    "service_account": infrastructure_trigger["matched_service_account"],
                    "trust_tier": infrastructure_trigger["matched_trust_tier"],
                },
            )
            return _create_hitl_approval(
                request=request,
                payment=payment,
                request_hash=request_hash,
                triggered_by=infrastructure_trigger["triggered_by"],
                decision_reason=infrastructure_trigger["decision_reason"],
                reason_code=infrastructure_trigger["reason_code"],
                approval_message=infrastructure_trigger["approval_message"],
                mcp_server_id=mcp_server_id,
                mcp_tool_name=mcp_tool_name,
                extra_decision_details={
                    "posture": infrastructure_trigger["posture"],
                    "threshold_amount": infrastructure_trigger["threshold_amount"],
                    "environment": infrastructure_trigger["matched_environment"],
                    "namespace": infrastructure_trigger["matched_namespace"],
                    "service_account": infrastructure_trigger["matched_service_account"],
                    "trust_tier": infrastructure_trigger["matched_trust_tier"],
                },
            )
        return validate_and_consume_spend_token(
            request=request,
            payment=payment,
            request_hash=request_hash,
            x_spend_token=x_spend_token,
            expected_mcp_tool_id=None,
            expected_action=None,
            mismatch_message="Spend token does not authorize this payment request.",
        )
    rule = _matching_rule(payment)
    if rule is None:
        anomaly_trigger = _infrastructure_identity_anomaly_hitl_trigger(anomaly_context)
        if anomaly_trigger is None:
            if not x_spend_token:
                _append_infrastructure_identity_evaluation_audit_entry(
                    request=request,
                    payment=payment,
                    request_hash=request_hash,
                    mcp_server_id=mcp_server_id,
                    mcp_tool_name=mcp_tool_name,
                    decision="passed",
                    reason_code="INFRASTRUCTURE_IDENTITY_POLICY_PASSED",
                    decision_reason="Infrastructure identity checks did not require escalation.",
                    anomaly_context=anomaly_context,
                )
            return None
        if not x_spend_token:
            _append_infrastructure_identity_evaluation_audit_entry(
                request=request,
                payment=payment,
                request_hash=request_hash,
                mcp_server_id=mcp_server_id,
                mcp_tool_name=mcp_tool_name,
                decision="hitl_required",
                reason_code=anomaly_trigger["reason_code"],
                decision_reason=anomaly_trigger["decision_reason"],
                anomaly_context=anomaly_context,
                extra_decision_details={
                    "anomaly_threshold_severity": anomaly_trigger["threshold_severity"],
                },
            )
            return _create_hitl_approval(
                request=request,
                payment=payment,
                request_hash=request_hash,
                triggered_by=anomaly_trigger["triggered_by"],
                decision_reason=anomaly_trigger["decision_reason"],
                reason_code=anomaly_trigger["reason_code"],
                approval_message=anomaly_trigger["approval_message"],
                mcp_server_id=mcp_server_id,
                mcp_tool_name=mcp_tool_name,
                extra_decision_details={
                    "anomaly_severity": anomaly_trigger["severity"],
                    "anomaly_score": anomaly_trigger["score"],
                    "anomaly_threshold_severity": anomaly_trigger["threshold_severity"],
                    "baseline_event_count": anomaly_trigger["baseline_event_count"],
                    "baseline_average_amount": anomaly_trigger["baseline_average_amount"],
                    "observed_amount": anomaly_trigger["observed_amount"],
                    "reason_codes": anomaly_trigger["reason_codes"],
                    "feature_details": anomaly_trigger["feature_details"],
                    "posture": anomaly_trigger["posture"],
                },
            )
        return validate_and_consume_spend_token(
            request=request,
            payment=payment,
            request_hash=request_hash,
            x_spend_token=x_spend_token,
            expected_mcp_tool_id=None,
            expected_action=None,
            mismatch_message="Spend token does not authorize this payment request.",
        )
    if not x_spend_token:
        _append_infrastructure_identity_evaluation_audit_entry(
            request=request,
            payment=payment,
            request_hash=request_hash,
            mcp_server_id=mcp_server_id,
            mcp_tool_name=mcp_tool_name,
            decision="passed",
            reason_code="INFRASTRUCTURE_IDENTITY_POLICY_PASSED",
            decision_reason="Infrastructure identity checks did not require escalation.",
            anomaly_context=anomaly_context,
        )
    if not x_spend_token:
        return _create_hitl_approval(
            request=request,
            payment=payment,
            request_hash=request_hash,
            triggered_by=f"hitl_rule:{rule['rule_id']}",
            decision_reason="Human approval required by HITL rule.",
            reason_code="HITL_RULE_TRIGGERED",
            approval_message="Human approval is required before this payment can proceed.",
            mcp_server_id=mcp_server_id,
            mcp_tool_name=mcp_tool_name,
            rule=rule,
        )
    return validate_and_consume_spend_token(
        request=request,
        payment=payment,
        request_hash=request_hash,
        x_spend_token=x_spend_token,
        expected_mcp_tool_id=None,
        expected_action=None,
        mismatch_message="Spend token does not authorize this payment request.",
    )


def enforce_mcp_hitl_policy(
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
    mcp_server_id: str,
    mcp_tool_name: str | None,
    mcp_server_trust_level: str,
    requires_permission_hitl: bool,
    requires_unknown_server_hitl: bool,
) -> JSONResponse | None:
    rule = _matching_rule(payment, mcp_server_trust_level=mcp_server_trust_level)
    infrastructure_trigger = _infrastructure_identity_trigger(request, payment)
    anomaly_context = _compute_infrastructure_identity_anomaly_context(request, payment)
    if anomaly_context is not None and anomaly_severity_meets_threshold(
        severity=anomaly_context["severity"],
        threshold=_current_anomaly_deny_threshold(),
    ):
        return _deny_for_infrastructure_identity_anomaly(
            request=request,
            payment=payment,
            request_hash=request_hash,
            amount_due=amount_due,
            started_at=started_at,
            idempotency_key=idempotency_key,
            receipt_id=receipt_id,
            receipt_source=receipt_source,
            mcp_server_id=mcp_server_id,
            mcp_tool_name=mcp_tool_name,
            anomaly_context=anomaly_context,
        )
    anomaly_trigger = None
    if not requires_permission_hitl and not requires_unknown_server_hitl and rule is None and infrastructure_trigger is None:
        anomaly_trigger = _infrastructure_identity_anomaly_hitl_trigger(anomaly_context)
    needs_hitl = (
        requires_permission_hitl
        or requires_unknown_server_hitl
        or rule is not None
        or infrastructure_trigger is not None
        or anomaly_trigger is not None
    )
    if not needs_hitl:
        if not x_spend_token:
            _append_infrastructure_identity_evaluation_audit_entry(
                request=request,
                payment=payment,
                request_hash=request_hash,
                mcp_server_id=mcp_server_id,
                mcp_tool_name=mcp_tool_name,
                decision="passed",
                reason_code="INFRASTRUCTURE_IDENTITY_POLICY_PASSED",
                decision_reason="Infrastructure identity checks did not require escalation.",
                anomaly_context=anomaly_context,
            )
        return None
    if not x_spend_token:
        if infrastructure_trigger is not None:
            _append_infrastructure_identity_evaluation_audit_entry(
                request=request,
                payment=payment,
                request_hash=request_hash,
                mcp_server_id=mcp_server_id,
                mcp_tool_name=mcp_tool_name,
                decision="hitl_required",
                reason_code=infrastructure_trigger["reason_code"],
                decision_reason=infrastructure_trigger["decision_reason"],
                anomaly_context=anomaly_context,
                extra_decision_details={
                    "threshold_amount": infrastructure_trigger["threshold_amount"],
                    "environment": infrastructure_trigger["matched_environment"],
                    "namespace": infrastructure_trigger["matched_namespace"],
                    "service_account": infrastructure_trigger["matched_service_account"],
                    "trust_tier": infrastructure_trigger["matched_trust_tier"],
                },
            )
        elif anomaly_trigger is not None:
            _append_infrastructure_identity_evaluation_audit_entry(
                request=request,
                payment=payment,
                request_hash=request_hash,
                mcp_server_id=mcp_server_id,
                mcp_tool_name=mcp_tool_name,
                decision="hitl_required",
                reason_code=anomaly_trigger["reason_code"],
                decision_reason=anomaly_trigger["decision_reason"],
                anomaly_context=anomaly_context,
                extra_decision_details={
                    "anomaly_threshold_severity": anomaly_trigger["threshold_severity"],
                },
            )
        elif _build_infrastructure_identity_trace_details(
            request=request,
            payment=payment,
            anomaly_context=anomaly_context,
        ) is not None:
            _append_infrastructure_identity_evaluation_audit_entry(
                request=request,
                payment=payment,
                request_hash=request_hash,
                mcp_server_id=mcp_server_id,
                mcp_tool_name=mcp_tool_name,
                decision="passed",
                reason_code="INFRASTRUCTURE_IDENTITY_POLICY_PASSED",
                decision_reason="Infrastructure identity checks did not require escalation.",
                anomaly_context=anomaly_context,
            )
        if requires_unknown_server_hitl:
            return _create_hitl_approval(
                request=request,
                payment=payment,
                request_hash=request_hash,
                triggered_by="mcp_unknown_server_risk",
                decision_reason="Human approval required because the MCP server is unknown and exceeds the risk threshold.",
                reason_code="MCP_UNKNOWN_SERVER_HITL_REQUIRED",
                approval_message="Human approval is required before this MCP payment can proceed.",
                mcp_server_id=mcp_server_id,
                mcp_tool_name=mcp_tool_name,
            )
        if requires_permission_hitl:
            return _create_hitl_approval(
                request=request,
                payment=payment,
                request_hash=request_hash,
                triggered_by="mcp_permission_requires_hitl",
                decision_reason="Human approval required by MCP tool permission.",
                reason_code="MCP_TOOL_HITL_REQUIRED",
                approval_message="Human approval is required before this MCP payment can proceed.",
                mcp_server_id=mcp_server_id,
                mcp_tool_name=mcp_tool_name,
            )
        if infrastructure_trigger is not None:
            return _create_hitl_approval(
                request=request,
                payment=payment,
                request_hash=request_hash,
                triggered_by=infrastructure_trigger["triggered_by"],
                decision_reason=infrastructure_trigger["decision_reason"],
                reason_code=infrastructure_trigger["reason_code"],
                approval_message=infrastructure_trigger["approval_message"],
                mcp_server_id=mcp_server_id,
                mcp_tool_name=mcp_tool_name,
                extra_decision_details={
                    "posture": infrastructure_trigger["posture"],
                    "threshold_amount": infrastructure_trigger["threshold_amount"],
                    "environment": infrastructure_trigger["matched_environment"],
                    "namespace": infrastructure_trigger["matched_namespace"],
                    "service_account": infrastructure_trigger["matched_service_account"],
                    "trust_tier": infrastructure_trigger["matched_trust_tier"],
                },
            )
        if anomaly_trigger is not None:
            return _create_hitl_approval(
                request=request,
                payment=payment,
                request_hash=request_hash,
                triggered_by=anomaly_trigger["triggered_by"],
                decision_reason=anomaly_trigger["decision_reason"],
                reason_code=anomaly_trigger["reason_code"],
                approval_message="Human approval is required because this MCP payment exceeded the configured anomaly threshold.",
                mcp_server_id=mcp_server_id,
                mcp_tool_name=mcp_tool_name,
                extra_decision_details={
                    "anomaly_severity": anomaly_trigger["severity"],
                    "anomaly_score": anomaly_trigger["score"],
                    "anomaly_threshold_severity": anomaly_trigger["threshold_severity"],
                    "baseline_event_count": anomaly_trigger["baseline_event_count"],
                    "baseline_average_amount": anomaly_trigger["baseline_average_amount"],
                    "observed_amount": anomaly_trigger["observed_amount"],
                    "reason_codes": anomaly_trigger["reason_codes"],
                    "feature_details": anomaly_trigger["feature_details"],
                    "posture": anomaly_trigger["posture"],
                },
            )
        return _create_hitl_approval(
            request=request,
            payment=payment,
            request_hash=request_hash,
            triggered_by=f"hitl_rule:{rule['rule_id']}",
            decision_reason="Human approval required by MCP HITL rule.",
            reason_code="MCP_HITL_RULE_TRIGGERED",
            approval_message="Human approval is required before this MCP payment can proceed.",
            mcp_server_id=mcp_server_id,
            mcp_tool_name=mcp_tool_name,
            rule=rule,
        )
    return validate_and_consume_spend_token(
        request=request,
        payment=payment,
        request_hash=request_hash,
        x_spend_token=x_spend_token,
        expected_mcp_tool_id=payment.mcp_tool_id,
        expected_action=payment.mcp_action,
        mismatch_message="Spend token does not authorize this MCP payment request.",
    )
