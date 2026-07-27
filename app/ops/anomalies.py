from __future__ import annotations

from decimal import Decimal
from typing import Any
from uuid import uuid4


INFRASTRUCTURE_IDENTITY_ANOMALY_SEVERITY_ORDER = {
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
}
INFRASTRUCTURE_IDENTITY_ANOMALY_SCORE_QUANTUM = Decimal("0.000001")
INFRASTRUCTURE_IDENTITY_ANOMALY_CONTEXT_MIN_EVENTS = 3
INFRASTRUCTURE_IDENTITY_ANOMALY_NEW_CURRENCY_SCORE = Decimal("0.750000")
INFRASTRUCTURE_IDENTITY_ANOMALY_FIRST_TIME_VENDOR_SCORE = Decimal("0.500000")
INFRASTRUCTURE_IDENTITY_ANOMALY_FIRST_TIME_AGENT_USER_SCORE = Decimal("0.500000")


def anomaly_severity_rank(severity: str) -> int:
    if severity == "disabled":
        return -1
    return INFRASTRUCTURE_IDENTITY_ANOMALY_SEVERITY_ORDER.get(severity, -1)


def anomaly_severity_meets_threshold(*, severity: str, threshold: str) -> bool:
    if threshold == "disabled":
        return False
    return anomaly_severity_rank(severity) >= anomaly_severity_rank(threshold)


def anomaly_severity_is_stricter(*, severity: str, baseline: str) -> bool:
    return anomaly_severity_rank(severity) > anomaly_severity_rank(baseline)


def build_infrastructure_identity_anomaly_inputs(
    *,
    store: Any,
    actor_id: str,
    user_id: str,
    vendor: str,
    provider_name: str | None,
    subject: str | None,
    posture: str,
    transaction_currency: str,
) -> dict[str, Any]:
    baseline_profiles = store.list_infrastructure_identity_profiles(
        actor_type="agent",
        actor_id=actor_id,
        event_type="payment",
        action="payment_authorize",
        provider_name=provider_name,
        subject=subject,
        posture=posture,
    )
    baseline_profile = None
    baseline_context_event_count = 0
    currency_history_count = 0
    for profile in baseline_profiles:
        event_count = int(profile["event_count"])
        baseline_context_event_count += event_count
        if profile.get("transaction_currency") == transaction_currency:
            currency_history_count += event_count
            if baseline_profile is None:
                baseline_profile = profile

    return {
        "baseline_profile": baseline_profile,
        "baseline_context_event_count": baseline_context_event_count,
        "currency_history_count": currency_history_count,
        "vendor_history_count": store.count_user_vendor_authorized_transactions(user_id, vendor),
        "agent_user_history_count": store.count_agent_user_authorized_transactions(actor_id, user_id),
    }


def compute_infrastructure_identity_anomaly(
    *,
    baseline_profile: dict[str, Any] | None,
    posture: str,
    observed_amount: Decimal,
    baseline_context_event_count: int = 0,
    currency_history_count: int = 0,
    vendor_history_count: int = 0,
    agent_user_history_count: int = 0,
) -> dict[str, Any]:
    reason_codes: list[str] = []
    baseline_event_count = 0 if baseline_profile is None else int(baseline_profile["event_count"])
    baseline_average_amount = None if baseline_profile is None else Decimal(str(baseline_profile["total_amount"])) / Decimal(
        str(max(1, baseline_event_count))
    )
    amount_score = Decimal("0")
    new_currency_score = Decimal("0")
    first_time_vendor_score = Decimal("0")
    first_time_agent_user_score = Decimal("0")
    amount_baseline_ready = baseline_average_amount is not None and baseline_event_count >= INFRASTRUCTURE_IDENTITY_ANOMALY_CONTEXT_MIN_EVENTS
    context_baseline_ready = baseline_context_event_count >= INFRASTRUCTURE_IDENTITY_ANOMALY_CONTEXT_MIN_EVENTS

    if posture == "oauth_only":
        reason_codes.append("OAUTH_ONLY_POSTURE")
    elif posture == "untrusted_workload":
        reason_codes.append("UNTRUSTED_WORKLOAD_POSTURE")

    if not amount_baseline_ready:
        reason_codes.append("INSUFFICIENT_BASELINE")
    else:
        if baseline_average_amount > Decimal("0"):
            amount_score = (observed_amount - baseline_average_amount).copy_abs() / baseline_average_amount
        if amount_score >= Decimal("2.0"):
            reason_codes.append("AMOUNT_SPIKE_HIGH")
        elif amount_score >= Decimal("1.0"):
            reason_codes.append("AMOUNT_SPIKE_MEDIUM")

    if context_baseline_ready:
        if currency_history_count == 0:
            new_currency_score = INFRASTRUCTURE_IDENTITY_ANOMALY_NEW_CURRENCY_SCORE
            reason_codes.append("NEW_CURRENCY")
        if vendor_history_count == 0:
            first_time_vendor_score = INFRASTRUCTURE_IDENTITY_ANOMALY_FIRST_TIME_VENDOR_SCORE
            reason_codes.append("FIRST_TIME_VENDOR")
        if agent_user_history_count == 0:
            first_time_agent_user_score = INFRASTRUCTURE_IDENTITY_ANOMALY_FIRST_TIME_AGENT_USER_SCORE
            reason_codes.append("FIRST_TIME_AGENT_USER")

    score = amount_score + new_currency_score + first_time_vendor_score + first_time_agent_user_score
    if amount_baseline_ready:
        if score >= Decimal("2.0"):
            severity = "high"
        elif score >= Decimal("1.0"):
            severity = "medium"
        else:
            severity = "low"
    elif score >= Decimal("2.0"):
        severity = "high"
    elif score >= Decimal("1.0"):
        severity = "medium"
    elif score > Decimal("0"):
        severity = "low"
    else:
        severity = "informational"

    if posture in {"oauth_only", "untrusted_workload"} and severity == "low":
        severity = "medium"

    feature_details = {
        "context_baseline_event_count": baseline_context_event_count,
        "context_baseline_ready": context_baseline_ready,
        "amount_baseline_ready": amount_baseline_ready,
        "amount_spike_score": format(amount_score.quantize(INFRASTRUCTURE_IDENTITY_ANOMALY_SCORE_QUANTUM), "f"),
        "currency_history_count": currency_history_count,
        "new_currency_score": format(new_currency_score.quantize(INFRASTRUCTURE_IDENTITY_ANOMALY_SCORE_QUANTUM), "f"),
        "vendor_history_count": vendor_history_count,
        "first_time_vendor_score": format(first_time_vendor_score.quantize(INFRASTRUCTURE_IDENTITY_ANOMALY_SCORE_QUANTUM), "f"),
        "agent_user_history_count": agent_user_history_count,
        "first_time_agent_user_score": format(
            first_time_agent_user_score.quantize(INFRASTRUCTURE_IDENTITY_ANOMALY_SCORE_QUANTUM), "f"
        ),
    }

    return {
        "anomaly_id": uuid4().hex,
        "score": score.quantize(INFRASTRUCTURE_IDENTITY_ANOMALY_SCORE_QUANTUM),
        "severity": severity,
        "reason_codes": reason_codes,
        "baseline_event_count": baseline_event_count,
        "baseline_average_amount": None
        if baseline_average_amount is None
        else baseline_average_amount.quantize(INFRASTRUCTURE_IDENTITY_ANOMALY_SCORE_QUANTUM),
        "observed_amount": observed_amount.quantize(INFRASTRUCTURE_IDENTITY_ANOMALY_SCORE_QUANTUM),
        "feature_details": feature_details,
    }
