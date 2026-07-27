from __future__ import annotations

from decimal import Decimal
from typing import Any, Callable

from fastapi import APIRouter, Header, HTTPException

from ..auth import (
    audit_infrastructure_identity_fields,
    capture_infrastructure_identity_profile,
    require_trusted_infrastructure_identity_for_admin,
)


router = APIRouter()

_store = None
_get_current_identity = None
_ensure_scope: Callable[[Any, list[str]], Any] | None = None
_list_infrastructure_identity_verifiers: Callable[[], list[dict[str, Any]]] | None = None
_append_audit_entry: Callable[..., None] | None = None


def _serialize_profile(profile: dict[str, Any]) -> dict[str, Any]:
    total_amount = profile.get("total_amount")
    return profile | {
        "total_amount": format(total_amount, "f") if isinstance(total_amount, Decimal) else total_amount,
    }


def _serialize_anomaly(anomaly: dict[str, Any]) -> dict[str, Any]:
    score = anomaly.get("score")
    observed_amount = anomaly.get("observed_amount")
    baseline_average_amount = anomaly.get("baseline_average_amount")
    return anomaly | {
        "score": format(score, "f") if isinstance(score, Decimal) else score,
        "observed_amount": format(observed_amount, "f") if isinstance(observed_amount, Decimal) else observed_amount,
        "baseline_average_amount": format(baseline_average_amount, "f")
        if isinstance(baseline_average_amount, Decimal)
        else baseline_average_amount,
    }


def _serialize_anomaly_alert(alert: dict[str, Any]) -> dict[str, Any]:
    score = alert.get("score")
    return alert | {
        "score": format(score, "f") if isinstance(score, Decimal) else score,
    }


def setup_phase3_api(
    *,
    store: Any,
    get_current_identity: Callable[..., Any],
    ensure_scope: Callable[[Any, list[str]], Any],
    list_infrastructure_identity_verifiers: Callable[[], list[dict[str, Any]]],
    append_audit_entry: Callable[..., None],
) -> None:
    global _store, _get_current_identity, _ensure_scope, _list_infrastructure_identity_verifiers, _append_audit_entry
    _store = store
    _get_current_identity = get_current_identity
    _ensure_scope = ensure_scope
    _list_infrastructure_identity_verifiers = list_infrastructure_identity_verifiers
    _append_audit_entry = append_audit_entry


def _require_phase3_identity(
    authorization: str | None,
    infrastructure_assertion: str | None = None,
    infrastructure_signature: str | None = None,
) -> Any:
    if _get_current_identity is None or _ensure_scope is None:
        raise RuntimeError("Phase 3 API not configured")
    identity = _get_current_identity(authorization, infrastructure_assertion, infrastructure_signature)
    return _ensure_scope(identity, ["audit:read"])


def _require_phase3_admin_identity(
    authorization: str | None,
    infrastructure_assertion: str | None = None,
    infrastructure_signature: str | None = None,
) -> Any:
    if _get_current_identity is None or _ensure_scope is None:
        raise RuntimeError("Phase 3 API not configured")
    identity = _get_current_identity(authorization, infrastructure_assertion, infrastructure_signature)
    return _ensure_scope(identity, ["admin:all"])


def _current_phase3_features() -> dict[str, Any]:
    policy = _store.get_current_policy_document()
    controls = policy.get("document", {}).get("controls", {})
    features = controls.get("phase3_features", {})
    if not isinstance(features, dict):
        features = {}
    return {
        "ap2_enabled": bool(features.get("ap2_enabled", False)),
        "advanced_x402_enabled": bool(features.get("advanced_x402_enabled", False)),
        "infrastructure_identity_enabled": bool(features.get("infrastructure_identity_enabled", False)),
        "active_policy_version": policy.get("version"),
    }


@router.get("/phase3/features")
def get_phase3_features(
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> dict[str, Any]:
    _require_phase3_identity(authorization)
    features = _current_phase3_features()
    return {
        "phase": "3",
        "features": {
            "ap2": {
                "enabled": features["ap2_enabled"],
                "status": "enabled" if features["ap2_enabled"] else "disabled",
                "intended_scope": "AP2 mandate parsing, verification, and enforcement",
            },
            "advanced_x402": {
                "enabled": features["advanced_x402_enabled"],
                "status": "enabled" if features["advanced_x402_enabled"] else "disabled",
                "intended_scope": "multi-chain x402 verification and machine-readable challenge handling",
            },
            "infrastructure_identity": {
                "enabled": features["infrastructure_identity_enabled"],
                "status": "enabled" if features["infrastructure_identity_enabled"] else "disabled",
                "intended_scope": "infrastructure-asserted workload identity verification and persistence",
            },
        },
        "active_policy_version": features["active_policy_version"],
    }


@router.get("/phase3/identity")
def get_phase3_identity(
    authorization: str | None = Header(default=None, alias="Authorization"),
    infrastructure_assertion: str | None = Header(default=None, alias="X-Infrastructure-Assertion"),
    infrastructure_signature: str | None = Header(default=None, alias="X-Infrastructure-Signature"),
) -> dict[str, Any]:
    identity = _require_phase3_identity(authorization, infrastructure_assertion, infrastructure_signature)
    infra = identity.infrastructure_identity
    return {
        "oauth_subject": identity.oauth_subject,
        "client_id": identity.client_id,
        "agent_id": identity.agent_id,
        "oauth_scopes": identity.oauth_scopes,
        "infrastructure_identity": None
        if infra is None
        else {
            "provider_name": infra.provider_name,
            "subject": infra.subject,
            "agent_id": infra.agent_id,
            "environment": infra.environment,
            "namespace": infra.namespace,
            "service_account": infra.service_account,
            "trust_tier": infra.trust_tier,
            "verification_status": infra.verification_status,
            "verification_reason_code": infra.verification_reason_code,
        },
    }


@router.get("/phase3/infrastructure/verifiers")
def list_phase3_infrastructure_verifiers(
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> dict[str, Any]:
    _require_phase3_identity(authorization)
    verifiers = [] if _list_infrastructure_identity_verifiers is None else _list_infrastructure_identity_verifiers()
    return {"verifiers": verifiers}


@router.get("/phase3/infrastructure/assertions")
def list_phase3_infrastructure_assertions(
    provider_name: str | None = None,
    subject: str | None = None,
    agent_id: str | None = None,
    verification_status: str | None = None,
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> list[dict[str, Any]]:
    _require_phase3_identity(authorization)
    return _store.list_agent_identity_assertions(
        provider_name=provider_name,
        subject=subject,
        agent_id=agent_id,
        verification_status=verification_status,
    )


@router.get("/phase3/infrastructure/profiles")
def list_phase3_infrastructure_profiles(
    actor_type: str | None = None,
    actor_id: str | None = None,
    event_type: str | None = None,
    action: str | None = None,
    provider_name: str | None = None,
    subject: str | None = None,
    posture: str | None = None,
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> list[dict[str, Any]]:
    _require_phase3_identity(authorization)
    return [
        _serialize_profile(item)
        for item in _store.list_infrastructure_identity_profiles(
            actor_type=actor_type,
            actor_id=actor_id,
            event_type=event_type,
            action=action,
            provider_name=provider_name,
            subject=subject,
            posture=posture,
        )
    ]


@router.get("/phase3/infrastructure/anomalies")
def list_phase3_infrastructure_anomalies(
    transaction_id: str | None = None,
    actor_id: str | None = None,
    provider_name: str | None = None,
    posture: str | None = None,
    severity: str | None = None,
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> list[dict[str, Any]]:
    _require_phase3_identity(authorization)
    return [
        _serialize_anomaly(item)
        for item in _store.list_infrastructure_identity_anomalies(
            transaction_id=transaction_id,
            actor_id=actor_id,
            provider_name=provider_name,
            posture=posture,
            severity=severity,
        )
    ]


@router.get("/phase3/infrastructure/anomaly-alerts/outbox")
def list_phase3_infrastructure_anomaly_alerts(
    status: str | None = None,
    severity: str | None = None,
    transaction_id: str | None = None,
    actor_id: str | None = None,
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> list[dict[str, Any]]:
    _require_phase3_identity(authorization)
    return [
        _serialize_anomaly_alert(item)
        for item in _store.list_infrastructure_identity_anomaly_alerts(
            status=status,
            severity=severity,
            transaction_id=transaction_id,
            actor_id=actor_id,
        )
    ]


@router.post("/phase3/infrastructure/anomaly-alerts/outbox/{alert_id}/ack")
def acknowledge_phase3_infrastructure_anomaly_alert(
    alert_id: str,
    authorization: str | None = Header(default=None, alias="Authorization"),
    infrastructure_assertion: str | None = Header(default=None, alias="X-Infrastructure-Assertion"),
    infrastructure_signature: str | None = Header(default=None, alias="X-Infrastructure-Signature"),
) -> dict[str, Any]:
    identity = _require_phase3_admin_identity(authorization, infrastructure_assertion, infrastructure_signature)
    require_trusted_infrastructure_identity_for_admin(identity)
    alert = _store.acknowledge_infrastructure_identity_anomaly_alert(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Infrastructure anomaly alert not found")
    if _append_audit_entry is None:
        raise RuntimeError("Phase 3 API not configured")
    _append_audit_entry(
        actor_type="admin",
        actor_id=identity.oauth_subject,
        action="infrastructure_anomaly_alert_acknowledge",
        request_path=f"/phase3/infrastructure/anomaly-alerts/outbox/{alert_id}/ack",
        request_payload_hash=alert_id,
        request_payload_summary={"alert_id": alert_id, "transaction_id": alert["transaction_id"]},
        decision="acknowledged",
        decision_reason=None,
        decision_details={"severity": alert["severity"], "anomaly_id": alert["anomaly_id"]},
        transaction_id=alert["transaction_id"],
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
        action="infrastructure_anomaly_alert_acknowledge",
        request_path=f"/phase3/infrastructure/anomaly-alerts/outbox/{alert_id}/ack",
    )
    return {"status": "acknowledged", "alert": _serialize_anomaly_alert(alert)}
