from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from typing import Any, Callable

from fastapi import APIRouter, Header
from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..auth import (
    audit_infrastructure_identity_fields,
    capture_infrastructure_identity_profile,
    require_trusted_infrastructure_identity_for_admin,
)


router = APIRouter()

_store = None
_append_audit_entry: Callable[..., None] | None = None
_hash_token: Callable[[str], str] | None = None
_sanitize_text: Callable[[str, int], str] | None = None
_get_current_identity = None
_ensure_scope: Callable[[Any, list[str]], Any] | None = None
_webhook_dispatch_enabled = False
_webhook_dispatch_interval_seconds = 30
_get_webhook_max_attempts: Callable[[], int] | None = None


def _default_webhook_sender(*, url: str, payload: dict[str, Any], shared_secret: str | None, timeout_seconds: int) -> dict[str, Any]:
    data = json.dumps(payload, sort_keys=True).encode("utf-8")
    request = urllib.request.Request(url=url, data=data, method="POST")
    request.add_header("Content-Type", "application/json")
    if shared_secret:
        request.add_header("X-Webhook-Secret", shared_secret)
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            body = response.read().decode("utf-8")
            return {"status_code": response.status, "body": body}
    except urllib.error.HTTPError as exc:
        return {"status_code": exc.code, "body": exc.read().decode("utf-8")}


_webhook_sender: Callable[..., dict[str, Any]] = _default_webhook_sender
_get_webhook_timeout_seconds: Callable[[], int] | None = None


class WebhookDispatcher:
    def __init__(self) -> None:
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, name="webhook-dispatcher", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=1.0)

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def run_once(self) -> dict[str, Any]:
        return _dispatch_webhooks_once(actor_type="system", actor_id="webhook_dispatcher", include_retryable_failed=True)

    def _run(self) -> None:
        while not self._stop_event.wait(_webhook_dispatch_interval_seconds):
            _dispatch_webhooks_once(actor_type="system", actor_id="webhook_dispatcher", include_retryable_failed=True)


dispatcher = WebhookDispatcher()


def setup_webhooks_api(
    *,
    store: Any,
    append_audit_entry: Callable[..., None],
    hash_token: Callable[[str], str],
    sanitize_text: Callable[[str, int], str],
    get_current_identity: Callable[..., Any],
    ensure_scope: Callable[[Any, list[str]], Any],
    get_webhook_timeout_seconds: Callable[[], int],
    webhook_dispatch_enabled: bool,
    webhook_dispatch_interval_seconds: int,
    get_webhook_max_attempts: Callable[[], int],
) -> None:
    global _store, _append_audit_entry, _hash_token, _sanitize_text, _get_current_identity, _ensure_scope
    global _get_webhook_timeout_seconds, _webhook_dispatch_enabled, _webhook_dispatch_interval_seconds, _get_webhook_max_attempts
    _store = store
    _append_audit_entry = append_audit_entry
    _hash_token = hash_token
    _sanitize_text = sanitize_text
    _get_current_identity = get_current_identity
    _ensure_scope = ensure_scope
    _get_webhook_timeout_seconds = get_webhook_timeout_seconds
    _webhook_dispatch_enabled = webhook_dispatch_enabled
    _webhook_dispatch_interval_seconds = webhook_dispatch_interval_seconds
    _get_webhook_max_attempts = get_webhook_max_attempts


def set_webhook_sender_for_tests(sender: Callable[..., dict[str, Any]]) -> None:
    global _webhook_sender
    _webhook_sender = sender


def reset_webhook_sender_for_tests() -> None:
    global _webhook_sender
    _webhook_sender = _default_webhook_sender


def run_webhook_dispatch_cycle_for_tests() -> dict[str, Any]:
    return dispatcher.run_once()


class WebhookEndpointRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    endpoint_id: str = Field(..., min_length=1)
    target_url: str = Field(..., min_length=1)
    subscribed_events: list[str] = Field(..., min_length=1)
    shared_secret: str | None = Field(default=None)
    is_active: bool = Field(default=True)

    @field_validator("endpoint_id", "target_url", "shared_secret")
    @classmethod
    def sanitize_text_fields(cls, value: str | None) -> str | None:
        if value is None:
            return None
        sanitized = _sanitize_text(value, max_length=500)
        if not sanitized:
            raise ValueError("field cannot be empty")
        return sanitized

    @field_validator("subscribed_events")
    @classmethod
    def sanitize_events(cls, value: list[str]) -> list[str]:
        normalized = sorted({_sanitize_text(item, max_length=100) for item in value})
        if not normalized:
            raise ValueError("at least one subscribed event is required")
        return normalized


def _require_admin_identity(
    authorization: str | None,
    infrastructure_assertion: str | None = None,
    infrastructure_signature: str | None = None,
) -> Any:
    identity = _get_current_identity(authorization, infrastructure_assertion, infrastructure_signature)
    return _ensure_scope(identity, ["admin:all"])


def _current_webhook_timeout_seconds() -> int:
    if _get_webhook_timeout_seconds is None:
        return 5
    return max(1, int(_get_webhook_timeout_seconds()))


def _current_webhook_max_attempts() -> int:
    if _get_webhook_max_attempts is None:
        return 3
    return max(1, int(_get_webhook_max_attempts()))


def _retryable_alerts(alert_source: str) -> list[dict[str, Any]]:
    if alert_source == "budget":
        alerts = _store.list_budget_alerts()
    elif alert_source == "approval":
        alerts = _store.list_approval_alerts()
    elif alert_source == "anomaly":
        alerts = _store.list_infrastructure_identity_anomaly_alerts()
    elif alert_source == "siem":
        alerts = _store.list_siem_exports()
    else:
        alerts = _store.list_mcp_alerts()
    return [item for item in alerts if item["status"] in {"pending", "failed"}]


def _dispatch_webhooks_once(
    *,
    actor_type: str,
    actor_id: str,
    include_retryable_failed: bool,
    infrastructure_provider_name: str | None = None,
    infrastructure_subject: str | None = None,
    infrastructure_trust_tier: str | None = None,
) -> dict[str, Any]:
    dispatch_started_at = time.perf_counter()
    webhook_timeout_seconds = _current_webhook_timeout_seconds()
    webhook_max_attempts = _current_webhook_max_attempts()
    endpoints = _store.list_webhook_endpoints(active_only=True)
    budget_alerts = _retryable_alerts("budget") if include_retryable_failed else _store.list_budget_alerts(status="pending")
    approval_alerts = _retryable_alerts("approval") if include_retryable_failed else _store.list_approval_alerts(status="pending")
    mcp_alerts = _retryable_alerts("mcp") if include_retryable_failed else _store.list_mcp_alerts(status="pending")
    anomaly_alerts = (
        _retryable_alerts("anomaly")
        if include_retryable_failed
        else _store.list_infrastructure_identity_anomaly_alerts(status="pending")
    )
    siem_exports = _retryable_alerts("siem") if include_retryable_failed else _store.list_siem_exports(status="pending")

    dispatched = 0
    failed = 0
    skipped = 0
    for endpoint in endpoints:
        subscribed = set(endpoint["subscribed_events"])
        for alert in budget_alerts:
            if "budget_alert" not in subscribed:
                continue
            if _store.count_webhook_delivery_attempts(alert_source="budget", alert_id=alert["alert_id"], endpoint_id=endpoint["endpoint_id"]) >= webhook_max_attempts:
                skipped += 1
                continue
            delivery_started_at = time.perf_counter()
            result = _webhook_sender(
                url=endpoint["target_url"],
                payload={"event_type": "budget_alert", "alert": alert},
                shared_secret=endpoint["shared_secret"],
                timeout_seconds=webhook_timeout_seconds,
            )
            delivery_status = "delivered" if 200 <= int(result["status_code"]) < 300 else "failed"
            _store.record_webhook_delivery_attempt(
                alert_source="budget",
                alert_id=alert["alert_id"],
                endpoint_id=endpoint["endpoint_id"],
                delivery_status=delivery_status,
                duration_ms=int((time.perf_counter() - delivery_started_at) * 1000),
                response_status=int(result["status_code"]),
                response_body=result.get("body"),
                error_message=None if delivery_status == "delivered" else "Non-success response",
            )
            _store.set_budget_alert_status(alert["alert_id"], delivery_status)
            if delivery_status == "delivered":
                dispatched += 1
            else:
                failed += 1
        for alert in approval_alerts:
            if alert["alert_type"] not in subscribed:
                continue
            if _store.count_webhook_delivery_attempts(alert_source="approval", alert_id=alert["alert_id"], endpoint_id=endpoint["endpoint_id"]) >= webhook_max_attempts:
                skipped += 1
                continue
            delivery_started_at = time.perf_counter()
            result = _webhook_sender(
                url=endpoint["target_url"],
                payload={"event_type": alert["alert_type"], "alert": alert},
                shared_secret=endpoint["shared_secret"],
                timeout_seconds=webhook_timeout_seconds,
            )
            delivery_status = "delivered" if 200 <= int(result["status_code"]) < 300 else "failed"
            _store.record_webhook_delivery_attempt(
                alert_source="approval",
                alert_id=alert["alert_id"],
                endpoint_id=endpoint["endpoint_id"],
                delivery_status=delivery_status,
                duration_ms=int((time.perf_counter() - delivery_started_at) * 1000),
                response_status=int(result["status_code"]),
                response_body=result.get("body"),
                error_message=None if delivery_status == "delivered" else "Non-success response",
            )
            _store.set_approval_alert_status(alert["alert_id"], delivery_status)
            if delivery_status == "delivered":
                dispatched += 1
            else:
                failed += 1
        for alert in mcp_alerts:
            if alert["alert_type"] not in subscribed:
                continue
            if _store.count_webhook_delivery_attempts(alert_source="mcp", alert_id=alert["alert_id"], endpoint_id=endpoint["endpoint_id"]) >= webhook_max_attempts:
                skipped += 1
                continue
            delivery_started_at = time.perf_counter()
            result = _webhook_sender(
                url=endpoint["target_url"],
                payload={"event_type": alert["alert_type"], "alert": alert},
                shared_secret=endpoint["shared_secret"],
                timeout_seconds=webhook_timeout_seconds,
            )
            delivery_status = "delivered" if 200 <= int(result["status_code"]) < 300 else "failed"
            _store.record_webhook_delivery_attempt(
                alert_source="mcp",
                alert_id=alert["alert_id"],
                endpoint_id=endpoint["endpoint_id"],
                delivery_status=delivery_status,
                duration_ms=int((time.perf_counter() - delivery_started_at) * 1000),
                response_status=int(result["status_code"]),
                response_body=result.get("body"),
                error_message=None if delivery_status == "delivered" else "Non-success response",
            )
            _store.set_mcp_alert_status(alert["alert_id"], delivery_status)
            if delivery_status == "delivered":
                dispatched += 1
            else:
                failed += 1
        for alert in anomaly_alerts:
            if "infrastructure_identity_anomaly_alert" not in subscribed:
                continue
            if _store.count_webhook_delivery_attempts(alert_source="anomaly", alert_id=alert["alert_id"], endpoint_id=endpoint["endpoint_id"]) >= webhook_max_attempts:
                skipped += 1
                continue
            delivery_started_at = time.perf_counter()
            result = _webhook_sender(
                url=endpoint["target_url"],
                payload={"event_type": "infrastructure_identity_anomaly_alert", "alert": alert},
                shared_secret=endpoint["shared_secret"],
                timeout_seconds=webhook_timeout_seconds,
            )
            delivery_status = "delivered" if 200 <= int(result["status_code"]) < 300 else "failed"
            _store.record_webhook_delivery_attempt(
                alert_source="anomaly",
                alert_id=alert["alert_id"],
                endpoint_id=endpoint["endpoint_id"],
                delivery_status=delivery_status,
                duration_ms=int((time.perf_counter() - delivery_started_at) * 1000),
                response_status=int(result["status_code"]),
                response_body=result.get("body"),
                error_message=None if delivery_status == "delivered" else "Non-success response",
            )
            _store.set_infrastructure_identity_anomaly_alert_status(alert["alert_id"], delivery_status)
            if delivery_status == "delivered":
                dispatched += 1
            else:
                failed += 1
        for export in siem_exports:
            if "siem_audit_anomaly_export" not in subscribed:
                continue
            if _store.count_webhook_delivery_attempts(alert_source="siem", alert_id=export["export_id"], endpoint_id=endpoint["endpoint_id"]) >= webhook_max_attempts:
                skipped += 1
                continue
            delivery_started_at = time.perf_counter()
            result = _webhook_sender(
                url=endpoint["target_url"],
                payload={"event_type": "siem_audit_anomaly_export", "export": export},
                shared_secret=endpoint["shared_secret"],
                timeout_seconds=webhook_timeout_seconds,
            )
            delivery_status = "delivered" if 200 <= int(result["status_code"]) < 300 else "failed"
            _store.record_webhook_delivery_attempt(
                alert_source="siem",
                alert_id=export["export_id"],
                endpoint_id=endpoint["endpoint_id"],
                delivery_status=delivery_status,
                duration_ms=int((time.perf_counter() - delivery_started_at) * 1000),
                response_status=int(result["status_code"]),
                response_body=result.get("body"),
                error_message=None if delivery_status == "delivered" else "Non-success response",
            )
            _store.set_siem_export_status(export["export_id"], delivery_status)
            if delivery_status == "delivered":
                dispatched += 1
            else:
                failed += 1

    _append_audit_entry(
        actor_type=actor_type,
        actor_id=actor_id,
        action="webhook_dispatch",
        request_path="/webhooks/dispatch",
        request_payload_hash=_hash_token(json.dumps({"endpoint_count": len(endpoints)}, sort_keys=True)),
        request_payload_summary={"endpoint_count": len(endpoints)},
        decision="completed",
        decision_reason=None,
        decision_details={
            "budget_alert_count": len(budget_alerts),
            "approval_alert_count": len(approval_alerts),
            "mcp_alert_count": len(mcp_alerts),
            "anomaly_alert_count": len(anomaly_alerts),
            "siem_export_count": len(siem_exports),
            "delivered_count": dispatched,
            "failed_count": failed,
            "skipped_count": skipped,
            "dispatch_duration_ms": int((time.perf_counter() - dispatch_started_at) * 1000),
        },
        transaction_amount=None,
        transaction_currency=None,
        infrastructure_provider_name=infrastructure_provider_name,
        infrastructure_subject=infrastructure_subject,
        infrastructure_trust_tier=infrastructure_trust_tier,
    )
    return {
        "status": "completed",
        "endpoint_count": len(endpoints),
        "budget_alert_count": len(budget_alerts),
        "approval_alert_count": len(approval_alerts),
        "mcp_alert_count": len(mcp_alerts),
        "anomaly_alert_count": len(anomaly_alerts),
        "siem_export_count": len(siem_exports),
        "delivered_count": dispatched,
        "failed_count": failed,
        "skipped_count": skipped,
    }


@router.get("/webhooks/endpoints")
def list_webhook_endpoints(authorization: str | None = Header(default=None, alias="Authorization")) -> list[dict[str, Any]]:
    _require_admin_identity(authorization)
    return _store.list_webhook_endpoints()


@router.post("/webhooks/endpoints")
def upsert_webhook_endpoint(
    payload: WebhookEndpointRequest,
    authorization: str | None = Header(default=None, alias="Authorization"),
    infrastructure_assertion: str | None = Header(default=None, alias="X-Infrastructure-Assertion"),
    infrastructure_signature: str | None = Header(default=None, alias="X-Infrastructure-Signature"),
) -> dict[str, Any]:
    identity = _require_admin_identity(authorization, infrastructure_assertion, infrastructure_signature)
    require_trusted_infrastructure_identity_for_admin(identity)
    endpoint = _store.upsert_webhook_endpoint(
        endpoint_id=payload.endpoint_id,
        target_url=payload.target_url,
        subscribed_events=payload.subscribed_events,
        shared_secret=payload.shared_secret,
        is_active=payload.is_active,
    )
    _append_audit_entry(
        actor_type="admin",
        actor_id=identity.oauth_subject,
        action="webhook_endpoint_upsert",
        request_path="/webhooks/endpoints",
        request_payload_hash=_hash_token(payload.model_dump_json()),
        request_payload_summary={"endpoint_id": payload.endpoint_id},
        decision="updated",
        decision_reason=None,
        decision_details={"subscribed_events": payload.subscribed_events, "is_active": payload.is_active},
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
        action="webhook_endpoint_upsert",
        request_path="/webhooks/endpoints",
    )
    return endpoint


@router.get("/webhooks/deliveries")
def list_webhook_deliveries(
    alert_source: str | None = None,
    alert_id: str | None = None,
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> list[dict[str, Any]]:
    _require_admin_identity(authorization)
    return _store.list_webhook_delivery_attempts(alert_source=alert_source, alert_id=alert_id)


@router.get("/webhooks/dispatcher")
def get_webhook_dispatcher_status(authorization: str | None = Header(default=None, alias="Authorization")) -> dict[str, Any]:
    _require_admin_identity(authorization)
    return {
        "enabled": _webhook_dispatch_enabled,
        "interval_seconds": _webhook_dispatch_interval_seconds,
        "timeout_seconds": _current_webhook_timeout_seconds(),
        "max_attempts": _current_webhook_max_attempts(),
        "running": dispatcher.is_running(),
    }


@router.post("/webhooks/dispatch")
def dispatch_pending_webhooks(
    authorization: str | None = Header(default=None, alias="Authorization"),
    infrastructure_assertion: str | None = Header(default=None, alias="X-Infrastructure-Assertion"),
    infrastructure_signature: str | None = Header(default=None, alias="X-Infrastructure-Signature"),
) -> dict[str, Any]:
    identity = _require_admin_identity(authorization, infrastructure_assertion, infrastructure_signature)
    require_trusted_infrastructure_identity_for_admin(identity)
    result = _dispatch_webhooks_once(
        actor_type="admin",
        actor_id=identity.oauth_subject,
        include_retryable_failed=True,
        **audit_infrastructure_identity_fields(identity),
    )
    capture_infrastructure_identity_profile(
        store=_store,
        identity=identity,
        actor_type="admin",
        actor_id=identity.oauth_subject,
        event_type="admin_mutation",
        action="webhook_dispatch",
        request_path="/webhooks/dispatch",
    )
    return result
