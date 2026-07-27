from __future__ import annotations

from typing import Any, Callable

from fastapi import APIRouter, Header


router = APIRouter()

_store = None
_metrics = None
_get_current_identity = None
_ensure_scope: Callable[[Any, list[str]], Any] | None = None
_database_backend = "sqlite"
_rate_limit_requests = 0
_rate_limit_window_seconds = 0
_payment_velocity_limit = 0
_payment_velocity_window_seconds = 0


def setup_ops_api(
    *,
    store: Any,
    metrics: Any,
    get_current_identity: Callable[..., Any],
    ensure_scope: Callable[[Any, list[str]], Any],
    database_backend: str,
    rate_limit_requests: int,
    rate_limit_window_seconds: int,
    payment_velocity_limit: int,
    payment_velocity_window_seconds: int,
) -> None:
    global _store, _metrics, _get_current_identity, _ensure_scope, _database_backend
    global _rate_limit_requests, _rate_limit_window_seconds, _payment_velocity_limit, _payment_velocity_window_seconds
    _store = store
    _metrics = metrics
    _get_current_identity = get_current_identity
    _ensure_scope = ensure_scope
    _database_backend = database_backend
    _rate_limit_requests = rate_limit_requests
    _rate_limit_window_seconds = rate_limit_window_seconds
    _payment_velocity_limit = payment_velocity_limit
    _payment_velocity_window_seconds = payment_velocity_window_seconds


def _require_identity(authorization: str | None, scopes: list[str] | None = None) -> Any:
    if _get_current_identity is None or _ensure_scope is None:
        raise RuntimeError("Ops API not configured")
    if scopes:
        identity = _get_current_identity(authorization)
        return _ensure_scope(identity, scopes)
    return None


@router.get("/health")
def healthcheck() -> dict[str, str]:
    return {"status": "ok", "database": _database_backend}


@router.get("/metrics")
def get_metrics() -> dict[str, Any]:
    return {
        "counters": _metrics.snapshot(),
        "database_backend": _database_backend,
        "rate_limit": {
            "requests": _rate_limit_requests,
            "window_seconds": _rate_limit_window_seconds,
        },
        "payment_velocity_limit": {
            "requests": _payment_velocity_limit,
            "window_seconds": _payment_velocity_window_seconds,
        },
    }


@router.get("/logs")
def get_logs(authorization: str | None = Header(default=None, alias="Authorization")) -> list[dict[str, Any]]:
    _require_identity(authorization, ["audit:read"])
    return _store.list_logs()
