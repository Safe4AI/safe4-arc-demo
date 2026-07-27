from __future__ import annotations

import json
from typing import Any, Callable

from fastapi import APIRouter, Header, HTTPException, Request, status

from ..auth import (
    audit_infrastructure_identity_fields,
    capture_infrastructure_identity_profile,
    require_trusted_infrastructure_identity_for_admin,
)
from .models import (
    ALLOWED_MCP_TRUST_LEVELS,
    MCPServerRegistrationRequest,
    MCPServerTrustUpdateRequest,
    MCPToolPermissionRequest,
    MCPToolRegistrationRequest,
    MCPToolReviewRequest,
    scan_mcp_description,
)


router = APIRouter()

_store = None
_append_audit_entry: Callable[..., None] | None = None
_hash_token: Callable[[str], str] | None = None
_get_current_identity = None
_ensure_scope: Callable[[Any, list[str]], Any] | None = None


def _emit_mcp_alert(
    *,
    alert_type: str,
    severity: str,
    mcp_server_id: str | None,
    mcp_tool_id: str | None,
    summary: str,
    details: dict[str, Any],
    event_key: str,
) -> dict[str, Any] | None:
    return _store.enqueue_mcp_alert(
        alert_type=alert_type,
        severity=severity,
        mcp_server_id=mcp_server_id,
        mcp_tool_id=mcp_tool_id,
        summary=summary,
        details=details,
        event_key=event_key,
    )


def setup_mcp_api(
    *,
    store: Any,
    append_audit_entry: Callable[..., None],
    hash_token: Callable[[str], str],
    get_current_identity: Callable[..., Any],
    ensure_scope: Callable[[Any, list[str]], Any],
) -> None:
    global _store, _append_audit_entry, _hash_token, _get_current_identity, _ensure_scope
    _store = store
    _append_audit_entry = append_audit_entry
    _hash_token = hash_token
    _get_current_identity = get_current_identity
    _ensure_scope = ensure_scope


def _require_admin_identity(
    authorization: str | None,
    infrastructure_assertion: str | None = None,
    infrastructure_signature: str | None = None,
) -> Any:
    if _get_current_identity is None or _ensure_scope is None:
        raise RuntimeError("MCP API not configured")
    identity = _get_current_identity(authorization, infrastructure_assertion, infrastructure_signature)
    return _ensure_scope(identity, ["admin:all"])


def _maybe_downgrade_server_for_tool_change(server_id: str, reason: str) -> dict[str, Any] | None:
    server = _store.get_mcp_server(server_id)
    if server is None:
        return None
    if server["trust_level"] in {"trusted", "verified"}:
        return _store.update_mcp_server_trust(server_id, "unknown", reason)
    return server


@router.get("/mcp/servers")
def list_mcp_servers(
    trust_level: str | None = None,
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> list[dict[str, Any]]:
    _require_admin_identity(authorization)
    if trust_level is not None and trust_level not in ALLOWED_MCP_TRUST_LEVELS:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"code": "INVALID_TRUST_LEVEL"})
    return _store.list_mcp_servers(trust_level)


@router.post("/mcp/servers")
def register_mcp_server(
    request: Request,
    payload: MCPServerRegistrationRequest,
    authorization: str | None = Header(default=None, alias="Authorization"),
    infrastructure_assertion: str | None = Header(default=None, alias="X-Infrastructure-Assertion"),
    infrastructure_signature: str | None = Header(default=None, alias="X-Infrastructure-Signature"),
) -> dict[str, Any]:
    identity = _require_admin_identity(authorization, infrastructure_assertion, infrastructure_signature)
    require_trusted_infrastructure_identity_for_admin(identity)
    description_hash = _hash_token(payload.description)
    server = _store.upsert_mcp_server(
        server_id=payload.server_id,
        server_name=payload.server_name,
        server_url=payload.server_url,
        transport_type=payload.transport_type,
        trust_level="unknown",
        trust_level_reason="Default registration state",
        description_hash=description_hash,
    )
    _append_audit_entry(
        actor_type="admin",
        actor_id=identity.oauth_subject,
        action="mcp_server_register",
        request_path="/mcp/servers",
        request_payload_hash=_hash_token(payload.model_dump_json()),
        request_payload_summary={"server_id": payload.server_id, "transport_type": payload.transport_type},
        decision="registered",
        decision_reason=None,
        decision_details={"trust_level": "unknown"},
        mcp_server_id=payload.server_id,
        **audit_infrastructure_identity_fields(identity),
    )
    capture_infrastructure_identity_profile(
        store=_store,
        identity=identity,
        actor_type="admin",
        actor_id=identity.oauth_subject,
        event_type="admin_mutation",
        action="mcp_server_register",
        request_path="/mcp/servers",
    )
    return server


@router.post("/mcp/servers/{server_id}/trust")
def update_mcp_server_trust(
    server_id: str,
    request: Request,
    payload: MCPServerTrustUpdateRequest,
    authorization: str | None = Header(default=None, alias="Authorization"),
    infrastructure_assertion: str | None = Header(default=None, alias="X-Infrastructure-Assertion"),
    infrastructure_signature: str | None = Header(default=None, alias="X-Infrastructure-Signature"),
) -> dict[str, Any]:
    identity = _require_admin_identity(authorization, infrastructure_assertion, infrastructure_signature)
    require_trusted_infrastructure_identity_for_admin(identity)
    server = _store.update_mcp_server_trust(server_id, payload.trust_level, payload.reason)
    if server is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"code": "MCP_SERVER_NOT_FOUND"})
    _append_audit_entry(
        actor_type="admin",
        actor_id=identity.oauth_subject,
        action="mcp_server_trust_update",
        request_path=f"/mcp/servers/{server_id}/trust",
        request_payload_hash=_hash_token(payload.model_dump_json()),
        request_payload_summary={"server_id": server_id, "trust_level": payload.trust_level},
        decision="updated",
        decision_reason=payload.reason,
        decision_details={"trust_level": payload.trust_level},
        mcp_server_id=server_id,
        **audit_infrastructure_identity_fields(identity),
    )
    capture_infrastructure_identity_profile(
        store=_store,
        identity=identity,
        actor_type="admin",
        actor_id=identity.oauth_subject,
        event_type="admin_mutation",
        action="mcp_server_trust_update",
        request_path=f"/mcp/servers/{server_id}/trust",
    )
    return server


@router.get("/mcp/tools")
def list_mcp_tools(
    server_id: str | None = None,
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> list[dict[str, Any]]:
    _require_admin_identity(authorization)
    return _store.list_mcp_tools(server_id)


@router.get("/mcp/permissions")
def list_mcp_permissions(
    user_id: str | None = None,
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> list[dict[str, Any]]:
    _require_admin_identity(authorization)
    return _store.list_mcp_tool_permissions(user_id)


@router.get("/mcp/alerts/outbox")
def list_mcp_alert_outbox(
    status: str | None = None,
    alert_type: str | None = None,
    mcp_server_id: str | None = None,
    mcp_tool_id: str | None = None,
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> list[dict[str, Any]]:
    _require_admin_identity(authorization)
    return _store.list_mcp_alerts(
        status=status,
        alert_type=alert_type,
        mcp_server_id=mcp_server_id,
        mcp_tool_id=mcp_tool_id,
    )


@router.post("/mcp/alerts/outbox/{alert_id}/ack")
def acknowledge_mcp_alert_outbox(
    alert_id: str,
    request: Request,
    authorization: str | None = Header(default=None, alias="Authorization"),
    infrastructure_assertion: str | None = Header(default=None, alias="X-Infrastructure-Assertion"),
    infrastructure_signature: str | None = Header(default=None, alias="X-Infrastructure-Signature"),
) -> dict[str, Any]:
    identity = _require_admin_identity(authorization, infrastructure_assertion, infrastructure_signature)
    require_trusted_infrastructure_identity_for_admin(identity)
    alert = _store.acknowledge_mcp_alert(alert_id)
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"code": "MCP_ALERT_NOT_FOUND"})
    _append_audit_entry(
        actor_type="admin",
        actor_id=identity.oauth_subject,
        action="mcp_alert_acknowledge",
        request_path=f"/mcp/alerts/outbox/{alert_id}/ack",
        request_payload_hash=_hash_token(json.dumps({"alert_id": alert_id}, sort_keys=True)),
        request_payload_summary={"alert_id": alert_id, "alert_type": alert["alert_type"]},
        decision="acknowledged",
        decision_reason=None,
        decision_details={"mcp_server_id": alert["mcp_server_id"], "mcp_tool_id": alert["mcp_tool_id"]},
        mcp_server_id=alert["mcp_server_id"],
        mcp_tool_id=alert["mcp_tool_id"],
        **audit_infrastructure_identity_fields(identity),
    )
    capture_infrastructure_identity_profile(
        store=_store,
        identity=identity,
        actor_type="admin",
        actor_id=identity.oauth_subject,
        event_type="admin_mutation",
        action="mcp_alert_acknowledge",
        request_path=f"/mcp/alerts/outbox/{alert_id}/ack",
    )
    return {"status": "acknowledged", "alert": alert}


@router.post("/mcp/permissions")
def upsert_mcp_permission(
    request: Request,
    payload: MCPToolPermissionRequest,
    authorization: str | None = Header(default=None, alias="Authorization"),
    infrastructure_assertion: str | None = Header(default=None, alias="X-Infrastructure-Assertion"),
    infrastructure_signature: str | None = Header(default=None, alias="X-Infrastructure-Signature"),
) -> dict[str, Any]:
    identity = _require_admin_identity(authorization, infrastructure_assertion, infrastructure_signature)
    require_trusted_infrastructure_identity_for_admin(identity)
    if _store.get_mcp_tool(payload.tool_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"code": "MCP_TOOL_NOT_FOUND"})
    permission = _store.upsert_mcp_tool_permission(
        tool_id=payload.tool_id,
        user_id=payload.user_id,
        allowed_actions=payload.allowed_actions,
        daily_cap=payload.daily_cap,
        transaction_cap=payload.transaction_cap,
        requires_hitl=payload.requires_hitl,
    )
    _append_audit_entry(
        actor_type="admin",
        actor_id=identity.oauth_subject,
        action="mcp_tool_permission_upsert",
        request_path="/mcp/permissions",
        request_payload_hash=_hash_token(payload.model_dump_json()),
        request_payload_summary={"tool_id": payload.tool_id, "user_id": payload.user_id},
        decision="updated",
        decision_reason=None,
        decision_details={"allowed_actions": payload.allowed_actions},
        mcp_tool_id=payload.tool_id,
        **audit_infrastructure_identity_fields(identity),
    )
    capture_infrastructure_identity_profile(
        store=_store,
        identity=identity,
        actor_type="admin",
        actor_id=identity.oauth_subject,
        event_type="admin_mutation",
        action="mcp_tool_permission_upsert",
        request_path="/mcp/permissions",
    )
    return permission


@router.delete("/mcp/permissions/{tool_id}")
def delete_mcp_permission(
    tool_id: str,
    user_id: str,
    request: Request,
    authorization: str | None = Header(default=None, alias="Authorization"),
    infrastructure_assertion: str | None = Header(default=None, alias="X-Infrastructure-Assertion"),
    infrastructure_signature: str | None = Header(default=None, alias="X-Infrastructure-Signature"),
) -> dict[str, Any]:
    identity = _require_admin_identity(authorization, infrastructure_assertion, infrastructure_signature)
    require_trusted_infrastructure_identity_for_admin(identity)
    deleted = _store.deactivate_mcp_tool_permission(tool_id, user_id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"code": "MCP_PERMISSION_NOT_FOUND"})
    _append_audit_entry(
        actor_type="admin",
        actor_id=identity.oauth_subject,
        action="mcp_tool_permission_delete",
        request_path=f"/mcp/permissions/{tool_id}",
        request_payload_hash=_hash_token(json.dumps({"tool_id": tool_id, "user_id": user_id}, sort_keys=True)),
        request_payload_summary={"tool_id": tool_id, "user_id": user_id},
        decision="deleted",
        decision_reason=None,
        decision_details={},
        mcp_tool_id=tool_id,
        **audit_infrastructure_identity_fields(identity),
    )
    capture_infrastructure_identity_profile(
        store=_store,
        identity=identity,
        actor_type="admin",
        actor_id=identity.oauth_subject,
        event_type="admin_mutation",
        action="mcp_tool_permission_delete",
        request_path=f"/mcp/permissions/{tool_id}",
    )
    return {"status": "deleted", "tool_id": tool_id, "user_id": user_id}


@router.post("/mcp/servers/{server_id}/tools")
def register_mcp_tool(
    server_id: str,
    request: Request,
    payload: MCPToolRegistrationRequest,
    authorization: str | None = Header(default=None, alias="Authorization"),
    infrastructure_assertion: str | None = Header(default=None, alias="X-Infrastructure-Assertion"),
    infrastructure_signature: str | None = Header(default=None, alias="X-Infrastructure-Signature"),
) -> dict[str, Any]:
    identity = _require_admin_identity(authorization, infrastructure_assertion, infrastructure_signature)
    require_trusted_infrastructure_identity_for_admin(identity)
    server = _store.get_mcp_server(server_id)
    if server is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"code": "MCP_SERVER_NOT_FOUND"})
    description_hash = _hash_token(payload.description)
    threat_flags, quarantine_status, is_payment_relevant = scan_mcp_description(payload.description)
    tool_id = f"{server_id}:{payload.tool_name}"
    prior_tool = _store.get_mcp_tool(tool_id)
    tool = _store.upsert_mcp_tool(
        tool_id=tool_id,
        tool_name=payload.tool_name,
        server_id=server_id,
        description=payload.description,
        description_hash=description_hash,
        input_schema=payload.input_schema,
        is_payment_relevant=is_payment_relevant,
        threat_flags=threat_flags,
        quarantine_status=quarantine_status,
    )
    decision = "registered"
    decision_details = {"quarantine_status": tool["quarantine_status"], "threat_flags": tool["threat_flags"]}
    decision_reason = None
    if prior_tool is not None and tool["description_changed"]:
        downgraded = _maybe_downgrade_server_for_tool_change(
            server_id,
            f"Tool description changed for {tool_id}; review required.",
        )
        decision = "description_changed"
        decision_reason = "Tool description changed since first registration."
        decision_details["description_changed"] = True
        if downgraded is not None:
            decision_details["server_trust_level"] = downgraded["trust_level"]
        _emit_mcp_alert(
            alert_type="mcp_tool_description_changed",
            severity="high" if tool["quarantine_status"] == "review" else "critical",
            mcp_server_id=server_id,
            mcp_tool_id=tool_id,
            summary=f"MCP tool description changed for {tool_id}.",
            details={
                "tool_id": tool_id,
                "server_id": server_id,
                "quarantine_status": tool["quarantine_status"],
                "threat_flags": tool["threat_flags"],
                "server_trust_level": decision_details.get("server_trust_level"),
            },
            event_key=f"description_changed:{tool_id}:{tool['description_hash']}",
        )
    if tool["quarantine_status"] != "clear":
        _emit_mcp_alert(
            alert_type="mcp_tool_quarantine",
            severity="critical" if tool["quarantine_status"] == "quarantined" else "high",
            mcp_server_id=server_id,
            mcp_tool_id=tool_id,
            summary=f"MCP tool {tool_id} entered {tool['quarantine_status']} state.",
            details={
                "tool_id": tool_id,
                "server_id": server_id,
                "quarantine_status": tool["quarantine_status"],
                "threat_flags": tool["threat_flags"],
                "description_changed": tool["description_changed"],
            },
            event_key=f"quarantine:{tool_id}:{tool['description_hash']}:{tool['quarantine_status']}",
        )
    _append_audit_entry(
        actor_type="admin",
        actor_id=identity.oauth_subject,
        action="mcp_tool_register",
        request_path=f"/mcp/servers/{server_id}/tools",
        request_payload_hash=_hash_token(payload.model_dump_json()),
        request_payload_summary={"tool_id": tool_id, "server_id": server_id},
        decision=decision,
        decision_reason=decision_reason,
        decision_details=decision_details,
        mcp_server_id=server_id,
        mcp_tool_id=tool_id,
        mcp_tool_name=payload.tool_name,
        **audit_infrastructure_identity_fields(identity),
    )
    capture_infrastructure_identity_profile(
        store=_store,
        identity=identity,
        actor_type="admin",
        actor_id=identity.oauth_subject,
        event_type="admin_mutation",
        action="mcp_tool_register",
        request_path=f"/mcp/servers/{server_id}/tools",
    )
    return tool


@router.get("/mcp/quarantine")
def list_mcp_quarantine(authorization: str | None = Header(default=None, alias="Authorization")) -> list[dict[str, Any]]:
    _require_admin_identity(authorization)
    return [tool for tool in _store.list_mcp_tools() if tool["quarantine_status"] != "clear"]


@router.post("/mcp/quarantine/{tool_id}/review")
def review_mcp_tool(
    tool_id: str,
    request: Request,
    payload: MCPToolReviewRequest,
    authorization: str | None = Header(default=None, alias="Authorization"),
    infrastructure_assertion: str | None = Header(default=None, alias="X-Infrastructure-Assertion"),
    infrastructure_signature: str | None = Header(default=None, alias="X-Infrastructure-Signature"),
) -> dict[str, Any]:
    identity = _require_admin_identity(authorization, infrastructure_assertion, infrastructure_signature)
    require_trusted_infrastructure_identity_for_admin(identity)
    tool = _store.get_mcp_tool(tool_id)
    if tool is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"code": "MCP_TOOL_NOT_FOUND"})
    next_flags = tool["threat_flags"] if payload.quarantine_status != "clear" else []
    updated = _store.update_mcp_tool_quarantine(tool_id, payload.quarantine_status, next_flags)
    _append_audit_entry(
        actor_type="admin",
        actor_id=identity.oauth_subject,
        action="mcp_tool_review",
        request_path=f"/mcp/quarantine/{tool_id}/review",
        request_payload_hash=_hash_token(payload.model_dump_json()),
        request_payload_summary={"tool_id": tool_id, "quarantine_status": payload.quarantine_status},
        decision="updated",
        decision_reason=payload.reason,
        decision_details={"quarantine_status": payload.quarantine_status},
        mcp_tool_id=tool_id,
        mcp_tool_name=tool["tool_name"],
        mcp_server_id=tool["server_id"],
        **audit_infrastructure_identity_fields(identity),
    )
    capture_infrastructure_identity_profile(
        store=_store,
        identity=identity,
        actor_type="admin",
        actor_id=identity.oauth_subject,
        event_type="admin_mutation",
        action="mcp_tool_review",
        request_path=f"/mcp/quarantine/{tool_id}/review",
    )
    return updated
