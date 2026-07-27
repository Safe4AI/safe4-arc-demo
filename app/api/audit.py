from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Callable

from fastapi import APIRouter, Header, HTTPException, status

from ..storage import GENESIS_AUDIT_HASH, canonicalize_audit_entry


router = APIRouter()

_store = None
_compute_audit_entry_hash: Callable[[dict[str, Any]], str] | None = None
_get_current_identity = None
_ensure_scope: Callable[[Any, list[str]], Any] | None = None

AUDIT_EXPORT_VERIFICATION_METHOD = "sha256 hash-chain over canonical audit entries"
LEGAL_COMPLIANCE_PACKAGE_PROFILE = "legal_compliance"
LEGAL_COMPLIANCE_PACKAGE_SCHEMA_VERSION = "audit_export_package.legal_compliance.v1"
SUPPORTED_AUDIT_EXPORT_PACKAGE_PROFILES = [LEGAL_COMPLIANCE_PACKAGE_PROFILE]
AUDIT_CANONICAL_ENTRY_FIELDS = [
    "sequence_number",
    "timestamp",
    "previous_hash",
    "transaction_id",
    "actor_type",
    "actor_id",
    "action",
    "request_payload_hash",
    "policy_version",
    "decision",
    "transaction_amount",
    "transaction_currency",
    "decision_details",
    "mcp_server_id",
    "mcp_tool_id",
    "mcp_tool_name",
    "infrastructure_provider_name",
    "infrastructure_subject",
    "infrastructure_trust_tier",
]


def setup_audit_api(
    *,
    store: Any,
    compute_audit_entry_hash: Callable[[dict[str, Any]], str],
    get_current_identity: Callable[..., Any],
    ensure_scope: Callable[[Any, list[str]], Any],
) -> None:
    global _store, _compute_audit_entry_hash, _get_current_identity, _ensure_scope
    _store = store
    _compute_audit_entry_hash = compute_audit_entry_hash
    _get_current_identity = get_current_identity
    _ensure_scope = ensure_scope


def _require_audit_identity(authorization: str | None) -> Any:
    if _get_current_identity is None or _ensure_scope is None:
        raise RuntimeError("Audit API not configured")
    identity = _get_current_identity(authorization)
    return _ensure_scope(identity, ["audit:read"])


def filter_audit_entries(
    *,
    action: str | None = None,
    decision: str | None = None,
    actor_id: str | None = None,
    transaction_id: str | None = None,
    mcp_server_id: str | None = None,
    mcp_tool_id: str | None = None,
    infrastructure_provider_name: str | None = None,
    infrastructure_subject: str | None = None,
    request_hash: str | None = None,
) -> list[dict[str, Any]]:
    entries = _store.list_audit_entries()
    results: list[dict[str, Any]] = []
    for entry in entries:
        if action is not None and entry["action"] != action:
            continue
        if decision is not None and entry["decision"] != decision:
            continue
        if actor_id is not None and entry["actor_id"] != actor_id:
            continue
        if transaction_id is not None and entry.get("transaction_id") != transaction_id:
            continue
        if mcp_server_id is not None and entry["mcp_server_id"] != mcp_server_id:
            continue
        if mcp_tool_id is not None and entry["mcp_tool_id"] != mcp_tool_id:
            continue
        if infrastructure_provider_name is not None and entry["infrastructure_provider_name"] != infrastructure_provider_name:
            continue
        if infrastructure_subject is not None and entry["infrastructure_subject"] != infrastructure_subject:
            continue
        if request_hash is not None and entry["request_payload_hash"] != request_hash:
            continue
        results.append(entry)
    return results


def get_approval_trace_entries(approval_id: str) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for entry in _store.list_audit_entries():
        if entry["request_payload_summary"].get("approval_id") == approval_id:
            matches.append(entry)
            continue
        if entry["decision_details"].get("approval_id") == approval_id:
            matches.append(entry)
    return matches


def slice_audit_entries(start_sequence: int | None = None, end_sequence: int | None = None) -> list[dict[str, Any]]:
    entries = _store.list_audit_entries()
    results: list[dict[str, Any]] = []
    for entry in entries:
        if start_sequence is not None and entry["sequence_number"] < start_sequence:
            continue
        if end_sequence is not None and entry["sequence_number"] > end_sequence:
            continue
        results.append(entry)
    return results


def _resolve_segment_range(
    entries: list[dict[str, Any]],
    *,
    start_sequence: int | None = None,
    end_sequence: int | None = None,
) -> dict[str, int | None]:
    return {
        "start_sequence": start_sequence if start_sequence is not None else (entries[0]["sequence_number"] if entries else None),
        "end_sequence": end_sequence if end_sequence is not None else (entries[-1]["sequence_number"] if entries else None),
    }


def build_audit_report_payload(
    entries: list[dict[str, Any]],
    *,
    start_sequence: int | None = None,
    end_sequence: int | None = None,
) -> dict[str, Any]:
    verification = verify_chain_segment(entries)
    return {
        "range": _resolve_segment_range(entries, start_sequence=start_sequence, end_sequence=end_sequence),
        "entry_count": len(entries),
        "verification": verification,
        "head_entry_hash": entries[0]["entry_hash"] if entries else None,
        "tail_entry_hash": entries[-1]["entry_hash"] if entries else None,
        "verification_method": AUDIT_EXPORT_VERIFICATION_METHOD,
        "supported_export_package_profiles": SUPPORTED_AUDIT_EXPORT_PACKAGE_PROFILES,
    }


def _count_entry_values(values: list[str], *, key_name: str) -> list[dict[str, Any]]:
    counts = Counter(values)
    return [{key_name: value, "entry_count": counts[value]} for value in sorted(counts)]


def _build_actor_summary(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counts: Counter[tuple[str, str]] = Counter(
        (str(entry["actor_type"]), str(entry["actor_id"]))
        for entry in entries
    )
    return [
        {
            "actor_type": actor_type,
            "actor_id": actor_id,
            "entry_count": counts[(actor_type, actor_id)],
        }
        for actor_type, actor_id in sorted(counts)
    ]


def _unique_string_values(entries: list[dict[str, Any]], field_name: str) -> list[str]:
    return sorted({str(entry[field_name]) for entry in entries if entry.get(field_name)})


def _build_package_reviewer_context(entries: list[dict[str, Any]]) -> dict[str, Any]:
    actions = [str(entry["action"]) for entry in entries]
    decisions = [str(entry["decision"]) for entry in entries]
    request_hashes = [str(entry["request_payload_hash"]) for entry in entries if entry.get("request_payload_hash")]
    policy_versions = [str(entry["policy_version"]) for entry in entries if entry.get("policy_version")]
    return {
        "time_range": {
            "started_at": entries[0]["timestamp"] if entries else None,
            "ended_at": entries[-1]["timestamp"] if entries else None,
        },
        "actors": _build_actor_summary(entries),
        "actions": _count_entry_values(actions, key_name="action"),
        "decisions": _count_entry_values(decisions, key_name="decision"),
        "transaction_ids": _unique_string_values(entries, "transaction_id"),
        "request_hashes": sorted(set(request_hashes)),
        "policy_versions": sorted(set(policy_versions)),
        "mcp_server_ids": _unique_string_values(entries, "mcp_server_id"),
        "mcp_tool_ids": _unique_string_values(entries, "mcp_tool_id"),
        "infrastructure_provider_names": _unique_string_values(entries, "infrastructure_provider_name"),
        "infrastructure_subjects": _unique_string_values(entries, "infrastructure_subject"),
        "live_system_access_required": False,
        "scope_statement": (
            "This package proves integrity within the exported bounded segment and records "
            "the boundary hashes for offline review. Continuity outside the exported range "
            "still requires adjacent segment exports or full-chain access."
        ),
    }


def _build_package_integrity_proof(entries: list[dict[str, Any]]) -> dict[str, Any]:
    proof_records: list[dict[str, Any]] = []
    if entries:
        segment_start_previous_hash = entries[0]["previous_hash"]
        previous_hash = segment_start_previous_hash
        for index, entry in enumerate(entries):
            expected_previous_hash = previous_hash if index == 0 else entries[index - 1]["entry_hash"]
            canonical_entry = canonicalize_audit_entry(entry)
            recomputed_entry_hash = _compute_audit_entry_hash(entry)
            proof_records.append(
                {
                    "sequence_number": entry["sequence_number"],
                    "timestamp": entry["timestamp"],
                    "expected_previous_hash": expected_previous_hash,
                    "previous_hash": entry["previous_hash"],
                    "stored_entry_hash": entry["entry_hash"],
                    "recomputed_entry_hash": recomputed_entry_hash,
                    "previous_hash_matches": entry["previous_hash"] == expected_previous_hash,
                    "entry_hash_matches": recomputed_entry_hash == entry["entry_hash"],
                    "canonical_entry": canonical_entry,
                }
            )
    else:
        segment_start_previous_hash = None

    return {
        "hash_algorithm": "sha256",
        "algorithm_description": (
            "Hash each canonical_entry string with SHA-256, confirm the result matches "
            "stored_entry_hash, then confirm each previous_hash links to the prior entry "
            "hash or the segment start_previous_hash for the first entry."
        ),
        "canonicalization": {
            "format": "json",
            "sort_keys": True,
            "separators": [",", ":"],
            "decimal_encoding": "transaction_amount decimals are encoded as plain strings",
            "field_names": AUDIT_CANONICAL_ENTRY_FIELDS,
        },
        "segment_boundary": {
            "start_sequence": entries[0]["sequence_number"] if entries else None,
            "end_sequence": entries[-1]["sequence_number"] if entries else None,
            "start_previous_hash": segment_start_previous_hash,
            "head_entry_hash": entries[0]["entry_hash"] if entries else None,
            "tail_entry_hash": entries[-1]["entry_hash"] if entries else None,
            "anchored_to_genesis": None if not entries else segment_start_previous_hash == GENESIS_AUDIT_HASH,
            "genesis_hash": GENESIS_AUDIT_HASH,
        },
        "hash_links": proof_records,
        "offline_verification_steps": [
            "Hash each canonical_entry with SHA-256 and compare it to stored_entry_hash.",
            "Confirm each previous_hash matches expected_previous_hash.",
            "Confirm the first record anchors to start_previous_hash and the final record matches tail_entry_hash.",
            "Confirm the integrity_report verification result remains valid for the exported range.",
        ],
    }


def build_audit_export_package(
    entries: list[dict[str, Any]],
    *,
    package_profile: str,
    exported_at: str,
    integrity_report: dict[str, Any],
) -> dict[str, Any]:
    if package_profile != LEGAL_COMPLIANCE_PACKAGE_PROFILE:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail={
                "code": "INVALID_EXPORT_PACKAGE_PROFILE",
                "supported_profiles": SUPPORTED_AUDIT_EXPORT_PACKAGE_PROFILES,
            },
        )
    return {
        "profile": LEGAL_COMPLIANCE_PACKAGE_PROFILE,
        "schema_version": LEGAL_COMPLIANCE_PACKAGE_SCHEMA_VERSION,
        "prepared_at": exported_at,
        "prepared_from": {
            "export_endpoint": "/audit/export",
            "integrity_report_endpoint": "/audit/report",
            "bounded_export": True,
        },
        "integrity_report": integrity_report,
        "reviewer_context": _build_package_reviewer_context(entries),
        "integrity_proof": _build_package_integrity_proof(entries),
    }


def _serialize_siem_value(value: Any) -> Any:
    if isinstance(value, Decimal):
        return format(value, "f")
    if isinstance(value, dict):
        return {key: _serialize_siem_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_serialize_siem_value(item) for item in value]
    return value


def build_siem_audit_anomaly_export(
    *,
    audit_entries: list[dict[str, Any]],
    anomaly: dict[str, Any],
    anomaly_alert: dict[str, Any] | None = None,
) -> dict[str, Any]:
    serialized_entries = [_serialize_siem_value(item) for item in audit_entries]
    serialized_anomaly = _serialize_siem_value(anomaly)
    serialized_alert = None if anomaly_alert is None else _serialize_siem_value(anomaly_alert)

    request_hashes = sorted(
        {
            str(entry["request_payload_hash"])
            for entry in audit_entries
            if entry.get("request_payload_hash")
        }
    )
    actor_ids = sorted(
        {
            str(candidate)
            for candidate in [anomaly.get("actor_id"), *[entry.get("actor_id") for entry in audit_entries]]
            if candidate
        }
    )
    mcp_server_ids = sorted({str(entry["mcp_server_id"]) for entry in audit_entries if entry.get("mcp_server_id")})
    mcp_tool_ids = sorted({str(entry["mcp_tool_id"]) for entry in audit_entries if entry.get("mcp_tool_id")})
    start_sequence = audit_entries[0]["sequence_number"] if audit_entries else None
    end_sequence = audit_entries[-1]["sequence_number"] if audit_entries else None

    return {
        "schema_version": "siem_audit_anomaly_export.v1",
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "correlation": {
            "transaction_id": anomaly.get("transaction_id"),
            "anomaly_id": anomaly.get("anomaly_id"),
            "anomaly_alert_id": None if anomaly_alert is None else anomaly_alert.get("alert_id"),
            "request_hashes": request_hashes,
            "actor_ids": actor_ids,
            "provider_name": anomaly.get("provider_name"),
            "subject": anomaly.get("subject"),
            "mcp_server_ids": mcp_server_ids,
            "mcp_tool_ids": mcp_tool_ids,
        },
        "anomaly": serialized_anomaly,
        "anomaly_alert": serialized_alert,
        "audit_context": {
            "range": {
                "start_sequence": start_sequence,
                "end_sequence": end_sequence,
            },
            "entry_count": len(serialized_entries),
            "verification": verify_chain_segment(audit_entries),
            "verification_method": "sha256 hash-chain over canonical audit entries",
            "entries": serialized_entries,
        },
    }


def _extract_approval_id(entry: dict[str, Any]) -> str | None:
    return entry["request_payload_summary"].get("approval_id") or entry["decision_details"].get("approval_id")


POLICY_MUTATION_ACTIONS = {
    "agent_budget_upsert",
    "budget_upsert",
    "hitl_rule_upsert",
    "mcp_server_register",
    "mcp_server_trust_update",
    "mcp_tool_register",
    "mcp_tool_review",
    "policy_activate",
    "webhook_endpoint_upsert",
}
PERMISSION_ACTIONS = {
    "mcp_tool_permission_delete",
    "mcp_tool_permission_upsert",
    "oauth_authorize",
}
APPROVAL_ACTIONS = {
    "approval_alert_acknowledge",
    "approval_decide",
    "approval_request",
    "spend_token_revoke",
}
ANOMALY_ACTIONS = {
    "infrastructure_anomaly_alert_acknowledge",
    "infrastructure_identity_evaluate",
    "payment_anomaly_score",
}


def _build_audit_timeline_item(entry: dict[str, Any]) -> dict[str, Any]:
    summary = entry.get("request_payload_summary", {})
    return {
        "occurred_at": entry["timestamp"],
        "source_type": "audit",
        "event_type": entry["action"],
        "identifiers": {
            "audit_sequence": entry["sequence_number"],
            "transaction_id": entry.get("transaction_id"),
            "approval_id": _extract_approval_id(entry),
            "request_hash": entry["request_payload_hash"],
            "agent_id": entry["actor_id"] if entry["actor_type"] == "agent" else summary.get("agent_id"),
            "user_id": summary.get("user_id") or (entry["actor_id"] if entry["actor_type"] == "user" else None),
            "policy_version": entry.get("policy_version"),
            "mcp_server_id": entry.get("mcp_server_id"),
            "mcp_tool_id": entry.get("mcp_tool_id"),
            "anomaly_id": entry.get("decision_details", {}).get("anomaly_id"),
        },
        "payload": entry,
    }


def _is_terminal_payment_entry(entry: dict[str, Any]) -> bool:
    return entry["action"] == "payment_authorize" and entry["decision"] in {"authorized", "denied"}


def _trace_request_hashes(transaction_entries: list[dict[str, Any]]) -> set[str]:
    return {
        str(entry["request_payload_hash"])
        for entry in transaction_entries
        if entry.get("request_payload_hash") and entry.get("request_path") == "/pay"
    }


def _extract_trace_ids(entries: list[dict[str, Any]]) -> dict[str, set[str]]:
    approval_ids: set[str] = set()
    mandate_ids: set[str] = set()
    receipt_ids: set[str] = set()
    for entry in entries:
        approval_id = _extract_approval_id(entry)
        if approval_id:
            approval_ids.add(str(approval_id))

        summary = entry.get("request_payload_summary", {})
        for candidate in (summary.get("mandate_id"), summary.get("ap2_mandate_id")):
            if candidate:
                mandate_ids.add(str(candidate))

        details = entry.get("decision_details", {})
        parsed_mandate = details.get("parsed_mandate")
        if isinstance(parsed_mandate, dict):
            mandate_id = parsed_mandate.get("mandate_id")
            if mandate_id:
                mandate_ids.add(str(mandate_id))

        for candidate in (details.get("receipt_id"), details.get("receipt")):
            if candidate:
                receipt_ids.add(str(candidate))

    return {
        "approval_ids": approval_ids,
        "mandate_ids": mandate_ids,
        "receipt_ids": receipt_ids,
    }


def _windowed_request_trace_entries(request_hash: str, *, terminal_sequence: int) -> list[dict[str, Any]]:
    matches = filter_audit_entries(request_hash=request_hash)
    cutoff_sequence = 0
    for entry in matches:
        if entry["sequence_number"] >= terminal_sequence:
            break
        if _is_terminal_payment_entry(entry):
            cutoff_sequence = entry["sequence_number"]
    return [
        entry
        for entry in matches
        if cutoff_sequence < entry["sequence_number"] <= terminal_sequence
    ]


def _build_trace_stage_records(
    *,
    transaction_id: str,
    approval_ids: set[str],
    mandate_ids: set[str],
    receipt_ids: set[str],
) -> list[dict[str, Any]]:
    records: dict[tuple[str, str], dict[str, Any]] = {}

    for approval_id in sorted(approval_ids):
        approval = _store.get_approval_request(approval_id)
        if approval is None:
            continue
        records[("approval_request", approval_id)] = {
            "occurred_at": approval["created_at"],
            "source_type": "approval_request",
            "event_type": approval["status"],
            "identifiers": {
                "transaction_id": transaction_id,
                "approval_id": approval["approval_id"],
                "request_hash": approval["request_hash"],
                "agent_id": approval["requestor_agent_id"],
                "user_id": approval["requestor_user_id"],
                "mcp_tool_id": approval["mcp_tool_id"],
            },
            "payload": _serialize_siem_value(approval),
        }

    for mandate_id in sorted(mandate_ids):
        mandate = _store.get_ap2_mandate(mandate_id)
        if mandate is None:
            continue
        records[("ap2_mandate", mandate_id)] = {
            "occurred_at": mandate["updated_at"],
            "source_type": "ap2_mandate",
            "event_type": mandate["verification_status"],
            "identifiers": {
                "transaction_id": transaction_id,
                "request_hash": mandate["request_hash"],
                "mandate_id": mandate["mandate_id"],
                "family_id": mandate["family_id"],
                "parent_mandate_id": mandate["parent_mandate_id"],
            },
            "payload": _serialize_siem_value(mandate),
        }

    for receipt_id in sorted(receipt_ids):
        receipt = _store.get_x402_provider_receipt(receipt_id)
        if receipt is None:
            continue
        records[("x402_provider_receipt", receipt_id)] = {
            "occurred_at": receipt["updated_at"],
            "source_type": "x402_provider_receipt",
            "event_type": receipt["verification_status"],
            "identifiers": {
                "transaction_id": transaction_id,
                "receipt_id": receipt["receipt_id"],
                "provider_name": receipt["provider_name"],
                "network": receipt["network"],
            },
            "payload": _serialize_siem_value(receipt),
        }

    for anomaly in _store.list_infrastructure_identity_anomalies(transaction_id=transaction_id):
        records[("infrastructure_anomaly", anomaly["anomaly_id"])] = {
            "occurred_at": anomaly["created_at"],
            "source_type": "infrastructure_anomaly",
            "event_type": anomaly["severity"],
            "identifiers": {
                "transaction_id": transaction_id,
                "anomaly_id": anomaly["anomaly_id"],
                "agent_id": anomaly["actor_id"],
                "provider_name": anomaly["provider_name"],
                "subject": anomaly["subject"],
            },
            "payload": _serialize_siem_value(anomaly),
        }

    return sorted(records.values(), key=lambda item: (item["occurred_at"], item["source_type"]))


def build_transaction_trace(transaction_id: str) -> dict[str, Any] | None:
    transaction_entries = filter_audit_entries(transaction_id=transaction_id)
    if not transaction_entries:
        return None

    terminal_candidates = [entry for entry in transaction_entries if _is_terminal_payment_entry(entry)]
    terminal_entry = min(
        terminal_candidates or transaction_entries,
        key=lambda entry: entry["sequence_number"],
    )
    terminal_sequence = terminal_entry["sequence_number"]

    related_entries: dict[int, dict[str, Any]] = {
        entry["sequence_number"]: entry for entry in transaction_entries
    }
    request_hashes = _trace_request_hashes(transaction_entries)
    for request_hash in request_hashes:
        for entry in _windowed_request_trace_entries(request_hash, terminal_sequence=terminal_sequence):
            related_entries.setdefault(entry["sequence_number"], entry)

    trace_entries = sorted(related_entries.values(), key=lambda entry: entry["sequence_number"])
    trace_ids = _extract_trace_ids(trace_entries)
    for approval_id in trace_ids["approval_ids"]:
        for entry in get_approval_trace_entries(approval_id):
            related_entries.setdefault(entry["sequence_number"], entry)

    trace_entries = sorted(related_entries.values(), key=lambda entry: entry["sequence_number"])
    trace_ids = _extract_trace_ids(trace_entries)
    stage_records = _build_trace_stage_records(
        transaction_id=transaction_id,
        approval_ids=trace_ids["approval_ids"],
        mandate_ids=trace_ids["mandate_ids"],
        receipt_ids=trace_ids["receipt_ids"],
    )
    return {
        "transaction_id": transaction_id,
        "correlation": {
            "request_hashes": sorted(request_hashes),
            "approval_ids": sorted(trace_ids["approval_ids"]),
            "ap2_mandate_ids": sorted(trace_ids["mandate_ids"]),
            "x402_receipt_ids": sorted(trace_ids["receipt_ids"]),
        },
        "entries": trace_entries,
        "stage_records": stage_records,
    }


def build_entity_timeline(
    *,
    transaction_id: str | None = None,
    approval_id: str | None = None,
    request_hash: str | None = None,
    user_id: str | None = None,
    agent_id: str | None = None,
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    transaction_trace = build_transaction_trace(transaction_id) if transaction_id is not None else None
    audit_source_entries = transaction_trace["entries"] if transaction_trace is not None else _store.list_audit_entries()
    trace_approval_ids = (
        set(transaction_trace["correlation"]["approval_ids"]) if transaction_trace is not None else set()
    )

    for entry in audit_source_entries:
        if transaction_id is not None and transaction_trace is None and entry.get("transaction_id") != transaction_id:
            continue
        if approval_id is not None:
            has_approval_id = (
                entry["request_payload_summary"].get("approval_id") == approval_id
                or entry["decision_details"].get("approval_id") == approval_id
            )
            if not has_approval_id:
                continue
        if request_hash is not None and entry["request_payload_hash"] != request_hash:
            continue
        if user_id is not None and entry["request_payload_summary"].get("user_id") != user_id:
            continue
        if agent_id is not None and entry["actor_id"] != agent_id and entry["request_payload_summary"].get("agent_id") != agent_id:
            continue
        items.append(_build_audit_timeline_item(entry))

    for log_entry in _store.list_logs():
        if transaction_id is not None and log_entry.get("transaction_id") != transaction_id:
            continue
        if request_hash is not None or approval_id is not None:
            continue
        if user_id is not None and log_entry["user_id"] != user_id:
            continue
        if agent_id is not None and log_entry["agent_id"] != agent_id:
            continue
        items.append(
            {
                "occurred_at": log_entry["timestamp"],
                "source_type": "log",
                "event_type": log_entry["result"],
                "identifiers": {
                    "transaction_id": log_entry.get("transaction_id"),
                    "request_id": log_entry["request_id"],
                    "agent_id": log_entry["agent_id"],
                    "user_id": log_entry["user_id"],
                },
                "payload": log_entry,
            }
        )

    for approval in _store.list_approval_requests():
        if approval_id is not None and approval["approval_id"] != approval_id:
            continue
        if request_hash is not None and approval["request_hash"] != request_hash:
            continue
        if user_id is not None and approval["requestor_user_id"] != user_id:
            continue
        if agent_id is not None and approval["requestor_agent_id"] != agent_id:
            continue
        if transaction_id is not None:
            continue
        items.append(
            {
                "occurred_at": approval["created_at"],
                "source_type": "approval_request",
                "event_type": approval["status"],
                "identifiers": {
                    "approval_id": approval["approval_id"],
                    "request_hash": approval["request_hash"],
                    "agent_id": approval["requestor_agent_id"],
                    "user_id": approval["requestor_user_id"],
                    "mcp_tool_id": approval["mcp_tool_id"],
                },
                "payload": approval,
            }
        )

    if transaction_trace is not None:
        items.extend(transaction_trace["stage_records"])

    matched_budget_alerts: list[dict[str, Any]] = []
    for alert in _store.list_budget_alerts():
        if transaction_id is not None and alert["trigger_details"].get("transaction_id") != transaction_id:
            continue
        if user_id is not None and not (
            alert["entity_id"] == user_id or alert["trigger_details"].get("user_id") == user_id
        ):
            continue
        if agent_id is not None and alert["trigger_details"].get("agent_id") != agent_id:
            continue
        if approval_id is not None or request_hash is not None:
            continue
        matched_budget_alerts.append(alert)
        items.append(
            {
                "occurred_at": alert["created_at"],
                "source_type": "budget_alert",
                "event_type": alert["trigger_source"],
                "identifiers": {
                    "alert_id": alert["alert_id"],
                    "transaction_id": alert["trigger_details"].get("transaction_id"),
                    "agent_id": alert["trigger_details"].get("agent_id"),
                    "user_id": alert["trigger_details"].get("user_id"),
                },
                "payload": alert,
            }
        )

    matched_approval_alerts: list[dict[str, Any]] = []
    for alert in _store.list_approval_alerts():
        if transaction_id is not None and alert["approval_id"] not in trace_approval_ids:
            continue
        if approval_id is not None and alert["approval_id"] != approval_id:
            continue
        if request_hash is not None and alert["request_hash"] != request_hash:
            continue
        if user_id is not None and alert["requestor_user_id"] != user_id:
            continue
        if agent_id is not None and alert["requestor_agent_id"] != agent_id:
            continue
        matched_approval_alerts.append(alert)
        items.append(
            {
                "occurred_at": alert["created_at"],
                "source_type": "approval_alert",
                "event_type": alert["alert_type"],
                "identifiers": {
                    "alert_id": alert["alert_id"],
                    "approval_id": alert["approval_id"],
                    "request_hash": alert["request_hash"],
                    "agent_id": alert["requestor_agent_id"],
                    "user_id": alert["requestor_user_id"],
                    "mcp_tool_id": alert["mcp_tool_id"],
                },
                "payload": alert,
            }
        )

    matched_anomaly_alerts: list[dict[str, Any]] = []
    for alert in _store.list_infrastructure_identity_anomaly_alerts():
        if transaction_id is not None and alert["transaction_id"] != transaction_id:
            continue
        if agent_id is not None and alert["actor_id"] != agent_id:
            continue
        if approval_id is not None or request_hash is not None:
            continue
        matched_anomaly_alerts.append(alert)
        items.append(
            {
                "occurred_at": alert["created_at"],
                "source_type": "infrastructure_anomaly_alert",
                "event_type": alert["severity"],
                "identifiers": {
                    "alert_id": alert["alert_id"],
                    "anomaly_id": alert["anomaly_id"],
                    "transaction_id": alert["transaction_id"],
                    "agent_id": alert["actor_id"],
                },
                "payload": alert,
            }
        )

    matched_siem_exports: list[dict[str, Any]] = []
    for export in _store.list_siem_exports():
        if transaction_id is not None and export["transaction_id"] != transaction_id:
            continue
        if agent_id is not None and export["actor_id"] != agent_id:
            continue
        if approval_id is not None or request_hash is not None:
            continue
        matched_siem_exports.append(export)
        items.append(
            {
                "occurred_at": export["created_at"],
                "source_type": "siem_export",
                "event_type": export["export_type"],
                "identifiers": {
                    "export_id": export["export_id"],
                    "transaction_id": export["transaction_id"],
                    "anomaly_id": export["anomaly_id"],
                    "agent_id": export["actor_id"],
                },
                "payload": export,
            }
        )

    delivery_targets: set[tuple[str, str]] = set()
    for alert in matched_budget_alerts:
        delivery_targets.add(("budget", alert["alert_id"]))
    for alert in matched_approval_alerts:
        delivery_targets.add(("approval", alert["alert_id"]))
    for alert in matched_anomaly_alerts:
        delivery_targets.add(("anomaly", alert["alert_id"]))
    for export in matched_siem_exports:
        delivery_targets.add(("siem", export["export_id"]))
    for delivery in _store.list_webhook_delivery_attempts():
        if delivery_targets and (delivery["alert_source"], delivery["alert_id"]) not in delivery_targets:
            continue
        if not delivery_targets:
            continue
        items.append(
            {
                "occurred_at": delivery["created_at"],
                "source_type": "webhook_delivery",
                "event_type": delivery["delivery_status"],
                "identifiers": {
                    "alert_source": delivery["alert_source"],
                    "alert_id": delivery["alert_id"],
                    "endpoint_id": delivery["endpoint_id"],
                },
                "payload": delivery,
            }
        )

    items.sort(key=lambda item: item["occurred_at"])
    return items


def _classify_audit_reference_type(entry: dict[str, Any]) -> str:
    action = entry["action"]
    request_path = entry["request_path"]
    if action in PERMISSION_ACTIONS or request_path.startswith("/mcp/permissions") or request_path.startswith("/oauth/authorize"):
        return "permission"
    if action in POLICY_MUTATION_ACTIONS:
        return "policy_mutation"
    if action in APPROVAL_ACTIONS or request_path.startswith("/approvals") or request_path.startswith("/approval-alerts") or request_path.startswith("/tokens"):
        return "approval"
    if action in ANOMALY_ACTIONS or request_path.startswith("/phase3/infrastructure/anomaly-alerts"):
        return "anomaly"
    if action == "webhook_dispatch" or request_path.startswith("/webhooks/dispatch"):
        return "webhook_delivery"
    return "transaction"


def _classify_timeline_reference_type(item: dict[str, Any]) -> str:
    source_type = item["source_type"]
    if source_type == "audit":
        return _classify_audit_reference_type(item["payload"])
    if source_type in {"approval_alert", "approval_request"}:
        return "approval"
    if source_type in {"infrastructure_anomaly", "infrastructure_anomaly_alert"}:
        return "anomaly"
    if source_type == "siem_export":
        return "siem_export"
    if source_type == "webhook_delivery":
        return "webhook_delivery"
    return "transaction"


def _annotate_investigation_item(item: dict[str, Any]) -> dict[str, Any]:
    annotated = dict(item)
    annotated["reference_type"] = _classify_timeline_reference_type(item)
    return annotated


def _timeline_item_identity(item: dict[str, Any]) -> tuple[str, str]:
    identifiers = item.get("identifiers", {})
    for key in (
        "audit_sequence",
        "attempt_id",
        "export_id",
        "alert_id",
        "approval_id",
        "mandate_id",
        "receipt_id",
        "anomaly_id",
        "request_id",
    ):
        if identifiers.get(key):
            return (item["source_type"], f"{key}:{identifiers[key]}")
    payload = item.get("payload", {})
    if isinstance(payload, dict):
        for key in (
            "sequence_number",
            "attempt_id",
            "export_id",
            "alert_id",
            "approval_id",
            "mandate_id",
            "receipt_id",
            "anomaly_id",
            "request_id",
        ):
            if payload.get(key):
                return (item["source_type"], f"{key}:{payload[key]}")
    return (item["source_type"], f"{item['event_type']}:{item['occurred_at']}")


def _parse_filter_values(raw_value: str | None) -> set[str] | None:
    if raw_value is None:
        return None
    values = {item.strip() for item in raw_value.split(",") if item.strip()}
    return values or None


def _new_cross_reference_context() -> dict[str, set[str]]:
    return {
        "agent_ids": set(),
        "anomaly_alert_ids": set(),
        "anomaly_ids": set(),
        "approval_alert_ids": set(),
        "approval_ids": set(),
        "budget_alert_ids": set(),
        "mcp_server_ids": set(),
        "mcp_tool_ids": set(),
        "policy_versions": set(),
        "request_hashes": set(),
        "siem_export_ids": set(),
        "transaction_ids": set(),
        "user_ids": set(),
    }


def _add_context_value(context: dict[str, set[str]], key: str, value: Any) -> None:
    if value is None:
        return
    text = str(value).strip()
    if text:
        context[key].add(text)


def _collect_context_from_audit_entry(context: dict[str, set[str]], entry: dict[str, Any]) -> None:
    summary = entry.get("request_payload_summary", {})
    details = entry.get("decision_details", {})
    _add_context_value(context, "transaction_ids", entry.get("transaction_id"))
    _add_context_value(context, "approval_ids", _extract_approval_id(entry))
    _add_context_value(context, "request_hashes", entry.get("request_payload_hash"))
    _add_context_value(context, "policy_versions", entry.get("policy_version"))
    _add_context_value(context, "mcp_server_ids", entry.get("mcp_server_id"))
    _add_context_value(context, "mcp_tool_ids", entry.get("mcp_tool_id"))
    _add_context_value(context, "anomaly_ids", details.get("anomaly_id"))
    _add_context_value(context, "agent_ids", summary.get("agent_id"))
    _add_context_value(context, "user_ids", summary.get("user_id"))
    if entry["actor_type"] == "agent":
        _add_context_value(context, "agent_ids", entry["actor_id"])
    if entry["actor_type"] == "user":
        _add_context_value(context, "user_ids", entry["actor_id"])


def _collect_context_from_timeline_item(context: dict[str, set[str]], item: dict[str, Any]) -> None:
    identifiers = item.get("identifiers", {})
    _add_context_value(context, "transaction_ids", identifiers.get("transaction_id"))
    _add_context_value(context, "approval_ids", identifiers.get("approval_id"))
    _add_context_value(context, "request_hashes", identifiers.get("request_hash"))
    _add_context_value(context, "agent_ids", identifiers.get("agent_id"))
    _add_context_value(context, "user_ids", identifiers.get("user_id"))
    _add_context_value(context, "mcp_server_ids", identifiers.get("mcp_server_id"))
    _add_context_value(context, "mcp_tool_ids", identifiers.get("mcp_tool_id"))
    _add_context_value(context, "policy_versions", identifiers.get("policy_version"))
    _add_context_value(context, "anomaly_ids", identifiers.get("anomaly_id"))
    payload = item.get("payload", {})
    if item["source_type"] == "audit":
        _collect_context_from_audit_entry(context, payload)
    elif item["source_type"] == "approval_alert":
        _add_context_value(context, "approval_alert_ids", payload.get("alert_id"))
    elif item["source_type"] == "budget_alert":
        _add_context_value(context, "budget_alert_ids", payload.get("alert_id"))
    elif item["source_type"] == "infrastructure_anomaly":
        _add_context_value(context, "anomaly_ids", payload.get("anomaly_id"))
        _add_context_value(context, "agent_ids", payload.get("actor_id"))
    elif item["source_type"] == "infrastructure_anomaly_alert":
        _add_context_value(context, "anomaly_alert_ids", payload.get("alert_id"))
        _add_context_value(context, "anomaly_ids", payload.get("anomaly_id"))
        _add_context_value(context, "agent_ids", payload.get("actor_id"))
    elif item["source_type"] == "siem_export":
        _add_context_value(context, "siem_export_ids", payload.get("export_id"))
        _add_context_value(context, "anomaly_ids", payload.get("anomaly_id"))
        _add_context_value(context, "agent_ids", payload.get("actor_id"))
    elif item["source_type"] == "approval_request":
        _add_context_value(context, "mcp_tool_ids", payload.get("mcp_tool_id"))
    elif item["source_type"] == "x402_provider_receipt":
        _add_context_value(context, "mcp_server_ids", payload.get("provider_name"))


def _expand_cross_reference_context(context: dict[str, set[str]]) -> None:
    for transaction_id in list(context["transaction_ids"]):
        trace = build_transaction_trace(transaction_id)
        if trace is None:
            continue
        for request_hash in trace["correlation"]["request_hashes"]:
            _add_context_value(context, "request_hashes", request_hash)
        for approval_id in trace["correlation"]["approval_ids"]:
            _add_context_value(context, "approval_ids", approval_id)
        for entry in trace["entries"]:
            _collect_context_from_audit_entry(context, entry)
        for record in trace["stage_records"]:
            _collect_context_from_timeline_item(context, record)

    for approval_id in list(context["approval_ids"]):
        approval = _store.get_approval_request(approval_id)
        if approval is not None:
            _add_context_value(context, "request_hashes", approval.get("request_hash"))
            _add_context_value(context, "agent_ids", approval.get("requestor_agent_id"))
            _add_context_value(context, "user_ids", approval.get("requestor_user_id"))
            _add_context_value(context, "mcp_tool_ids", approval.get("mcp_tool_id"))
        for entry in get_approval_trace_entries(approval_id):
            _collect_context_from_audit_entry(context, entry)

    for request_hash in list(context["request_hashes"]):
        for entry in filter_audit_entries(request_hash=request_hash):
            _collect_context_from_audit_entry(context, entry)


def _context_has_value(context: dict[str, set[str]], key: str, value: Any) -> bool:
    return value is not None and str(value) in context[key]


def _audit_entry_matches_cross_reference(entry: dict[str, Any], context: dict[str, set[str]]) -> bool:
    summary = entry.get("request_payload_summary", {})
    approval_id = _extract_approval_id(entry)
    if _context_has_value(context, "transaction_ids", entry.get("transaction_id")):
        return True
    if _context_has_value(context, "request_hashes", entry.get("request_payload_hash")):
        return True
    if _context_has_value(context, "approval_ids", approval_id):
        return True
    if entry["actor_type"] == "agent" and _context_has_value(context, "agent_ids", entry["actor_id"]):
        return True
    if entry["actor_type"] == "user" and _context_has_value(context, "user_ids", entry["actor_id"]):
        return True
    if _context_has_value(context, "agent_ids", summary.get("agent_id")):
        return True
    if _context_has_value(context, "user_ids", summary.get("user_id")):
        return True

    reference_type = _classify_audit_reference_type(entry)
    if reference_type == "policy_mutation":
        return any(
            [
                _context_has_value(context, "policy_versions", entry.get("policy_version")),
                _context_has_value(context, "mcp_server_ids", entry.get("mcp_server_id")),
                _context_has_value(context, "mcp_tool_ids", entry.get("mcp_tool_id")),
                _context_has_value(context, "policy_versions", summary.get("version")),
                _context_has_value(context, "agent_ids", summary.get("agent_id")),
                _context_has_value(context, "user_ids", summary.get("user_id")),
            ]
        )
    if reference_type == "permission":
        return any(
            [
                _context_has_value(context, "user_ids", summary.get("user_id")),
                _context_has_value(context, "mcp_tool_ids", entry.get("mcp_tool_id")),
                entry["actor_type"] == "user" and _context_has_value(context, "user_ids", entry["actor_id"]),
            ]
        )
    return False


def _build_request_reference(request_hash: str) -> dict[str, Any] | None:
    entries = filter_audit_entries(request_hash=request_hash)
    if not entries:
        return None
    trace_ids = _extract_trace_ids(entries)
    transaction_ids = sorted({str(entry["transaction_id"]) for entry in entries if entry.get("transaction_id")})
    agent_ids = sorted(
        {
            str(candidate)
            for candidate in [
                *[entry["actor_id"] for entry in entries if entry["actor_type"] == "agent"],
                *[entry["request_payload_summary"].get("agent_id") for entry in entries],
            ]
            if candidate
        }
    )
    user_ids = sorted(
        {
            str(candidate)
            for candidate in [
                *[entry["actor_id"] for entry in entries if entry["actor_type"] == "user"],
                *[entry["request_payload_summary"].get("user_id") for entry in entries],
            ]
            if candidate
        }
    )
    return {
        "request_hash": request_hash,
        "started_at": entries[0]["timestamp"],
        "ended_at": entries[-1]["timestamp"],
        "entry_count": len(entries),
        "transaction_ids": transaction_ids,
        "approval_ids": sorted(trace_ids["approval_ids"]),
        "ap2_mandate_ids": sorted(trace_ids["mandate_ids"]),
        "x402_receipt_ids": sorted(trace_ids["receipt_ids"]),
        "agent_ids": agent_ids,
        "user_ids": user_ids,
        "decisions": sorted({entry["decision"] for entry in entries}),
    }


def _build_approval_reference(approval_id: str, approval_alerts: list[dict[str, Any]]) -> dict[str, Any] | None:
    approval = _store.get_approval_request(approval_id)
    trace_entries = get_approval_trace_entries(approval_id)
    if approval is None and not trace_entries:
        return None
    related_alerts = [alert for alert in approval_alerts if alert["approval_id"] == approval_id]
    return {
        "approval_id": approval_id,
        "status": None if approval is None else approval["status"],
        "request_hash": None if approval is None else approval["request_hash"],
        "requestor_agent_id": None if approval is None else approval["requestor_agent_id"],
        "requestor_user_id": None if approval is None else approval["requestor_user_id"],
        "mcp_tool_id": None if approval is None else approval["mcp_tool_id"],
        "created_at": None if approval is None else approval["created_at"],
        "decided_at": None if approval is None else approval["decided_at"],
        "decision_reason": None if approval is None else approval["decision_reason"],
        "trace_entry_count": len(trace_entries),
        "trace_actions": sorted({entry["action"] for entry in trace_entries}),
        "alert_ids": [alert["alert_id"] for alert in related_alerts],
        "alert_types": sorted({alert["alert_type"] for alert in related_alerts}),
    }


def _build_transaction_reference(
    transaction_id: str,
    anomalies: list[dict[str, Any]],
    anomaly_alerts: list[dict[str, Any]],
    siem_exports: list[dict[str, Any]],
    webhook_deliveries: list[dict[str, Any]],
) -> dict[str, Any] | None:
    trace = build_transaction_trace(transaction_id)
    if trace is None:
        return None
    payment_entries = [
        entry for entry in trace["entries"] if entry.get("transaction_id") == transaction_id and entry["action"] == "payment_authorize"
    ]
    final_entry = payment_entries[-1] if payment_entries else trace["entries"][-1]
    related_anomalies = [item for item in anomalies if item["transaction_id"] == transaction_id]
    related_anomaly_alerts = [item for item in anomaly_alerts if item["transaction_id"] == transaction_id]
    related_exports = [item for item in siem_exports if item["transaction_id"] == transaction_id]
    delivery_targets = {
        ("anomaly", item["alert_id"]) for item in related_anomaly_alerts
    } | {
        ("siem", item["export_id"]) for item in related_exports
    }
    related_deliveries = [
        item for item in webhook_deliveries if (item["alert_source"], item["alert_id"]) in delivery_targets
    ]
    stage_record_counts: dict[str, int] = {}
    for record in trace["stage_records"]:
        stage_record_counts[record["source_type"]] = stage_record_counts.get(record["source_type"], 0) + 1
    return {
        "transaction_id": transaction_id,
        "started_at": trace["entries"][0]["timestamp"],
        "ended_at": trace["entries"][-1]["timestamp"],
        "final_action": final_entry["action"],
        "final_decision": final_entry["decision"],
        "policy_versions": sorted({entry["policy_version"] for entry in trace["entries"] if entry.get("policy_version")}),
        "correlation": trace["correlation"],
        "entry_count": len(trace["entries"]),
        "stage_record_count": len(trace["stage_records"]),
        "stage_record_counts": stage_record_counts,
        "anomaly_ids": [item["anomaly_id"] for item in related_anomalies],
        "anomaly_alert_ids": [item["alert_id"] for item in related_anomaly_alerts],
        "siem_export_ids": [item["export_id"] for item in related_exports],
        "webhook_delivery_count": len(related_deliveries),
    }


def _build_audit_reference(entry: dict[str, Any]) -> dict[str, Any]:
    return {
        "sequence_number": entry["sequence_number"],
        "occurred_at": entry["timestamp"],
        "reference_type": _classify_audit_reference_type(entry),
        "action": entry["action"],
        "actor_type": entry["actor_type"],
        "actor_id": entry["actor_id"],
        "decision": entry["decision"],
        "decision_reason": entry.get("decision_reason"),
        "policy_version": entry.get("policy_version"),
        "request_path": entry["request_path"],
        "request_payload_hash": entry["request_payload_hash"],
        "request_payload_summary": _serialize_siem_value(entry["request_payload_summary"]),
        "decision_details": _serialize_siem_value(entry["decision_details"]),
        "transaction_id": entry.get("transaction_id"),
        "mcp_server_id": entry.get("mcp_server_id"),
        "mcp_tool_id": entry.get("mcp_tool_id"),
    }


def _build_infrastructure_anomaly_alert_timeline_item(alert: dict[str, Any]) -> dict[str, Any]:
    return {
        "occurred_at": alert["created_at"],
        "source_type": "infrastructure_anomaly_alert",
        "event_type": alert["severity"],
        "identifiers": {
            "alert_id": alert["alert_id"],
            "anomaly_id": alert["anomaly_id"],
            "transaction_id": alert["transaction_id"],
            "agent_id": alert["actor_id"],
        },
        "payload": _serialize_siem_value(alert),
    }


def _build_siem_export_timeline_item(export: dict[str, Any]) -> dict[str, Any]:
    return {
        "occurred_at": export["created_at"],
        "source_type": "siem_export",
        "event_type": export["export_type"],
        "identifiers": {
            "export_id": export["export_id"],
            "transaction_id": export["transaction_id"],
            "anomaly_id": export["anomaly_id"],
            "agent_id": export["actor_id"],
        },
        "payload": _serialize_siem_value(export),
    }


def _build_webhook_delivery_timeline_item(delivery: dict[str, Any]) -> dict[str, Any]:
    return {
        "occurred_at": delivery["created_at"],
        "source_type": "webhook_delivery",
        "event_type": delivery["delivery_status"],
        "identifiers": {
            "attempt_id": delivery["attempt_id"],
            "alert_source": delivery["alert_source"],
            "alert_id": delivery["alert_id"],
            "endpoint_id": delivery["endpoint_id"],
        },
        "payload": _serialize_siem_value(delivery),
    }


def build_cross_reference(
    *,
    user_id: str | None = None,
    agent_id: str | None = None,
    transaction_id: str | None = None,
    approval_id: str | None = None,
    request_hash: str | None = None,
    source_type_filter: str | None = None,
    reference_type_filter: str | None = None,
) -> dict[str, Any] | None:
    base_entries = build_entity_timeline(
        transaction_id=transaction_id,
        approval_id=approval_id,
        request_hash=request_hash,
        user_id=user_id,
        agent_id=agent_id,
    )
    if not base_entries:
        return None

    context = _new_cross_reference_context()
    for key, value in (
        ("user_ids", user_id),
        ("agent_ids", agent_id),
        ("transaction_ids", transaction_id),
        ("approval_ids", approval_id),
        ("request_hashes", request_hash),
    ):
        _add_context_value(context, key, value)
    for item in base_entries:
        _collect_context_from_timeline_item(context, item)
    _expand_cross_reference_context(context)
    existing_item_keys = {_timeline_item_identity(item) for item in base_entries}

    for related_transaction_id in sorted(context["transaction_ids"]):
        trace = build_transaction_trace(related_transaction_id)
        if trace is None:
            continue
        for record in trace["stage_records"]:
            record_key = _timeline_item_identity(record)
            if record_key in existing_item_keys:
                continue
            base_entries.append(record)
            existing_item_keys.add(record_key)
            _collect_context_from_timeline_item(context, record)
        for alert in _store.list_infrastructure_identity_anomaly_alerts(transaction_id=related_transaction_id):
            item = _build_infrastructure_anomaly_alert_timeline_item(alert)
            item_key = _timeline_item_identity(item)
            if item_key in existing_item_keys:
                continue
            base_entries.append(item)
            existing_item_keys.add(item_key)
            _collect_context_from_timeline_item(context, item)
        for export in _store.list_siem_exports(transaction_id=related_transaction_id):
            item = _build_siem_export_timeline_item(export)
            item_key = _timeline_item_identity(item)
            if item_key in existing_item_keys:
                continue
            base_entries.append(item)
            existing_item_keys.add(item_key)
            _collect_context_from_timeline_item(context, item)

    matched_audit_entries = [
        entry for entry in _store.list_audit_entries() if _audit_entry_matches_cross_reference(entry, context)
    ]
    for entry in matched_audit_entries:
        item = _build_audit_timeline_item(entry)
        item_key = _timeline_item_identity(item)
        if item_key in existing_item_keys:
            continue
        base_entries.append(item)
        existing_item_keys.add(item_key)
        _collect_context_from_timeline_item(context, item)

    approval_alerts = [
        alert
        for alert in _store.list_approval_alerts()
        if alert["approval_id"] in context["approval_ids"]
    ]
    anomaly_alerts = [
        _serialize_siem_value(alert)
        for alert in _store.list_infrastructure_identity_anomaly_alerts()
        if alert["transaction_id"] in context["transaction_ids"] or alert["actor_id"] in context["agent_ids"]
    ]
    anomaly_alerts.sort(key=lambda item: item["created_at"])
    anomalies = [
        _serialize_siem_value(item)
        for item in _store.list_infrastructure_identity_anomalies()
        if item["transaction_id"] in context["transaction_ids"] or item["actor_id"] in context["agent_ids"]
    ]
    anomalies.sort(key=lambda item: item["created_at"])
    siem_exports = [
        _serialize_siem_value(item)
        for item in _store.list_siem_exports()
        if item["transaction_id"] in context["transaction_ids"] or item["actor_id"] in context["agent_ids"]
    ]
    siem_exports.sort(key=lambda item: item["created_at"])

    current_permissions: dict[tuple[str, str], dict[str, Any]] = {}
    for related_user_id in sorted(context["user_ids"]):
        for permission in _store.list_mcp_tool_permissions(user_id=related_user_id):
            if context["mcp_tool_ids"] and permission["tool_id"] not in context["mcp_tool_ids"]:
                continue
            current_permissions[(permission["tool_id"], permission["user_id"])] = _serialize_siem_value(permission)

    webhook_deliveries = [
        _serialize_siem_value(item)
        for item in _store.list_webhook_delivery_attempts()
        if any(
            [
                item["alert_source"] == "budget" and item["alert_id"] in context["budget_alert_ids"],
                item["alert_source"] == "approval" and item["alert_id"] in context["approval_alert_ids"],
                item["alert_source"] == "anomaly" and item["alert_id"] in context["anomaly_alert_ids"],
                item["alert_source"] == "siem" and item["alert_id"] in context["siem_export_ids"],
            ]
        )
    ]
    webhook_deliveries.sort(key=lambda item: item["created_at"])
    for delivery in webhook_deliveries:
        item = _build_webhook_delivery_timeline_item(delivery)
        item_key = _timeline_item_identity(item)
        if item_key in existing_item_keys:
            continue
        base_entries.append(item)
        existing_item_keys.add(item_key)

    annotated_entries = [_annotate_investigation_item(item) for item in base_entries]
    annotated_entries.sort(key=lambda item: (item["occurred_at"], item["source_type"], item["event_type"]))

    request_references = [
        reference
        for reference in [
            _build_request_reference(related_request_hash) for related_request_hash in sorted(context["request_hashes"])
        ]
        if reference is not None
    ]
    approval_references = [
        reference
        for reference in [
            _build_approval_reference(related_approval_id, approval_alerts)
            for related_approval_id in sorted(context["approval_ids"])
        ]
        if reference is not None
    ]
    transaction_references = [
        reference
        for reference in [
            _build_transaction_reference(
                related_transaction_id,
                anomalies=anomalies,
                anomaly_alerts=anomaly_alerts,
                siem_exports=siem_exports,
                webhook_deliveries=webhook_deliveries,
            )
            for related_transaction_id in sorted(context["transaction_ids"])
        ]
        if reference is not None
    ]
    policy_mutation_references = [
        _build_audit_reference(entry)
        for entry in matched_audit_entries
        if _classify_audit_reference_type(entry) == "policy_mutation"
    ]
    permission_audit_references = [
        _build_audit_reference(entry)
        for entry in matched_audit_entries
        if _classify_audit_reference_type(entry) == "permission"
    ]
    policy_mutation_references.sort(key=lambda item: item["sequence_number"])
    permission_audit_references.sort(key=lambda item: item["sequence_number"])

    requested_source_types = _parse_filter_values(source_type_filter)
    requested_reference_types = _parse_filter_values(reference_type_filter)
    filtered_entries = [
        item
        for item in annotated_entries
        if (requested_source_types is None or item["source_type"] in requested_source_types)
        and (requested_reference_types is None or item["reference_type"] in requested_reference_types)
    ]

    def include_reference(reference_name: str) -> bool:
        if requested_reference_types is None:
            return True
        return reference_name in requested_reference_types

    references = {
        "transactions": transaction_references if include_reference("transaction") else [],
        "requests": request_references if include_reference("request") else [],
        "approvals": approval_references if include_reference("approval") else [],
        "policy_mutations": policy_mutation_references if include_reference("policy_mutation") else [],
        "permissions": {
            "audit_entries": permission_audit_references if include_reference("permission") else [],
            "current_mcp_permissions": (
                sorted(current_permissions.values(), key=lambda item: (item["updated_at"], item["tool_id"], item["user_id"]))
                if include_reference("permission")
                else []
            ),
        },
        "anomalies": anomalies if include_reference("anomaly") else [],
        "siem_exports": siem_exports if include_reference("siem_export") else [],
        "webhook_deliveries": webhook_deliveries if include_reference("webhook_delivery") else [],
    }

    source_counts: dict[str, int] = {}
    reference_counts: dict[str, int] = {
        "transactions": len(references["transactions"]),
        "requests": len(references["requests"]),
        "approvals": len(references["approvals"]),
        "policy_mutations": len(references["policy_mutations"]),
        "permissions": len(references["permissions"]["audit_entries"]) + len(references["permissions"]["current_mcp_permissions"]),
        "anomalies": len(references["anomalies"]),
        "siem_exports": len(references["siem_exports"]),
        "webhook_deliveries": len(references["webhook_deliveries"]),
    }
    for item in filtered_entries:
        source_counts[item["source_type"]] = source_counts.get(item["source_type"], 0) + 1

    return {
        "filters": {
            "user_id": user_id,
            "agent_id": agent_id,
            "transaction_id": transaction_id,
            "approval_id": approval_id,
            "request_hash": request_hash,
            "source_type": source_type_filter,
            "reference_type": reference_type_filter,
        },
        "summary": {
            "entry_count": len(filtered_entries),
            "source_counts": source_counts,
            "reference_counts": reference_counts,
            "started_at": None if not filtered_entries else filtered_entries[0]["occurred_at"],
            "ended_at": None if not filtered_entries else filtered_entries[-1]["occurred_at"],
        },
        "correlation": {key: sorted(values) for key, values in context.items()},
        "references": references,
        "entries": filtered_entries,
    }


def verify_chain_segment(entries: list[dict[str, Any]]) -> dict[str, Any]:
    if not entries:
        return {
            "valid": True,
            "entries_checked": 0,
            "first_invalid_sequence": None,
            "error": None,
        }

    previous_hash = entries[0]["previous_hash"]
    for index, entry in enumerate(entries):
        expected_previous = previous_hash if index == 0 else entries[index - 1]["entry_hash"]
        if entry["previous_hash"] != expected_previous:
            return {
                "valid": False,
                "entries_checked": index + 1,
                "first_invalid_sequence": entry["sequence_number"],
                "error": "previous_hash mismatch",
            }
        computed_hash = _compute_audit_entry_hash(entry)
        if computed_hash != entry["entry_hash"]:
            return {
                "valid": False,
                "entries_checked": index + 1,
                "first_invalid_sequence": entry["sequence_number"],
                "error": "entry_hash mismatch",
            }
    return {
        "valid": True,
        "entries_checked": len(entries),
        "first_invalid_sequence": None,
        "error": None,
    }


@router.get("/audit/entries")
def get_audit_entries(
    action: str | None = None,
    decision: str | None = None,
    actor_id: str | None = None,
    transaction_id: str | None = None,
    mcp_server_id: str | None = None,
    mcp_tool_id: str | None = None,
    infrastructure_provider_name: str | None = None,
    infrastructure_subject: str | None = None,
    request_hash: str | None = None,
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> list[dict[str, Any]]:
    _require_audit_identity(authorization)
    return filter_audit_entries(
        action=action,
        decision=decision,
        actor_id=actor_id,
        transaction_id=transaction_id,
        mcp_server_id=mcp_server_id,
        mcp_tool_id=mcp_tool_id,
        infrastructure_provider_name=infrastructure_provider_name,
        infrastructure_subject=infrastructure_subject,
        request_hash=request_hash,
    )


@router.get("/audit/verify")
def verify_audit_entries(authorization: str | None = Header(default=None, alias="Authorization")) -> dict[str, Any]:
    _require_audit_identity(authorization)
    return _store.verify_audit_chain()


@router.get("/audit/report")
def get_audit_report(
    start_sequence: int | None = None,
    end_sequence: int | None = None,
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> dict[str, Any]:
    _require_audit_identity(authorization)
    entries = slice_audit_entries(start_sequence, end_sequence)
    return build_audit_report_payload(entries, start_sequence=start_sequence, end_sequence=end_sequence)


@router.get("/audit/export")
def export_audit_entries(
    start_sequence: int | None = None,
    end_sequence: int | None = None,
    package_profile: str | None = None,
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> dict[str, Any]:
    _require_audit_identity(authorization)
    entries = slice_audit_entries(start_sequence, end_sequence)
    integrity_report = build_audit_report_payload(entries, start_sequence=start_sequence, end_sequence=end_sequence)
    exported_at = datetime.now(timezone.utc).isoformat()
    response: dict[str, Any] = {
        "exported_at": exported_at,
        "range": integrity_report["range"],
        "verification": integrity_report["verification"],
        "verification_method": integrity_report["verification_method"],
        "entries": entries,
    }
    if package_profile is not None:
        response["package"] = build_audit_export_package(
            entries,
            package_profile=package_profile,
            exported_at=exported_at,
            integrity_report=integrity_report,
        )
    return response


@router.get("/audit/siem/exports/outbox")
def list_siem_exports(
    status: str | None = None,
    transaction_id: str | None = None,
    anomaly_id: str | None = None,
    severity: str | None = None,
    actor_id: str | None = None,
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> list[dict[str, Any]]:
    _require_audit_identity(authorization)
    return _store.list_siem_exports(
        status=status,
        transaction_id=transaction_id,
        anomaly_id=anomaly_id,
        severity=severity,
        actor_id=actor_id,
    )


@router.get("/audit/trace/request/{request_hash}")
def get_request_trace(
    request_hash: str,
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> dict[str, Any]:
    _require_audit_identity(authorization)
    entries = filter_audit_entries(request_hash=request_hash)
    if not entries:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"code": "TRACE_NOT_FOUND"})
    return {"request_hash": request_hash, "entries": entries}


@router.get("/audit/trace/transaction/{transaction_id}")
def get_transaction_trace(
    transaction_id: str,
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> dict[str, Any]:
    _require_audit_identity(authorization)
    trace = build_transaction_trace(transaction_id)
    if trace is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"code": "TRACE_NOT_FOUND"})
    return trace


@router.get("/audit/trace/approval/{approval_id}")
def get_approval_trace(
    approval_id: str,
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> dict[str, Any]:
    _require_audit_identity(authorization)
    entries = get_approval_trace_entries(approval_id)
    if not entries:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"code": "TRACE_NOT_FOUND"})
    return {"approval_id": approval_id, "entries": entries}


@router.get("/audit/timeline")
def get_entity_timeline(
    transaction_id: str | None = None,
    approval_id: str | None = None,
    request_hash: str | None = None,
    user_id: str | None = None,
    agent_id: str | None = None,
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> dict[str, Any]:
    _require_audit_identity(authorization)
    if not any([transaction_id, approval_id, request_hash, user_id, agent_id]):
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail={"code": "TIMELINE_FILTER_REQUIRED"})
    entries = build_entity_timeline(
        transaction_id=transaction_id,
        approval_id=approval_id,
        request_hash=request_hash,
        user_id=user_id,
        agent_id=agent_id,
    )
    if not entries:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"code": "TRACE_NOT_FOUND"})
    return {
        "filters": {
            "transaction_id": transaction_id,
            "approval_id": approval_id,
            "request_hash": request_hash,
            "user_id": user_id,
            "agent_id": agent_id,
        },
        "entries": entries,
    }


@router.get("/audit/cross-reference")
def get_cross_reference(
    user_id: str | None = None,
    agent_id: str | None = None,
    transaction_id: str | None = None,
    approval_id: str | None = None,
    request_hash: str | None = None,
    source_type: str | None = None,
    reference_type: str | None = None,
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> dict[str, Any]:
    _require_audit_identity(authorization)
    if not any([user_id, agent_id]):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"code": "CROSS_REFERENCE_SUBJECT_REQUIRED"},
        )
    cross_reference = build_cross_reference(
        user_id=user_id,
        agent_id=agent_id,
        transaction_id=transaction_id,
        approval_id=approval_id,
        request_hash=request_hash,
        source_type_filter=source_type,
        reference_type_filter=reference_type,
    )
    if cross_reference is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"code": "TRACE_NOT_FOUND"})
    return cross_reference
