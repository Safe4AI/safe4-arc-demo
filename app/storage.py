"""Database-backed storage for the Agentic Payments Firewall MVP."""

from __future__ import annotations

import json
import sqlite3
import threading
import hashlib
from contextlib import closing
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any

MONEY_SCALE = Decimal("0.000001")

try:
    import psycopg
    from psycopg.rows import dict_row
except ImportError:  # pragma: no cover - optional in sqlite-only environments
    psycopg = None
    dict_row = None


def utc_now() -> str:
    """Return a timezone-aware UTC timestamp."""

    return datetime.now(timezone.utc).isoformat()


def decimal_to_text(value: Decimal) -> str:
    """Serialize Decimal values without losing precision."""

    return format(value, "f")


def text_to_decimal(value: Any) -> Decimal:
    """Parse persisted numeric values as Decimal."""

    if isinstance(value, Decimal):
        return value.quantize(MONEY_SCALE)
    return Decimal(str(value)).quantize(MONEY_SCALE)


def sql_bool(value: bool) -> bool:
    """Return a driver-friendly boolean value for SQLite and PostgreSQL."""

    return bool(value)


@dataclass(frozen=True)
class IdempotencyRecord:
    """Stored response for a previously completed request."""

    status_code: int
    response_body: dict[str, Any]


GENESIS_AUDIT_HASH = "0" * 64


def canonicalize_audit_entry(entry: dict[str, Any]) -> str:
    """Create a deterministic JSON representation for hash chaining."""

    transaction_amount = entry.get("transaction_amount")
    if isinstance(transaction_amount, Decimal):
        transaction_amount = decimal_to_text(transaction_amount)

    payload = {
        "sequence_number": int(entry["sequence_number"]),
        "timestamp": entry["timestamp"],
        "previous_hash": entry["previous_hash"],
        "transaction_id": entry.get("transaction_id"),
        "actor_type": entry["actor_type"],
        "actor_id": entry["actor_id"],
        "action": entry["action"],
        "request_payload_hash": entry["request_payload_hash"],
        "policy_version": entry["policy_version"],
        "decision": entry["decision"],
        "transaction_amount": transaction_amount,
        "transaction_currency": entry.get("transaction_currency"),
        "decision_details": entry.get("decision_details", {}),
        "mcp_server_id": entry.get("mcp_server_id"),
        "mcp_tool_id": entry.get("mcp_tool_id"),
        "mcp_tool_name": entry.get("mcp_tool_name"),
        "infrastructure_provider_name": entry.get("infrastructure_provider_name"),
        "infrastructure_subject": entry.get("infrastructure_subject"),
        "infrastructure_trust_tier": entry.get("infrastructure_trust_tier"),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def compute_audit_entry_hash(entry: dict[str, Any]) -> str:
    """Compute the SHA-256 hash for an audit entry."""

    return hashlib.sha256(canonicalize_audit_entry(entry).encode("utf-8")).hexdigest()


class FirewallStore:
    """Thread-safe SQL wrapper for budgets, receipts, logs, and idempotency."""

    def __init__(
        self,
        db_url: str,
        default_budgets: dict[str, dict[str, Decimal]],
        default_receipts: dict[str, dict[str, Any]],
        default_policy_version: str = "mvp-0.4.0",
        default_policy_document: dict[str, Any] | None = None,
    ) -> None:
        self.db_url = db_url
        self.default_budgets = default_budgets
        self.default_receipts = default_receipts
        self.default_policy_version = default_policy_version
        self.default_policy_document = default_policy_document or {"version": default_policy_version}
        self._lock = threading.Lock()
        self.is_postgres = db_url.startswith("postgresql://") or db_url.startswith("postgres://")
        self._initialize()

    def _connect(self):
        if self.is_postgres:
            if psycopg is None:
                raise RuntimeError("psycopg is required for PostgreSQL storage.")
            return psycopg.connect(self.db_url, row_factory=dict_row)

        db_path = Path(self.db_url)
        db_path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(db_path, check_same_thread=False)
        connection.row_factory = sqlite3.Row
        return connection

    @property
    def _p(self) -> str:
        return "%s" if self.is_postgres else "?"

    def _initialize(self) -> None:
        if not self.is_postgres:
            Path(self.db_url).parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS budgets (
                    user_id TEXT PRIMARY KEY,
                    daily_cap NUMERIC NOT NULL,
                    transaction_cap NUMERIC NOT NULL,
                    spent_today NUMERIC NOT NULL,
                    spent_date TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS receipts (
                    receipt TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    pay_to TEXT NOT NULL,
                    used_at TEXT,
                    metadata_json TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS transaction_logs (
                    id INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
                    timestamp TEXT NOT NULL,
                    transaction_id TEXT,
                    request_id TEXT NOT NULL,
                    client_ip TEXT,
                    agent_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    vendor TEXT NOT NULL,
                    amount NUMERIC NOT NULL,
                    currency TEXT NOT NULL,
                    firewall_fee NUMERIC NOT NULL,
                    justification TEXT NOT NULL,
                    context_json TEXT NOT NULL,
                    result TEXT NOT NULL,
                    reason TEXT,
                    decision_latency_ms INTEGER NOT NULL,
                    idempotency_key TEXT
                )
                """
                if self.is_postgres
                else """
                CREATE TABLE IF NOT EXISTS transaction_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    transaction_id TEXT,
                    request_id TEXT NOT NULL,
                    client_ip TEXT,
                    agent_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    vendor TEXT NOT NULL,
                    amount NUMERIC NOT NULL,
                    currency TEXT NOT NULL,
                    firewall_fee NUMERIC NOT NULL,
                    justification TEXT NOT NULL,
                    context_json TEXT NOT NULL,
                    result TEXT NOT NULL,
                    reason TEXT,
                    decision_latency_ms INTEGER NOT NULL,
                    idempotency_key TEXT
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS idempotency_records (
                    idempotency_key TEXT PRIMARY KEY,
                    request_hash TEXT NOT NULL,
                    status_code INTEGER NOT NULL,
                    response_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_entries (
                    entry_id INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
                    sequence_number INTEGER NOT NULL UNIQUE,
                    timestamp TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL UNIQUE,
                    transaction_id TEXT,
                    actor_type TEXT NOT NULL,
                    actor_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    request_path TEXT NOT NULL,
                    request_payload_hash TEXT NOT NULL,
                    request_payload_summary_json TEXT NOT NULL,
                    policy_version TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    decision_reason TEXT,
                    decision_details_json TEXT NOT NULL,
                    transaction_amount NUMERIC,
                    transaction_currency TEXT,
                    mcp_server_id TEXT,
                    mcp_tool_id TEXT,
                    mcp_tool_name TEXT,
                    infrastructure_provider_name TEXT,
                    infrastructure_subject TEXT,
                    infrastructure_trust_tier TEXT
                )
                """
                if self.is_postgres
                else """
                CREATE TABLE IF NOT EXISTS audit_entries (
                    entry_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sequence_number INTEGER NOT NULL UNIQUE,
                    timestamp TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL UNIQUE,
                    transaction_id TEXT,
                    actor_type TEXT NOT NULL,
                    actor_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    request_path TEXT NOT NULL,
                    request_payload_hash TEXT NOT NULL,
                    request_payload_summary_json TEXT NOT NULL,
                    policy_version TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    decision_reason TEXT,
                    decision_details_json TEXT NOT NULL,
                    transaction_amount NUMERIC,
                    transaction_currency TEXT,
                    mcp_server_id TEXT,
                    mcp_tool_id TEXT,
                    mcp_tool_name TEXT,
                    infrastructure_provider_name TEXT,
                    infrastructure_subject TEXT,
                    infrastructure_trust_tier TEXT
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS policy_documents (
                    version TEXT PRIMARY KEY,
                    document_json TEXT NOT NULL,
                    notes TEXT,
                    is_active BOOLEAN NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS budget_alert_outbox (
                    alert_id TEXT PRIMARY KEY,
                    entity_type TEXT NOT NULL,
                    entity_id TEXT NOT NULL,
                    threshold_ratio NUMERIC NOT NULL,
                    threshold_percent INTEGER NOT NULL,
                    spent_date TEXT NOT NULL,
                    spent_today NUMERIC NOT NULL,
                    daily_cap NUMERIC NOT NULL,
                    remaining_budget NUMERIC NOT NULL,
                    trigger_source TEXT NOT NULL,
                    trigger_details_json TEXT NOT NULL,
                    status TEXT NOT NULL,
                    acknowledged_at TEXT,
                    created_at TEXT NOT NULL,
                    event_key TEXT NOT NULL UNIQUE
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS mcp_alert_outbox (
                    alert_id TEXT PRIMARY KEY,
                    alert_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    mcp_server_id TEXT,
                    mcp_tool_id TEXT,
                    summary TEXT NOT NULL,
                    details_json TEXT NOT NULL,
                    status TEXT NOT NULL,
                    acknowledged_at TEXT,
                    created_at TEXT NOT NULL,
                    event_key TEXT NOT NULL UNIQUE
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS approval_alert_outbox (
                    alert_id TEXT PRIMARY KEY,
                    alert_type TEXT NOT NULL DEFAULT 'hitl_approval_requested',
                    approval_id TEXT NOT NULL,
                    request_hash TEXT NOT NULL,
                    triggered_by TEXT NOT NULL,
                    requestor_agent_id TEXT NOT NULL,
                    requestor_user_id TEXT NOT NULL,
                    mcp_tool_id TEXT,
                    summary TEXT NOT NULL,
                    details_json TEXT NOT NULL,
                    status TEXT NOT NULL,
                    acknowledged_at TEXT,
                    created_at TEXT NOT NULL,
                    event_key TEXT NOT NULL UNIQUE
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS anomaly_alert_outbox (
                    alert_id TEXT PRIMARY KEY,
                    anomaly_id TEXT NOT NULL,
                    transaction_id TEXT NOT NULL,
                    actor_id TEXT NOT NULL,
                    provider_name TEXT,
                    subject TEXT,
                    posture TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    score NUMERIC NOT NULL,
                    summary TEXT NOT NULL,
                    details_json TEXT NOT NULL,
                    status TEXT NOT NULL,
                    acknowledged_at TEXT,
                    created_at TEXT NOT NULL,
                    event_key TEXT NOT NULL UNIQUE
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS siem_export_outbox (
                    export_id TEXT PRIMARY KEY,
                    export_type TEXT NOT NULL,
                    transaction_id TEXT NOT NULL,
                    anomaly_id TEXT NOT NULL,
                    anomaly_alert_id TEXT,
                    actor_id TEXT NOT NULL,
                    provider_name TEXT,
                    subject TEXT,
                    severity TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    status TEXT NOT NULL,
                    acknowledged_at TEXT,
                    created_at TEXT NOT NULL,
                    event_key TEXT NOT NULL UNIQUE
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS webhook_endpoints (
                    endpoint_id TEXT PRIMARY KEY,
                    target_url TEXT NOT NULL,
                    subscribed_events_json TEXT NOT NULL,
                    shared_secret TEXT,
                    is_active BOOLEAN NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS webhook_delivery_attempts (
                    attempt_id TEXT PRIMARY KEY,
                    alert_source TEXT NOT NULL,
                    alert_id TEXT NOT NULL,
                    endpoint_id TEXT NOT NULL,
                    delivery_status TEXT NOT NULL,
                    duration_ms INTEGER,
                    response_status INTEGER,
                    response_body TEXT,
                    error_message TEXT,
                    delivered_at TEXT,
                    created_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS x402_provider_receipts (
                    receipt_id TEXT PRIMARY KEY,
                    provider_name TEXT NOT NULL,
                    receipt_version TEXT,
                    issuer_url TEXT,
                    key_id TEXT,
                    issued_at TEXT,
                    settlement_reference TEXT,
                    settlement_proof_type TEXT,
                    settlement_proof_value TEXT,
                    confirmation_count INTEGER,
                    confirmed_at TEXT,
                    network TEXT NOT NULL,
                    pay_to TEXT NOT NULL,
                    amount_paid NUMERIC NOT NULL,
                    currency TEXT NOT NULL,
                    status TEXT NOT NULL,
                    settled_at TEXT NOT NULL,
                    expires_at TEXT,
                    used_at TEXT,
                    verification_status TEXT NOT NULL,
                    verification_reason_code TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS x402_provider_configs (
                    provider_name TEXT PRIMARY KEY,
                    adapter_name TEXT NOT NULL,
                    issuer_url TEXT,
                    issuer_urls_json TEXT NOT NULL DEFAULT '[]',
                    verifier_key_id TEXT,
                    verifier_key_ids_json TEXT NOT NULL DEFAULT '[]',
                    trust_anchor_ids_json TEXT NOT NULL DEFAULT '[]',
                    required_settlement_proof_type TEXT,
                    minimum_confirmations INTEGER,
                    supported_networks_json TEXT NOT NULL,
                    is_enabled BOOLEAN NOT NULL,
                    notes TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS hitl_rules (
                    rule_id TEXT PRIMARY KEY,
                    applies_to TEXT NOT NULL DEFAULT 'direct',
                    trigger_type TEXT NOT NULL,
                    threshold_amount NUMERIC,
                    vendor_pattern TEXT,
                    currency TEXT,
                    mcp_tool_id TEXT,
                    mcp_action TEXT,
                    mcp_server_trust_level TEXT,
                    secondary_trigger_type TEXT,
                    secondary_threshold_amount NUMERIC,
                    secondary_vendor_pattern TEXT,
                    secondary_currency TEXT,
                    secondary_mcp_tool_id TEXT,
                    secondary_mcp_action TEXT,
                    secondary_mcp_server_trust_level TEXT,
                    is_active BOOLEAN NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS oauth_clients (
                    client_id TEXT PRIMARY KEY,
                    client_secret_hash TEXT,
                    client_name TEXT NOT NULL,
                    client_type TEXT NOT NULL,
                    redirect_uris_json TEXT NOT NULL,
                    allowed_scopes_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    is_active INTEGER NOT NULL DEFAULT 1
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS oauth_authorization_codes (
                    code_hash TEXT PRIMARY KEY,
                    client_id TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    agent_id TEXT,
                    redirect_uri TEXT NOT NULL,
                    scopes_json TEXT NOT NULL,
                    code_challenge TEXT NOT NULL,
                    code_challenge_method TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    used INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS oauth_access_tokens (
                    token_hash TEXT PRIMARY KEY,
                    client_id TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    agent_id TEXT,
                    scopes_json TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    revoked INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
                    token_hash TEXT PRIMARY KEY,
                    client_id TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    agent_id TEXT,
                    scopes_json TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    revoked INTEGER NOT NULL DEFAULT 0,
                    replaced_by TEXT,
                    created_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS agent_budgets (
                    agent_id TEXT PRIMARY KEY,
                    daily_cap NUMERIC NOT NULL,
                    transaction_cap NUMERIC NOT NULL,
                    spent_today NUMERIC NOT NULL,
                    spent_date TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS transaction_events (
                    event_id INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
                    transaction_id TEXT,
                    agent_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
                if self.is_postgres
                else """
                CREATE TABLE IF NOT EXISTS transaction_events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    transaction_id TEXT,
                    agent_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS mcp_servers (
                    server_id TEXT PRIMARY KEY,
                    server_name TEXT NOT NULL,
                    server_url TEXT,
                    transport_type TEXT NOT NULL,
                    trust_level TEXT NOT NULL,
                    trust_level_reason TEXT,
                    description_hash TEXT NOT NULL,
                    first_seen_at TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL,
                    is_active INTEGER NOT NULL DEFAULT 1
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS mcp_tools (
                    tool_id TEXT PRIMARY KEY,
                    tool_name TEXT NOT NULL,
                    server_id TEXT NOT NULL,
                    description TEXT NOT NULL,
                    description_hash TEXT NOT NULL,
                    description_first_seen_hash TEXT NOT NULL,
                    description_changed INTEGER NOT NULL DEFAULT 0,
                    input_schema_json TEXT NOT NULL,
                    is_payment_relevant INTEGER NOT NULL DEFAULT 0,
                    threat_flags_json TEXT NOT NULL,
                    quarantine_status TEXT NOT NULL DEFAULT 'clear',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS mcp_tool_permissions (
                    permission_id INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
                    tool_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    allowed_actions_json TEXT NOT NULL,
                    daily_cap NUMERIC,
                    transaction_cap NUMERIC,
                    requires_hitl INTEGER NOT NULL DEFAULT 0,
                    is_active INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(tool_id, user_id)
                )
                """
                if self.is_postgres
                else """
                CREATE TABLE IF NOT EXISTS mcp_tool_permissions (
                    permission_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tool_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    allowed_actions_json TEXT NOT NULL,
                    daily_cap NUMERIC,
                    transaction_cap NUMERIC,
                    requires_hitl INTEGER NOT NULL DEFAULT 0,
                    is_active INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(tool_id, user_id)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS approval_requests (
                    approval_id TEXT PRIMARY KEY,
                    request_hash TEXT NOT NULL,
                    request_path TEXT NOT NULL,
                    request_payload_json TEXT NOT NULL,
                    triggered_by TEXT NOT NULL,
                    requestor_agent_id TEXT NOT NULL,
                    requestor_user_id TEXT NOT NULL,
                    mcp_tool_id TEXT,
                    status TEXT NOT NULL,
                    decided_by TEXT,
                    decided_at TEXT,
                    decision_reason TEXT,
                    expires_at TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS spend_tokens (
                    token_hash TEXT PRIMARY KEY,
                    token_id TEXT NOT NULL UNIQUE,
                    request_hash TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    mcp_tool_id TEXT,
                    authorized_amount NUMERIC NOT NULL,
                    authorized_currency TEXT NOT NULL,
                    authorized_action TEXT,
                    expires_at TEXT NOT NULL,
                    is_used INTEGER NOT NULL DEFAULT 0,
                    used_at TEXT,
                    revoked INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS ap2_mandates (
                    mandate_id TEXT PRIMARY KEY,
                    mandate_type TEXT NOT NULL,
                    signer_id TEXT,
                    key_id TEXT,
                    family_id TEXT NOT NULL DEFAULT '',
                    parent_mandate_id TEXT,
                    chain_status TEXT NOT NULL DEFAULT 'standalone',
                    chain_depth INTEGER NOT NULL DEFAULT 1,
                    lifecycle_status TEXT NOT NULL DEFAULT 'active',
                    superseded_by_mandate_id TEXT,
                    retained_until TEXT,
                    archived_at TEXT,
                    redacted_at TEXT,
                    request_hash TEXT NOT NULL,
                    requestor_agent_id TEXT NOT NULL,
                    requestor_user_id TEXT NOT NULL,
                    vendor TEXT NOT NULL,
                    amount NUMERIC NOT NULL,
                    currency TEXT NOT NULL,
                    reference TEXT,
                    signature TEXT,
                    payload_json TEXT NOT NULL,
                    parsed_mandate_json TEXT,
                    verifier_name TEXT NOT NULL,
                    verification_status TEXT NOT NULL,
                    verification_reason_code TEXT NOT NULL,
                    discrepancies_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS ap2_signer_configs (
                    signer_id TEXT PRIMARY KEY,
                    verifier_name TEXT NOT NULL,
                    verifier_key_id TEXT,
                    is_enabled BOOLEAN NOT NULL,
                    notes TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS agent_identity_assertions (
                    assertion_hash TEXT PRIMARY KEY,
                    provider_name TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    agent_id TEXT,
                    client_id TEXT NOT NULL,
                    environment TEXT,
                    namespace TEXT,
                    service_account TEXT,
                    trust_tier TEXT,
                    claims_json TEXT NOT NULL,
                    verification_status TEXT NOT NULL,
                    verification_reason_code TEXT NOT NULL,
                    first_seen_at TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL,
                    seen_count INTEGER NOT NULL DEFAULT 1
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS infrastructure_identity_profiles (
                    profile_key TEXT PRIMARY KEY,
                    actor_type TEXT NOT NULL,
                    actor_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    action TEXT NOT NULL,
                    provider_name TEXT,
                    subject TEXT,
                    posture TEXT NOT NULL,
                    environment TEXT,
                    namespace TEXT,
                    service_account TEXT,
                    trust_tier TEXT,
                    transaction_currency TEXT,
                    event_count INTEGER NOT NULL,
                    total_amount NUMERIC NOT NULL,
                    first_seen_at TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL,
                    last_transaction_id TEXT,
                    last_request_path TEXT
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS infrastructure_identity_anomalies (
                    anomaly_id TEXT PRIMARY KEY,
                    transaction_id TEXT,
                    actor_type TEXT NOT NULL,
                    actor_id TEXT NOT NULL,
                    provider_name TEXT,
                    subject TEXT,
                    posture TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    score NUMERIC NOT NULL,
                    baseline_event_count INTEGER NOT NULL,
                    baseline_average_amount NUMERIC,
                    observed_amount NUMERIC NOT NULL,
                    transaction_currency TEXT,
                    reason_codes_json TEXT NOT NULL,
                    feature_details_json TEXT NOT NULL DEFAULT '{}',
                    request_path TEXT,
                    created_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS mcp_tool_usage_events (
                    usage_id INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
                    tool_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    amount NUMERIC NOT NULL,
                    currency TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
                if self.is_postgres
                else """
                CREATE TABLE IF NOT EXISTS mcp_tool_usage_events (
                    usage_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tool_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    amount NUMERIC NOT NULL,
                    currency TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            connection.commit()
        self._migrate_schema()
        self.seed_defaults()

    def _column_exists(self, connection, table: str, column: str) -> bool:
        if self.is_postgres:
            row = connection.execute(
                f"""
                SELECT 1
                FROM information_schema.columns
                WHERE table_name = {self._p} AND column_name = {self._p}
                """,
                (table, column),
            ).fetchone()
            return row is not None

        rows = connection.execute(f"PRAGMA table_info({table})").fetchall()
        return any(row["name"] == column for row in rows)

    def _migrate_schema(self) -> None:
        """Add columns introduced after earlier MVP revisions."""

        additions = {
            "transaction_id": "TEXT",
            "request_id": "TEXT NOT NULL DEFAULT 'legacy'",
            "client_ip": "TEXT",
            "firewall_fee": "NUMERIC NOT NULL DEFAULT 0",
            "decision_latency_ms": "INTEGER NOT NULL DEFAULT 0",
            "idempotency_key": "TEXT",
        }
        with self._lock, closing(self._connect()) as connection:
            for column, definition in additions.items():
                if not self._column_exists(connection, "transaction_logs", column):
                    connection.execute(f"ALTER TABLE transaction_logs ADD COLUMN {column} {definition}")
            audit_additions = {
                "transaction_id": "TEXT",
                "mcp_server_id": "TEXT",
                "mcp_tool_id": "TEXT",
                "mcp_tool_name": "TEXT",
                "infrastructure_provider_name": "TEXT",
                "infrastructure_subject": "TEXT",
                "infrastructure_trust_tier": "TEXT",
            }
            for column, definition in audit_additions.items():
                if not self._column_exists(connection, "audit_entries", column):
                    connection.execute(f"ALTER TABLE audit_entries ADD COLUMN {column} {definition}")
            if not self._column_exists(connection, "transaction_events", "transaction_id"):
                connection.execute(f"ALTER TABLE transaction_events ADD COLUMN transaction_id TEXT")
            hitl_rule_additions = {
                "applies_to": "TEXT NOT NULL DEFAULT 'direct'",
                "mcp_tool_id": "TEXT",
                "mcp_action": "TEXT",
                "mcp_server_trust_level": "TEXT",
                "secondary_trigger_type": "TEXT",
                "secondary_threshold_amount": "NUMERIC",
                "secondary_vendor_pattern": "TEXT",
                "secondary_currency": "TEXT",
                "secondary_mcp_tool_id": "TEXT",
                "secondary_mcp_action": "TEXT",
                "secondary_mcp_server_trust_level": "TEXT",
            }
            for column, definition in hitl_rule_additions.items():
                if not self._column_exists(connection, "hitl_rules", column):
                    connection.execute(f"ALTER TABLE hitl_rules ADD COLUMN {column} {definition}")
            approval_alert_additions = {
                "alert_type": "TEXT NOT NULL DEFAULT 'hitl_approval_requested'",
            }
            for column, definition in approval_alert_additions.items():
                if not self._column_exists(connection, "approval_alert_outbox", column):
                    connection.execute(f"ALTER TABLE approval_alert_outbox ADD COLUMN {column} {definition}")
            anomaly_alert_additions = {
                "provider_name": "TEXT",
                "subject": "TEXT",
            }
            for column, definition in anomaly_alert_additions.items():
                if not self._column_exists(connection, "anomaly_alert_outbox", column):
                    connection.execute(f"ALTER TABLE anomaly_alert_outbox ADD COLUMN {column} {definition}")
            anomaly_additions = {
                "feature_details_json": "TEXT NOT NULL DEFAULT '{}'",
            }
            for column, definition in anomaly_additions.items():
                if not self._column_exists(connection, "infrastructure_identity_anomalies", column):
                    connection.execute(f"ALTER TABLE infrastructure_identity_anomalies ADD COLUMN {column} {definition}")
            if not self._column_exists(connection, "webhook_delivery_attempts", "duration_ms"):
                connection.execute("ALTER TABLE webhook_delivery_attempts ADD COLUMN duration_ms INTEGER")
            ap2_mandate_additions = {
                "family_id": "TEXT NOT NULL DEFAULT ''",
                "signer_id": "TEXT",
                "key_id": "TEXT",
                "parent_mandate_id": "TEXT",
                "chain_status": "TEXT NOT NULL DEFAULT 'standalone'",
                "chain_depth": "INTEGER NOT NULL DEFAULT 1",
                "lifecycle_status": "TEXT NOT NULL DEFAULT 'active'",
                "superseded_by_mandate_id": "TEXT",
                "retained_until": "TEXT",
                "archived_at": "TEXT",
                "redacted_at": "TEXT",
            }
            for column, definition in ap2_mandate_additions.items():
                if not self._column_exists(connection, "ap2_mandates", column):
                    connection.execute(f"ALTER TABLE ap2_mandates ADD COLUMN {column} {definition}")
            if not self._column_exists(connection, "ap2_signer_configs", "verifier_key_id"):
                connection.execute("ALTER TABLE ap2_signer_configs ADD COLUMN verifier_key_id TEXT")
            x402_receipt_additions = {
                "receipt_version": "TEXT",
                "issuer_url": "TEXT",
                "key_id": "TEXT",
                "issued_at": "TEXT",
                "settlement_reference": "TEXT",
                "settlement_proof_type": "TEXT",
                "settlement_proof_value": "TEXT",
                "confirmation_count": "INTEGER",
                "confirmed_at": "TEXT",
            }
            for column, definition in x402_receipt_additions.items():
                if not self._column_exists(connection, "x402_provider_receipts", column):
                    connection.execute(f"ALTER TABLE x402_provider_receipts ADD COLUMN {column} {definition}")
            if not self._column_exists(connection, "x402_provider_configs", "verifier_key_id"):
                connection.execute("ALTER TABLE x402_provider_configs ADD COLUMN verifier_key_id TEXT")
            if not self._column_exists(connection, "x402_provider_configs", "required_settlement_proof_type"):
                connection.execute("ALTER TABLE x402_provider_configs ADD COLUMN required_settlement_proof_type TEXT")
            if not self._column_exists(connection, "x402_provider_configs", "minimum_confirmations"):
                connection.execute("ALTER TABLE x402_provider_configs ADD COLUMN minimum_confirmations INTEGER")
            if not self._column_exists(connection, "x402_provider_configs", "issuer_urls_json"):
                connection.execute("ALTER TABLE x402_provider_configs ADD COLUMN issuer_urls_json TEXT NOT NULL DEFAULT '[]'")
            if not self._column_exists(connection, "x402_provider_configs", "verifier_key_ids_json"):
                connection.execute("ALTER TABLE x402_provider_configs ADD COLUMN verifier_key_ids_json TEXT NOT NULL DEFAULT '[]'")
            if not self._column_exists(connection, "x402_provider_configs", "trust_anchor_ids_json"):
                connection.execute("ALTER TABLE x402_provider_configs ADD COLUMN trust_anchor_ids_json TEXT NOT NULL DEFAULT '[]'")
            connection.commit()

    def seed_defaults(self) -> None:
        """Ensure the baseline demo budgets and receipts exist."""

        with self._lock, closing(self._connect()) as connection:
            today = date.today().isoformat()
            for user_id, budget in self.default_budgets.items():
                connection.execute(
                    f"""
                    INSERT INTO budgets (user_id, daily_cap, transaction_cap, spent_today, spent_date)
                    VALUES ({self._p}, {self._p}, {self._p}, {self._p}, {self._p})
                    ON CONFLICT(user_id) DO NOTHING
                    """,
                    (
                        user_id,
                        decimal_to_text(budget["daily_cap"]),
                        decimal_to_text(budget["transaction_cap"]),
                        decimal_to_text(budget.get("spent_today", Decimal("0"))),
                        today,
                    ),
                )

            for receipt, payload in self.default_receipts.items():
                connection.execute(
                    f"""
                    INSERT INTO receipts (receipt, status, pay_to, used_at, metadata_json)
                    VALUES ({self._p}, {self._p}, {self._p}, {self._p}, {self._p})
                    ON CONFLICT(receipt) DO NOTHING
                    """,
                    (
                        receipt,
                        payload["status"],
                        payload["pay_to"],
                        payload.get("used_at"),
                        json.dumps(payload, sort_keys=True),
                    ),
                )
            connection.execute(
                f"""
                INSERT INTO policy_documents (
                    version, document_json, notes, is_active, created_at, updated_at
                )
                VALUES ({self._p}, {self._p}, {self._p}, {self._p}, {self._p}, {self._p})
                ON CONFLICT(version) DO NOTHING
                """,
                (
                    self.default_policy_version,
                    json.dumps(self.default_policy_document, sort_keys=True),
                    "Default embedded MVP policy",
                    sql_bool(True),
                    utc_now(),
                    utc_now(),
                ),
            )
            connection.execute(
                f"""
                INSERT INTO oauth_clients (
                    client_id, client_secret_hash, client_name, client_type,
                    redirect_uris_json, allowed_scopes_json, created_at, is_active
                )
                VALUES ({self._p}, {self._p}, {self._p}, {self._p}, {self._p}, {self._p}, {self._p}, {self._p})
                ON CONFLICT(client_id) DO NOTHING
                """,
                (
                    "dev-public-client",
                    None,
                    "Development Public Client",
                    "public",
                    json.dumps(["https://localhost/callback"]),
                    json.dumps(
                        [
                            "payment:read",
                            "payment:authorize",
                            "budget:manage",
                            "audit:read",
                            "admin:all",
                        ],
                        sort_keys=True,
                    ),
                    utc_now(),
                    1,
                ),
            )
            connection.execute(
                f"""
                INSERT INTO agent_budgets (agent_id, daily_cap, transaction_cap, spent_today, spent_date)
                VALUES ({self._p}, {self._p}, {self._p}, {self._p}, {self._p})
                ON CONFLICT(agent_id) DO NOTHING
                """,
                (
                    "agent_alpha",
                    decimal_to_text(Decimal("150.00")),
                    decimal_to_text(Decimal("25.00")),
                    decimal_to_text(Decimal("0")),
                    today,
                ),
            )
            connection.commit()

    def reset_for_tests(self) -> None:
        """Clear all data and reseed defaults."""

        with self._lock, closing(self._connect()) as connection:
            connection.execute("DELETE FROM budgets")
            connection.execute("DELETE FROM receipts")
            connection.execute("DELETE FROM transaction_logs")
            connection.execute("DELETE FROM idempotency_records")
            connection.execute("DELETE FROM audit_entries")
            connection.execute("DELETE FROM policy_documents")
            connection.execute("DELETE FROM oauth_clients")
            connection.execute("DELETE FROM oauth_authorization_codes")
            connection.execute("DELETE FROM oauth_access_tokens")
            connection.execute("DELETE FROM oauth_refresh_tokens")
            connection.execute("DELETE FROM agent_budgets")
            connection.execute("DELETE FROM transaction_events")
            connection.execute("DELETE FROM mcp_servers")
            connection.execute("DELETE FROM mcp_tools")
            connection.execute("DELETE FROM mcp_tool_permissions")
            connection.execute("DELETE FROM approval_requests")
            connection.execute("DELETE FROM spend_tokens")
            connection.execute("DELETE FROM mcp_tool_usage_events")
            connection.execute("DELETE FROM budget_alert_outbox")
            connection.execute("DELETE FROM mcp_alert_outbox")
            connection.execute("DELETE FROM approval_alert_outbox")
            connection.execute("DELETE FROM anomaly_alert_outbox")
            connection.execute("DELETE FROM siem_export_outbox")
            connection.execute("DELETE FROM webhook_endpoints")
            connection.execute("DELETE FROM webhook_delivery_attempts")
            connection.execute("DELETE FROM hitl_rules")
            connection.execute("DELETE FROM ap2_mandates")
            connection.execute("DELETE FROM ap2_signer_configs")
            connection.execute("DELETE FROM agent_identity_assertions")
            connection.execute("DELETE FROM infrastructure_identity_profiles")
            connection.execute("DELETE FROM infrastructure_identity_anomalies")
            connection.execute("DELETE FROM x402_provider_receipts")
            connection.execute("DELETE FROM x402_provider_configs")
            connection.commit()
        self.seed_defaults()

    def get_current_policy_document(self) -> dict[str, Any]:
        """Return the active policy document."""

        with self._lock, closing(self._connect()) as connection:
            row = connection.execute(
                f"""
                SELECT version, document_json, notes, is_active, created_at, updated_at
                FROM policy_documents
                WHERE is_active = {self._p}
                ORDER BY updated_at DESC
                LIMIT 1
                """,
                (sql_bool(True),),
            ).fetchone()
            if row is None:
                return {
                    "version": self.default_policy_version,
                    "document": self.default_policy_document,
                    "notes": "Default embedded MVP policy",
                    "is_active": True,
                    "created_at": utc_now(),
                    "updated_at": utc_now(),
                }
            return {
                "version": row["version"],
                "document": json.loads(row["document_json"]),
                "notes": row["notes"],
                "is_active": bool(row["is_active"]),
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            }

    def get_current_policy_version(self) -> str:
        """Return the active policy version."""

        return self.get_current_policy_document()["version"]

    def list_policy_documents(self) -> list[dict[str, Any]]:
        """Return all policy documents ordered by most recently updated."""

        with self._lock, closing(self._connect()) as connection:
            rows = connection.execute(
                """
                SELECT version, document_json, notes, is_active, created_at, updated_at
                FROM policy_documents
                ORDER BY updated_at DESC, version DESC
                """
            ).fetchall()
        return [
            {
                "version": row["version"],
                "document": json.loads(row["document_json"]),
                "notes": row["notes"],
                "is_active": bool(row["is_active"]),
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            }
            for row in rows
        ]

    def activate_policy_document(self, version: str, document: dict[str, Any], notes: str | None = None) -> dict[str, Any]:
        """Upsert and activate a policy document."""

        with self._lock, closing(self._connect()) as connection:
            now = utc_now()
            connection.execute(
                f"UPDATE policy_documents SET is_active = {self._p}, updated_at = {self._p}",
                (sql_bool(False), now),
            )
            connection.execute(
                f"""
                INSERT INTO policy_documents (version, document_json, notes, is_active, created_at, updated_at)
                VALUES ({self._p}, {self._p}, {self._p}, {self._p}, {self._p}, {self._p})
                ON CONFLICT(version) DO UPDATE SET
                    document_json = excluded.document_json,
                    notes = excluded.notes,
                    is_active = excluded.is_active,
                    updated_at = excluded.updated_at
                """,
                (
                    version,
                    json.dumps(document, sort_keys=True),
                    notes,
                    sql_bool(True),
                    now,
                    now,
                ),
            )
            connection.commit()
        return self.get_current_policy_document()

    def get_budget(self, user_id: str) -> dict[str, Decimal] | None:
        """Load a user's budget, resetting daily spend if the day rolled over."""

        today = date.today().isoformat()
        with self._lock, closing(self._connect()) as connection:
            row = connection.execute(
                f"""
                SELECT user_id, daily_cap, transaction_cap, spent_today, spent_date
                FROM budgets
                WHERE user_id = {self._p}
                """,
                (user_id,),
            ).fetchone()
            if row is None:
                return None

            spent_today = text_to_decimal(row["spent_today"])
            if row["spent_date"] != today:
                spent_today = Decimal("0")
                connection.execute(
                    f"UPDATE budgets SET spent_today = {self._p}, spent_date = {self._p} WHERE user_id = {self._p}",
                    (decimal_to_text(spent_today), today, user_id),
                )
                connection.commit()

            return {
                "daily_cap": text_to_decimal(row["daily_cap"]),
                "transaction_cap": text_to_decimal(row["transaction_cap"]),
                "spent_today": spent_today,
            }

    def list_budgets(self) -> dict[str, dict[str, str]]:
        """Return all budgets keyed by user ID."""

        today = date.today().isoformat()
        results: dict[str, dict[str, str]] = {}
        with self._lock, closing(self._connect()) as connection:
            rows = connection.execute(
                """
                SELECT user_id, daily_cap, transaction_cap, spent_today, spent_date
                FROM budgets
                ORDER BY user_id ASC
                """
            ).fetchall()
            for row in rows:
                spent_today = text_to_decimal(row["spent_today"])
                if row["spent_date"] != today:
                    spent_today = Decimal("0")
                    connection.execute(
                        f"UPDATE budgets SET spent_today = {self._p}, spent_date = {self._p} WHERE user_id = {self._p}",
                        (decimal_to_text(spent_today), today, row["user_id"]),
                    )
                results[row["user_id"]] = {
                    "daily_cap": decimal_to_text(text_to_decimal(row["daily_cap"])),
                    "transaction_cap": decimal_to_text(text_to_decimal(row["transaction_cap"])),
                    "spent_today": decimal_to_text(spent_today),
                }
            connection.commit()
        return results

    def upsert_budget(
        self, user_id: str, daily_cap: Decimal, transaction_cap: Decimal, spent_today: Decimal
    ) -> dict[str, Decimal]:
        """Create or update a budget row."""

        today = date.today().isoformat()
        with self._lock, closing(self._connect()) as connection:
            connection.execute(
                f"""
                INSERT INTO budgets (user_id, daily_cap, transaction_cap, spent_today, spent_date)
                VALUES ({self._p}, {self._p}, {self._p}, {self._p}, {self._p})
                ON CONFLICT(user_id) DO UPDATE SET
                    daily_cap = excluded.daily_cap,
                    transaction_cap = excluded.transaction_cap,
                    spent_today = excluded.spent_today,
                    spent_date = excluded.spent_date
                """,
                (
                    user_id,
                    decimal_to_text(daily_cap),
                    decimal_to_text(transaction_cap),
                    decimal_to_text(spent_today),
                    today,
                ),
            )
            connection.commit()
        return {
            "daily_cap": daily_cap,
            "transaction_cap": transaction_cap,
            "spent_today": spent_today,
        }

    def update_spent_today(self, user_id: str, spent_today: Decimal) -> dict[str, Decimal]:
        """Persist a new spent-today value and return the fresh budget snapshot."""

        today = date.today().isoformat()
        with self._lock, closing(self._connect()) as connection:
            connection.execute(
                f"UPDATE budgets SET spent_today = {self._p}, spent_date = {self._p} WHERE user_id = {self._p}",
                (decimal_to_text(spent_today), today, user_id),
            )
            connection.commit()
        budget = self.get_budget(user_id)
        if budget is None:
            raise KeyError(f"Budget missing for user_id={user_id}")
        return budget

    def enqueue_budget_alerts(
        self,
        *,
        entity_type: str,
        entity_id: str,
        budget: dict[str, Decimal],
        thresholds: list[Decimal],
        trigger_source: str,
        trigger_details: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        daily_cap = budget["daily_cap"]
        if daily_cap <= Decimal("0"):
            return []

        spent_today = budget["spent_today"]
        consumed_ratio = spent_today / daily_cap
        spent_date = date.today().isoformat()
        created_alerts: list[dict[str, Any]] = []
        now = utc_now()
        remaining_budget = max(Decimal("0"), daily_cap - spent_today)
        serialized_details = json.dumps(trigger_details or {}, sort_keys=True)

        with self._lock, closing(self._connect()) as connection:
            for threshold in thresholds:
                if consumed_ratio < threshold:
                    continue
                threshold_value = text_to_decimal(threshold)
                threshold_text = decimal_to_text(threshold_value)
                threshold_percent = int((threshold_value * Decimal("100")).quantize(Decimal("1")))
                event_key = f"{entity_type}:{entity_id}:{spent_date}:{threshold_text}"
                connection.execute(
                    f"""
                    INSERT INTO budget_alert_outbox (
                        alert_id, entity_type, entity_id, threshold_ratio, threshold_percent,
                        spent_date, spent_today, daily_cap, remaining_budget, trigger_source,
                        trigger_details_json, status, acknowledged_at, created_at, event_key
                    )
                    VALUES (
                        {self._p}, {self._p}, {self._p}, {self._p}, {self._p},
                        {self._p}, {self._p}, {self._p}, {self._p}, {self._p},
                        {self._p}, {self._p}, {self._p}, {self._p}, {self._p}
                    )
                    ON CONFLICT(event_key) DO NOTHING
                    """,
                    (
                        hashlib.sha256(f"{event_key}:{now}".encode("utf-8")).hexdigest(),
                        entity_type,
                        entity_id,
                        threshold_text,
                        threshold_percent,
                        spent_date,
                        decimal_to_text(spent_today),
                        decimal_to_text(daily_cap),
                        decimal_to_text(remaining_budget),
                        trigger_source,
                        serialized_details,
                        "pending",
                        None,
                        now,
                        event_key,
                    ),
                )
                if getattr(connection, "total_changes", 0) > 0:
                    row = connection.execute(
                        f"""
                        SELECT alert_id, entity_type, entity_id, threshold_ratio, threshold_percent,
                               spent_date, spent_today, daily_cap, remaining_budget, trigger_source,
                               trigger_details_json, status, acknowledged_at, created_at, event_key
                        FROM budget_alert_outbox
                        WHERE event_key = {self._p}
                        """,
                        (event_key,),
                    ).fetchone()
                    if row is not None:
                        created_alerts.append(self._row_to_budget_alert(row))
            connection.commit()
        return created_alerts

    def get_agent_budget(self, agent_id: str) -> dict[str, Decimal] | None:
        today = date.today().isoformat()
        with self._lock, closing(self._connect()) as connection:
            row = connection.execute(
                f"""
                SELECT agent_id, daily_cap, transaction_cap, spent_today, spent_date
                FROM agent_budgets
                WHERE agent_id = {self._p}
                """,
                (agent_id,),
            ).fetchone()
            if row is None:
                return None
            spent_today = text_to_decimal(row["spent_today"])
            if row["spent_date"] != today:
                spent_today = Decimal("0")
                connection.execute(
                    f"""
                    UPDATE agent_budgets
                    SET spent_today = {self._p}, spent_date = {self._p}
                    WHERE agent_id = {self._p}
                    """,
                    (decimal_to_text(spent_today), today, agent_id),
                )
                connection.commit()
            return {
                "daily_cap": text_to_decimal(row["daily_cap"]),
                "transaction_cap": text_to_decimal(row["transaction_cap"]),
                "spent_today": spent_today,
            }

    def list_agent_budgets(self) -> dict[str, dict[str, str]]:
        today = date.today().isoformat()
        results: dict[str, dict[str, str]] = {}
        with self._lock, closing(self._connect()) as connection:
            rows = connection.execute(
                """
                SELECT agent_id, daily_cap, transaction_cap, spent_today, spent_date
                FROM agent_budgets
                ORDER BY agent_id ASC
                """
            ).fetchall()
            for row in rows:
                spent_today = text_to_decimal(row["spent_today"])
                if row["spent_date"] != today:
                    spent_today = Decimal("0")
                    connection.execute(
                        f"""
                        UPDATE agent_budgets
                        SET spent_today = {self._p}, spent_date = {self._p}
                        WHERE agent_id = {self._p}
                        """,
                        (decimal_to_text(spent_today), today, row["agent_id"]),
                    )
                results[row["agent_id"]] = {
                    "daily_cap": decimal_to_text(text_to_decimal(row["daily_cap"])),
                    "transaction_cap": decimal_to_text(text_to_decimal(row["transaction_cap"])),
                    "spent_today": decimal_to_text(spent_today),
                }
            connection.commit()
        return results

    def upsert_agent_budget(
        self, agent_id: str, daily_cap: Decimal, transaction_cap: Decimal, spent_today: Decimal
    ) -> dict[str, Decimal]:
        today = date.today().isoformat()
        with self._lock, closing(self._connect()) as connection:
            connection.execute(
                f"""
                INSERT INTO agent_budgets (agent_id, daily_cap, transaction_cap, spent_today, spent_date)
                VALUES ({self._p}, {self._p}, {self._p}, {self._p}, {self._p})
                ON CONFLICT(agent_id) DO UPDATE SET
                    daily_cap = excluded.daily_cap,
                    transaction_cap = excluded.transaction_cap,
                    spent_today = excluded.spent_today,
                    spent_date = excluded.spent_date
                """,
                (
                    agent_id,
                    decimal_to_text(daily_cap),
                    decimal_to_text(transaction_cap),
                    decimal_to_text(spent_today),
                    today,
                ),
            )
            connection.commit()
        return {
            "daily_cap": daily_cap,
            "transaction_cap": transaction_cap,
            "spent_today": spent_today,
        }

    def update_agent_spent_today(self, agent_id: str, spent_today: Decimal) -> dict[str, Decimal]:
        today = date.today().isoformat()
        with self._lock, closing(self._connect()) as connection:
            connection.execute(
                f"""
                UPDATE agent_budgets
                SET spent_today = {self._p}, spent_date = {self._p}
                WHERE agent_id = {self._p}
                """,
                (decimal_to_text(spent_today), today, agent_id),
            )
            connection.commit()
        budget = self.get_agent_budget(agent_id)
        if budget is None:
            raise KeyError(f"Agent budget missing for agent_id={agent_id}")
        return budget

    def list_budget_alerts(
        self,
        *,
        status: str | None = None,
        entity_type: str | None = None,
        entity_id: str | None = None,
    ) -> list[dict[str, Any]]:
        query = """
            SELECT alert_id, entity_type, entity_id, threshold_ratio, threshold_percent,
                   spent_date, spent_today, daily_cap, remaining_budget, trigger_source,
                   trigger_details_json, status, acknowledged_at, created_at, event_key
            FROM budget_alert_outbox
        """
        clauses: list[str] = []
        params: list[Any] = []
        if status is not None:
            clauses.append(f"status = {self._p}")
            params.append(status)
        if entity_type is not None:
            clauses.append(f"entity_type = {self._p}")
            params.append(entity_type)
        if entity_id is not None:
            clauses.append(f"entity_id = {self._p}")
            params.append(entity_id)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY created_at ASC"
        with self._lock, closing(self._connect()) as connection:
            rows = connection.execute(query, tuple(params)).fetchall()
        return [self._row_to_budget_alert(row) for row in rows]

    def acknowledge_budget_alert(self, alert_id: str) -> dict[str, Any] | None:
        with self._lock, closing(self._connect()) as connection:
            connection.execute(
                f"""
                UPDATE budget_alert_outbox
                SET status = {self._p}, acknowledged_at = {self._p}
                WHERE alert_id = {self._p}
                """,
                ("acknowledged", utc_now(), alert_id),
            )
            row = connection.execute(
                f"""
                SELECT alert_id, entity_type, entity_id, threshold_ratio, threshold_percent,
                       spent_date, spent_today, daily_cap, remaining_budget, trigger_source,
                       trigger_details_json, status, acknowledged_at, created_at, event_key
                FROM budget_alert_outbox
                WHERE alert_id = {self._p}
                """,
                (alert_id,),
            ).fetchone()
            connection.commit()
        if row is None:
            return None
        return self._row_to_budget_alert(row)

    def _row_to_budget_alert(self, row: Any) -> dict[str, Any]:
        return {
            "alert_id": row["alert_id"],
            "entity_type": row["entity_type"],
            "entity_id": row["entity_id"],
            "threshold_ratio": decimal_to_text(text_to_decimal(row["threshold_ratio"])),
            "threshold_percent": int(row["threshold_percent"]),
            "spent_date": row["spent_date"],
            "spent_today": decimal_to_text(text_to_decimal(row["spent_today"])),
            "daily_cap": decimal_to_text(text_to_decimal(row["daily_cap"])),
            "remaining_budget": decimal_to_text(text_to_decimal(row["remaining_budget"])),
            "trigger_source": row["trigger_source"],
            "trigger_details": json.loads(row["trigger_details_json"]),
            "status": row["status"],
            "acknowledged_at": row["acknowledged_at"],
            "created_at": row["created_at"],
            "event_key": row["event_key"],
        }

    def set_budget_alert_status(self, alert_id: str, status: str) -> dict[str, Any] | None:
        with self._lock, closing(self._connect()) as connection:
            connection.execute(
                f"UPDATE budget_alert_outbox SET status = {self._p} WHERE alert_id = {self._p}",
                (status, alert_id),
            )
            row = connection.execute(
                f"""
                SELECT alert_id, entity_type, entity_id, threshold_ratio, threshold_percent,
                       spent_date, spent_today, daily_cap, remaining_budget, trigger_source,
                       trigger_details_json, status, acknowledged_at, created_at, event_key
                FROM budget_alert_outbox
                WHERE alert_id = {self._p}
                """,
                (alert_id,),
            ).fetchone()
            connection.commit()
        if row is None:
            return None
        return self._row_to_budget_alert(row)

    def enqueue_mcp_alert(
        self,
        *,
        alert_type: str,
        severity: str,
        mcp_server_id: str | None,
        mcp_tool_id: str | None,
        summary: str,
        details: dict[str, Any] | None,
        event_key: str,
    ) -> dict[str, Any] | None:
        now = utc_now()
        alert_id = hashlib.sha256(f"{event_key}:{now}".encode("utf-8")).hexdigest()
        with self._lock, closing(self._connect()) as connection:
            connection.execute(
                f"""
                INSERT INTO mcp_alert_outbox (
                    alert_id, alert_type, severity, mcp_server_id, mcp_tool_id,
                    summary, details_json, status, acknowledged_at, created_at, event_key
                )
                VALUES (
                    {self._p}, {self._p}, {self._p}, {self._p}, {self._p},
                    {self._p}, {self._p}, {self._p}, {self._p}, {self._p}, {self._p}
                )
                ON CONFLICT(event_key) DO NOTHING
                """,
                (
                    alert_id,
                    alert_type,
                    severity,
                    mcp_server_id,
                    mcp_tool_id,
                    summary,
                    json.dumps(details or {}, sort_keys=True),
                    "pending",
                    None,
                    now,
                    event_key,
                ),
            )
            row = connection.execute(
                f"""
                SELECT alert_id, alert_type, severity, mcp_server_id, mcp_tool_id,
                       summary, details_json, status, acknowledged_at, created_at, event_key
                FROM mcp_alert_outbox
                WHERE event_key = {self._p}
                """,
                (event_key,),
            ).fetchone()
            connection.commit()
        if row is None:
            return None
        return self._row_to_mcp_alert(row)

    def list_mcp_alerts(
        self,
        *,
        status: str | None = None,
        alert_type: str | None = None,
        mcp_server_id: str | None = None,
        mcp_tool_id: str | None = None,
    ) -> list[dict[str, Any]]:
        query = """
            SELECT alert_id, alert_type, severity, mcp_server_id, mcp_tool_id,
                   summary, details_json, status, acknowledged_at, created_at, event_key
            FROM mcp_alert_outbox
        """
        clauses: list[str] = []
        params: list[Any] = []
        if status is not None:
            clauses.append(f"status = {self._p}")
            params.append(status)
        if alert_type is not None:
            clauses.append(f"alert_type = {self._p}")
            params.append(alert_type)
        if mcp_server_id is not None:
            clauses.append(f"mcp_server_id = {self._p}")
            params.append(mcp_server_id)
        if mcp_tool_id is not None:
            clauses.append(f"mcp_tool_id = {self._p}")
            params.append(mcp_tool_id)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY created_at ASC"
        with self._lock, closing(self._connect()) as connection:
            rows = connection.execute(query, tuple(params)).fetchall()
        return [self._row_to_mcp_alert(row) for row in rows]

    def acknowledge_mcp_alert(self, alert_id: str) -> dict[str, Any] | None:
        with self._lock, closing(self._connect()) as connection:
            connection.execute(
                f"""
                UPDATE mcp_alert_outbox
                SET status = {self._p}, acknowledged_at = {self._p}
                WHERE alert_id = {self._p}
                """,
                ("acknowledged", utc_now(), alert_id),
            )
            row = connection.execute(
                f"""
                SELECT alert_id, alert_type, severity, mcp_server_id, mcp_tool_id,
                       summary, details_json, status, acknowledged_at, created_at, event_key
                FROM mcp_alert_outbox
                WHERE alert_id = {self._p}
                """,
                (alert_id,),
            ).fetchone()
            connection.commit()
        if row is None:
            return None
        return self._row_to_mcp_alert(row)

    def _row_to_mcp_alert(self, row: Any) -> dict[str, Any]:
        return {
            "alert_id": row["alert_id"],
            "alert_type": row["alert_type"],
            "severity": row["severity"],
            "mcp_server_id": row["mcp_server_id"],
            "mcp_tool_id": row["mcp_tool_id"],
            "summary": row["summary"],
            "details": json.loads(row["details_json"]),
            "status": row["status"],
            "acknowledged_at": row["acknowledged_at"],
            "created_at": row["created_at"],
            "event_key": row["event_key"],
        }

    def set_mcp_alert_status(self, alert_id: str, status: str) -> dict[str, Any] | None:
        with self._lock, closing(self._connect()) as connection:
            connection.execute(
                f"UPDATE mcp_alert_outbox SET status = {self._p} WHERE alert_id = {self._p}",
                (status, alert_id),
            )
            row = connection.execute(
                f"""
                SELECT alert_id, alert_type, severity, mcp_server_id, mcp_tool_id,
                       summary, details_json, status, acknowledged_at, created_at, event_key
                FROM mcp_alert_outbox
                WHERE alert_id = {self._p}
                """,
                (alert_id,),
            ).fetchone()
            connection.commit()
        if row is None:
            return None
        return self._row_to_mcp_alert(row)

    def enqueue_approval_alert(
        self,
        *,
        alert_type: str,
        approval_id: str,
        request_hash: str,
        triggered_by: str,
        requestor_agent_id: str,
        requestor_user_id: str,
        mcp_tool_id: str | None,
        summary: str,
        details: dict[str, Any] | None,
        event_key: str,
    ) -> dict[str, Any] | None:
        now = utc_now()
        alert_id = hashlib.sha256(f"{event_key}:{now}".encode("utf-8")).hexdigest()
        with self._lock, closing(self._connect()) as connection:
            connection.execute(
                f"""
                INSERT INTO approval_alert_outbox (
                    alert_id, alert_type, approval_id, request_hash, triggered_by, requestor_agent_id,
                    requestor_user_id, mcp_tool_id, summary, details_json, status,
                    acknowledged_at, created_at, event_key
                )
                VALUES (
                    {self._p}, {self._p}, {self._p}, {self._p}, {self._p}, {self._p},
                    {self._p}, {self._p}, {self._p}, {self._p}, {self._p},
                    {self._p}, {self._p}, {self._p}
                )
                ON CONFLICT(event_key) DO NOTHING
                """,
                (
                    alert_id,
                    alert_type,
                    approval_id,
                    request_hash,
                    triggered_by,
                    requestor_agent_id,
                    requestor_user_id,
                    mcp_tool_id,
                    summary,
                    json.dumps(details or {}, sort_keys=True),
                    "pending",
                    None,
                    now,
                    event_key,
                ),
            )
            row = connection.execute(
                f"""
                SELECT alert_id, alert_type, approval_id, request_hash, triggered_by, requestor_agent_id,
                       requestor_user_id, mcp_tool_id, summary, details_json, status,
                       acknowledged_at, created_at, event_key
                FROM approval_alert_outbox
                WHERE event_key = {self._p}
                """,
                (event_key,),
            ).fetchone()
            connection.commit()
        if row is None:
            return None
        return self._row_to_approval_alert(row)

    def list_approval_alerts(
        self,
        *,
        status: str | None = None,
        alert_type: str | None = None,
        approval_id: str | None = None,
        requestor_user_id: str | None = None,
        requestor_agent_id: str | None = None,
    ) -> list[dict[str, Any]]:
        query = """
            SELECT alert_id, alert_type, approval_id, request_hash, triggered_by, requestor_agent_id,
                   requestor_user_id, mcp_tool_id, summary, details_json, status,
                   acknowledged_at, created_at, event_key
            FROM approval_alert_outbox
        """
        clauses: list[str] = []
        params: list[Any] = []
        if status is not None:
            clauses.append(f"status = {self._p}")
            params.append(status)
        if alert_type is not None:
            clauses.append(f"alert_type = {self._p}")
            params.append(alert_type)
        if approval_id is not None:
            clauses.append(f"approval_id = {self._p}")
            params.append(approval_id)
        if requestor_user_id is not None:
            clauses.append(f"requestor_user_id = {self._p}")
            params.append(requestor_user_id)
        if requestor_agent_id is not None:
            clauses.append(f"requestor_agent_id = {self._p}")
            params.append(requestor_agent_id)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY created_at ASC"
        with self._lock, closing(self._connect()) as connection:
            rows = connection.execute(query, tuple(params)).fetchall()
        return [self._row_to_approval_alert(row) for row in rows]

    def acknowledge_approval_alert(self, alert_id: str) -> dict[str, Any] | None:
        with self._lock, closing(self._connect()) as connection:
            connection.execute(
                f"""
                UPDATE approval_alert_outbox
                SET status = {self._p}, acknowledged_at = {self._p}
                WHERE alert_id = {self._p}
                """,
                ("acknowledged", utc_now(), alert_id),
            )
            row = connection.execute(
                f"""
                SELECT alert_id, alert_type, approval_id, request_hash, triggered_by, requestor_agent_id,
                       requestor_user_id, mcp_tool_id, summary, details_json, status,
                       acknowledged_at, created_at, event_key
                FROM approval_alert_outbox
                WHERE alert_id = {self._p}
                """,
                (alert_id,),
            ).fetchone()
            connection.commit()
        if row is None:
            return None
        return self._row_to_approval_alert(row)

    def _row_to_approval_alert(self, row: Any) -> dict[str, Any]:
        return {
            "alert_id": row["alert_id"],
            "alert_type": row["alert_type"],
            "approval_id": row["approval_id"],
            "request_hash": row["request_hash"],
            "triggered_by": row["triggered_by"],
            "requestor_agent_id": row["requestor_agent_id"],
            "requestor_user_id": row["requestor_user_id"],
            "mcp_tool_id": row["mcp_tool_id"],
            "summary": row["summary"],
            "details": json.loads(row["details_json"]),
            "status": row["status"],
            "acknowledged_at": row["acknowledged_at"],
            "created_at": row["created_at"],
            "event_key": row["event_key"],
        }

    def set_approval_alert_status(self, alert_id: str, status: str) -> dict[str, Any] | None:
        with self._lock, closing(self._connect()) as connection:
            connection.execute(
                f"UPDATE approval_alert_outbox SET status = {self._p} WHERE alert_id = {self._p}",
                (status, alert_id),
            )
            row = connection.execute(
                f"""
                SELECT alert_id, alert_type, approval_id, request_hash, triggered_by, requestor_agent_id,
                       requestor_user_id, mcp_tool_id, summary, details_json, status,
                       acknowledged_at, created_at, event_key
                FROM approval_alert_outbox
                WHERE alert_id = {self._p}
                """,
                (alert_id,),
            ).fetchone()
            connection.commit()
        if row is None:
            return None
        return self._row_to_approval_alert(row)

    def enqueue_infrastructure_identity_anomaly_alert(
        self,
        *,
        anomaly_id: str,
        transaction_id: str,
        actor_id: str,
        provider_name: str | None,
        subject: str | None,
        posture: str,
        severity: str,
        score: Decimal,
        summary: str,
        details: dict[str, Any] | None,
        event_key: str,
    ) -> dict[str, Any] | None:
        now = utc_now()
        alert_id = hashlib.sha256(f"{event_key}:{now}".encode("utf-8")).hexdigest()
        with self._lock, closing(self._connect()) as connection:
            connection.execute(
                f"""
                INSERT INTO anomaly_alert_outbox (
                    alert_id, anomaly_id, transaction_id, actor_id, provider_name, subject,
                    posture, severity, score, summary, details_json, status,
                    acknowledged_at, created_at, event_key
                )
                VALUES (
                    {self._p}, {self._p}, {self._p}, {self._p}, {self._p}, {self._p},
                    {self._p}, {self._p}, {self._p}, {self._p}, {self._p}, {self._p},
                    {self._p}, {self._p}, {self._p}
                )
                ON CONFLICT(event_key) DO NOTHING
                """,
                (
                    alert_id,
                    anomaly_id,
                    transaction_id,
                    actor_id,
                    provider_name,
                    subject,
                    posture,
                    severity,
                    decimal_to_text(score),
                    summary,
                    json.dumps(details or {}, sort_keys=True),
                    "pending",
                    None,
                    now,
                    event_key,
                ),
            )
            row = connection.execute(
                f"""
                SELECT alert_id, anomaly_id, transaction_id, actor_id, provider_name, subject,
                       posture, severity, score, summary, details_json, status,
                       acknowledged_at, created_at, event_key
                FROM anomaly_alert_outbox
                WHERE event_key = {self._p}
                """,
                (event_key,),
            ).fetchone()
            connection.commit()
        if row is None:
            return None
        return self._row_to_infrastructure_identity_anomaly_alert(row)

    def list_infrastructure_identity_anomaly_alerts(
        self,
        *,
        status: str | None = None,
        severity: str | None = None,
        transaction_id: str | None = None,
        actor_id: str | None = None,
    ) -> list[dict[str, Any]]:
        query = """
            SELECT alert_id, anomaly_id, transaction_id, actor_id, provider_name, subject,
                   posture, severity, score, summary, details_json, status,
                   acknowledged_at, created_at, event_key
            FROM anomaly_alert_outbox
        """
        clauses: list[str] = []
        params: list[Any] = []
        if status is not None:
            clauses.append(f"status = {self._p}")
            params.append(status)
        if severity is not None:
            clauses.append(f"severity = {self._p}")
            params.append(severity)
        if transaction_id is not None:
            clauses.append(f"transaction_id = {self._p}")
            params.append(transaction_id)
        if actor_id is not None:
            clauses.append(f"actor_id = {self._p}")
            params.append(actor_id)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY created_at ASC"
        with self._lock, closing(self._connect()) as connection:
            rows = connection.execute(query, tuple(params)).fetchall()
        return [self._row_to_infrastructure_identity_anomaly_alert(row) for row in rows]

    def acknowledge_infrastructure_identity_anomaly_alert(self, alert_id: str) -> dict[str, Any] | None:
        with self._lock, closing(self._connect()) as connection:
            connection.execute(
                f"""
                UPDATE anomaly_alert_outbox
                SET status = {self._p}, acknowledged_at = {self._p}
                WHERE alert_id = {self._p}
                """,
                ("acknowledged", utc_now(), alert_id),
            )
            row = connection.execute(
                f"""
                SELECT alert_id, anomaly_id, transaction_id, actor_id, provider_name, subject,
                       posture, severity, score, summary, details_json, status,
                       acknowledged_at, created_at, event_key
                FROM anomaly_alert_outbox
                WHERE alert_id = {self._p}
                """,
                (alert_id,),
            ).fetchone()
            connection.commit()
        if row is None:
            return None
        return self._row_to_infrastructure_identity_anomaly_alert(row)

    def set_infrastructure_identity_anomaly_alert_status(self, alert_id: str, status: str) -> dict[str, Any] | None:
        with self._lock, closing(self._connect()) as connection:
            connection.execute(
                f"UPDATE anomaly_alert_outbox SET status = {self._p} WHERE alert_id = {self._p}",
                (status, alert_id),
            )
            row = connection.execute(
                f"""
                SELECT alert_id, anomaly_id, transaction_id, actor_id, provider_name, subject,
                       posture, severity, score, summary, details_json, status,
                       acknowledged_at, created_at, event_key
                FROM anomaly_alert_outbox
                WHERE alert_id = {self._p}
                """,
                (alert_id,),
            ).fetchone()
            connection.commit()
        if row is None:
            return None
        return self._row_to_infrastructure_identity_anomaly_alert(row)

    def _row_to_infrastructure_identity_anomaly_alert(self, row: Any) -> dict[str, Any]:
        return {
            "alert_id": row["alert_id"],
            "anomaly_id": row["anomaly_id"],
            "transaction_id": row["transaction_id"],
            "actor_id": row["actor_id"],
            "provider_name": row["provider_name"],
            "subject": row["subject"],
            "posture": row["posture"],
            "severity": row["severity"],
            "score": decimal_to_text(text_to_decimal(row["score"])),
            "summary": row["summary"],
            "details": json.loads(row["details_json"]),
            "status": row["status"],
            "acknowledged_at": row["acknowledged_at"],
            "created_at": row["created_at"],
            "event_key": row["event_key"],
        }

    def enqueue_siem_export(
        self,
        *,
        export_type: str,
        transaction_id: str,
        anomaly_id: str,
        anomaly_alert_id: str | None,
        actor_id: str,
        provider_name: str | None,
        subject: str | None,
        severity: str,
        summary: str,
        payload: dict[str, Any] | None,
        event_key: str,
    ) -> dict[str, Any] | None:
        now = utc_now()
        export_id = hashlib.sha256(f"{event_key}:{now}".encode("utf-8")).hexdigest()
        with self._lock, closing(self._connect()) as connection:
            connection.execute(
                f"""
                INSERT INTO siem_export_outbox (
                    export_id, export_type, transaction_id, anomaly_id, anomaly_alert_id,
                    actor_id, provider_name, subject, severity, summary, payload_json,
                    status, acknowledged_at, created_at, event_key
                )
                VALUES (
                    {self._p}, {self._p}, {self._p}, {self._p}, {self._p},
                    {self._p}, {self._p}, {self._p}, {self._p}, {self._p}, {self._p},
                    {self._p}, {self._p}, {self._p}, {self._p}
                )
                ON CONFLICT(event_key) DO NOTHING
                """,
                (
                    export_id,
                    export_type,
                    transaction_id,
                    anomaly_id,
                    anomaly_alert_id,
                    actor_id,
                    provider_name,
                    subject,
                    severity,
                    summary,
                    json.dumps(payload or {}, sort_keys=True),
                    "pending",
                    None,
                    now,
                    event_key,
                ),
            )
            row = connection.execute(
                f"""
                SELECT export_id, export_type, transaction_id, anomaly_id, anomaly_alert_id,
                       actor_id, provider_name, subject, severity, summary, payload_json,
                       status, acknowledged_at, created_at, event_key
                FROM siem_export_outbox
                WHERE event_key = {self._p}
                """,
                (event_key,),
            ).fetchone()
            connection.commit()
        if row is None:
            return None
        return self._row_to_siem_export(row)

    def list_siem_exports(
        self,
        *,
        status: str | None = None,
        transaction_id: str | None = None,
        anomaly_id: str | None = None,
        severity: str | None = None,
        actor_id: str | None = None,
    ) -> list[dict[str, Any]]:
        query = """
            SELECT export_id, export_type, transaction_id, anomaly_id, anomaly_alert_id,
                   actor_id, provider_name, subject, severity, summary, payload_json,
                   status, acknowledged_at, created_at, event_key
            FROM siem_export_outbox
        """
        clauses: list[str] = []
        params: list[Any] = []
        for column, value in (
            ("status", status),
            ("transaction_id", transaction_id),
            ("anomaly_id", anomaly_id),
            ("severity", severity),
            ("actor_id", actor_id),
        ):
            if value is not None:
                clauses.append(f"{column} = {self._p}")
                params.append(value)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY created_at ASC"
        with self._lock, closing(self._connect()) as connection:
            rows = connection.execute(query, tuple(params)).fetchall()
        return [self._row_to_siem_export(row) for row in rows]

    def acknowledge_siem_export(self, export_id: str) -> dict[str, Any] | None:
        with self._lock, closing(self._connect()) as connection:
            connection.execute(
                f"""
                UPDATE siem_export_outbox
                SET status = {self._p}, acknowledged_at = {self._p}
                WHERE export_id = {self._p}
                """,
                ("acknowledged", utc_now(), export_id),
            )
            row = connection.execute(
                f"""
                SELECT export_id, export_type, transaction_id, anomaly_id, anomaly_alert_id,
                       actor_id, provider_name, subject, severity, summary, payload_json,
                       status, acknowledged_at, created_at, event_key
                FROM siem_export_outbox
                WHERE export_id = {self._p}
                """,
                (export_id,),
            ).fetchone()
            connection.commit()
        if row is None:
            return None
        return self._row_to_siem_export(row)

    def set_siem_export_status(self, export_id: str, status: str) -> dict[str, Any] | None:
        with self._lock, closing(self._connect()) as connection:
            connection.execute(
                f"UPDATE siem_export_outbox SET status = {self._p} WHERE export_id = {self._p}",
                (status, export_id),
            )
            row = connection.execute(
                f"""
                SELECT export_id, export_type, transaction_id, anomaly_id, anomaly_alert_id,
                       actor_id, provider_name, subject, severity, summary, payload_json,
                       status, acknowledged_at, created_at, event_key
                FROM siem_export_outbox
                WHERE export_id = {self._p}
                """,
                (export_id,),
            ).fetchone()
            connection.commit()
        if row is None:
            return None
        return self._row_to_siem_export(row)

    def _row_to_siem_export(self, row: Any) -> dict[str, Any]:
        return {
            "export_id": row["export_id"],
            "export_type": row["export_type"],
            "transaction_id": row["transaction_id"],
            "anomaly_id": row["anomaly_id"],
            "anomaly_alert_id": row["anomaly_alert_id"],
            "actor_id": row["actor_id"],
            "provider_name": row["provider_name"],
            "subject": row["subject"],
            "severity": row["severity"],
            "summary": row["summary"],
            "payload": json.loads(row["payload_json"]),
            "status": row["status"],
            "acknowledged_at": row["acknowledged_at"],
            "created_at": row["created_at"],
            "event_key": row["event_key"],
        }

    def upsert_webhook_endpoint(
        self,
        *,
        endpoint_id: str,
        target_url: str,
        subscribed_events: list[str],
        shared_secret: str | None,
        is_active: bool,
    ) -> dict[str, Any]:
        now = utc_now()
        with self._lock, closing(self._connect()) as connection:
            connection.execute(
                f"""
                INSERT INTO webhook_endpoints (
                    endpoint_id, target_url, subscribed_events_json, shared_secret,
                    is_active, created_at, updated_at
                )
                VALUES ({self._p}, {self._p}, {self._p}, {self._p}, {self._p}, {self._p}, {self._p})
                ON CONFLICT(endpoint_id) DO UPDATE SET
                    target_url = excluded.target_url,
                    subscribed_events_json = excluded.subscribed_events_json,
                    shared_secret = excluded.shared_secret,
                    is_active = excluded.is_active,
                    updated_at = excluded.updated_at
                """,
                (
                    endpoint_id,
                    target_url,
                    json.dumps(subscribed_events, sort_keys=True),
                    shared_secret,
                    sql_bool(is_active),
                    now,
                    now,
                ),
            )
            connection.commit()
        return self.get_webhook_endpoint(endpoint_id)  # type: ignore[return-value]

    def get_webhook_endpoint(self, endpoint_id: str) -> dict[str, Any] | None:
        with self._lock, closing(self._connect()) as connection:
            row = connection.execute(
                f"""
                SELECT endpoint_id, target_url, subscribed_events_json, shared_secret,
                       is_active, created_at, updated_at
                FROM webhook_endpoints
                WHERE endpoint_id = {self._p}
                """,
                (endpoint_id,),
            ).fetchone()
        if row is None:
            return None
        return self._row_to_webhook_endpoint(row)

    def list_webhook_endpoints(self, active_only: bool = False) -> list[dict[str, Any]]:
        with self._lock, closing(self._connect()) as connection:
            if active_only:
                rows = connection.execute(
                    f"""
                    SELECT endpoint_id, target_url, subscribed_events_json, shared_secret,
                           is_active, created_at, updated_at
                    FROM webhook_endpoints
                    WHERE is_active = {self._p}
                    ORDER BY endpoint_id ASC
                    """,
                    (sql_bool(True),),
                ).fetchall()
            else:
                rows = connection.execute(
                    """
                    SELECT endpoint_id, target_url, subscribed_events_json, shared_secret,
                           is_active, created_at, updated_at
                    FROM webhook_endpoints
                    ORDER BY endpoint_id ASC
                    """
                ).fetchall()
        return [self._row_to_webhook_endpoint(row) for row in rows]

    def _row_to_webhook_endpoint(self, row: Any) -> dict[str, Any]:
        return {
            "endpoint_id": row["endpoint_id"],
            "target_url": row["target_url"],
            "subscribed_events": json.loads(row["subscribed_events_json"]),
            "shared_secret": row["shared_secret"],
            "is_active": bool(row["is_active"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def record_webhook_delivery_attempt(
        self,
        *,
        alert_source: str,
        alert_id: str,
        endpoint_id: str,
        delivery_status: str,
        duration_ms: int | None,
        response_status: int | None,
        response_body: str | None,
        error_message: str | None,
    ) -> dict[str, Any]:
        now = utc_now()
        attempt_id = hashlib.sha256(f"{alert_source}:{alert_id}:{endpoint_id}:{now}".encode("utf-8")).hexdigest()
        with self._lock, closing(self._connect()) as connection:
            connection.execute(
                f"""
                INSERT INTO webhook_delivery_attempts (
                    attempt_id, alert_source, alert_id, endpoint_id, delivery_status,
                    duration_ms, response_status, response_body, error_message, delivered_at, created_at
                )
                VALUES ({self._p}, {self._p}, {self._p}, {self._p}, {self._p}, {self._p}, {self._p}, {self._p}, {self._p}, {self._p}, {self._p})
                """,
                (
                    attempt_id,
                    alert_source,
                    alert_id,
                    endpoint_id,
                    delivery_status,
                    duration_ms,
                    response_status,
                    response_body,
                    error_message,
                    now if delivery_status == "delivered" else None,
                    now,
                ),
            )
            connection.commit()
        return {
            "attempt_id": attempt_id,
            "alert_source": alert_source,
            "alert_id": alert_id,
            "endpoint_id": endpoint_id,
            "delivery_status": delivery_status,
            "duration_ms": duration_ms,
            "response_status": response_status,
            "response_body": response_body,
            "error_message": error_message,
            "delivered_at": now if delivery_status == "delivered" else None,
            "created_at": now,
        }

    def list_webhook_delivery_attempts(self, alert_source: str | None = None, alert_id: str | None = None) -> list[dict[str, Any]]:
        query = """
            SELECT attempt_id, alert_source, alert_id, endpoint_id, delivery_status,
                   duration_ms, response_status, response_body, error_message, delivered_at, created_at
            FROM webhook_delivery_attempts
        """
        clauses: list[str] = []
        params: list[Any] = []
        if alert_source is not None:
            clauses.append(f"alert_source = {self._p}")
            params.append(alert_source)
        if alert_id is not None:
            clauses.append(f"alert_id = {self._p}")
            params.append(alert_id)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY created_at ASC"
        with self._lock, closing(self._connect()) as connection:
            rows = connection.execute(query, tuple(params)).fetchall()
        return [
            {
                "attempt_id": row["attempt_id"],
                "alert_source": row["alert_source"],
                "alert_id": row["alert_id"],
                "endpoint_id": row["endpoint_id"],
                "delivery_status": row["delivery_status"],
                "duration_ms": row["duration_ms"],
                "response_status": row["response_status"],
                "response_body": row["response_body"],
                "error_message": row["error_message"],
                "delivered_at": row["delivered_at"],
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    def count_webhook_delivery_attempts(self, *, alert_source: str, alert_id: str, endpoint_id: str) -> int:
        with self._lock, closing(self._connect()) as connection:
            row = connection.execute(
                f"""
                SELECT COUNT(*) AS total_count
                FROM webhook_delivery_attempts
                WHERE alert_source = {self._p} AND alert_id = {self._p} AND endpoint_id = {self._p}
                """,
                (alert_source, alert_id, endpoint_id),
            ).fetchone()
        return int(row["total_count"])

    def upsert_hitl_rule(
        self,
        *,
        rule_id: str,
        applies_to: str,
        trigger_type: str,
        threshold_amount: Decimal | None,
        vendor_pattern: str | None,
        currency: str | None,
        mcp_tool_id: str | None,
        mcp_action: str | None,
        mcp_server_trust_level: str | None,
        secondary_trigger_type: str | None,
        secondary_threshold_amount: Decimal | None,
        secondary_vendor_pattern: str | None,
        secondary_currency: str | None,
        secondary_mcp_tool_id: str | None,
        secondary_mcp_action: str | None,
        secondary_mcp_server_trust_level: str | None,
        is_active: bool,
    ) -> dict[str, Any]:
        now = utc_now()
        with self._lock, closing(self._connect()) as connection:
            connection.execute(
                f"""
                INSERT INTO hitl_rules (
                    rule_id, applies_to, trigger_type, threshold_amount, vendor_pattern, currency,
                    mcp_tool_id, mcp_action, mcp_server_trust_level,
                    secondary_trigger_type, secondary_threshold_amount, secondary_vendor_pattern,
                    secondary_currency, secondary_mcp_tool_id, secondary_mcp_action, secondary_mcp_server_trust_level,
                    is_active, created_at, updated_at
                )
                VALUES (
                    {self._p}, {self._p}, {self._p}, {self._p}, {self._p}, {self._p},
                    {self._p}, {self._p}, {self._p},
                    {self._p}, {self._p}, {self._p},
                    {self._p}, {self._p}, {self._p}, {self._p},
                    {self._p}, {self._p}, {self._p}
                )
                ON CONFLICT(rule_id) DO UPDATE SET
                    applies_to = excluded.applies_to,
                    trigger_type = excluded.trigger_type,
                    threshold_amount = excluded.threshold_amount,
                    vendor_pattern = excluded.vendor_pattern,
                    currency = excluded.currency,
                    mcp_tool_id = excluded.mcp_tool_id,
                    mcp_action = excluded.mcp_action,
                    mcp_server_trust_level = excluded.mcp_server_trust_level,
                    secondary_trigger_type = excluded.secondary_trigger_type,
                    secondary_threshold_amount = excluded.secondary_threshold_amount,
                    secondary_vendor_pattern = excluded.secondary_vendor_pattern,
                    secondary_currency = excluded.secondary_currency,
                    secondary_mcp_tool_id = excluded.secondary_mcp_tool_id,
                    secondary_mcp_action = excluded.secondary_mcp_action,
                    secondary_mcp_server_trust_level = excluded.secondary_mcp_server_trust_level,
                    is_active = excluded.is_active,
                    updated_at = excluded.updated_at
                """,
                (
                    rule_id,
                    applies_to,
                    trigger_type,
                    decimal_to_text(threshold_amount) if threshold_amount is not None else None,
                    vendor_pattern,
                    currency,
                    mcp_tool_id,
                    mcp_action,
                    mcp_server_trust_level,
                    secondary_trigger_type,
                    decimal_to_text(secondary_threshold_amount) if secondary_threshold_amount is not None else None,
                    secondary_vendor_pattern,
                    secondary_currency,
                    secondary_mcp_tool_id,
                    secondary_mcp_action,
                    secondary_mcp_server_trust_level,
                    sql_bool(is_active),
                    now,
                    now,
                ),
            )
            connection.commit()
        return self.get_hitl_rule(rule_id)  # type: ignore[return-value]

    def get_hitl_rule(self, rule_id: str) -> dict[str, Any] | None:
        with self._lock, closing(self._connect()) as connection:
            row = connection.execute(
                f"""
                SELECT rule_id, applies_to, trigger_type, threshold_amount, vendor_pattern, currency,
                       mcp_tool_id, mcp_action, mcp_server_trust_level,
                       secondary_trigger_type, secondary_threshold_amount, secondary_vendor_pattern,
                       secondary_currency, secondary_mcp_tool_id, secondary_mcp_action, secondary_mcp_server_trust_level,
                       is_active, created_at, updated_at
                FROM hitl_rules
                WHERE rule_id = {self._p}
                """,
                (rule_id,),
            ).fetchone()
        if row is None:
            return None
        return {
            "rule_id": row["rule_id"],
            "applies_to": row["applies_to"],
            "trigger_type": row["trigger_type"],
            "threshold_amount": (
                decimal_to_text(text_to_decimal(row["threshold_amount"]))
                if row["threshold_amount"] is not None
                else None
            ),
            "vendor_pattern": row["vendor_pattern"],
            "currency": row["currency"],
            "mcp_tool_id": row["mcp_tool_id"],
            "mcp_action": row["mcp_action"],
            "mcp_server_trust_level": row["mcp_server_trust_level"],
            "secondary_trigger_type": row["secondary_trigger_type"],
            "secondary_threshold_amount": (
                decimal_to_text(text_to_decimal(row["secondary_threshold_amount"]))
                if row["secondary_threshold_amount"] is not None
                else None
            ),
            "secondary_vendor_pattern": row["secondary_vendor_pattern"],
            "secondary_currency": row["secondary_currency"],
            "secondary_mcp_tool_id": row["secondary_mcp_tool_id"],
            "secondary_mcp_action": row["secondary_mcp_action"],
            "secondary_mcp_server_trust_level": row["secondary_mcp_server_trust_level"],
            "is_active": bool(row["is_active"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def list_hitl_rules(self, active_only: bool = False) -> list[dict[str, Any]]:
        with self._lock, closing(self._connect()) as connection:
            if active_only:
                rows = connection.execute(
                    f"""
                    SELECT rule_id, applies_to, trigger_type, threshold_amount, vendor_pattern, currency,
                           mcp_tool_id, mcp_action, mcp_server_trust_level,
                           secondary_trigger_type, secondary_threshold_amount, secondary_vendor_pattern,
                           secondary_currency, secondary_mcp_tool_id, secondary_mcp_action, secondary_mcp_server_trust_level,
                           is_active, created_at, updated_at
                    FROM hitl_rules
                    WHERE is_active = {self._p}
                    ORDER BY created_at ASC
                    """,
                    (sql_bool(True),),
                ).fetchall()
            else:
                rows = connection.execute(
                    """
                    SELECT rule_id, applies_to, trigger_type, threshold_amount, vendor_pattern, currency,
                           mcp_tool_id, mcp_action, mcp_server_trust_level,
                           secondary_trigger_type, secondary_threshold_amount, secondary_vendor_pattern,
                           secondary_currency, secondary_mcp_tool_id, secondary_mcp_action, secondary_mcp_server_trust_level,
                           is_active, created_at, updated_at
                    FROM hitl_rules
                    ORDER BY created_at ASC
                    """
                ).fetchall()
        return [
            {
                "rule_id": row["rule_id"],
                "applies_to": row["applies_to"],
                "trigger_type": row["trigger_type"],
                "threshold_amount": (
                    decimal_to_text(text_to_decimal(row["threshold_amount"]))
                    if row["threshold_amount"] is not None
                    else None
                ),
                "vendor_pattern": row["vendor_pattern"],
                "currency": row["currency"],
                "mcp_tool_id": row["mcp_tool_id"],
                "mcp_action": row["mcp_action"],
                "mcp_server_trust_level": row["mcp_server_trust_level"],
                "secondary_trigger_type": row["secondary_trigger_type"],
                "secondary_threshold_amount": (
                    decimal_to_text(text_to_decimal(row["secondary_threshold_amount"]))
                    if row["secondary_threshold_amount"] is not None
                    else None
                ),
                "secondary_vendor_pattern": row["secondary_vendor_pattern"],
                "secondary_currency": row["secondary_currency"],
                "secondary_mcp_tool_id": row["secondary_mcp_tool_id"],
                "secondary_mcp_action": row["secondary_mcp_action"],
                "secondary_mcp_server_trust_level": row["secondary_mcp_server_trust_level"],
                "is_active": bool(row["is_active"]),
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            }
            for row in rows
        ]

    def count_user_vendor_authorized_transactions(self, user_id: str, vendor: str) -> int:
        with self._lock, closing(self._connect()) as connection:
            row = connection.execute(
                f"""
                SELECT COUNT(*) AS total_count
                FROM transaction_logs
                WHERE user_id = {self._p} AND vendor = {self._p} AND result = {self._p}
                """,
                (user_id, vendor, "AUTHORIZED"),
            ).fetchone()
        return int(row["total_count"])

    def count_agent_user_authorized_transactions(self, agent_id: str, user_id: str) -> int:
        with self._lock, closing(self._connect()) as connection:
            row = connection.execute(
                f"""
                SELECT COUNT(*) AS total_count
                FROM transaction_logs
                WHERE agent_id = {self._p} AND user_id = {self._p} AND result = {self._p}
                """,
                (agent_id, user_id, "AUTHORIZED"),
            ).fetchone()
        return int(row["total_count"])

    def record_transaction_event(self, transaction_id: str, agent_id: str, user_id: str, created_at: str | None = None) -> None:
        with self._lock, closing(self._connect()) as connection:
            connection.execute(
                f"""
                INSERT INTO transaction_events (transaction_id, agent_id, user_id, created_at)
                VALUES ({self._p}, {self._p}, {self._p}, {self._p})
                """,
                (transaction_id, agent_id, user_id, created_at or utc_now()),
            )
            connection.commit()

    def count_recent_transaction_events(self, agent_id: str, user_id: str, window_start: str) -> int:
        with self._lock, closing(self._connect()) as connection:
            row = connection.execute(
                f"""
                SELECT COUNT(*) AS event_count
                FROM transaction_events
                WHERE agent_id = {self._p} AND user_id = {self._p} AND created_at >= {self._p}
                """,
                (agent_id, user_id, window_start),
            ).fetchone()
        return int(row["event_count"])

    def get_receipt(self, receipt: str) -> dict[str, Any] | None:
        """Load a receipt definition."""

        with self._lock, closing(self._connect()) as connection:
            row = connection.execute(
                f"""
                SELECT receipt, status, pay_to, used_at, metadata_json
                FROM receipts
                WHERE receipt = {self._p}
                """,
                (receipt,),
            ).fetchone()
            if row is None:
                return None
            payload = json.loads(row["metadata_json"])
            payload.update(
                {
                    "receipt": row["receipt"],
                    "status": row["status"],
                    "pay_to": row["pay_to"],
                    "used_at": row["used_at"],
                }
            )
            return payload

    def upsert_receipt(
        self,
        receipt: str,
        status: str,
        pay_to: str,
        metadata: dict[str, Any],
        used_at: str | None = None,
    ) -> dict[str, Any]:
        """Create or update a receipt row."""

        payload = metadata.copy()
        payload.update({"status": status, "pay_to": pay_to})
        with self._lock, closing(self._connect()) as connection:
            connection.execute(
                f"""
                INSERT INTO receipts (receipt, status, pay_to, used_at, metadata_json)
                VALUES ({self._p}, {self._p}, {self._p}, {self._p}, {self._p})
                ON CONFLICT(receipt) DO UPDATE SET
                    status = excluded.status,
                    pay_to = excluded.pay_to,
                    used_at = excluded.used_at,
                    metadata_json = excluded.metadata_json
                """,
                (receipt, status, pay_to, used_at, json.dumps(payload, sort_keys=True)),
            )
            connection.commit()
        stored = payload.copy()
        stored.update({"receipt": receipt, "status": status, "pay_to": pay_to, "used_at": used_at})
        return stored

    def mark_receipt_used(self, receipt: str) -> None:
        """Mark a receipt as consumed so it cannot authorize unrelated requests again."""

        with self._lock, closing(self._connect()) as connection:
            connection.execute(
                f"UPDATE receipts SET used_at = {self._p} WHERE receipt = {self._p}",
                (utc_now(), receipt),
            )
            connection.commit()

    def append_log(self, entry: dict[str, Any]) -> None:
        """Persist an audit log entry."""

        with self._lock, closing(self._connect()) as connection:
            connection.execute(
                f"""
                INSERT INTO transaction_logs (
                    timestamp, transaction_id, request_id, client_ip, agent_id, user_id, vendor, amount,
                    currency, firewall_fee, justification, context_json, result, reason,
                    decision_latency_ms, idempotency_key
                ) VALUES (
                    {self._p}, {self._p}, {self._p}, {self._p}, {self._p}, {self._p}, {self._p}, {self._p},
                    {self._p}, {self._p}, {self._p}, {self._p}, {self._p}, {self._p}, {self._p}, {self._p}
                )
                """,
                (
                    entry["timestamp"],
                    entry.get("transaction_id"),
                    entry["request_id"],
                    entry.get("client_ip"),
                    entry["agent_id"],
                    entry["user_id"],
                    entry["vendor"],
                    decimal_to_text(entry["amount"]),
                    entry["currency"],
                    decimal_to_text(entry["firewall_fee"]),
                    entry["justification"],
                    json.dumps(entry["context"], sort_keys=True),
                    entry["result"],
                    entry.get("reason"),
                    entry["decision_latency_ms"],
                    entry.get("idempotency_key"),
                ),
            )
            connection.commit()

    def append_audit_entry(self, entry: dict[str, Any]) -> dict[str, Any]:
        """Persist a hash-chained audit entry and return the stored record."""

        with self._lock, closing(self._connect()) as connection:
            last_row = connection.execute(
                """
                SELECT sequence_number, entry_hash
                FROM audit_entries
                ORDER BY sequence_number DESC
                LIMIT 1
                """
            ).fetchone()
            sequence_number = 1 if last_row is None else int(last_row["sequence_number"]) + 1
            previous_hash = GENESIS_AUDIT_HASH if last_row is None else last_row["entry_hash"]
            timestamp = entry.get("timestamp", utc_now())
            stored = {
                "sequence_number": sequence_number,
                "timestamp": timestamp,
                "previous_hash": previous_hash,
                "transaction_id": entry.get("transaction_id"),
                "actor_type": entry["actor_type"],
                "actor_id": entry["actor_id"],
                "action": entry["action"],
                "request_path": entry["request_path"],
                "request_payload_hash": entry["request_payload_hash"],
                "request_payload_summary": entry["request_payload_summary"],
                "policy_version": entry["policy_version"],
                "decision": entry["decision"],
                "decision_reason": entry.get("decision_reason"),
                "decision_details": entry.get("decision_details", {}),
                "transaction_amount": entry.get("transaction_amount"),
                "transaction_currency": entry.get("transaction_currency"),
                "mcp_server_id": entry.get("mcp_server_id"),
                "mcp_tool_id": entry.get("mcp_tool_id"),
                "mcp_tool_name": entry.get("mcp_tool_name"),
                "infrastructure_provider_name": entry.get("infrastructure_provider_name"),
                "infrastructure_subject": entry.get("infrastructure_subject"),
                "infrastructure_trust_tier": entry.get("infrastructure_trust_tier"),
            }
            stored["entry_hash"] = compute_audit_entry_hash(stored)
            connection.execute(
                f"""
                INSERT INTO audit_entries (
                    sequence_number, timestamp, previous_hash, entry_hash, transaction_id, actor_type, actor_id,
                    action, request_path, request_payload_hash, request_payload_summary_json,
                    policy_version, decision, decision_reason, decision_details_json,
                    transaction_amount, transaction_currency, mcp_server_id, mcp_tool_id, mcp_tool_name,
                    infrastructure_provider_name, infrastructure_subject, infrastructure_trust_tier
                ) VALUES (
                    {self._p}, {self._p}, {self._p}, {self._p}, {self._p}, {self._p}, {self._p},
                    {self._p}, {self._p}, {self._p}, {self._p}, {self._p}, {self._p},
                    {self._p}, {self._p}, {self._p}, {self._p}, {self._p}, {self._p}, {self._p},
                    {self._p}, {self._p}, {self._p}
                )
                """,
                (
                    stored["sequence_number"],
                    stored["timestamp"],
                    stored["previous_hash"],
                    stored["entry_hash"],
                    stored["transaction_id"],
                    stored["actor_type"],
                    stored["actor_id"],
                    stored["action"],
                    stored["request_path"],
                    stored["request_payload_hash"],
                    json.dumps(stored["request_payload_summary"], sort_keys=True),
                    stored["policy_version"],
                    stored["decision"],
                    stored["decision_reason"],
                    json.dumps(stored["decision_details"], sort_keys=True),
                    decimal_to_text(stored["transaction_amount"]) if stored["transaction_amount"] is not None else None,
                    stored["transaction_currency"],
                    stored["mcp_server_id"],
                    stored["mcp_tool_id"],
                    stored["mcp_tool_name"],
                    stored["infrastructure_provider_name"],
                    stored["infrastructure_subject"],
                    stored["infrastructure_trust_tier"],
                ),
            )
            connection.commit()
        return stored

    def list_audit_entries(self) -> list[dict[str, Any]]:
        """Return audit entries in sequence order."""

        with self._lock, closing(self._connect()) as connection:
            rows = connection.execute(
                """
                SELECT sequence_number, timestamp, previous_hash, entry_hash, transaction_id, actor_type, actor_id,
                       action, request_path, request_payload_hash, request_payload_summary_json,
                       policy_version, decision, decision_reason, decision_details_json,
                       transaction_amount, transaction_currency, mcp_server_id, mcp_tool_id, mcp_tool_name,
                       infrastructure_provider_name, infrastructure_subject, infrastructure_trust_tier
                FROM audit_entries
                ORDER BY sequence_number ASC
                """
            ).fetchall()
        return [
            {
                "sequence_number": int(row["sequence_number"]),
                "timestamp": row["timestamp"],
                "previous_hash": row["previous_hash"],
                "entry_hash": row["entry_hash"],
                "transaction_id": row["transaction_id"],
                "actor_type": row["actor_type"],
                "actor_id": row["actor_id"],
                "action": row["action"],
                "request_path": row["request_path"],
                "request_payload_hash": row["request_payload_hash"],
                "request_payload_summary": json.loads(row["request_payload_summary_json"]),
                "policy_version": row["policy_version"],
                "decision": row["decision"],
                "decision_reason": row["decision_reason"],
                "decision_details": json.loads(row["decision_details_json"]),
                "transaction_amount": (
                    decimal_to_text(text_to_decimal(row["transaction_amount"]))
                    if row["transaction_amount"] is not None
                    else None
                ),
                "transaction_currency": row["transaction_currency"],
                "mcp_server_id": row["mcp_server_id"],
                "mcp_tool_id": row["mcp_tool_id"],
                "mcp_tool_name": row["mcp_tool_name"],
                "infrastructure_provider_name": row["infrastructure_provider_name"],
                "infrastructure_subject": row["infrastructure_subject"],
                "infrastructure_trust_tier": row["infrastructure_trust_tier"],
            }
            for row in rows
        ]

    def verify_audit_chain(self) -> dict[str, Any]:
        """Verify the integrity of the audit hash chain."""

        entries = self.list_audit_entries()
        previous_hash = GENESIS_AUDIT_HASH
        for entry in entries:
            if entry["previous_hash"] != previous_hash:
                return {
                    "valid": False,
                    "entries_checked": entry["sequence_number"],
                    "first_invalid_sequence": entry["sequence_number"],
                    "error": "previous_hash mismatch",
                }
            computed = compute_audit_entry_hash(entry)
            if computed != entry["entry_hash"]:
                return {
                    "valid": False,
                    "entries_checked": entry["sequence_number"],
                    "first_invalid_sequence": entry["sequence_number"],
                    "error": "entry_hash mismatch",
                }
            previous_hash = entry["entry_hash"]
        return {
            "valid": True,
            "entries_checked": len(entries),
            "first_invalid_sequence": None,
            "error": None,
        }

    def get_oauth_client(self, client_id: str) -> dict[str, Any] | None:
        with self._lock, closing(self._connect()) as connection:
            row = connection.execute(
                f"""
                SELECT client_id, client_secret_hash, client_name, client_type,
                       redirect_uris_json, allowed_scopes_json, created_at, is_active
                FROM oauth_clients
                WHERE client_id = {self._p}
                """,
                (client_id,),
            ).fetchone()
        if row is None:
            return None
        return {
            "client_id": row["client_id"],
            "client_secret_hash": row["client_secret_hash"],
            "client_name": row["client_name"],
            "client_type": row["client_type"],
            "redirect_uris": json.loads(row["redirect_uris_json"]),
            "allowed_scopes": json.loads(row["allowed_scopes_json"]),
            "created_at": row["created_at"],
            "is_active": bool(row["is_active"]),
        }

    def create_oauth_authorization_code(
        self,
        code_hash: str,
        client_id: str,
        subject: str,
        agent_id: str | None,
        redirect_uri: str,
        scopes: list[str],
        code_challenge: str,
        code_challenge_method: str,
        expires_at: str,
    ) -> None:
        with self._lock, closing(self._connect()) as connection:
            connection.execute(
                f"""
                INSERT INTO oauth_authorization_codes (
                    code_hash, client_id, subject, agent_id, redirect_uri, scopes_json,
                    code_challenge, code_challenge_method, expires_at, used, created_at
                ) VALUES (
                    {self._p}, {self._p}, {self._p}, {self._p}, {self._p}, {self._p},
                    {self._p}, {self._p}, {self._p}, {self._p}, {self._p}
                )
                """,
                (
                    code_hash,
                    client_id,
                    subject,
                    agent_id,
                    redirect_uri,
                    json.dumps(scopes, sort_keys=True),
                    code_challenge,
                    code_challenge_method,
                    expires_at,
                    0,
                    utc_now(),
                ),
            )
            connection.commit()

    def consume_oauth_authorization_code(self, code_hash: str) -> dict[str, Any] | None:
        with self._lock, closing(self._connect()) as connection:
            row = connection.execute(
                f"""
                SELECT code_hash, client_id, subject, agent_id, redirect_uri, scopes_json,
                       code_challenge, code_challenge_method, expires_at, used
                FROM oauth_authorization_codes
                WHERE code_hash = {self._p}
                """,
                (code_hash,),
            ).fetchone()
            if row is None or bool(row["used"]):
                return None
            connection.execute(
                f"UPDATE oauth_authorization_codes SET used = {self._p} WHERE code_hash = {self._p}",
                (1, code_hash),
            )
            connection.commit()
        return {
            "code_hash": row["code_hash"],
            "client_id": row["client_id"],
            "subject": row["subject"],
            "agent_id": row["agent_id"],
            "redirect_uri": row["redirect_uri"],
            "scopes": json.loads(row["scopes_json"]),
            "code_challenge": row["code_challenge"],
            "code_challenge_method": row["code_challenge_method"],
            "expires_at": row["expires_at"],
        }

    def create_oauth_access_token(
        self,
        token_hash: str,
        client_id: str,
        subject: str,
        agent_id: str | None,
        scopes: list[str],
        expires_at: str,
    ) -> None:
        with self._lock, closing(self._connect()) as connection:
            connection.execute(
                f"""
                INSERT INTO oauth_access_tokens (
                    token_hash, client_id, subject, agent_id, scopes_json, expires_at, revoked, created_at
                ) VALUES ({self._p}, {self._p}, {self._p}, {self._p}, {self._p}, {self._p}, {self._p}, {self._p})
                """,
                (
                    token_hash,
                    client_id,
                    subject,
                    agent_id,
                    json.dumps(scopes, sort_keys=True),
                    expires_at,
                    0,
                    utc_now(),
                ),
            )
            connection.commit()

    def get_oauth_access_token(self, token_hash: str) -> dict[str, Any] | None:
        with self._lock, closing(self._connect()) as connection:
            row = connection.execute(
                f"""
                SELECT token_hash, client_id, subject, agent_id, scopes_json, expires_at, revoked, created_at
                FROM oauth_access_tokens
                WHERE token_hash = {self._p}
                """,
                (token_hash,),
            ).fetchone()
        if row is None:
            return None
        return {
            "token_hash": row["token_hash"],
            "client_id": row["client_id"],
            "subject": row["subject"],
            "agent_id": row["agent_id"],
            "scopes": json.loads(row["scopes_json"]),
            "expires_at": row["expires_at"],
            "revoked": bool(row["revoked"]),
            "created_at": row["created_at"],
        }

    def create_oauth_refresh_token(
        self,
        token_hash: str,
        client_id: str,
        subject: str,
        agent_id: str | None,
        scopes: list[str],
        expires_at: str,
    ) -> None:
        with self._lock, closing(self._connect()) as connection:
            connection.execute(
                f"""
                INSERT INTO oauth_refresh_tokens (
                    token_hash, client_id, subject, agent_id, scopes_json, expires_at, revoked, replaced_by, created_at
                ) VALUES (
                    {self._p}, {self._p}, {self._p}, {self._p}, {self._p}, {self._p}, {self._p}, {self._p}, {self._p}
                )
                """,
                (
                    token_hash,
                    client_id,
                    subject,
                    agent_id,
                    json.dumps(scopes, sort_keys=True),
                    expires_at,
                    0,
                    None,
                    utc_now(),
                ),
            )
            connection.commit()

    def consume_oauth_refresh_token(self, token_hash: str, replaced_by: str) -> dict[str, Any] | None:
        with self._lock, closing(self._connect()) as connection:
            row = connection.execute(
                f"""
                SELECT token_hash, client_id, subject, agent_id, scopes_json, expires_at, revoked, replaced_by
                FROM oauth_refresh_tokens
                WHERE token_hash = {self._p}
                """,
                (token_hash,),
            ).fetchone()
            if row is None or bool(row["revoked"]):
                return None
            connection.execute(
                f"""
                UPDATE oauth_refresh_tokens
                SET revoked = {self._p}, replaced_by = {self._p}
                WHERE token_hash = {self._p}
                """,
                (1, replaced_by, token_hash),
            )
            connection.commit()
        return {
            "token_hash": row["token_hash"],
            "client_id": row["client_id"],
            "subject": row["subject"],
            "agent_id": row["agent_id"],
            "scopes": json.loads(row["scopes_json"]),
            "expires_at": row["expires_at"],
            "revoked": bool(row["revoked"]),
            "replaced_by": row["replaced_by"],
        }

    def revoke_oauth_token(self, token_hash: str) -> bool:
        with self._lock, closing(self._connect()) as connection:
            access_updated = connection.execute(
                f"UPDATE oauth_access_tokens SET revoked = {self._p} WHERE token_hash = {self._p}",
                (1, token_hash),
            ).rowcount
            refresh_updated = connection.execute(
                f"UPDATE oauth_refresh_tokens SET revoked = {self._p} WHERE token_hash = {self._p}",
                (1, token_hash),
            ).rowcount
            connection.commit()
        return bool(access_updated or refresh_updated)

    def upsert_mcp_server(
        self,
        server_id: str,
        server_name: str,
        server_url: str | None,
        transport_type: str,
        trust_level: str,
        trust_level_reason: str | None,
        description_hash: str,
    ) -> dict[str, Any]:
        now = utc_now()
        with self._lock, closing(self._connect()) as connection:
            existing = connection.execute(
                f"SELECT first_seen_at FROM mcp_servers WHERE server_id = {self._p}",
                (server_id,),
            ).fetchone()
            first_seen_at = existing["first_seen_at"] if existing is not None else now
            connection.execute(
                f"""
                INSERT INTO mcp_servers (
                    server_id, server_name, server_url, transport_type, trust_level,
                    trust_level_reason, description_hash, first_seen_at, last_seen_at, is_active
                ) VALUES (
                    {self._p}, {self._p}, {self._p}, {self._p}, {self._p},
                    {self._p}, {self._p}, {self._p}, {self._p}, {self._p}
                )
                ON CONFLICT(server_id) DO UPDATE SET
                    server_name = excluded.server_name,
                    server_url = excluded.server_url,
                    transport_type = excluded.transport_type,
                    trust_level = excluded.trust_level,
                    trust_level_reason = excluded.trust_level_reason,
                    description_hash = excluded.description_hash,
                    last_seen_at = excluded.last_seen_at,
                    is_active = excluded.is_active
                """,
                (
                    server_id,
                    server_name,
                    server_url,
                    transport_type,
                    trust_level,
                    trust_level_reason,
                    description_hash,
                    first_seen_at,
                    now,
                    1,
                ),
            )
            connection.commit()
        return self.get_mcp_server(server_id)  # type: ignore[return-value]

    def get_mcp_server(self, server_id: str) -> dict[str, Any] | None:
        with self._lock, closing(self._connect()) as connection:
            row = connection.execute(
                f"""
                SELECT server_id, server_name, server_url, transport_type, trust_level,
                       trust_level_reason, description_hash, first_seen_at, last_seen_at, is_active
                FROM mcp_servers
                WHERE server_id = {self._p}
                """,
                (server_id,),
            ).fetchone()
        if row is None:
            return None
        return {
            "server_id": row["server_id"],
            "server_name": row["server_name"],
            "server_url": row["server_url"],
            "transport_type": row["transport_type"],
            "trust_level": row["trust_level"],
            "trust_level_reason": row["trust_level_reason"],
            "description_hash": row["description_hash"],
            "first_seen_at": row["first_seen_at"],
            "last_seen_at": row["last_seen_at"],
            "is_active": bool(row["is_active"]),
        }

    def list_mcp_servers(self, trust_level: str | None = None) -> list[dict[str, Any]]:
        with self._lock, closing(self._connect()) as connection:
            if trust_level is None:
                rows = connection.execute(
                    """
                    SELECT server_id, server_name, server_url, transport_type, trust_level,
                           trust_level_reason, description_hash, first_seen_at, last_seen_at, is_active
                    FROM mcp_servers
                    ORDER BY server_id ASC
                    """
                ).fetchall()
            else:
                rows = connection.execute(
                    f"""
                    SELECT server_id, server_name, server_url, transport_type, trust_level,
                           trust_level_reason, description_hash, first_seen_at, last_seen_at, is_active
                    FROM mcp_servers
                    WHERE trust_level = {self._p}
                    ORDER BY server_id ASC
                    """,
                    (trust_level,),
                ).fetchall()
        return [
            {
                "server_id": row["server_id"],
                "server_name": row["server_name"],
                "server_url": row["server_url"],
                "transport_type": row["transport_type"],
                "trust_level": row["trust_level"],
                "trust_level_reason": row["trust_level_reason"],
                "description_hash": row["description_hash"],
                "first_seen_at": row["first_seen_at"],
                "last_seen_at": row["last_seen_at"],
                "is_active": bool(row["is_active"]),
            }
            for row in rows
        ]

    def update_mcp_server_trust(self, server_id: str, trust_level: str, reason: str | None) -> dict[str, Any] | None:
        with self._lock, closing(self._connect()) as connection:
            updated = connection.execute(
                f"""
                UPDATE mcp_servers
                SET trust_level = {self._p}, trust_level_reason = {self._p}, last_seen_at = {self._p}
                WHERE server_id = {self._p}
                """,
                (trust_level, reason, utc_now(), server_id),
            ).rowcount
            connection.commit()
        if not updated:
            return None
        return self.get_mcp_server(server_id)

    def upsert_mcp_tool(
        self,
        tool_id: str,
        tool_name: str,
        server_id: str,
        description: str,
        description_hash: str,
        input_schema: dict[str, Any],
        is_payment_relevant: bool,
        threat_flags: list[str],
        quarantine_status: str,
    ) -> dict[str, Any]:
        now = utc_now()
        with self._lock, closing(self._connect()) as connection:
            existing = connection.execute(
                f"""
                SELECT description_first_seen_hash, quarantine_status, threat_flags_json
                FROM mcp_tools
                WHERE tool_id = {self._p}
                """,
                (tool_id,),
            ).fetchone()
            first_seen_hash = existing["description_first_seen_hash"] if existing is not None else description_hash
            description_changed = int(first_seen_hash != description_hash)
            prior_quarantine_status = existing["quarantine_status"] if existing is not None else None
            prior_threat_flags = json.loads(existing["threat_flags_json"]) if existing is not None else []
            merged_flags = sorted(set(prior_threat_flags) | set(threat_flags))
            next_quarantine_status = quarantine_status
            if description_changed and not merged_flags and next_quarantine_status == "clear":
                next_quarantine_status = "review"
                merged_flags = ["description_changed"]
            elif description_changed and "critical" in merged_flags:
                next_quarantine_status = "quarantined"
            elif description_changed and prior_quarantine_status in {"quarantined", "blocked"}:
                next_quarantine_status = prior_quarantine_status
            connection.execute(
                f"""
                INSERT INTO mcp_tools (
                    tool_id, tool_name, server_id, description, description_hash,
                    description_first_seen_hash, description_changed, input_schema_json,
                    is_payment_relevant, threat_flags_json, quarantine_status, created_at, updated_at
                ) VALUES (
                    {self._p}, {self._p}, {self._p}, {self._p}, {self._p},
                    {self._p}, {self._p}, {self._p}, {self._p}, {self._p}, {self._p}, {self._p}, {self._p}
                )
                ON CONFLICT(tool_id) DO UPDATE SET
                    tool_name = excluded.tool_name,
                    server_id = excluded.server_id,
                    description = excluded.description,
                    description_hash = excluded.description_hash,
                    description_changed = excluded.description_changed,
                    input_schema_json = excluded.input_schema_json,
                    is_payment_relevant = excluded.is_payment_relevant,
                    threat_flags_json = excluded.threat_flags_json,
                    quarantine_status = excluded.quarantine_status,
                    updated_at = excluded.updated_at
                """,
                (
                    tool_id,
                    tool_name,
                    server_id,
                    description,
                    description_hash,
                    first_seen_hash,
                    description_changed,
                    json.dumps(input_schema, sort_keys=True),
                    int(is_payment_relevant),
                    json.dumps(merged_flags, sort_keys=True),
                    next_quarantine_status,
                    now,
                    now,
                ),
            )
            connection.commit()
        return self.get_mcp_tool(tool_id)  # type: ignore[return-value]

    def get_mcp_tool(self, tool_id: str) -> dict[str, Any] | None:
        with self._lock, closing(self._connect()) as connection:
            row = connection.execute(
                f"""
                SELECT tool_id, tool_name, server_id, description, description_hash,
                       description_first_seen_hash, description_changed, input_schema_json,
                       is_payment_relevant, threat_flags_json, quarantine_status, created_at, updated_at
                FROM mcp_tools
                WHERE tool_id = {self._p}
                """,
                (tool_id,),
            ).fetchone()
        if row is None:
            return None
        return {
            "tool_id": row["tool_id"],
            "tool_name": row["tool_name"],
            "server_id": row["server_id"],
            "description": row["description"],
            "description_hash": row["description_hash"],
            "description_first_seen_hash": row["description_first_seen_hash"],
            "description_changed": bool(row["description_changed"]),
            "input_schema": json.loads(row["input_schema_json"]),
            "is_payment_relevant": bool(row["is_payment_relevant"]),
            "threat_flags": json.loads(row["threat_flags_json"]),
            "quarantine_status": row["quarantine_status"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def list_mcp_tools(self, server_id: str | None = None) -> list[dict[str, Any]]:
        with self._lock, closing(self._connect()) as connection:
            if server_id is None:
                rows = connection.execute(
                    """
                    SELECT tool_id, tool_name, server_id, description, description_hash,
                           description_first_seen_hash, description_changed, input_schema_json,
                           is_payment_relevant, threat_flags_json, quarantine_status, created_at, updated_at
                    FROM mcp_tools
                    ORDER BY tool_id ASC
                    """
                ).fetchall()
            else:
                rows = connection.execute(
                    f"""
                    SELECT tool_id, tool_name, server_id, description, description_hash,
                           description_first_seen_hash, description_changed, input_schema_json,
                           is_payment_relevant, threat_flags_json, quarantine_status, created_at, updated_at
                    FROM mcp_tools
                    WHERE server_id = {self._p}
                    ORDER BY tool_id ASC
                    """,
                    (server_id,),
                ).fetchall()
        return [
            {
                "tool_id": row["tool_id"],
                "tool_name": row["tool_name"],
                "server_id": row["server_id"],
                "description": row["description"],
                "description_hash": row["description_hash"],
                "description_first_seen_hash": row["description_first_seen_hash"],
                "description_changed": bool(row["description_changed"]),
                "input_schema": json.loads(row["input_schema_json"]),
                "is_payment_relevant": bool(row["is_payment_relevant"]),
                "threat_flags": json.loads(row["threat_flags_json"]),
                "quarantine_status": row["quarantine_status"],
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            }
            for row in rows
        ]

    def update_mcp_tool_quarantine(self, tool_id: str, quarantine_status: str, threat_flags: list[str]) -> dict[str, Any] | None:
        with self._lock, closing(self._connect()) as connection:
            updated = connection.execute(
                f"""
                UPDATE mcp_tools
                SET quarantine_status = {self._p}, threat_flags_json = {self._p}, updated_at = {self._p}
                WHERE tool_id = {self._p}
                """,
                (quarantine_status, json.dumps(threat_flags, sort_keys=True), utc_now(), tool_id),
            ).rowcount
            connection.commit()
        if not updated:
            return None
        return self.get_mcp_tool(tool_id)

    def upsert_mcp_tool_permission(
        self,
        tool_id: str,
        user_id: str,
        allowed_actions: list[str],
        daily_cap: Decimal | None,
        transaction_cap: Decimal | None,
        requires_hitl: bool,
    ) -> dict[str, Any]:
        now = utc_now()
        with self._lock, closing(self._connect()) as connection:
            connection.execute(
                f"""
                INSERT INTO mcp_tool_permissions (
                    tool_id, user_id, allowed_actions_json, daily_cap, transaction_cap,
                    requires_hitl, is_active, created_at, updated_at
                ) VALUES (
                    {self._p}, {self._p}, {self._p}, {self._p}, {self._p},
                    {self._p}, {self._p}, {self._p}, {self._p}
                )
                ON CONFLICT(tool_id, user_id) DO UPDATE SET
                    allowed_actions_json = excluded.allowed_actions_json,
                    daily_cap = excluded.daily_cap,
                    transaction_cap = excluded.transaction_cap,
                    requires_hitl = excluded.requires_hitl,
                    is_active = excluded.is_active,
                    updated_at = excluded.updated_at
                """,
                (
                    tool_id,
                    user_id,
                    json.dumps(sorted(allowed_actions), sort_keys=True),
                    decimal_to_text(daily_cap) if daily_cap is not None else None,
                    decimal_to_text(transaction_cap) if transaction_cap is not None else None,
                    int(requires_hitl),
                    1,
                    now,
                    now,
                ),
            )
            connection.commit()
        return self.get_mcp_tool_permission(tool_id, user_id)  # type: ignore[return-value]

    def get_mcp_tool_permission(self, tool_id: str, user_id: str) -> dict[str, Any] | None:
        with self._lock, closing(self._connect()) as connection:
            row = connection.execute(
                f"""
                SELECT tool_id, user_id, allowed_actions_json, daily_cap, transaction_cap,
                       requires_hitl, is_active, created_at, updated_at
                FROM mcp_tool_permissions
                WHERE tool_id = {self._p} AND user_id = {self._p}
                """,
                (tool_id, user_id),
            ).fetchone()
        if row is None:
            return None
        return {
            "tool_id": row["tool_id"],
            "user_id": row["user_id"],
            "allowed_actions": json.loads(row["allowed_actions_json"]),
            "daily_cap": decimal_to_text(text_to_decimal(row["daily_cap"])) if row["daily_cap"] is not None else None,
            "transaction_cap": (
                decimal_to_text(text_to_decimal(row["transaction_cap"])) if row["transaction_cap"] is not None else None
            ),
            "requires_hitl": bool(row["requires_hitl"]),
            "is_active": bool(row["is_active"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def list_mcp_tool_permissions(self, user_id: str | None = None) -> list[dict[str, Any]]:
        with self._lock, closing(self._connect()) as connection:
            if user_id is None:
                rows = connection.execute(
                    """
                    SELECT tool_id, user_id, allowed_actions_json, daily_cap, transaction_cap,
                           requires_hitl, is_active, created_at, updated_at
                    FROM mcp_tool_permissions
                    WHERE is_active = 1
                    ORDER BY tool_id ASC, user_id ASC
                    """
                ).fetchall()
            else:
                rows = connection.execute(
                    f"""
                    SELECT tool_id, user_id, allowed_actions_json, daily_cap, transaction_cap,
                           requires_hitl, is_active, created_at, updated_at
                    FROM mcp_tool_permissions
                    WHERE is_active = 1 AND user_id = {self._p}
                    ORDER BY tool_id ASC
                    """,
                    (user_id,),
                ).fetchall()
        return [
            {
                "tool_id": row["tool_id"],
                "user_id": row["user_id"],
                "allowed_actions": json.loads(row["allowed_actions_json"]),
                "daily_cap": decimal_to_text(text_to_decimal(row["daily_cap"])) if row["daily_cap"] is not None else None,
                "transaction_cap": (
                    decimal_to_text(text_to_decimal(row["transaction_cap"])) if row["transaction_cap"] is not None else None
                ),
                "requires_hitl": bool(row["requires_hitl"]),
                "is_active": bool(row["is_active"]),
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            }
            for row in rows
        ]

    def deactivate_mcp_tool_permission(self, tool_id: str, user_id: str) -> bool:
        with self._lock, closing(self._connect()) as connection:
            updated = connection.execute(
                f"""
                UPDATE mcp_tool_permissions
                SET is_active = {self._p}, updated_at = {self._p}
                WHERE tool_id = {self._p} AND user_id = {self._p}
                """,
                (0, utc_now(), tool_id, user_id),
            ).rowcount
            connection.commit()
        return bool(updated)

    def create_approval_request(
        self,
        approval_id: str,
        request_hash: str,
        request_path: str,
        request_payload: dict[str, Any],
        triggered_by: str,
        requestor_agent_id: str,
        requestor_user_id: str,
        mcp_tool_id: str | None,
        expires_at: str,
    ) -> dict[str, Any]:
        now = utc_now()
        with self._lock, closing(self._connect()) as connection:
            connection.execute(
                f"""
                INSERT INTO approval_requests (
                    approval_id, request_hash, request_path, request_payload_json, triggered_by,
                    requestor_agent_id, requestor_user_id, mcp_tool_id, status,
                    decided_by, decided_at, decision_reason, expires_at, created_at
                ) VALUES (
                    {self._p}, {self._p}, {self._p}, {self._p}, {self._p},
                    {self._p}, {self._p}, {self._p}, {self._p},
                    {self._p}, {self._p}, {self._p}, {self._p}, {self._p}
                )
                """,
                (
                    approval_id,
                    request_hash,
                    request_path,
                    json.dumps(request_payload, sort_keys=True),
                    triggered_by,
                    requestor_agent_id,
                    requestor_user_id,
                    mcp_tool_id,
                    "pending",
                    None,
                    None,
                    None,
                    expires_at,
                    now,
                ),
            )
            connection.commit()
        return self.get_approval_request(approval_id)  # type: ignore[return-value]

    def get_approval_request(self, approval_id: str) -> dict[str, Any] | None:
        with self._lock, closing(self._connect()) as connection:
            row = connection.execute(
                f"""
                SELECT approval_id, request_hash, request_path, request_payload_json, triggered_by,
                       requestor_agent_id, requestor_user_id, mcp_tool_id, status,
                       decided_by, decided_at, decision_reason, expires_at, created_at
                FROM approval_requests
                WHERE approval_id = {self._p}
                """,
                (approval_id,),
            ).fetchone()
        if row is None:
            return None
        return {
            "approval_id": row["approval_id"],
            "request_hash": row["request_hash"],
            "request_path": row["request_path"],
            "request_payload": json.loads(row["request_payload_json"]),
            "triggered_by": row["triggered_by"],
            "requestor_agent_id": row["requestor_agent_id"],
            "requestor_user_id": row["requestor_user_id"],
            "mcp_tool_id": row["mcp_tool_id"],
            "status": row["status"],
            "decided_by": row["decided_by"],
            "decided_at": row["decided_at"],
            "decision_reason": row["decision_reason"],
            "expires_at": row["expires_at"],
            "created_at": row["created_at"],
        }

    def list_approval_requests(self, status: str | None = None) -> list[dict[str, Any]]:
        with self._lock, closing(self._connect()) as connection:
            if status is None:
                rows = connection.execute(
                    """
                    SELECT approval_id, request_hash, request_path, request_payload_json, triggered_by,
                           requestor_agent_id, requestor_user_id, mcp_tool_id, status,
                           decided_by, decided_at, decision_reason, expires_at, created_at
                    FROM approval_requests
                    ORDER BY created_at ASC
                    """
                ).fetchall()
            else:
                rows = connection.execute(
                    f"""
                    SELECT approval_id, request_hash, request_path, request_payload_json, triggered_by,
                           requestor_agent_id, requestor_user_id, mcp_tool_id, status,
                           decided_by, decided_at, decision_reason, expires_at, created_at
                    FROM approval_requests
                    WHERE status = {self._p}
                    ORDER BY created_at ASC
                    """,
                    (status,),
                ).fetchall()
        return [
            {
                "approval_id": row["approval_id"],
                "request_hash": row["request_hash"],
                "request_path": row["request_path"],
                "request_payload": json.loads(row["request_payload_json"]),
                "triggered_by": row["triggered_by"],
                "requestor_agent_id": row["requestor_agent_id"],
                "requestor_user_id": row["requestor_user_id"],
                "mcp_tool_id": row["mcp_tool_id"],
                "status": row["status"],
                "decided_by": row["decided_by"],
                "decided_at": row["decided_at"],
                "decision_reason": row["decision_reason"],
                "expires_at": row["expires_at"],
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    def decide_approval_request(self, approval_id: str, status: str, decided_by: str, reason: str | None) -> dict[str, Any] | None:
        with self._lock, closing(self._connect()) as connection:
            row = connection.execute(
                f"SELECT status FROM approval_requests WHERE approval_id = {self._p}",
                (approval_id,),
            ).fetchone()
            if row is None or row["status"] != "pending":
                return None
            now = utc_now()
            connection.execute(
                f"""
                UPDATE approval_requests
                SET status = {self._p}, decided_by = {self._p}, decided_at = {self._p}, decision_reason = {self._p}
                WHERE approval_id = {self._p}
                """,
                (status, decided_by, now, reason, approval_id),
            )
            connection.commit()
        return self.get_approval_request(approval_id)

    def expire_approval_requests(self, now_iso: str | None = None) -> int:
        now_value = now_iso or utc_now()
        with self._lock, closing(self._connect()) as connection:
            updated = connection.execute(
                f"""
                UPDATE approval_requests
                SET status = {self._p}, decision_reason = COALESCE(decision_reason, {self._p}), decided_at = {self._p}
                WHERE status = {self._p} AND expires_at <= {self._p}
                """,
                ("expired", "Approval expired before review.", now_value, "pending", now_value),
            ).rowcount
            connection.commit()
        return int(updated)

    def create_spend_token(
        self,
        token_hash: str,
        token_id: str,
        request_hash: str,
        user_id: str,
        agent_id: str,
        mcp_tool_id: str | None,
        authorized_amount: Decimal,
        authorized_currency: str,
        authorized_action: str | None,
        expires_at: str,
    ) -> None:
        with self._lock, closing(self._connect()) as connection:
            connection.execute(
                f"""
                INSERT INTO spend_tokens (
                    token_hash, token_id, request_hash, user_id, agent_id, mcp_tool_id,
                    authorized_amount, authorized_currency, authorized_action, expires_at,
                    is_used, used_at, revoked, created_at
                ) VALUES (
                    {self._p}, {self._p}, {self._p}, {self._p}, {self._p}, {self._p},
                    {self._p}, {self._p}, {self._p}, {self._p},
                    {self._p}, {self._p}, {self._p}, {self._p}
                )
                """,
                (
                    token_hash,
                    token_id,
                    request_hash,
                    user_id,
                    agent_id,
                    mcp_tool_id,
                    decimal_to_text(authorized_amount),
                    authorized_currency,
                    authorized_action,
                    expires_at,
                    0,
                    None,
                    0,
                    utc_now(),
                ),
            )
            connection.commit()

    def upsert_ap2_mandate(
        self,
        *,
        mandate_id: str,
        mandate_type: str,
        signer_id: str | None,
        key_id: str | None,
        family_id: str,
        parent_mandate_id: str | None,
        chain_status: str,
        chain_depth: int,
        lifecycle_status: str,
        request_hash: str,
        requestor_agent_id: str,
        requestor_user_id: str,
        vendor: str,
        amount: Decimal,
        currency: str,
        reference: str | None,
        signature: str | None,
        payload: dict[str, Any],
        parsed_mandate: dict[str, Any] | None,
        verifier_name: str,
        verification_status: str,
        verification_reason_code: str,
        discrepancies: list[str],
    ) -> dict[str, Any]:
        now = utc_now()
        with self._lock, closing(self._connect()) as connection:
            connection.execute(
                f"""
                INSERT INTO ap2_mandates (
                    mandate_id, mandate_type, signer_id, key_id, family_id, parent_mandate_id, chain_status, chain_depth,
                    lifecycle_status, superseded_by_mandate_id, retained_until, archived_at, redacted_at,
                    request_hash, requestor_agent_id, requestor_user_id,
                    vendor, amount, currency, reference, signature, payload_json, parsed_mandate_json,
                    verifier_name, verification_status, verification_reason_code, discrepancies_json,
                    created_at, updated_at
                ) VALUES (
                    {self._p}, {self._p}, {self._p}, {self._p}, {self._p}, {self._p}, {self._p}, {self._p},
                    {self._p}, {self._p}, {self._p}, {self._p}, {self._p},
                    {self._p}, {self._p}, {self._p},
                    {self._p}, {self._p}, {self._p}, {self._p}, {self._p}, {self._p}, {self._p},
                    {self._p}, {self._p}, {self._p}, {self._p},
                    {self._p}, {self._p}
                )
                ON CONFLICT(mandate_id) DO UPDATE SET
                    mandate_type = excluded.mandate_type,
                    signer_id = excluded.signer_id,
                    key_id = excluded.key_id,
                    family_id = excluded.family_id,
                    parent_mandate_id = excluded.parent_mandate_id,
                    chain_status = excluded.chain_status,
                    chain_depth = excluded.chain_depth,
                    lifecycle_status = CASE
                        WHEN ap2_mandates.archived_at IS NOT NULL THEN ap2_mandates.lifecycle_status
                        WHEN ap2_mandates.lifecycle_status IN ('consumed', 'consumed_by_child')
                            THEN ap2_mandates.lifecycle_status
                        ELSE excluded.lifecycle_status
                    END,
                    request_hash = excluded.request_hash,
                    requestor_agent_id = excluded.requestor_agent_id,
                    requestor_user_id = excluded.requestor_user_id,
                    vendor = excluded.vendor,
                    amount = excluded.amount,
                    currency = excluded.currency,
                    reference = CASE
                        WHEN ap2_mandates.redacted_at IS NULL THEN excluded.reference
                        ELSE ap2_mandates.reference
                    END,
                    signature = CASE
                        WHEN ap2_mandates.redacted_at IS NULL THEN excluded.signature
                        ELSE ap2_mandates.signature
                    END,
                    payload_json = CASE
                        WHEN ap2_mandates.redacted_at IS NULL THEN excluded.payload_json
                        ELSE ap2_mandates.payload_json
                    END,
                    parsed_mandate_json = CASE
                        WHEN ap2_mandates.redacted_at IS NULL THEN excluded.parsed_mandate_json
                        ELSE ap2_mandates.parsed_mandate_json
                    END,
                    verifier_name = excluded.verifier_name,
                    verification_status = excluded.verification_status,
                    verification_reason_code = excluded.verification_reason_code,
                    discrepancies_json = excluded.discrepancies_json,
                    updated_at = excluded.updated_at
                """,
                (
                    mandate_id,
                    mandate_type,
                    signer_id,
                    key_id,
                    family_id,
                    parent_mandate_id,
                    chain_status,
                    chain_depth,
                    lifecycle_status,
                    None,
                    None,
                    None,
                    None,
                    request_hash,
                    requestor_agent_id,
                    requestor_user_id,
                    vendor,
                    decimal_to_text(amount),
                    currency,
                    reference,
                    signature,
                    json.dumps(payload, sort_keys=True),
                    json.dumps(parsed_mandate or {}, sort_keys=True),
                    verifier_name,
                    verification_status,
                    verification_reason_code,
                    json.dumps(discrepancies, sort_keys=True),
                    now,
                    now,
                ),
            )
            connection.commit()
        return self.get_ap2_mandate(mandate_id)  # type: ignore[return-value]

    def update_ap2_mandate_lifecycle(
        self,
        *,
        mandate_id: str,
        lifecycle_status: str,
        retained_until: str | None = None,
        superseded_by_mandate_id: str | None = None,
        archived_at: str | None = None,
    ) -> dict[str, Any] | None:
        with self._lock, closing(self._connect()) as connection:
            connection.execute(
                f"""
                UPDATE ap2_mandates
                SET lifecycle_status = {self._p},
                    retained_until = {self._p},
                    superseded_by_mandate_id = {self._p},
                    archived_at = {self._p},
                    updated_at = {self._p}
                WHERE mandate_id = {self._p}
                """,
                (
                    lifecycle_status,
                    retained_until,
                    superseded_by_mandate_id,
                    archived_at,
                    utc_now(),
                    mandate_id,
                ),
            )
            connection.commit()
        return self.get_ap2_mandate(mandate_id)

    @staticmethod
    def _ap2_has_unarchived_descendants(
        mandate_id: str,
        *,
        children_by_parent: dict[str, list[str]],
        archived_ids: set[str],
    ) -> bool:
        seen: set[str] = set()
        stack = list(children_by_parent.get(mandate_id, []))
        while stack:
            child_id = stack.pop()
            if child_id in seen:
                continue
            seen.add(child_id)
            if child_id not in archived_ids:
                return True
            stack.extend(children_by_parent.get(child_id, []))
        return False

    def archive_expired_ap2_mandates(self, *, now_value: str | None = None) -> int:
        effective_now = now_value or utc_now()
        with self._lock, closing(self._connect()) as connection:
            rows = connection.execute(
                f"""
                SELECT mandate_id, parent_mandate_id, retained_until, archived_at
                FROM ap2_mandates
                """
            ).fetchall()
            effective_now_dt = datetime.fromisoformat(effective_now.replace("Z", "+00:00"))
            children_by_parent: dict[str, list[str]] = {}
            archived_ids: set[str] = set()
            expired_candidate_ids: set[str] = set()
            for row in rows:
                mandate_id = str(row["mandate_id"])
                parent_id = row["parent_mandate_id"]
                if parent_id:
                    children_by_parent.setdefault(str(parent_id), []).append(mandate_id)
                if row["archived_at"] is not None:
                    archived_ids.add(mandate_id)
                    continue
                retained_until = row["retained_until"]
                if retained_until is None:
                    continue
                try:
                    retained_until_dt = datetime.fromisoformat(str(retained_until).replace("Z", "+00:00"))
                except ValueError:
                    continue
                if retained_until_dt <= effective_now_dt:
                    expired_candidate_ids.add(mandate_id)

            archived_this_sweep: list[str] = []
            progressed = True
            while progressed:
                progressed = False
                for mandate_id in list(expired_candidate_ids):
                    if self._ap2_has_unarchived_descendants(
                        mandate_id,
                        children_by_parent=children_by_parent,
                        archived_ids=archived_ids,
                    ):
                        continue
                    archived_ids.add(mandate_id)
                    expired_candidate_ids.remove(mandate_id)
                    archived_this_sweep.append(mandate_id)
                    progressed = True

            if not archived_this_sweep:
                return 0
            placeholders = ", ".join(self._p for _ in archived_this_sweep)
            cursor = connection.execute(
                f"""
                UPDATE ap2_mandates
                SET lifecycle_status = 'archived',
                    archived_at = {self._p},
                    updated_at = {self._p}
                WHERE mandate_id IN ({placeholders})
                """,
                (effective_now, effective_now, *archived_this_sweep),
            )
            connection.commit()
        return int(getattr(cursor, "rowcount", 0) or 0)

    def redact_archived_ap2_mandates(
        self,
        *,
        redaction_delay_days: int,
        now_value: str | None = None,
    ) -> int:
        effective_now = now_value or utc_now()
        effective_now_dt = datetime.fromisoformat(effective_now.replace("Z", "+00:00"))
        redact_before_dt = effective_now_dt - timedelta(days=max(0, redaction_delay_days))
        redacted_payload = json.dumps({"redacted": True}, sort_keys=True)
        redacted_parsed_mandate = json.dumps({"redacted": True}, sort_keys=True)
        with self._lock, closing(self._connect()) as connection:
            rows = connection.execute(
                f"""
                SELECT mandate_id, family_id, archived_at, redacted_at
                FROM ap2_mandates
                """
            ).fetchall()
            families_with_unarchived_members: set[str] = set()
            candidate_ids: list[tuple[str, str]] = []
            for row in rows:
                mandate_id = str(row["mandate_id"])
                family_id = str(row["family_id"] or mandate_id)
                archived_at = row["archived_at"]
                if archived_at is None:
                    families_with_unarchived_members.add(family_id)
                    continue
                if row["redacted_at"] is not None:
                    continue
                try:
                    archived_at_dt = datetime.fromisoformat(str(archived_at).replace("Z", "+00:00"))
                except ValueError:
                    continue
                if archived_at_dt <= redact_before_dt:
                    candidate_ids.append((mandate_id, family_id))

            redact_ids = [
                mandate_id
                for mandate_id, family_id in candidate_ids
                if family_id not in families_with_unarchived_members
            ]
            if not redact_ids:
                return 0
            placeholders = ", ".join(self._p for _ in redact_ids)
            cursor = connection.execute(
                f"""
                UPDATE ap2_mandates
                SET reference = NULL,
                    signature = NULL,
                    payload_json = {self._p},
                    parsed_mandate_json = {self._p},
                    redacted_at = {self._p},
                    updated_at = {self._p}
                WHERE mandate_id IN ({placeholders}) AND archived_at IS NOT NULL AND redacted_at IS NULL
                """,
                (redacted_payload, redacted_parsed_mandate, effective_now, effective_now, *redact_ids),
            )
            connection.commit()
        return int(getattr(cursor, "rowcount", 0) or 0)

    def list_ap2_mandate_family(self, family_id: str) -> list[dict[str, Any]]:
        with self._lock, closing(self._connect()) as connection:
            rows = connection.execute(
                f"""
                SELECT mandate_id, mandate_type, signer_id, key_id, family_id, parent_mandate_id, chain_status, chain_depth,
                       lifecycle_status, superseded_by_mandate_id, retained_until, archived_at, redacted_at,
                       request_hash, requestor_agent_id, requestor_user_id,
                       vendor, amount, currency, reference, signature, payload_json, parsed_mandate_json,
                       verifier_name, verification_status, verification_reason_code, discrepancies_json,
                       created_at, updated_at
                FROM ap2_mandates
                WHERE family_id = {self._p}
                ORDER BY chain_depth ASC, created_at ASC
                """,
                (family_id,),
            ).fetchall()
        return [self._row_to_ap2_mandate(row) for row in rows]

    def upsert_ap2_signer_config(
        self,
        *,
        signer_id: str,
        verifier_name: str,
        verifier_key_id: str | None,
        is_enabled: bool,
        notes: str | None,
    ) -> dict[str, Any]:
        now = utc_now()
        with self._lock, closing(self._connect()) as connection:
            connection.execute(
                f"""
                INSERT INTO ap2_signer_configs (
                    signer_id, verifier_name, verifier_key_id, is_enabled, notes, created_at, updated_at
                ) VALUES (
                    {self._p}, {self._p}, {self._p}, {self._p}, {self._p}, {self._p}, {self._p}
                )
                ON CONFLICT(signer_id) DO UPDATE SET
                    verifier_name = excluded.verifier_name,
                    verifier_key_id = excluded.verifier_key_id,
                    is_enabled = excluded.is_enabled,
                    notes = excluded.notes,
                    updated_at = excluded.updated_at
                """,
                (
                    signer_id,
                    verifier_name,
                    verifier_key_id,
                    sql_bool(is_enabled),
                    notes,
                    now,
                    now,
                ),
            )
            connection.commit()
        return self.get_ap2_signer_config(signer_id)  # type: ignore[return-value]

    def get_ap2_signer_config(self, signer_id: str) -> dict[str, Any] | None:
        with self._lock, closing(self._connect()) as connection:
            row = connection.execute(
                f"""
                SELECT signer_id, verifier_name, verifier_key_id, is_enabled, notes, created_at, updated_at
                FROM ap2_signer_configs
                WHERE signer_id = {self._p}
                """,
                (signer_id,),
            ).fetchone()
        if row is None:
            return None
        return {
            "signer_id": row["signer_id"],
            "verifier_name": row["verifier_name"],
            "verifier_key_id": row["verifier_key_id"],
            "is_enabled": bool(row["is_enabled"]),
            "notes": row["notes"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def list_ap2_signer_configs(self, *, is_enabled: bool | None = None) -> list[dict[str, Any]]:
        query = """
            SELECT signer_id, verifier_name, verifier_key_id, is_enabled, notes, created_at, updated_at
            FROM ap2_signer_configs
        """
        params: list[Any] = []
        if is_enabled is not None:
            query += f" WHERE is_enabled = {self._p}"
            params.append(sql_bool(is_enabled))
        query += " ORDER BY signer_id ASC"
        with self._lock, closing(self._connect()) as connection:
            rows = connection.execute(query, tuple(params)).fetchall()
        return [
            {
                "signer_id": row["signer_id"],
                "verifier_name": row["verifier_name"],
                "verifier_key_id": row["verifier_key_id"],
                "is_enabled": bool(row["is_enabled"]),
                "notes": row["notes"],
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            }
            for row in rows
        ]

    def upsert_agent_identity_assertion(
        self,
        *,
        assertion_hash: str,
        provider_name: str,
        subject: str,
        agent_id: str | None,
        client_id: str,
        environment: str | None,
        namespace: str | None,
        service_account: str | None,
        trust_tier: str | None,
        claims: dict[str, Any],
        verification_status: str,
        verification_reason_code: str,
    ) -> dict[str, Any]:
        now = utc_now()
        with self._lock, closing(self._connect()) as connection:
            connection.execute(
                f"""
                INSERT INTO agent_identity_assertions (
                    assertion_hash, provider_name, subject, agent_id, client_id,
                    environment, namespace, service_account, trust_tier, claims_json,
                    verification_status, verification_reason_code, first_seen_at, last_seen_at, seen_count
                ) VALUES (
                    {self._p}, {self._p}, {self._p}, {self._p}, {self._p},
                    {self._p}, {self._p}, {self._p}, {self._p}, {self._p},
                    {self._p}, {self._p}, {self._p}, {self._p}, {self._p}
                )
                ON CONFLICT(assertion_hash) DO UPDATE SET
                    provider_name = excluded.provider_name,
                    subject = excluded.subject,
                    agent_id = excluded.agent_id,
                    client_id = excluded.client_id,
                    environment = excluded.environment,
                    namespace = excluded.namespace,
                    service_account = excluded.service_account,
                    trust_tier = excluded.trust_tier,
                    claims_json = excluded.claims_json,
                    verification_status = excluded.verification_status,
                    verification_reason_code = excluded.verification_reason_code,
                    last_seen_at = excluded.last_seen_at,
                    seen_count = agent_identity_assertions.seen_count + 1
                """,
                (
                    assertion_hash,
                    provider_name,
                    subject,
                    agent_id,
                    client_id,
                    environment,
                    namespace,
                    service_account,
                    trust_tier,
                    json.dumps(claims, sort_keys=True),
                    verification_status,
                    verification_reason_code,
                    now,
                    now,
                    1,
                ),
            )
            connection.commit()
        return self.get_agent_identity_assertion(assertion_hash)  # type: ignore[return-value]

    def get_agent_identity_assertion(self, assertion_hash: str) -> dict[str, Any] | None:
        with self._lock, closing(self._connect()) as connection:
            row = connection.execute(
                f"""
                SELECT assertion_hash, provider_name, subject, agent_id, client_id,
                       environment, namespace, service_account, trust_tier, claims_json,
                       verification_status, verification_reason_code, first_seen_at, last_seen_at, seen_count
                FROM agent_identity_assertions
                WHERE assertion_hash = {self._p}
                """,
                (assertion_hash,),
            ).fetchone()
        if row is None:
            return None
        return {
            "assertion_hash": row["assertion_hash"],
            "provider_name": row["provider_name"],
            "subject": row["subject"],
            "agent_id": row["agent_id"],
            "client_id": row["client_id"],
            "environment": row["environment"],
            "namespace": row["namespace"],
            "service_account": row["service_account"],
            "trust_tier": row["trust_tier"],
            "claims": json.loads(row["claims_json"]),
            "verification_status": row["verification_status"],
            "verification_reason_code": row["verification_reason_code"],
            "first_seen_at": row["first_seen_at"],
            "last_seen_at": row["last_seen_at"],
            "seen_count": int(row["seen_count"]),
        }

    def list_agent_identity_assertions(
        self,
        *,
        provider_name: str | None = None,
        subject: str | None = None,
        agent_id: str | None = None,
        verification_status: str | None = None,
    ) -> list[dict[str, Any]]:
        query = """
            SELECT assertion_hash, provider_name, subject, agent_id, client_id,
                   environment, namespace, service_account, trust_tier, claims_json,
                   verification_status, verification_reason_code, first_seen_at, last_seen_at, seen_count
            FROM agent_identity_assertions
        """
        clauses: list[str] = []
        params: list[Any] = []
        if provider_name is not None:
            clauses.append(f"provider_name = {self._p}")
            params.append(provider_name)
        if subject is not None:
            clauses.append(f"subject = {self._p}")
            params.append(subject)
        if agent_id is not None:
            clauses.append(f"agent_id = {self._p}")
            params.append(agent_id)
        if verification_status is not None:
            clauses.append(f"verification_status = {self._p}")
            params.append(verification_status)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY last_seen_at DESC"
        with self._lock, closing(self._connect()) as connection:
            rows = connection.execute(query, tuple(params)).fetchall()
        return [
            {
                "assertion_hash": row["assertion_hash"],
                "provider_name": row["provider_name"],
                "subject": row["subject"],
                "agent_id": row["agent_id"],
                "client_id": row["client_id"],
                "environment": row["environment"],
                "namespace": row["namespace"],
                "service_account": row["service_account"],
                "trust_tier": row["trust_tier"],
                "claims": json.loads(row["claims_json"]),
                "verification_status": row["verification_status"],
                "verification_reason_code": row["verification_reason_code"],
                "first_seen_at": row["first_seen_at"],
                "last_seen_at": row["last_seen_at"],
                "seen_count": int(row["seen_count"]),
            }
            for row in rows
        ]

    def upsert_infrastructure_identity_profile(
        self,
        *,
        actor_type: str,
        actor_id: str,
        event_type: str,
        action: str,
        provider_name: str | None,
        subject: str | None,
        posture: str,
        environment: str | None,
        namespace: str | None,
        service_account: str | None,
        trust_tier: str | None,
        transaction_currency: str | None,
        amount: Decimal | None,
        transaction_id: str | None,
        request_path: str | None,
    ) -> dict[str, Any]:
        profile_key = hashlib.sha256(
            json.dumps(
                {
                    "actor_type": actor_type,
                    "actor_id": actor_id,
                    "event_type": event_type,
                    "action": action,
                    "provider_name": provider_name,
                    "subject": subject,
                    "posture": posture,
                    "environment": environment,
                    "namespace": namespace,
                    "service_account": service_account,
                    "trust_tier": trust_tier,
                    "transaction_currency": transaction_currency,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        now_value = utc_now()
        amount_text = decimal_to_text(amount) if amount is not None else "0.000000"
        with self._lock, closing(self._connect()) as connection:
            connection.execute(
                f"""
                INSERT INTO infrastructure_identity_profiles (
                    profile_key, actor_type, actor_id, event_type, action,
                    provider_name, subject, posture, environment, namespace,
                    service_account, trust_tier, transaction_currency,
                    event_count, total_amount, first_seen_at, last_seen_at,
                    last_transaction_id, last_request_path
                ) VALUES (
                    {self._p}, {self._p}, {self._p}, {self._p}, {self._p},
                    {self._p}, {self._p}, {self._p}, {self._p}, {self._p},
                    {self._p}, {self._p}, {self._p}, {self._p}, {self._p},
                    {self._p}, {self._p}, {self._p}, {self._p}
                )
                ON CONFLICT(profile_key) DO UPDATE SET
                    event_count = infrastructure_identity_profiles.event_count + 1,
                    total_amount = infrastructure_identity_profiles.total_amount + excluded.total_amount,
                    last_seen_at = excluded.last_seen_at,
                    last_transaction_id = excluded.last_transaction_id,
                    last_request_path = excluded.last_request_path
                """,
                (
                    profile_key,
                    actor_type,
                    actor_id,
                    event_type,
                    action,
                    provider_name,
                    subject,
                    posture,
                    environment,
                    namespace,
                    service_account,
                    trust_tier,
                    transaction_currency,
                    1,
                    amount_text,
                    now_value,
                    now_value,
                    transaction_id,
                    request_path,
                ),
            )
            connection.commit()
        return self.get_infrastructure_identity_profile(profile_key)  # type: ignore[return-value]

    def get_infrastructure_identity_profile(self, profile_key: str) -> dict[str, Any] | None:
        with self._lock, closing(self._connect()) as connection:
            row = connection.execute(
                f"""
                SELECT profile_key, actor_type, actor_id, event_type, action,
                       provider_name, subject, posture, environment, namespace,
                       service_account, trust_tier, transaction_currency,
                       event_count, total_amount, first_seen_at, last_seen_at,
                       last_transaction_id, last_request_path
                FROM infrastructure_identity_profiles
                WHERE profile_key = {self._p}
                """,
                (profile_key,),
            ).fetchone()
        if row is None:
            return None
        return {
            "profile_key": row["profile_key"],
            "actor_type": row["actor_type"],
            "actor_id": row["actor_id"],
            "event_type": row["event_type"],
            "action": row["action"],
            "provider_name": row["provider_name"],
            "subject": row["subject"],
            "posture": row["posture"],
            "environment": row["environment"],
            "namespace": row["namespace"],
            "service_account": row["service_account"],
            "trust_tier": row["trust_tier"],
            "transaction_currency": row["transaction_currency"],
            "event_count": int(row["event_count"]),
            "total_amount": text_to_decimal(row["total_amount"]),
            "first_seen_at": row["first_seen_at"],
            "last_seen_at": row["last_seen_at"],
            "last_transaction_id": row["last_transaction_id"],
            "last_request_path": row["last_request_path"],
        }

    def list_infrastructure_identity_profiles(
        self,
        *,
        actor_type: str | None = None,
        actor_id: str | None = None,
        event_type: str | None = None,
        action: str | None = None,
        provider_name: str | None = None,
        subject: str | None = None,
        posture: str | None = None,
        transaction_currency: str | None = None,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        for column, value in (
            ("actor_type", actor_type),
            ("actor_id", actor_id),
            ("event_type", event_type),
            ("action", action),
            ("provider_name", provider_name),
            ("subject", subject),
            ("posture", posture),
            ("transaction_currency", transaction_currency),
        ):
            if value is not None:
                clauses.append(f"{column} = {self._p}")
                params.append(value)
        where_clause = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._lock, closing(self._connect()) as connection:
            rows = connection.execute(
                f"""
                SELECT profile_key, actor_type, actor_id, event_type, action,
                       provider_name, subject, posture, environment, namespace,
                       service_account, trust_tier, transaction_currency,
                       event_count, total_amount, first_seen_at, last_seen_at,
                       last_transaction_id, last_request_path
                FROM infrastructure_identity_profiles
                {where_clause}
                ORDER BY last_seen_at DESC, profile_key DESC
                """,
                tuple(params),
            ).fetchall()
        return [
            {
                "profile_key": row["profile_key"],
                "actor_type": row["actor_type"],
                "actor_id": row["actor_id"],
                "event_type": row["event_type"],
                "action": row["action"],
                "provider_name": row["provider_name"],
                "subject": row["subject"],
                "posture": row["posture"],
                "environment": row["environment"],
                "namespace": row["namespace"],
                "service_account": row["service_account"],
                "trust_tier": row["trust_tier"],
                "transaction_currency": row["transaction_currency"],
                "event_count": int(row["event_count"]),
                "total_amount": text_to_decimal(row["total_amount"]),
                "first_seen_at": row["first_seen_at"],
                "last_seen_at": row["last_seen_at"],
                "last_transaction_id": row["last_transaction_id"],
                "last_request_path": row["last_request_path"],
            }
            for row in rows
        ]

    def record_infrastructure_identity_anomaly(
        self,
        *,
        anomaly_id: str,
        transaction_id: str | None,
        actor_type: str,
        actor_id: str,
        provider_name: str | None,
        subject: str | None,
        posture: str,
        severity: str,
        score: Decimal,
        baseline_event_count: int,
        baseline_average_amount: Decimal | None,
        observed_amount: Decimal,
        transaction_currency: str | None,
        reason_codes: list[str],
        feature_details: dict[str, Any] | None,
        request_path: str | None,
        created_at: str | None = None,
    ) -> dict[str, Any]:
        created_value = created_at or utc_now()
        with self._lock, closing(self._connect()) as connection:
            connection.execute(
                f"""
                INSERT INTO infrastructure_identity_anomalies (
                    anomaly_id, transaction_id, actor_type, actor_id, provider_name, subject,
                    posture, severity, score, baseline_event_count, baseline_average_amount,
                    observed_amount, transaction_currency, reason_codes_json, feature_details_json, request_path, created_at
                ) VALUES (
                    {self._p}, {self._p}, {self._p}, {self._p}, {self._p}, {self._p},
                    {self._p}, {self._p}, {self._p}, {self._p}, {self._p},
                    {self._p}, {self._p}, {self._p}, {self._p}, {self._p}, {self._p}
                )
                """,
                (
                    anomaly_id,
                    transaction_id,
                    actor_type,
                    actor_id,
                    provider_name,
                    subject,
                    posture,
                    severity,
                    decimal_to_text(score),
                    baseline_event_count,
                    None if baseline_average_amount is None else decimal_to_text(baseline_average_amount),
                    decimal_to_text(observed_amount),
                    transaction_currency,
                    json.dumps(reason_codes, sort_keys=True),
                    json.dumps(feature_details or {}, sort_keys=True),
                    request_path,
                    created_value,
                ),
            )
            connection.commit()
        return self.get_infrastructure_identity_anomaly(anomaly_id)  # type: ignore[return-value]

    def get_infrastructure_identity_anomaly(self, anomaly_id: str) -> dict[str, Any] | None:
        with self._lock, closing(self._connect()) as connection:
            row = connection.execute(
                f"""
                SELECT anomaly_id, transaction_id, actor_type, actor_id, provider_name, subject,
                       posture, severity, score, baseline_event_count, baseline_average_amount,
                       observed_amount, transaction_currency, reason_codes_json, feature_details_json, request_path, created_at
                FROM infrastructure_identity_anomalies
                WHERE anomaly_id = {self._p}
                """,
                (anomaly_id,),
            ).fetchone()
        if row is None:
            return None
        return {
            "anomaly_id": row["anomaly_id"],
            "transaction_id": row["transaction_id"],
            "actor_type": row["actor_type"],
            "actor_id": row["actor_id"],
            "provider_name": row["provider_name"],
            "subject": row["subject"],
            "posture": row["posture"],
            "severity": row["severity"],
            "score": text_to_decimal(row["score"]),
            "baseline_event_count": int(row["baseline_event_count"]),
            "baseline_average_amount": None
            if row["baseline_average_amount"] is None
            else text_to_decimal(row["baseline_average_amount"]),
            "observed_amount": text_to_decimal(row["observed_amount"]),
            "transaction_currency": row["transaction_currency"],
            "reason_codes": json.loads(row["reason_codes_json"]),
            "feature_details": json.loads(row["feature_details_json"] or "{}"),
            "request_path": row["request_path"],
            "created_at": row["created_at"],
        }

    def list_infrastructure_identity_anomalies(
        self,
        *,
        transaction_id: str | None = None,
        actor_id: str | None = None,
        provider_name: str | None = None,
        posture: str | None = None,
        severity: str | None = None,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        for column, value in (
            ("transaction_id", transaction_id),
            ("actor_id", actor_id),
            ("provider_name", provider_name),
            ("posture", posture),
            ("severity", severity),
        ):
            if value is not None:
                clauses.append(f"{column} = {self._p}")
                params.append(value)
        where_clause = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._lock, closing(self._connect()) as connection:
            rows = connection.execute(
                f"""
                SELECT anomaly_id, transaction_id, actor_type, actor_id, provider_name, subject,
                       posture, severity, score, baseline_event_count, baseline_average_amount,
                       observed_amount, transaction_currency, reason_codes_json, feature_details_json, request_path, created_at
                FROM infrastructure_identity_anomalies
                {where_clause}
                ORDER BY created_at DESC, anomaly_id DESC
                """,
                tuple(params),
            ).fetchall()
        return [
            {
                "anomaly_id": row["anomaly_id"],
                "transaction_id": row["transaction_id"],
                "actor_type": row["actor_type"],
                "actor_id": row["actor_id"],
                "provider_name": row["provider_name"],
                "subject": row["subject"],
                "posture": row["posture"],
                "severity": row["severity"],
                "score": text_to_decimal(row["score"]),
                "baseline_event_count": int(row["baseline_event_count"]),
                "baseline_average_amount": None
                if row["baseline_average_amount"] is None
                else text_to_decimal(row["baseline_average_amount"]),
                "observed_amount": text_to_decimal(row["observed_amount"]),
                "transaction_currency": row["transaction_currency"],
                "reason_codes": json.loads(row["reason_codes_json"]),
                "feature_details": json.loads(row["feature_details_json"] or "{}"),
                "request_path": row["request_path"],
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    def upsert_x402_provider_receipt(
        self,
        *,
        receipt_id: str,
        provider_name: str,
        receipt_version: str | None,
        issuer_url: str | None,
        key_id: str | None,
        issued_at: str | None,
        settlement_reference: str | None,
        settlement_proof_type: str | None,
        settlement_proof_value: str | None,
        confirmation_count: int | None,
        confirmed_at: str | None,
        network: str,
        pay_to: str,
        amount_paid: Decimal,
        currency: str,
        status: str,
        settled_at: str,
        expires_at: str | None,
        verification_status: str,
        verification_reason_code: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        now = utc_now()
        with self._lock, closing(self._connect()) as connection:
            connection.execute(
                f"""
                INSERT INTO x402_provider_receipts (
                    receipt_id, provider_name, receipt_version, issuer_url, key_id, issued_at, settlement_reference,
                    settlement_proof_type, settlement_proof_value, confirmation_count, confirmed_at,
                    network, pay_to, amount_paid, currency,
                    status, settled_at, expires_at, used_at, verification_status,
                    verification_reason_code, payload_json, created_at, updated_at
                ) VALUES (
                    {self._p}, {self._p}, {self._p}, {self._p}, {self._p}, {self._p}, {self._p},
                    {self._p}, {self._p}, {self._p}, {self._p},
                    {self._p}, {self._p}, {self._p}, {self._p},
                    {self._p}, {self._p}, {self._p}, {self._p}, {self._p},
                    {self._p}, {self._p}, {self._p}, {self._p}
                )
                ON CONFLICT(receipt_id) DO UPDATE SET
                    provider_name = excluded.provider_name,
                    receipt_version = excluded.receipt_version,
                    issuer_url = excluded.issuer_url,
                    key_id = excluded.key_id,
                    issued_at = excluded.issued_at,
                    settlement_reference = excluded.settlement_reference,
                    settlement_proof_type = excluded.settlement_proof_type,
                    settlement_proof_value = excluded.settlement_proof_value,
                    confirmation_count = excluded.confirmation_count,
                    confirmed_at = excluded.confirmed_at,
                    network = excluded.network,
                    pay_to = excluded.pay_to,
                    amount_paid = excluded.amount_paid,
                    currency = excluded.currency,
                    status = excluded.status,
                    settled_at = excluded.settled_at,
                    expires_at = excluded.expires_at,
                    verification_status = excluded.verification_status,
                    verification_reason_code = excluded.verification_reason_code,
                    payload_json = excluded.payload_json,
                    updated_at = excluded.updated_at
                """,
                (
                    receipt_id,
                    provider_name,
                    receipt_version,
                    issuer_url,
                    key_id,
                    issued_at,
                    settlement_reference,
                    settlement_proof_type,
                    settlement_proof_value,
                    confirmation_count,
                    confirmed_at,
                    network,
                    pay_to,
                    decimal_to_text(amount_paid),
                    currency,
                    status,
                    settled_at,
                    expires_at,
                    None,
                    verification_status,
                    verification_reason_code,
                    json.dumps(payload, sort_keys=True),
                    now,
                    now,
                ),
            )
            connection.commit()
        return self.get_x402_provider_receipt(receipt_id)  # type: ignore[return-value]

    def upsert_x402_provider_receipt_verification(
        self,
        *,
        receipt_id: str,
        verification_status: str,
        verification_reason_code: str,
    ) -> dict[str, Any]:
        with self._lock, closing(self._connect()) as connection:
            connection.execute(
                f"""
                UPDATE x402_provider_receipts
                SET verification_status = {self._p},
                    verification_reason_code = {self._p},
                    updated_at = {self._p}
                WHERE receipt_id = {self._p}
                """,
                (verification_status, verification_reason_code, utc_now(), receipt_id),
            )
            connection.commit()
        return self.get_x402_provider_receipt(receipt_id)  # type: ignore[return-value]

    def get_x402_provider_receipt(self, receipt_id: str) -> dict[str, Any] | None:
        with self._lock, closing(self._connect()) as connection:
            row = connection.execute(
                f"""
                SELECT receipt_id, provider_name, network, pay_to, amount_paid, currency,
                       receipt_version, issuer_url, key_id, issued_at, settlement_reference, settlement_proof_type, settlement_proof_value,
                       confirmation_count, confirmed_at, status, settled_at, expires_at, used_at, verification_status,
                       verification_reason_code, payload_json, created_at, updated_at
                FROM x402_provider_receipts
                WHERE receipt_id = {self._p}
                """,
                (receipt_id,),
            ).fetchone()
        if row is None:
            return None
        return {
            "receipt_id": row["receipt_id"],
            "provider_name": row["provider_name"],
            "receipt_version": row["receipt_version"],
            "issuer_url": row["issuer_url"],
            "key_id": row["key_id"],
            "issued_at": row["issued_at"],
            "settlement_reference": row["settlement_reference"],
            "settlement_proof_type": row["settlement_proof_type"],
            "settlement_proof_value": row["settlement_proof_value"],
            "confirmation_count": row["confirmation_count"],
            "confirmed_at": row["confirmed_at"],
            "network": row["network"],
            "pay_to": row["pay_to"],
            "amount_paid": decimal_to_text(text_to_decimal(row["amount_paid"])),
            "currency": row["currency"],
            "status": row["status"],
            "settled_at": row["settled_at"],
            "expires_at": row["expires_at"],
            "used_at": row["used_at"],
            "verification_status": row["verification_status"],
            "verification_reason_code": row["verification_reason_code"],
            "payload": json.loads(row["payload_json"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def list_x402_provider_receipts(
        self,
        *,
        verification_status: str | None = None,
        provider_name: str | None = None,
        network: str | None = None,
        status: str | None = None,
    ) -> list[dict[str, Any]]:
        query = """
            SELECT receipt_id, provider_name, network, pay_to, amount_paid, currency,
                   receipt_version, issuer_url, key_id, issued_at, settlement_reference, settlement_proof_type, settlement_proof_value,
                   confirmation_count, confirmed_at, status, settled_at, expires_at, used_at, verification_status,
                   verification_reason_code, payload_json, created_at, updated_at
            FROM x402_provider_receipts
        """
        clauses: list[str] = []
        params: list[Any] = []
        if verification_status is not None:
            clauses.append(f"verification_status = {self._p}")
            params.append(verification_status)
        if provider_name is not None:
            clauses.append(f"provider_name = {self._p}")
            params.append(provider_name)
        if network is not None:
            clauses.append(f"network = {self._p}")
            params.append(network)
        if status is not None:
            clauses.append(f"status = {self._p}")
            params.append(status)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY updated_at ASC"
        with self._lock, closing(self._connect()) as connection:
            rows = connection.execute(query, tuple(params)).fetchall()
        return [
            {
                "receipt_id": row["receipt_id"],
                "provider_name": row["provider_name"],
                "receipt_version": row["receipt_version"],
                "issuer_url": row["issuer_url"],
                "key_id": row["key_id"],
                "issued_at": row["issued_at"],
                "settlement_reference": row["settlement_reference"],
                "settlement_proof_type": row["settlement_proof_type"],
                "settlement_proof_value": row["settlement_proof_value"],
                "confirmation_count": row["confirmation_count"],
                "confirmed_at": row["confirmed_at"],
                "network": row["network"],
                "pay_to": row["pay_to"],
                "amount_paid": decimal_to_text(text_to_decimal(row["amount_paid"])),
                "currency": row["currency"],
                "status": row["status"],
                "settled_at": row["settled_at"],
                "expires_at": row["expires_at"],
                "used_at": row["used_at"],
                "verification_status": row["verification_status"],
                "verification_reason_code": row["verification_reason_code"],
                "payload": json.loads(row["payload_json"]),
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            }
            for row in rows
        ]

    def upsert_x402_provider_config(
        self,
        *,
        provider_name: str,
        adapter_name: str,
        issuer_url: str | None,
        issuer_urls: list[str],
        verifier_key_id: str | None,
        verifier_key_ids: list[str],
        trust_anchor_ids: list[str],
        required_settlement_proof_type: str | None,
        minimum_confirmations: int | None,
        supported_networks: list[str],
        is_enabled: bool,
        notes: str | None,
    ) -> dict[str, Any]:
        now = utc_now()
        with self._lock, closing(self._connect()) as connection:
            connection.execute(
                f"""
                INSERT INTO x402_provider_configs (
                    provider_name, adapter_name, issuer_url, issuer_urls_json, verifier_key_id, verifier_key_ids_json, trust_anchor_ids_json,
                    required_settlement_proof_type, minimum_confirmations, supported_networks_json,
                    is_enabled, notes, created_at, updated_at
                ) VALUES (
                    {self._p}, {self._p}, {self._p}, {self._p}, {self._p}, {self._p}, {self._p},
                    {self._p}, {self._p}, {self._p},
                    {self._p}, {self._p}, {self._p}, {self._p}
                )
                ON CONFLICT(provider_name) DO UPDATE SET
                    adapter_name = excluded.adapter_name,
                    issuer_url = excluded.issuer_url,
                    issuer_urls_json = excluded.issuer_urls_json,
                    verifier_key_id = excluded.verifier_key_id,
                    verifier_key_ids_json = excluded.verifier_key_ids_json,
                    trust_anchor_ids_json = excluded.trust_anchor_ids_json,
                    required_settlement_proof_type = excluded.required_settlement_proof_type,
                    minimum_confirmations = excluded.minimum_confirmations,
                    supported_networks_json = excluded.supported_networks_json,
                    is_enabled = excluded.is_enabled,
                    notes = excluded.notes,
                    updated_at = excluded.updated_at
                """,
                (
                    provider_name,
                    adapter_name,
                    issuer_url,
                    json.dumps(issuer_urls, sort_keys=True),
                    verifier_key_id,
                    json.dumps(verifier_key_ids, sort_keys=True),
                    json.dumps(trust_anchor_ids, sort_keys=True),
                    required_settlement_proof_type,
                    minimum_confirmations,
                    json.dumps(supported_networks, sort_keys=True),
                    sql_bool(is_enabled),
                    notes,
                    now,
                    now,
                ),
            )
            connection.commit()
        return self.get_x402_provider_config(provider_name)  # type: ignore[return-value]

    def get_x402_provider_config(self, provider_name: str) -> dict[str, Any] | None:
        with self._lock, closing(self._connect()) as connection:
            row = connection.execute(
                f"""
                SELECT provider_name, adapter_name, issuer_url, issuer_urls_json, supported_networks_json,
                       verifier_key_id, verifier_key_ids_json, trust_anchor_ids_json, required_settlement_proof_type, minimum_confirmations, is_enabled, notes, created_at, updated_at
                FROM x402_provider_configs
                WHERE provider_name = {self._p}
                """,
                (provider_name,),
            ).fetchone()
        if row is None:
            return None
        return {
            "provider_name": row["provider_name"],
            "adapter_name": row["adapter_name"],
            "issuer_url": row["issuer_url"],
            "issuer_urls": json.loads(row["issuer_urls_json"]),
            "verifier_key_id": row["verifier_key_id"],
            "verifier_key_ids": json.loads(row["verifier_key_ids_json"]),
            "trust_anchor_ids": json.loads(row["trust_anchor_ids_json"]),
            "required_settlement_proof_type": row["required_settlement_proof_type"],
            "minimum_confirmations": row["minimum_confirmations"],
            "supported_networks": json.loads(row["supported_networks_json"]),
            "is_enabled": bool(row["is_enabled"]),
            "notes": row["notes"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def list_x402_provider_configs(self, *, is_enabled: bool | None = None) -> list[dict[str, Any]]:
        query = """
            SELECT provider_name, adapter_name, issuer_url, issuer_urls_json, supported_networks_json,
                   verifier_key_id, verifier_key_ids_json, trust_anchor_ids_json, required_settlement_proof_type, minimum_confirmations, is_enabled, notes, created_at, updated_at
            FROM x402_provider_configs
        """
        params: list[Any] = []
        if is_enabled is not None:
            query += f" WHERE is_enabled = {self._p}"
            params.append(sql_bool(is_enabled))
        query += " ORDER BY provider_name ASC"
        with self._lock, closing(self._connect()) as connection:
            rows = connection.execute(query, tuple(params)).fetchall()
        return [
            {
                "provider_name": row["provider_name"],
                "adapter_name": row["adapter_name"],
                "issuer_url": row["issuer_url"],
                "issuer_urls": json.loads(row["issuer_urls_json"]),
                "verifier_key_id": row["verifier_key_id"],
                "verifier_key_ids": json.loads(row["verifier_key_ids_json"]),
                "trust_anchor_ids": json.loads(row["trust_anchor_ids_json"]),
                "required_settlement_proof_type": row["required_settlement_proof_type"],
                "minimum_confirmations": row["minimum_confirmations"],
                "supported_networks": json.loads(row["supported_networks_json"]),
                "is_enabled": bool(row["is_enabled"]),
                "notes": row["notes"],
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            }
            for row in rows
        ]

    def mark_x402_provider_receipt_used(self, receipt_id: str) -> None:
        with self._lock, closing(self._connect()) as connection:
            connection.execute(
                f"""
                UPDATE x402_provider_receipts
                SET used_at = {self._p}, updated_at = {self._p}
                WHERE receipt_id = {self._p}
                """,
                (utc_now(), utc_now(), receipt_id),
            )
            connection.commit()

    def get_ap2_mandate(self, mandate_id: str) -> dict[str, Any] | None:
        with self._lock, closing(self._connect()) as connection:
            row = connection.execute(
                f"""
                SELECT mandate_id, mandate_type, signer_id, key_id, family_id, parent_mandate_id, chain_status, chain_depth,
                       lifecycle_status, superseded_by_mandate_id, retained_until, archived_at, redacted_at,
                       request_hash, requestor_agent_id, requestor_user_id,
                       vendor, amount, currency, reference, signature, payload_json, parsed_mandate_json,
                       verifier_name, verification_status, verification_reason_code, discrepancies_json,
                       created_at, updated_at
                FROM ap2_mandates
                WHERE mandate_id = {self._p}
                """,
                (mandate_id,),
            ).fetchone()
        if row is None:
            return None
        return self._row_to_ap2_mandate(row)

    def list_ap2_mandates(
        self,
        *,
        verification_status: str | None = None,
        lifecycle_status: str | None = None,
        requestor_user_id: str | None = None,
        requestor_agent_id: str | None = None,
    ) -> list[dict[str, Any]]:
        query = """
            SELECT mandate_id, mandate_type, signer_id, key_id, family_id, parent_mandate_id, chain_status, chain_depth,
                   lifecycle_status, superseded_by_mandate_id, retained_until, archived_at, redacted_at,
                   request_hash, requestor_agent_id, requestor_user_id,
                   vendor, amount, currency, reference, signature, payload_json, parsed_mandate_json,
                   verifier_name, verification_status, verification_reason_code, discrepancies_json,
                   created_at, updated_at
            FROM ap2_mandates
        """
        clauses: list[str] = []
        params: list[Any] = []
        if verification_status is not None:
            clauses.append(f"verification_status = {self._p}")
            params.append(verification_status)
        if lifecycle_status is not None:
            clauses.append(f"lifecycle_status = {self._p}")
            params.append(lifecycle_status)
        if requestor_user_id is not None:
            clauses.append(f"requestor_user_id = {self._p}")
            params.append(requestor_user_id)
        if requestor_agent_id is not None:
            clauses.append(f"requestor_agent_id = {self._p}")
            params.append(requestor_agent_id)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY updated_at ASC"
        with self._lock, closing(self._connect()) as connection:
            rows = connection.execute(query, tuple(params)).fetchall()
        return [self._row_to_ap2_mandate(row) for row in rows]

    def _row_to_ap2_mandate(self, row: Any) -> dict[str, Any]:
        return {
            "mandate_id": row["mandate_id"],
            "mandate_type": row["mandate_type"],
            "signer_id": row["signer_id"],
            "key_id": row["key_id"],
            "family_id": row["family_id"] or row["mandate_id"],
            "parent_mandate_id": row["parent_mandate_id"],
            "chain_status": row["chain_status"],
            "chain_depth": row["chain_depth"],
            "lifecycle_status": row["lifecycle_status"],
            "superseded_by_mandate_id": row["superseded_by_mandate_id"],
            "retained_until": row["retained_until"],
            "archived_at": row["archived_at"],
            "redacted_at": row["redacted_at"],
            "request_hash": row["request_hash"],
            "requestor_agent_id": row["requestor_agent_id"],
            "requestor_user_id": row["requestor_user_id"],
            "vendor": row["vendor"],
            "amount": decimal_to_text(text_to_decimal(row["amount"])),
            "currency": row["currency"],
            "reference": row["reference"],
            "signature": row["signature"],
            "payload": json.loads(row["payload_json"]),
            "parsed_mandate": json.loads(row["parsed_mandate_json"]),
            "verifier_name": row["verifier_name"],
            "verification_status": row["verification_status"],
            "verification_reason_code": row["verification_reason_code"],
            "discrepancies": json.loads(row["discrepancies_json"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def get_spend_token(self, token_hash: str) -> dict[str, Any] | None:
        with self._lock, closing(self._connect()) as connection:
            row = connection.execute(
                f"""
                SELECT token_hash, token_id, request_hash, user_id, agent_id, mcp_tool_id,
                       authorized_amount, authorized_currency, authorized_action, expires_at,
                       is_used, used_at, revoked, created_at
                FROM spend_tokens
                WHERE token_hash = {self._p}
                """,
                (token_hash,),
            ).fetchone()
        if row is None:
            return None
        return {
            "token_hash": row["token_hash"],
            "token_id": row["token_id"],
            "request_hash": row["request_hash"],
            "user_id": row["user_id"],
            "agent_id": row["agent_id"],
            "mcp_tool_id": row["mcp_tool_id"],
            "authorized_amount": text_to_decimal(row["authorized_amount"]),
            "authorized_currency": row["authorized_currency"],
            "authorized_action": row["authorized_action"],
            "expires_at": row["expires_at"],
            "is_used": bool(row["is_used"]),
            "used_at": row["used_at"],
            "revoked": bool(row["revoked"]),
            "created_at": row["created_at"],
        }

    def consume_spend_token(self, token_hash: str) -> bool:
        with self._lock, closing(self._connect()) as connection:
            updated = connection.execute(
                f"""
                UPDATE spend_tokens
                SET is_used = {self._p}, used_at = {self._p}
                WHERE token_hash = {self._p} AND is_used = {self._p} AND revoked = {self._p}
                """,
                (1, utc_now(), token_hash, 0, 0),
            ).rowcount
            connection.commit()
        return bool(updated)

    def revoke_spend_token(self, token_hash: str) -> bool:
        with self._lock, closing(self._connect()) as connection:
            updated = connection.execute(
                f"""
                UPDATE spend_tokens
                SET revoked = {self._p}
                WHERE token_hash = {self._p} AND is_used = {self._p} AND revoked = {self._p}
                """,
                (1, token_hash, 0, 0),
            ).rowcount
            connection.commit()
        return bool(updated)

    def record_mcp_tool_usage(
        self,
        tool_id: str,
        user_id: str,
        amount: Decimal,
        currency: str,
        created_at: str | None = None,
    ) -> None:
        with self._lock, closing(self._connect()) as connection:
            connection.execute(
                f"""
                INSERT INTO mcp_tool_usage_events (tool_id, user_id, amount, currency, created_at)
                VALUES ({self._p}, {self._p}, {self._p}, {self._p}, {self._p})
                """,
                (
                    tool_id,
                    user_id,
                    decimal_to_text(amount),
                    currency,
                    created_at or utc_now(),
                ),
            )
            connection.commit()

    def get_mcp_tool_spent_today(self, tool_id: str, user_id: str, currency: str) -> Decimal:
        today_prefix = datetime.now(timezone.utc).date().isoformat()
        with self._lock, closing(self._connect()) as connection:
            row = connection.execute(
                f"""
                SELECT COALESCE(SUM(amount), 0) AS spent_total
                FROM mcp_tool_usage_events
                WHERE tool_id = {self._p}
                  AND user_id = {self._p}
                  AND currency = {self._p}
                  AND created_at >= {self._p}
                """,
                (tool_id, user_id, currency, f"{today_prefix}T00:00:00"),
            ).fetchone()
        return text_to_decimal(row["spent_total"])

    def list_logs(self) -> list[dict[str, Any]]:
        """Return all audit entries in chronological order."""

        with self._lock, closing(self._connect()) as connection:
            rows = connection.execute(
                """
                SELECT timestamp, transaction_id, request_id, client_ip, agent_id, user_id, vendor, amount,
                       currency, firewall_fee, justification, context_json, result, reason,
                       decision_latency_ms, idempotency_key
                FROM transaction_logs
                ORDER BY id ASC
                """
            ).fetchall()
        return [
            {
                "timestamp": row["timestamp"],
                "transaction_id": row["transaction_id"],
                "request_id": row["request_id"],
                "client_ip": row["client_ip"],
                "agent_id": row["agent_id"],
                "user_id": row["user_id"],
                "vendor": row["vendor"],
                "amount": decimal_to_text(text_to_decimal(row["amount"])),
                "currency": row["currency"],
                "firewall_fee": decimal_to_text(text_to_decimal(row["firewall_fee"])),
                "justification": row["justification"],
                "context": json.loads(row["context_json"]),
                "result": row["result"],
                "reason": row["reason"],
                "decision_latency_ms": int(row["decision_latency_ms"]),
                "idempotency_key": row["idempotency_key"],
            }
            for row in rows
        ]

    def get_idempotency(self, idempotency_key: str) -> tuple[str, IdempotencyRecord] | None:
        """Load a previously stored idempotent response."""

        with self._lock, closing(self._connect()) as connection:
            row = connection.execute(
                f"""
                SELECT request_hash, status_code, response_json
                FROM idempotency_records
                WHERE idempotency_key = {self._p}
                """,
                (idempotency_key,),
            ).fetchone()
            if row is None:
                return None
        return (
            row["request_hash"],
            IdempotencyRecord(
                status_code=int(row["status_code"]),
                response_body=json.loads(row["response_json"]),
            ),
        )

    def save_idempotency(
        self, idempotency_key: str, request_hash: str, status_code: int, response_body: dict[str, Any]
    ) -> None:
        """Persist the first completed response for an idempotency key."""

        with self._lock, closing(self._connect()) as connection:
            connection.execute(
                f"""
                INSERT INTO idempotency_records (
                    idempotency_key, request_hash, status_code, response_json, created_at
                ) VALUES ({self._p}, {self._p}, {self._p}, {self._p}, {self._p})
                ON CONFLICT(idempotency_key) DO UPDATE SET
                    request_hash = excluded.request_hash,
                    status_code = excluded.status_code,
                    response_json = excluded.response_json,
                    created_at = excluded.created_at
                """,
                (
                    idempotency_key,
                    request_hash,
                    status_code,
                    json.dumps(response_body, sort_keys=True),
                    utc_now(),
                ),
            )
            connection.commit()
