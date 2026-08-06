"""Run Safe4's deterministic, local-only payment edge-case matrix.

This module is intentionally a subprocess entry point.  It imports ``app.main``
only after forcing a unique SQLite database below ``.tmp`` and disabling every
external execution path used by the application.  Its JSON output contains
allowlisted observations only: raw headers, bodies, credentials, logs, database
contents, absolute paths, and application-generated identifiers are never
serialized.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from typing import Any, Callable, Iterator, Mapping
from unittest.mock import patch


SCHEMA_VERSION = "safe4-transaction-evidence/1.0"
REQUIRED_TRANSACTION_IDS = (
    "T01", "T02", "T03", "T04A", "T04B", "T05", "T06", "T07",
    "T08", "T09", "T10", "T11", "T12", "T13", "T14", "T15",
    "T16", "T17", "T18", "T19", "T20", "T21",
)
REQUIRED_CANARY_IDS = ("C01", "C02", "C03")
REQUIRED_SETTLEMENT_FIXTURE_IDS = tuple(f"S{index:02d}" for index in range(1, 9))

BASE_DESCRIPTION = "Generate a competitor pricing research brief from company data."
DENIED_DESCRIPTION = "Purchase a gift card for an unrelated entertainment giveaway."
CANARY_DESCRIPTION = "Purchase a competitor research gift card for an unrelated giveaway."
TASK = "Research competitor pricing using a paid company data service."
BASE_VENDOR = "circle_marketplace_company_research"
BASE_AGENT = "agent_alpha"
BASE_USER = "user_123"
MONEY_SCALE = Decimal("0.000001")

BASE_PAYLOAD: dict[str, Any] = {
    "agent_id": BASE_AGENT,
    "user_id": BASE_USER,
    "vendor": BASE_VENDOR,
    "amount": 0.001,
    "currency": "USDC",
    "description": BASE_DESCRIPTION,
    "context": {
        "payment_intent": {
            "task_id": "task_competitor_pricing_001",
            "task": TASK,
            "allowed_service_categories": ["company-research"],
            "service_category": "company-research",
            "purchase_purpose": BASE_DESCRIPTION,
        }
    },
}


def _payload() -> dict[str, Any]:
    return deepcopy(BASE_PAYLOAD)


def _money(value: Any) -> str | None:
    if value is None:
        return None
    return format(Decimal(str(value)).quantize(MONEY_SCALE), "f")


def _scenario_sort_key(value: str) -> tuple[int, int, str]:
    match = re.fullmatch(r"([TC])(\d+)([A-Z]?)", value)
    if match is None:
        raise ValueError(f"invalid scenario id: {value}")
    return (0 if match.group(1) == "T" else 1, int(match.group(2)), match.group(3))


@dataclass
class IdentifierAliases:
    """Map random application identifiers to deterministic per-scenario labels."""

    values: dict[tuple[str, str], str] = field(default_factory=dict)
    counters: dict[str, int] = field(default_factory=dict)

    def alias(self, kind: str, value: Any) -> str | None:
        if not isinstance(value, str) or not value:
            return None
        key = (kind, value)
        if key not in self.values:
            self.counters[kind] = self.counters.get(kind, 0) + 1
            self.values[key] = f"{kind}-{self.counters[kind]}"
        return self.values[key]


def _blocked_network(*_args: Any, **_kwargs: Any) -> Any:
    raise RuntimeError("network access is disabled by the local evidence runner")


@contextmanager
def _network_disabled() -> Iterator[None]:
    with (
        patch("socket.create_connection", side_effect=_blocked_network),
        patch.object(socket.socket, "connect", _blocked_network),
        patch.object(socket.socket, "connect_ex", _blocked_network),
    ):
        yield


def _configure_local_environment(database_path: Path) -> None:
    """Override ambient configuration before importing any application module."""

    for name in tuple(os.environ):
        if (
            name.startswith("PAYMENT_FIREWALL_")
            or name.startswith("SAFE4_PROVIDER_")
            or name == "SAFE4_DEMO_MODE"
        ):
            os.environ.pop(name, None)
    fixed = {
        "PAYMENT_FIREWALL_ENV": "development",
        "PAYMENT_FIREWALL_DB_PATH": str(database_path),
        "PAYMENT_FIREWALL_PAY_TO": "0x1111111111111111111111111111111111111111",
        "PAYMENT_FIREWALL_RECEIPT_SECRET": "edge-case-local-receipt-secret",
        "PAYMENT_FIREWALL_ADMIN_SECRET": "edge-case-local-admin-secret",
        "PAYMENT_FIREWALL_WEBHOOK_DISPATCH_ENABLED": "false",
        "PAYMENT_FIREWALL_PHASE3_X402_ADVANCED_ENABLED": "false",
        "PAYMENT_FIREWALL_PHASE3_AP2_ENABLED": "false",
        "PAYMENT_FIREWALL_PHASE3_INFRASTRUCTURE_IDENTITY_ENABLED": "false",
        "PAYMENT_FIREWALL_DEMO_X402_RECEIPT_ENABLED": "false",
        "PAYMENT_FIREWALL_RATE_LIMIT_REQUESTS": "1000",
        "PAYMENT_FIREWALL_RATE_LIMIT_WINDOW_SECONDS": "60",
        "PAYMENT_FIREWALL_VELOCITY_LIMIT": "3",
        "PAYMENT_FIREWALL_VELOCITY_WINDOW_SECONDS": "60",
        "PAYMENT_FIREWALL_RECEIPT_TTL_SECONDS": "300",
        "PAYMENT_FIREWALL_HITL_APPROVAL_TTL_SECONDS": "300",
        "PAYMENT_FIREWALL_SPEND_TOKEN_TTL_SECONDS": "300",
        "SAFE4_DEMO_MODE": "local-evidence",
        "PAYMENT_FIREWALL_AP2_FEDERATION_DISCOVERY_POLL_URL": "",
        "SAFE4_PROVIDER_RANGE_RISK_API_KEY": "",
        "SAFE4_PROVIDER_RANGE_RISK_BASE_URL": "http://127.0.0.1:9",
    }
    os.environ.update(fixed)


def _assert_isolated_sqlite(main: Any, database_path: Path, temporary_root: Path) -> None:
    if os.getenv("PAYMENT_FIREWALL_POSTGRES_DSN"):
        raise RuntimeError("PostgreSQL must be disabled for local evidence")
    resolved_database = database_path.resolve()
    resolved_root = temporary_root.resolve()
    if resolved_database.parent != resolved_root:
        raise RuntimeError("SQLite database escaped its unique temporary state directory")
    if Path(str(main.DB_URL)).resolve() != resolved_database:
        raise RuntimeError("app.main did not bind to the isolated SQLite database")
    repository_tmp = (Path(__file__).resolve().parents[1] / ".tmp").resolve()
    if repository_tmp not in resolved_database.parents:
        raise RuntimeError("SQLite database is not below the repository's ignored .tmp directory")


def _intent_details(body: Mapping[str, Any]) -> Mapping[str, Any] | None:
    direct = body.get("intent_decision")
    if isinstance(direct, Mapping):
        return direct
    details = body.get("details")
    if isinstance(details, Mapping) and isinstance(details.get("intent_decision"), Mapping):
        return details["intent_decision"]
    return None


def _classify_outcome(status_code: int, body: Mapping[str, Any]) -> str:
    if status_code == 200 and body.get("status") == "AUTHORIZED":
        return "ALLOW"
    if status_code == 202 and body.get("status") == "PENDING_APPROVAL":
        return "PENDING_APPROVAL"
    if status_code == 402:
        return "CHALLENGE"
    if status_code == 429:
        return "RATE_LIMIT"
    if status_code == 409:
        return "CONFLICT"
    if status_code in {413, 422}:
        return "VALIDATION_REJECT"
    return "DENY"


def _safe_step(label: str, response: Any, aliases: IdentifierAliases) -> dict[str, Any]:
    try:
        body: Mapping[str, Any] = response.json()
    except (TypeError, ValueError):
        body = {}
    intent = _intent_details(body)
    details = body.get("details") if isinstance(body.get("details"), Mapping) else {}
    monetary_detail_keys = {
        "agent_transaction_cap", "transaction_cap", "daily_cap", "spent_today",
        "requested_amount", "max_cost",
    }
    selected_details: dict[str, Any] = {}
    for key in (*sorted(monetary_detail_keys), "velocity_limit", "recent_event_count"):
        value = details.get(key)
        if not isinstance(value, (str, int, float, bool)):
            continue
        selected_details[key] = _money(value) if key in monetary_detail_keys else int(value)
    retry_after_raw = response.headers.get("Retry-After")
    retry_after_seconds = (
        int(retry_after_raw) if isinstance(retry_after_raw, str) and retry_after_raw.isdigit() else None
    )
    return {
        "label": label,
        "http_status": response.status_code,
        "outcome": _classify_outcome(response.status_code, body),
        "response_status": body.get("status") if isinstance(body.get("status"), str) else None,
        "top_level_code": body.get("code") if isinstance(body.get("code"), str) else None,
        "nested_reason_code": (
            intent.get("reason_code") if isinstance(intent, Mapping) else None
        ),
        "intent": None
        if not isinstance(intent, Mapping)
        else {
            "allowed": bool(intent.get("allowed")),
            "reason_code": intent.get("reason_code"),
            "mode": intent.get("mode"),
            "matched_concepts": list(intent.get("matched_concepts", [])),
            "task_context_trust": intent.get("task_context_trust"),
        },
        "policy_details": selected_details,
        "correlation": {
            "request": aliases.alias(
                "request",
                body.get("request_id") or response.headers.get("X-Request-Id"),
            ),
            "local_transaction": aliases.alias("local-transaction", body.get("transaction_id")),
            "approval_fixture": aliases.alias("approval-fixture", body.get("approval_id")),
        },
        "retry_after_present": "Retry-After" in response.headers,
        "retry_after_seconds": retry_after_seconds,
    }


class EvidenceHarness:
    """Private in-process client state; no credential leaves this object."""

    def __init__(self, main_module: Any, webhooks_module: Any, client: Any) -> None:
        self.main = main_module
        self.webhooks = webhooks_module
        self.client = client
        self._credential = ""
        self._default_limiter = main_module.rate_limiter

    def reset(self, *, token_agent: str = BASE_AGENT) -> None:
        self.main.rate_limiter = self._default_limiter
        self.main.reset_runtime_state()
        self.webhooks.reset_webhook_sender_for_tests()
        self._credential = self._issue_credential(token_agent)

    def _issue_credential(self, agent_id: str) -> str:
        verifier = "v" * 43
        authorization = self.client.post(
            "/oauth/authorize",
            json={
                "client_id": "dev-public-client",
                "redirect_uri": "https://localhost/callback",
                "scope": "payment:read payment:authorize budget:manage audit:read admin:all",
                "code_challenge": self.main.compute_code_challenge(verifier),
                "code_challenge_method": "S256",
                "subject": "synthetic_edge_case_operator",
                "agent_id": agent_id,
            },
        )
        if authorization.status_code != 200:
            raise RuntimeError(f"synthetic OAuth authorization failed ({authorization.status_code})")
        token = self.client.post(
            "/oauth/token",
            json={
                "grant_type": "authorization_code",
                "client_id": "dev-public-client",
                "code": authorization.json()["code"],
                "redirect_uri": "https://localhost/callback",
                "code_verifier": verifier,
            },
        )
        if token.status_code != 200:
            raise RuntimeError(f"synthetic OAuth exchange failed ({token.status_code})")
        return str(token.json()["access_token"])

    def headers(self, **extra: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._credential}"} | extra

    def pay(
        self,
        payload: Mapping[str, Any],
        *,
        receipt: str | None = None,
        idempotency_label: str | None = None,
        approval_credential: str | None = None,
        client_ip: str | None = None,
    ) -> Any:
        headers: dict[str, str] = {}
        if receipt is not None:
            headers["X-Payment-Receipt"] = receipt
        if idempotency_label is not None:
            headers["Idempotency-Key"] = idempotency_label
        if approval_credential is not None:
            headers["X-Spend-Token"] = approval_credential
        if client_ip is not None:
            headers["X-Forwarded-For"] = client_ip
        return self.client.post("/pay", json=dict(payload), headers=self.headers(**headers))

    def issue_receipt(
        self,
        payload: Mapping[str, Any],
        *,
        expires_in_seconds: int = 300,
    ) -> tuple[Any, str]:
        challenge = self.pay(payload)
        if challenge.status_code != 402 or challenge.json().get("code") != "PAYMENT_REQUIRED":
            raise RuntimeError(f"local receipt challenge failed ({challenge.status_code})")
        details = challenge.json()["details"]
        issue = self.client.post(
            "/receipts/issue",
            json={
                "amount_due": float(details["amount_due"]),
                "currency": details["currency"],
                "expires_in_seconds": expires_in_seconds,
            },
            headers=self.headers(**{"X-Admin-Secret": self.main.RECEIPT_ADMIN_SECRET}),
        )
        if issue.status_code != 200:
            raise RuntimeError(f"local receipt fixture creation failed ({issue.status_code})")
        return challenge, str(issue.json()["receipt_token"])

    def receipt_consumed(self, receipt_credential: str) -> bool:
        _receipt_id, receipt = self.main.parse_and_validate_receipt_token(receipt_credential)
        return bool(isinstance(receipt, Mapping) and receipt.get("used_at"))

    def update_user_budget(
        self,
        *,
        daily_cap: float,
        transaction_cap: float,
        spent_today: float,
        user_id: str = BASE_USER,
    ) -> None:
        response = self.client.post(
            "/budgets",
            json={
                "user_id": user_id,
                "daily_cap": daily_cap,
                "transaction_cap": transaction_cap,
                "spent_today": spent_today,
            },
            headers=self.headers(),
        )
        if response.status_code != 200:
            raise RuntimeError(f"local user budget setup failed ({response.status_code})")

    def activate_velocity_one(self) -> None:
        response = self.client.post(
            "/policies/current",
            json={
                "version": "edge-case-velocity-one",
                "document": {
                    "version": "edge-case-velocity-one",
                    "controls": {
                        "payment_velocity_limit": {"requests": 1, "window_seconds": 300}
                    },
                },
            },
            headers=self.headers(),
        )
        if response.status_code != 200:
            raise RuntimeError(f"local velocity policy setup failed ({response.status_code})")

    def create_hitl_rule(self) -> None:
        response = self.client.post(
            "/hitl/rules",
            json={
                "rule_id": "edge_case_direct_review",
                "applies_to": "direct",
                "trigger_type": "amount_threshold",
                "threshold_amount": 5.0,
                "is_active": True,
            },
            headers=self.headers(),
        )
        if response.status_code != 200:
            raise RuntimeError(f"local HITL rule setup failed ({response.status_code})")

    def approve_fixture(self, approval_id: str) -> str:
        response = self.client.post(
            f"/approvals/{approval_id}/decide",
            json={"decision": "approved", "reason": "Synthetic local test fixture approval."},
            headers=self.headers(),
        )
        if response.status_code != 200:
            raise RuntimeError(f"local approval fixture failed ({response.status_code})")
        return str(response.json()["spend_token"])

    def state(self, *, user_id: str = BASE_USER, agent_id: str = BASE_AGENT) -> dict[str, Any]:
        budget = self.main.store.get_budget(user_id)
        agent_budget = self.main.store.get_agent_budget(agent_id)
        logs = self.main.store.list_logs()
        audits = self.main.store.list_audit_entries()
        reason_codes: set[str] = set()
        for entry in audits:
            details = entry.get("decision_details")
            if isinstance(details, str):
                try:
                    details = json.loads(details)
                except ValueError:
                    details = None
            if isinstance(details, Mapping) and isinstance(details.get("reason_code"), str):
                reason_codes.add(details["reason_code"])
        return {
            "user_configured": budget is not None,
            "user_spend": _money(None if budget is None else budget["spent_today"]),
            "agent_spend": _money(None if agent_budget is None else agent_budget["spent_today"]),
            "payment_log_count": len(logs),
            "payment_log_results": sorted(
                str(item.get("result")) for item in logs if isinstance(item.get("result"), str)
            ),
            "audit_entry_count": len(audits),
            "audit_reason_codes": sorted(reason_codes),
        }


def _spend_delta(before: Mapping[str, Any], after: Mapping[str, Any], field: str) -> str | None:
    if before.get(field) is None and after.get(field) is None:
        return "0.000000"
    if before.get(field) is None or after.get(field) is None:
        return None
    return _money(Decimal(str(after[field])) - Decimal(str(before[field])))


def _build_scenario(
    *,
    scenario_id: str,
    evidence_class: str,
    input_delta: Mapping[str, Any],
    steps: list[dict[str, Any]],
    expected_steps: list[Mapping[str, Any]],
    primary_label: str,
    before: Mapping[str, Any],
    after: Mapping[str, Any],
    expected_user_spend_delta: str | None,
    expected_agent_spend_delta: str | None = None,
    extra_assertions: Mapping[str, bool] | None = None,
    known_gap: bool = False,
    observations: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    by_label = {step["label"]: step for step in steps}
    if primary_label not in by_label:
        raise AssertionError(f"{scenario_id} primary step is absent")
    step_assertions: dict[str, bool] = {}
    for index, expected in enumerate(expected_steps):
        label = str(expected["label"])
        actual = by_label.get(label)
        step_assertions[f"step_{index + 1}_{label}"] = bool(
            actual is not None
            and all(actual.get(key) == value for key, value in expected.items() if key != "label")
        )
    user_delta = _spend_delta(before, after, "user_spend")
    agent_delta = _spend_delta(before, after, "agent_spend")
    if expected_agent_spend_delta is None:
        expected_agent_spend_delta = expected_user_spend_delta
    assertions = {
        **step_assertions,
        "expected_user_spend_delta": (
            True if expected_user_spend_delta is None else user_delta == expected_user_spend_delta
        ),
        "expected_agent_spend_delta": (
            True if expected_agent_spend_delta is None else agent_delta == expected_agent_spend_delta
        ),
    }
    assertions.update(dict(extra_assertions or {}))
    primary = by_label[primary_label]
    expected_primary_outcome = next(
        (item.get("outcome") for item in expected_steps if item.get("label") == primary_label),
        None,
    )
    if expected_primary_outcome != "ALLOW":
        assertions["primary_not_authorized"] = primary.get("response_status") != "AUTHORIZED"
    passed = all(assertions.values())
    return {
        "id": scenario_id,
        "evidence_class": evidence_class,
        "input_delta": dict(input_delta),
        "expected": {
            "ordered_steps": [dict(item) for item in expected_steps],
            "primary_label": primary_label,
            "user_spend_delta": expected_user_spend_delta,
            "agent_spend_delta": expected_agent_spend_delta,
            "settlement_executor": "NOT_OBSERVED",
        },
        "actual": {
            "ordered_steps": steps,
            "primary": primary,
            "state": {
                "before": dict(before),
                "after": dict(after),
                "user_spend_delta": user_delta,
                "agent_spend_delta": agent_delta,
                "payment_log_delta": after["payment_log_count"] - before["payment_log_count"],
                "audit_entry_delta": after["audit_entry_count"] - before["audit_entry_count"],
            },
            "settlement_executor": {
                "status": "NOT_OBSERVED",
                "reason": "POST /pay is a local authorization path and exposes no settlement executor.",
            },
            "observations": dict(observations or {}),
        },
        "assertions": assertions,
        "verdict": "PASS" if passed else "FAIL",
        "known_gap": bool(known_gap and not passed),
    }


def _receipted_scenario(
    harness: EvidenceHarness,
    *,
    scenario_id: str,
    payload: Mapping[str, Any],
    input_delta: Mapping[str, Any],
    expected_final: Mapping[str, Any],
    expected_user_spend_delta: str,
    evidence_class: str = "local_application_authorization",
    known_gap: bool = False,
    setup: Callable[[EvidenceHarness], None] | None = None,
    extra_check: Callable[[Mapping[str, Any], Mapping[str, Any], Any, str], Mapping[str, bool]] | None = None,
    observations: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    harness.reset()
    if setup is not None:
        setup(harness)
    aliases = IdentifierAliases()
    before = harness.state(user_id=str(payload.get("user_id", BASE_USER)))
    challenge, receipt = harness.issue_receipt(payload)
    response = harness.pay(payload, receipt=receipt)
    after = harness.state(user_id=str(payload.get("user_id", BASE_USER)))
    steps = [
        _safe_step("receipt_challenge", challenge, aliases),
        _safe_step("authorization", response, aliases),
    ]
    expected_steps = [
        {
            "label": "receipt_challenge",
            "http_status": 402,
            "outcome": "CHALLENGE",
            "top_level_code": "PAYMENT_REQUIRED",
        },
        {"label": "authorization", **dict(expected_final)},
    ]
    checks = dict(extra_check(before, after, response, receipt)) if extra_check else {}
    receipt_observations = {
        "receipt_consumed": harness.receipt_consumed(receipt),
        **dict(observations or {}),
    }
    return _build_scenario(
        scenario_id=scenario_id,
        evidence_class=evidence_class,
        input_delta=input_delta,
        steps=steps,
        expected_steps=expected_steps,
        primary_label="authorization",
        before=before,
        after=after,
        expected_user_spend_delta=expected_user_spend_delta,
        extra_assertions=checks,
        known_gap=known_gap,
        observations=receipt_observations,
    )


def _run_transaction_scenarios(harness: EvidenceHarness) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []

    results.append(
        _receipted_scenario(
            harness,
            scenario_id="T01",
            payload=_payload(),
            input_delta={"baseline": True, "amount": "0.001000", "currency": "USDC"},
            expected_final={
                "http_status": 200,
                "outcome": "ALLOW",
                "response_status": "AUTHORIZED",
                "nested_reason_code": "TASK_PURCHASE_MATCH",
            },
            expected_user_spend_delta="0.001000",
        )
    )

    payload = _payload()
    payload["description"] = DENIED_DESCRIPTION
    payload["context"]["payment_intent"]["purchase_purpose"] = DENIED_DESCRIPTION
    results.append(
        _receipted_scenario(
            harness,
            scenario_id="T02",
            payload=payload,
            input_delta={"description": DENIED_DESCRIPTION, "purchase_purpose": DENIED_DESCRIPTION},
            expected_final={
                "http_status": 403,
                "outcome": "DENY",
                "top_level_code": "INTENT_VERIFICATION_FAILED",
                "nested_reason_code": "PURCHASE_PURPOSE_MISMATCH",
            },
            expected_user_spend_delta="0.000000",
        )
    )

    payload = _payload()
    payload["context"]["payment_intent"]["service_category"] = "gift-cards"
    results.append(
        _receipted_scenario(
            harness,
            scenario_id="T03",
            payload=payload,
            input_delta={"service_category": "gift-cards", "allowed_categories_unchanged": True},
            expected_final={
                "http_status": 403,
                "outcome": "DENY",
                "top_level_code": "INTENT_VERIFICATION_FAILED",
                "nested_reason_code": "SERVICE_CATEGORY_OUTSIDE_TASK",
            },
            expected_user_spend_delta="0.000000",
        )
    )

    payload = _payload()
    payload["description"] = (
        "Book the approved train ticket for tomorrow client meeting with the sales team."
    )
    payload["context"] = {"synthetic_trip_id": "trip_fixture_001"}
    results.append(
        _receipted_scenario(
            harness,
            scenario_id="T04A",
            payload=payload,
            input_delta={"payment_intent": "ABSENT", "legacy_description": "detailed"},
            expected_final={
                "http_status": 200,
                "outcome": "ALLOW",
                "response_status": "AUTHORIZED",
                "nested_reason_code": "LEGACY_JUSTIFICATION_ACCEPTED",
            },
            expected_user_spend_delta="0.001000",
            extra_check=lambda _before, _after, response, _receipt: {
                "legacy_mode_recorded": response.json().get("intent_decision", {}).get("mode")
                == "legacy-justification",
                "no_task_match_claim": response.json().get("intent_decision", {}).get("reason_code")
                != "TASK_PURCHASE_MATCH",
            },
            observations={"claim_boundary": "Legacy justification acceptance is not task matching."},
        )
    )

    payload = _payload()
    payload["context"]["payment_intent"] = "malformed"
    results.append(
        _receipted_scenario(
            harness,
            scenario_id="T04B",
            payload=payload,
            input_delta={"payment_intent": "NON_OBJECT"},
            expected_final={
                "http_status": 403,
                "outcome": "DENY",
                "top_level_code": "INTENT_VERIFICATION_FAILED",
                "nested_reason_code": "INTENT_CONTEXT_INVALID",
            },
            expected_user_spend_delta="0.000000",
        )
    )

    payload = _payload()
    payload["amount"] = 25.01
    results.append(
        _receipted_scenario(
            harness,
            scenario_id="T05",
            payload=payload,
            input_delta={"amount": "25.010000", "default_agent_transaction_cap": "25.000000"},
            expected_final={
                "http_status": 403,
                "outcome": "DENY",
                "top_level_code": "AGENT_TRANSACTION_CAP_EXCEEDED",
            },
            expected_user_spend_delta="0.000000",
            extra_check=lambda before, after, _response, receipt: {
                "denied_log_created": after["payment_log_results"] == ["DENIED"],
                "denial_audit_recorded": "AGENT_TRANSACTION_CAP_EXCEEDED" in after["audit_reason_codes"],
                "receipt_consumed_on_denial": harness.receipt_consumed(receipt),
            },
        )
    )

    payload = _payload()
    payload["amount"] = 10.01
    results.append(
        _receipted_scenario(
            harness,
            scenario_id="T06",
            payload=payload,
            input_delta={
                "amount": "10.010000",
                "agent_cap_permits": True,
                "default_user_transaction_cap": "10.000000",
            },
            expected_final={
                "http_status": 403,
                "outcome": "DENY",
                "top_level_code": "TRANSACTION_CAP_EXCEEDED",
            },
            expected_user_spend_delta="0.000000",
        )
    )

    payload = _payload()
    payload["amount"] = 6.0
    results.append(
        _receipted_scenario(
            harness,
            scenario_id="T07",
            payload=payload,
            input_delta={
                "amount": "6.000000",
                "daily_cap": "100.000000",
                "prior_spend": "95.000000",
            },
            setup=lambda h: h.update_user_budget(
                daily_cap=100.0, transaction_cap=10.0, spent_today=95.0
            ),
            expected_final={
                "http_status": 403,
                "outcome": "DENY",
                "top_level_code": "DAILY_CAP_EXCEEDED",
            },
            expected_user_spend_delta="0.000000",
            extra_check=lambda _before, _after, response, _receipt: {
                "cap_details_recorded": response.json().get("details")
                == {
                    "daily_cap": "100.000000",
                    "spent_today": "95.000000",
                    "requested_amount": "6.000000",
                }
            },
        )
    )

    # T08: state is intentionally retained only inside this ordered pair.
    harness.reset()
    harness.activate_velocity_one()
    aliases = IdentifierAliases()
    before = harness.state()
    first_payload = _payload()
    first_challenge, first_receipt = harness.issue_receipt(first_payload)
    first = harness.pay(first_payload, receipt=first_receipt)
    first_state = harness.state()
    second_payload = _payload()
    second_payload["vendor"] = "synthetic_company_research_alternate"
    second_challenge, second_receipt = harness.issue_receipt(second_payload)
    second = harness.pay(second_payload, receipt=second_receipt)
    after = harness.state()
    results.append(
        _build_scenario(
            scenario_id="T08",
            evidence_class="local_application_authorization",
            input_delta={"velocity_requests": 1, "window_seconds": 300, "second_request": "distinct"},
            steps=[
                _safe_step("first_receipt_challenge", first_challenge, aliases),
                _safe_step("first_authorization", first, aliases),
                _safe_step("second_receipt_challenge", second_challenge, aliases),
                _safe_step("second_authorization", second, aliases),
            ],
            expected_steps=[
                {"label": "first_receipt_challenge", "http_status": 402, "outcome": "CHALLENGE", "top_level_code": "PAYMENT_REQUIRED"},
                {"label": "first_authorization", "http_status": 200, "outcome": "ALLOW", "response_status": "AUTHORIZED"},
                {"label": "second_receipt_challenge", "http_status": 402, "outcome": "CHALLENGE", "top_level_code": "PAYMENT_REQUIRED"},
                {"label": "second_authorization", "http_status": 429, "outcome": "RATE_LIMIT", "top_level_code": "VELOCITY_LIMIT_EXCEEDED"},
            ],
            primary_label="second_authorization",
            before=before,
            after=after,
            expected_user_spend_delta="0.001000",
            extra_assertions={
                "second_user_spend_unchanged": _spend_delta(first_state, after, "user_spend") == "0.000000",
                "second_agent_spend_unchanged": _spend_delta(first_state, after, "agent_spend") == "0.000000",
                "second_authorized_log_count_unchanged": (
                    first_state["payment_log_results"].count("AUTHORIZED")
                    == after["payment_log_results"].count("AUTHORIZED")
                ),
            },
            observations={
                "state_scope": "ordered_pair_only",
                "state_after_first_authorization": {
                    "user_spend": first_state["user_spend"],
                    "agent_spend": first_state["agent_spend"],
                    "authorized_log_count": first_state["payment_log_results"].count("AUTHORIZED"),
                },
            },
        )
    )

    # T09: the second response is a stored local authorization replay.
    harness.reset()
    aliases = IdentifierAliases()
    before = harness.state()
    payload = _payload()
    challenge, receipt = harness.issue_receipt(payload)
    key = "11111111-1111-4111-8111-111111111111"
    first = harness.pay(payload, receipt=receipt, idempotency_label=key)
    first_state = harness.state()
    second = harness.pay(payload, receipt=receipt, idempotency_label=key)
    after = harness.state()
    results.append(
        _build_scenario(
            scenario_id="T09",
            evidence_class="local_application_authorization",
            input_delta={"idempotency_key": "FIXED_VALID_UUIDV4", "second_payload": "IDENTICAL"},
            steps=[
                _safe_step("receipt_challenge", challenge, aliases),
                _safe_step("first_authorization", first, aliases),
                _safe_step("idempotent_replay", second, aliases),
            ],
            expected_steps=[
                {"label": "receipt_challenge", "http_status": 402, "outcome": "CHALLENGE", "top_level_code": "PAYMENT_REQUIRED"},
                {"label": "first_authorization", "http_status": 200, "outcome": "ALLOW", "response_status": "AUTHORIZED"},
                {"label": "idempotent_replay", "http_status": 200, "outcome": "ALLOW", "response_status": "AUTHORIZED"},
            ],
            primary_label="idempotent_replay",
            before=before,
            after=after,
            expected_user_spend_delta="0.001000",
            extra_assertions={
                "identical_response_bodies": first.json() == second.json(),
                "one_payment_log": after["payment_log_count"] - before["payment_log_count"] == 1,
                "replay_user_spend_unchanged": _spend_delta(first_state, after, "user_spend") == "0.000000",
                "replay_agent_spend_unchanged": _spend_delta(first_state, after, "agent_spend") == "0.000000",
            },
            observations={"external_exactly_once_settlement": "NOT_PROVEN"},
        )
    )

    # T10: conflict is checked before the already-used receipt.
    harness.reset()
    aliases = IdentifierAliases()
    before = harness.state()
    payload = _payload()
    challenge, receipt = harness.issue_receipt(payload)
    key = "22222222-2222-4222-8222-222222222222"
    first = harness.pay(payload, receipt=receipt, idempotency_label=key)
    first_state = harness.state()
    changed = _payload()
    changed["amount"] = 0.002
    conflict = harness.pay(changed, receipt=receipt, idempotency_label=key)
    after = harness.state()
    results.append(
        _build_scenario(
            scenario_id="T10",
            evidence_class="local_application_authorization",
            input_delta={"idempotency_key": "SAME_AS_FIRST", "second_amount": "0.002000"},
            steps=[
                _safe_step("receipt_challenge", challenge, aliases),
                _safe_step("first_authorization", first, aliases),
                _safe_step("conflicting_reuse", conflict, aliases),
            ],
            expected_steps=[
                {"label": "receipt_challenge", "http_status": 402, "outcome": "CHALLENGE", "top_level_code": "PAYMENT_REQUIRED"},
                {"label": "first_authorization", "http_status": 200, "outcome": "ALLOW", "response_status": "AUTHORIZED"},
                {"label": "conflicting_reuse", "http_status": 409, "outcome": "CONFLICT", "top_level_code": "IDEMPOTENCY_KEY_REUSED"},
            ],
            primary_label="conflicting_reuse",
            before=before,
            after=after,
            expected_user_spend_delta="0.001000",
            extra_assertions={
                "conflict_user_spend_unchanged": _spend_delta(first_state, after, "user_spend") == "0.000000",
                "conflict_agent_spend_unchanged": _spend_delta(first_state, after, "agent_spend") == "0.000000",
                "conflict_payment_log_unchanged": after["payment_log_count"] == first_state["payment_log_count"],
            },
        )
    )

    # T11: receipt consumption is independent from request-body identity.
    harness.reset()
    aliases = IdentifierAliases()
    before = harness.state()
    payload = _payload()
    challenge, receipt = harness.issue_receipt(payload)
    first = harness.pay(payload, receipt=receipt)
    first_state = harness.state()
    changed = _payload()
    changed["vendor"] = "synthetic_company_research_alternate"
    reused = harness.pay(changed, receipt=receipt)
    after = harness.state()
    results.append(
        _build_scenario(
            scenario_id="T11",
            evidence_class="local_application_authorization",
            input_delta={"second_vendor": "synthetic_company_research_alternate", "receipt": "REUSED"},
            steps=[
                _safe_step("receipt_challenge", challenge, aliases),
                _safe_step("first_authorization", first, aliases),
                _safe_step("receipt_reuse", reused, aliases),
            ],
            expected_steps=[
                {"label": "receipt_challenge", "http_status": 402, "outcome": "CHALLENGE", "top_level_code": "PAYMENT_REQUIRED"},
                {"label": "first_authorization", "http_status": 200, "outcome": "ALLOW", "response_status": "AUTHORIZED"},
                {"label": "receipt_reuse", "http_status": 402, "outcome": "CHALLENGE", "top_level_code": "PAYMENT_RECEIPT_ALREADY_USED"},
            ],
            primary_label="receipt_reuse",
            before=before,
            after=after,
            expected_user_spend_delta="0.001000",
            extra_assertions={
                "reuse_user_spend_unchanged": _spend_delta(first_state, after, "user_spend") == "0.000000",
                "reuse_agent_spend_unchanged": _spend_delta(first_state, after, "agent_spend") == "0.000000",
                "reuse_payment_log_unchanged": after["payment_log_count"] == first_state["payment_log_count"],
            },
        )
    )

    # T12: use the shortest public fixture expiry and wait without changing global time.
    harness.reset()
    aliases = IdentifierAliases()
    before = harness.state()
    payload = _payload()
    challenge, receipt = harness.issue_receipt(payload, expires_in_seconds=1)
    time.sleep(1.2)
    expired = harness.pay(payload, receipt=receipt)
    after = harness.state()
    results.append(
        _build_scenario(
            scenario_id="T12",
            evidence_class="local_application_authorization",
            input_delta={"receipt_expiry_seconds": 1, "global_clock_modified": False},
            steps=[
                _safe_step("receipt_challenge", challenge, aliases),
                _safe_step("expired_receipt", expired, aliases),
            ],
            expected_steps=[
                {"label": "receipt_challenge", "http_status": 402, "outcome": "CHALLENGE", "top_level_code": "PAYMENT_REQUIRED"},
                {"label": "expired_receipt", "http_status": 402, "outcome": "CHALLENGE", "top_level_code": "PAYMENT_RECEIPT_EXPIRED"},
            ],
            primary_label="expired_receipt",
            before=before,
            after=after,
            expected_user_spend_delta="0.000000",
        )
    )

    # T13: mutate one signature character; never serialize either credential.
    harness.reset()
    aliases = IdentifierAliases()
    before = harness.state()
    payload = _payload()
    challenge, receipt = harness.issue_receipt(payload)
    tampered = receipt[:-1] + ("0" if receipt[-1] != "0" else "1")
    rejected = harness.pay(payload, receipt=tampered)
    after = harness.state()
    results.append(
        _build_scenario(
            scenario_id="T13",
            evidence_class="local_application_authorization",
            input_delta={"receipt_signature": "ONE_CHARACTER_MODIFIED"},
            steps=[
                _safe_step("receipt_challenge", challenge, aliases),
                _safe_step("tampered_receipt", rejected, aliases),
            ],
            expected_steps=[
                {"label": "receipt_challenge", "http_status": 402, "outcome": "CHALLENGE", "top_level_code": "PAYMENT_REQUIRED"},
                {"label": "tampered_receipt", "http_status": 402, "outcome": "CHALLENGE", "top_level_code": "PAYMENT_REQUIRED"},
            ],
            primary_label="tampered_receipt",
            before=before,
            after=after,
            expected_user_spend_delta="0.000000",
        )
    )

    # T14: malformed key is rejected before receipt processing.
    harness.reset()
    aliases = IdentifierAliases()
    before = harness.state()
    response = harness.pay(_payload(), idempotency_label="not-a-uuid")
    after = harness.state()
    results.append(
        _build_scenario(
            scenario_id="T14",
            evidence_class="local_application_authorization",
            input_delta={"idempotency_key": "MALFORMED"},
            steps=[_safe_step("validation", response, aliases)],
            expected_steps=[{"label": "validation", "http_status": 422, "outcome": "VALIDATION_REJECT", "top_level_code": "INVALID_IDEMPOTENCY_KEY"}],
            primary_label="validation",
            before=before,
            after=after,
            expected_user_spend_delta="0.000000",
        )
    )

    # T15: the fixed address is from TEST-NET-2 and is aliased in output.
    harness.reset()
    aliases = IdentifierAliases()
    before = harness.state()
    original_limiter = harness.main.rate_limiter
    synthetic_ip = "198.51.100.10"
    try:
        harness.main.rate_limiter = harness.main.RateLimiter(limit=1, window_seconds=60)
        first = harness.pay(_payload(), client_ip=synthetic_ip)
        second = harness.pay(_payload(), client_ip=synthetic_ip)
    finally:
        harness.main.rate_limiter = original_limiter
    after = harness.state()
    results.append(
        _build_scenario(
            scenario_id="T15",
            evidence_class="local_application_authorization",
            input_delta={"synthetic_client": "client-ip-1", "api_limit": 1, "window_seconds": 60},
            steps=[
                _safe_step("first_request", first, aliases),
                _safe_step("second_request", second, aliases),
            ],
            expected_steps=[
                {"label": "first_request", "http_status": 402, "outcome": "CHALLENGE", "top_level_code": "PAYMENT_REQUIRED"},
                {"label": "second_request", "http_status": 429, "outcome": "RATE_LIMIT", "top_level_code": "RATE_LIMITED", "retry_after_present": True},
            ],
            primary_label="second_request",
            before=before,
            after=after,
            expected_user_spend_delta="0.000000",
            extra_assertions={
                "positive_retry_after_seconds": int(second.headers.get("Retry-After", "0")) > 0,
            },
            observations={
                "client_dimension": "client-ip-1",
                "client_key_source": "caller-supplied-forwarded-address",
            },
        )
    )

    # T16: identity mismatch is evaluated before the receipt gate.
    harness.reset(token_agent=BASE_AGENT)
    aliases = IdentifierAliases()
    before = harness.state()
    beta_before = harness.state(agent_id="agent_beta")
    payload = _payload()
    payload["agent_id"] = "agent_beta"
    response = harness.pay(payload)
    after = harness.state()
    beta_after = harness.state(agent_id="agent_beta")
    results.append(
        _build_scenario(
            scenario_id="T16",
            evidence_class="local_application_authorization",
            input_delta={"token_agent": BASE_AGENT, "request_agent": "agent_beta"},
            steps=[_safe_step("identity_check", response, aliases)],
            expected_steps=[{"label": "identity_check", "http_status": 403, "outcome": "DENY", "top_level_code": "AGENT_ID_MISMATCH"}],
            primary_label="identity_check",
            before=before,
            after=after,
            expected_user_spend_delta="0.000000",
            extra_assertions={
                "token_agent_spend_unchanged": _spend_delta(before, after, "agent_spend") == "0.000000",
                "request_agent_budget_unchanged": beta_before["agent_spend"] == beta_after["agent_spend"],
                "no_payment_log": after["payment_log_count"] == before["payment_log_count"],
                "no_audit_entry": after["audit_entry_count"] == before["audit_entry_count"],
            },
            observations={
                "token_agent_state": {"before": before["agent_spend"], "after": after["agent_spend"]},
                "request_agent_state": {"before": beta_before["agent_spend"], "after": beta_after["agent_spend"]},
            },
        )
    )

    # T17: generic Pydantic 422 responses intentionally have no Safe4 top-level code.
    harness.reset()
    aliases = IdentifierAliases()
    before = harness.state()
    invalid_variants: list[tuple[str, dict[str, Any], int, str | None]] = []
    zero = _payload(); zero["amount"] = 0
    invalid_variants.append(("zero_amount", zero, 422, None))
    negative = _payload(); negative["amount"] = -0.001
    invalid_variants.append(("negative_amount", negative, 422, None))
    precision = _payload(); precision["amount"] = 0.0000001
    invalid_variants.append(("excess_precision", precision, 422, None))
    currency = _payload(); currency["currency"] = "JPY"
    invalid_variants.append(("unsupported_currency", currency, 422, None))
    extra = _payload(); extra["unexpected_field"] = True
    invalid_variants.append(("extra_field", extra, 422, None))
    oversized = _payload(); oversized["description"] = "x" * (harness.main.MAX_BODY_BYTES + 1)
    invalid_variants.append(("oversized_body", oversized, 413, "REQUEST_TOO_LARGE"))
    steps: list[dict[str, Any]] = []
    expectations: list[dict[str, Any]] = []
    for label, variant, status, code in invalid_variants:
        response = harness.pay(variant)
        steps.append(_safe_step(label, response, aliases))
        expectations.append({
            "label": label,
            "http_status": status,
            "outcome": "VALIDATION_REJECT",
            "top_level_code": code,
        })
    after = harness.state()
    results.append(
        _build_scenario(
            scenario_id="T17",
            evidence_class="local_application_authorization",
            input_delta={"variants": [item[0] for item in invalid_variants]},
            steps=steps,
            expected_steps=expectations,
            primary_label="oversized_body",
            before=before,
            after=after,
            expected_user_spend_delta="0.000000",
            observations={"generic_422_safe4_top_level_code": "ABSENT"},
        )
    )

    payload = _payload()
    payload["scope_of_autonomy"] = {"max_cost": 0.0005}
    results.append(
        _receipted_scenario(
            harness,
            scenario_id="T18",
            payload=payload,
            input_delta={"scope_max_cost": "0.000500", "projected_spend": "0.001000"},
            expected_final={
                "http_status": 403,
                "outcome": "DENY",
                "top_level_code": "SCOPE_OF_AUTONOMY_MAX_COST_EXCEEDED",
            },
            expected_user_spend_delta="0.000000",
            extra_check=lambda before, after, _response, receipt: {
                "current_scope_denial_creates_no_payment_log": after["payment_log_count"] == before["payment_log_count"],
                "current_scope_denial_leaves_receipt_unconsumed": not harness.receipt_consumed(receipt),
                "scope_denial_audit_recorded": "SCOPE_OF_AUTONOMY_MAX_COST_EXCEEDED" in after["audit_reason_codes"],
            },
            observations={
                "current_log_behavior": "NO_DENIED_PAYMENT_LOG",
                "current_receipt_behavior": "NOT_CONSUMED",
            },
        )
    )

    payload = _payload()
    payload["user_id"] = "synthetic_unconfigured_user"
    results.append(
        _receipted_scenario(
            harness,
            scenario_id="T19",
            payload=payload,
            input_delta={"user_id": "synthetic-unconfigured-user-1"},
            expected_final={
                "http_status": 403,
                "outcome": "DENY",
                "top_level_code": "BUDGET_NOT_FOUND",
            },
            expected_user_spend_delta="0.000000",
            extra_check=lambda before, after, _response, _receipt: {
                "user_remains_unconfigured": not before["user_configured"] and not after["user_configured"],
                "agent_spend_unchanged": _spend_delta(before, after, "agent_spend") == "0.000000",
            },
        )
    )

    # T20: approval is an explicitly synthetic local fixture; its credential is never serialized.
    harness.reset()
    harness.create_hitl_rule()
    aliases = IdentifierAliases()
    before = harness.state()
    payload = _payload(); payload["amount"] = 9.99
    challenge, receipt = harness.issue_receipt(payload)
    pending = harness.pay(payload, receipt=receipt)
    pending_state = harness.state()
    approval_id = str(pending.json()["approval_id"])
    approval_credential = harness.approve_fixture(approval_id)
    approved = harness.pay(payload, receipt=receipt, approval_credential=approval_credential)
    after = harness.state()
    results.append(
        _build_scenario(
            scenario_id="T20",
            evidence_class="local_application_authorization",
            input_delta={"amount": "9.990000", "hitl_threshold": "5.000000", "approval": "SYNTHETIC_LOCAL_FIXTURE"},
            steps=[
                _safe_step("receipt_challenge", challenge, aliases),
                _safe_step("pending_approval", pending, aliases),
                _safe_step("approved_fixture_retry", approved, aliases),
            ],
            expected_steps=[
                {"label": "receipt_challenge", "http_status": 402, "outcome": "CHALLENGE", "top_level_code": "PAYMENT_REQUIRED"},
                {"label": "pending_approval", "http_status": 202, "outcome": "PENDING_APPROVAL", "response_status": "PENDING_APPROVAL", "top_level_code": None},
                {"label": "approved_fixture_retry", "http_status": 200, "outcome": "ALLOW", "response_status": "AUTHORIZED", "nested_reason_code": "TASK_PURCHASE_MATCH"},
            ],
            primary_label="pending_approval",
            before=before,
            after=after,
            expected_user_spend_delta="9.990000",
            extra_assertions={
                "hitl_audit_reason_recorded": "HITL_RULE_TRIGGERED" in pending_state["audit_reason_codes"],
                "pending_spend_unchanged": _spend_delta(before, pending_state, "user_spend") == "0.000000",
                "pending_agent_spend_unchanged": _spend_delta(before, pending_state, "agent_spend") == "0.000000",
                "pending_payment_log_unchanged": pending_state["payment_log_count"] == before["payment_log_count"],
            },
            observations={
                "approval_authority": "SYNTHETIC_LOCAL_TEST_FIXTURE",
                "pending_state": pending_state,
            },
        )
    )

    # T21: paired MCP fields are validated before the receipt gate.
    harness.reset()
    aliases = IdentifierAliases()
    before = harness.state()
    payload = _payload(); payload["mcp_tool_id"] = "srv_synthetic:catalog"
    response = harness.pay(payload)
    after = harness.state()
    results.append(
        _build_scenario(
            scenario_id="T21",
            evidence_class="local_application_authorization",
            input_delta={"mcp_tool_id": "srv_synthetic:catalog", "mcp_action": "ABSENT"},
            steps=[_safe_step("mcp_context_validation", response, aliases)],
            expected_steps=[{"label": "mcp_context_validation", "http_status": 422, "outcome": "VALIDATION_REJECT", "top_level_code": "INVALID_MCP_CONTEXT"}],
            primary_label="mcp_context_validation",
            before=before,
            after=after,
            expected_user_spend_delta="0.000000",
        )
    )

    # Red-team canaries retain a desired DENY expectation.  Current ALLOW results are FAIL.
    canary_payloads: list[tuple[str, dict[str, Any], dict[str, Any]]] = []
    payload = _payload(); payload["description"] = CANARY_DESCRIPTION; payload["context"]["payment_intent"]["purchase_purpose"] = CANARY_DESCRIPTION
    canary_payloads.append(("C01", payload, {"description": CANARY_DESCRIPTION, "purchase_purpose": CANARY_DESCRIPTION}))
    payload = _payload(); payload["description"] = DENIED_DESCRIPTION; payload["context"]["payment_intent"]["purchase_purpose"] = BASE_DESCRIPTION
    canary_payloads.append(("C02", payload, {"description": DENIED_DESCRIPTION, "purchase_purpose": "SPOOFED_ALLOWED_SENTENCE"}))
    payload = _payload(); payload["vendor"] = "gift_card_shop"
    canary_payloads.append(("C03", payload, {"vendor": "gift_card_shop", "task_and_category_unchanged": True}))
    for scenario_id, payload, input_delta in canary_payloads:
        results.append(
            _receipted_scenario(
                harness,
                scenario_id=scenario_id,
                payload=payload,
                input_delta=input_delta,
                expected_final={"http_status": 403, "outcome": "DENY"},
                expected_user_spend_delta="0.000000",
            evidence_class="red_team_canary",
                known_gap=True,
                observations={
                    "desired_outcome": "DENY",
                    "external_execution": "NOT_ATTEMPTED",
                },
            )
        )

    return sorted(results, key=lambda item: _scenario_sort_key(str(item["id"])))


def _run_settlement_fixtures() -> list[dict[str, Any]]:
    """Run local payload-verifier fixtures; this function performs no RPC call."""

    from scripts.verify_arc_settlement import (
        ArcSettlementError,
        TRANSFER_TOPIC,
        USER_OPERATION_EVENT_TOPIC,
        address_topic,
        encode_transfer,
        scale_amount_units,
        verify_circle_agent_wallet_payloads,
        verify_settlement_payloads,
    )

    tx_hash = "0x" + ("a" * 64)
    usdc = "0x3600000000000000000000000000000000000000"
    sender = "0x1111111111111111111111111111111111111111"
    recipient = "0x2222222222222222222222222222222222222222"
    alternate = "0x3333333333333333333333333333333333333333"
    amount_units = 10_000
    entrypoint = "0x5ff137d4b0fdcd49dca30c7cf57e578a026d2789"
    native_usdc = "0xfffffffffffffffffffffffffffffffffffffffe"
    native_amount_units = 10_000_000_000_000_000

    def base_payloads() -> tuple[dict[str, Any], dict[str, Any]]:
        return (
            {
                "hash": tx_hash,
                "from": sender,
                "to": usdc,
                "value": "0x0",
                "input": encode_transfer(recipient, amount_units),
            },
            {
                "transactionHash": tx_hash,
                "status": "0x1",
                "blockNumber": "0x2a",
                "logs": [
                    {
                        "address": usdc,
                        "topics": [
                            TRANSFER_TOPIC,
                            address_topic(sender),
                            address_topic(recipient),
                        ],
                        "data": hex(amount_units),
                    }
                ],
            },
        )

    def circle_payloads() -> tuple[dict[str, Any], dict[str, Any]]:
        return (
            {
                "hash": tx_hash,
                "from": alternate,
                "to": entrypoint,
                "value": "0x0",
                "input": "0x1234",
            },
            {
                "transactionHash": tx_hash,
                "status": "0x1",
                "blockNumber": "0x2b",
                "logs": [
                    {
                        "address": native_usdc,
                        "topics": [
                            TRANSFER_TOPIC,
                            address_topic(sender),
                            address_topic(recipient),
                        ],
                        "data": hex(native_amount_units),
                    },
                    {
                        "address": entrypoint,
                        "topics": [
                            USER_OPERATION_EVENT_TOPIC,
                            "0x" + ("4" * 64),
                            address_topic(sender),
                        ],
                        "data": "0x" + ("0" * 64) + f"{1:064x}" + ("0" * 128),
                    },
                ],
            },
        )

    def verify_base(transaction: Any, receipt: Any) -> int:
        return verify_settlement_payloads(
            transaction,
            receipt,
            transaction_hash=tx_hash,
            usdc_address=usdc,
            sender=sender,
            recipient=recipient,
            amount_units=amount_units,
        )

    def verify_circle(transaction: Any, receipt: Any) -> int:
        return verify_circle_agent_wallet_payloads(
            transaction,
            receipt,
            transaction_hash=tx_hash,
            entrypoint_address=entrypoint,
            native_usdc_address=native_usdc,
            sender=sender,
            recipient=recipient,
            native_amount_units=native_amount_units,
        )

    fixture_calls: list[tuple[str, str, Callable[[], Any], str]] = []
    transaction, receipt = base_payloads()
    fixture_calls.append(("S01", "missing_transaction", lambda r=receipt: verify_base(None, r), "transaction not found"))
    transaction, receipt = base_payloads()
    fixture_calls.append(("S02", "missing_receipt", lambda t=transaction: verify_base(t, None), "receipt not found"))
    transaction, receipt = base_payloads(); receipt["status"] = "0x0"
    fixture_calls.append(("S03", "reverted_receipt", lambda t=transaction, r=receipt: verify_base(t, r), "not successful"))
    transaction, receipt = circle_payloads(); receipt["logs"][0]["topics"][2] = address_topic(alternate)
    fixture_calls.append(("S04", "wrong_recipient", lambda t=transaction, r=receipt: verify_circle(t, r), "native USDC"))
    transaction, receipt = base_payloads(); receipt["logs"][0]["data"] = hex(amount_units + 1)
    fixture_calls.append(("S05", "wrong_amount", lambda t=transaction, r=receipt: verify_base(t, r), "no matching"))
    transaction, receipt = base_payloads(); transaction["input"] = encode_transfer(alternate, amount_units)
    fixture_calls.append(("S06", "unrelated_transfer", lambda t=transaction, r=receipt: verify_base(t, r), "calldata"))
    transaction, receipt = circle_payloads(); receipt["logs"][1]["data"] = "0x" + ("0" * 64) + f"{0:064x}" + ("0" * 128)
    fixture_calls.append(("S07", "failed_user_operation", lambda t=transaction, r=receipt: verify_circle(t, r), "successful ERC-4337"))
    fixture_calls.append(("S08", "unsafe_decimal_downscaling", lambda: scale_amount_units(1, 18, 6), "represented exactly"))

    results: list[dict[str, Any]] = []
    for fixture_id, case, operation, expected_fragment in fixture_calls:
        rejected = False
        matched = False
        error_class: str | None = None
        try:
            operation()
        except ArcSettlementError as exc:
            rejected = True
            matched = expected_fragment in str(exc)
            error_class = "ArcSettlementError"
        passed = rejected and matched
        results.append(
            {
                "id": fixture_id,
                "evidence_class": "local_settlement_fixture",
                "input_delta": {"fixture_case": case},
                "expected": {
                    "outcome": "REJECT",
                    "error_class": "ArcSettlementError",
                    "reason_category": case,
                },
                "actual": {
                    "outcome": "REJECT" if rejected else "ACCEPT",
                    "error_class": error_class,
                    "reason_category_matched": matched,
                    "rpc_invoked": False,
                },
                "verdict": "PASS" if passed else "FAIL",
                "known_gap": False,
            }
        )
    return results


def _canonical_json(value: Any, *, pretty: bool) -> str:
    return json.dumps(
        value,
        indent=2 if pretty else None,
        separators=None if pretty else (",", ":"),
        sort_keys=True,
        ensure_ascii=True,
    )


def _source_metadata(repository_root: Path) -> dict[str, Any]:
    manifest_files = (
        "app/core/intent.py",
        "app/main.py",
        "app/payment_entry_checks.py",
        "app/payment_finalize.py",
        "app/payment_flow.py",
        "scripts/run_edge_case_evidence.py",
        "scripts/verify_arc_settlement.py",
    )
    digest = hashlib.sha256()
    for relative in manifest_files:
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update((repository_root / relative).read_bytes())
        digest.update(b"\0")
    if not (repository_root / ".git").exists():
        identity: dict[str, Any] = {"kind": "unversioned_snapshot"}
    else:
        revision = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repository_root,
            text=True,
            capture_output=True,
            check=False,
        )
        dirty = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=repository_root,
            text=True,
            capture_output=True,
            check=False,
        )
        identity = {
            "kind": "git" if revision.returncode == 0 else "unversioned_snapshot",
            "revision": revision.stdout.strip() if revision.returncode == 0 else None,
            "dirty": bool(dirty.stdout.strip()) if dirty.returncode == 0 else None,
        }
    return {
        "source": identity,
        "manifest_algorithm": "SHA256",
        "manifest_digest": digest.hexdigest(),
        "manifest_files": list(manifest_files),
    }


def _assert_sanitized(result: Mapping[str, Any]) -> None:
    encoded = _canonical_json(result, pretty=False)
    forbidden = (
        "Bearer ", "X-Payment-Receipt", "X-Admin-Secret", "X-Spend-Token",
        "access_token", "receipt_token", "spend_token", "private_key", "cookie",
    )
    lowered = encoded.lower()
    for marker in forbidden:
        if marker.lower() in lowered:
            raise RuntimeError(f"sanitization failure for forbidden category: {marker}")
    if re.search(r"[A-Za-z]:\\", encoded) or re.search(r"/(?:home|users|tmp)/", lowered):
        raise RuntimeError("absolute filesystem path escaped into evidence")

    def walk(value: Any, key: str = "") -> None:
        if isinstance(value, Mapping):
            for child_key, child_value in value.items():
                walk(child_value, str(child_key))
            return
        if isinstance(value, list):
            for child in value:
                walk(child, key)
            return
        if not isinstance(value, str):
            return
        if key == "manifest_digest":
            return
        if re.fullmatch(r"[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}", value):
            raise RuntimeError("secret-shaped three-part credential escaped into evidence")
        if re.fullmatch(r"0x[0-9a-fA-F]{64}", value):
            raise RuntimeError("secret-shaped 32-byte value escaped into evidence")
        if re.fullmatch(r"[0-9a-fA-F]{64}", value):
            raise RuntimeError("secret-shaped hexadecimal value escaped into evidence")
        if (
            len(value) >= 40
            and re.fullmatch(r"[A-Za-z0-9_-]+", value)
            and re.search(r"[a-z]", value)
            and re.search(r"[A-Z]", value)
            and re.search(r"\d", value)
        ):
            raise RuntimeError("secret-shaped opaque value escaped into evidence")

    walk(result)


def _build_summary(
    scenarios: list[dict[str, Any]],
    settlement_fixtures: list[dict[str, Any]],
) -> dict[str, Any]:
    ids = [str(item["id"]) for item in scenarios]
    if tuple(item for item in ids if item.startswith("T")) != REQUIRED_TRANSACTION_IDS:
        raise RuntimeError("transaction scenario coverage is incomplete or out of order")
    if tuple(item for item in ids if item.startswith("C")) != REQUIRED_CANARY_IDS:
        raise RuntimeError("canary coverage is incomplete or out of order")
    if tuple(str(item["id"]) for item in settlement_fixtures) != REQUIRED_SETTLEMENT_FIXTURE_IDS:
        raise RuntimeError("settlement fixture coverage is incomplete or out of order")

    required = [item for item in scenarios if str(item["id"]).startswith("T")]
    canaries = [item for item in scenarios if str(item["id"]).startswith("C")]
    outcomes = (
        "ALLOW", "DENY", "CHALLENGE", "PENDING_APPROVAL", "RATE_LIMIT",
        "CONFLICT", "VALIDATION_REJECT",
    )
    primary_counts = {
        outcome: sum(item["actual"]["primary"]["outcome"] == outcome for item in scenarios)
        for outcome in outcomes
    }
    passed = sum(item["verdict"] == "PASS" for item in scenarios)
    failed = len(scenarios) - passed
    required_failed = sum(item["verdict"] == "FAIL" for item in required)
    known_gap_count = sum(bool(item["known_gap"]) for item in canaries)
    fixture_passed = sum(item["verdict"] == "PASS" for item in settlement_fixtures)
    fixture_failed = len(settlement_fixtures) - fixture_passed
    if required_failed or fixture_failed:
        overall_verdict = "FAIL_REQUIRED_EVIDENCE"
    elif known_gap_count:
        overall_verdict = "REQUIRED_PASS_WITH_KNOWN_GAPS"
    else:
        overall_verdict = "PASS"
    return {
        "scenario_count": len(scenarios),
        "passed": passed,
        "failed": failed,
        "required_scenarios_passed": sum(item["verdict"] == "PASS" for item in required),
        "required_scenarios_failed": required_failed,
        "known_gap_canaries": known_gap_count,
        "coverage_verdicts": {"PASS": passed, "FAIL": failed},
        "allowed": primary_counts["ALLOW"],
        "denied": primary_counts["DENY"],
        "challenged": primary_counts["CHALLENGE"],
        "pending_approval": primary_counts["PENDING_APPROVAL"],
        "rate_limited": primary_counts["RATE_LIMIT"],
        "conflict": primary_counts["CONFLICT"],
        "validation_rejected": primary_counts["VALIDATION_REJECT"],
        "primary_outcomes": primary_counts,
        "challenge_step_count": sum(
            step["outcome"] == "CHALLENGE"
            for item in scenarios
            for step in item["actual"]["ordered_steps"]
        ),
        "authorization_only_cases": len(scenarios),
        "settlement_fixtures_passed": fixture_passed,
        "settlement_fixtures_failed": fixture_failed,
        "overall_verdict": overall_verdict,
    }


def _events(result: Mapping[str, Any]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    event_index = 0
    for scenario in result["scenarios"]:
        for step_index, step in enumerate(scenario["actual"]["ordered_steps"]):
            events.append(
                {
                    "schema_version": result["schema_version"],
                    "run_id": result["run_id"],
                    "event_index": event_index,
                    "type": "scenario_step",
                    "scenario_id": scenario["id"],
                    "evidence_class": scenario["evidence_class"],
                    "step_index": step_index,
                    "step_label": step["label"],
                    "http_status": step["http_status"],
                    "outcome": step["outcome"],
                    "top_level_code": step["top_level_code"],
                    "nested_reason_code": step["nested_reason_code"],
                    "request_alias": step["correlation"]["request"],
                    "local_transaction_alias": step["correlation"]["local_transaction"],
                    "scenario_verdict": scenario["verdict"],
                    "known_gap": scenario["known_gap"],
                }
            )
            event_index += 1
    for fixture in result["settlement_fixtures"]:
        events.append(
            {
                "schema_version": result["schema_version"],
                "run_id": result["run_id"],
                "event_index": event_index,
                "type": "settlement_fixture",
                "scenario_id": fixture["id"],
                "evidence_class": fixture["evidence_class"],
                "expected": fixture["expected"],
                "actual": fixture["actual"],
                "scenario_verdict": fixture["verdict"],
                "known_gap": fixture["known_gap"],
            }
        )
        event_index += 1
    return events


def _summary_markdown(result: Mapping[str, Any]) -> str:
    lines = [
        "# Safe4 local transaction edge-case evidence",
        "",
        f"Run ID: `{result['run_id']}`",
        "",
        "This bundle records local application authorization behavior and separate local",
        "settlement-verifier fixtures. It contains no live chain or settlement execution.",
        "",
        "| ID | Evidence class | Primary HTTP | Primary outcome | Reason | Verdict |",
        "|---|---|---:|---|---|---|",
    ]
    for scenario in result["scenarios"]:
        primary = scenario["actual"]["primary"]
        reason = primary["nested_reason_code"] or primary["top_level_code"] or "NONE"
        lines.append(
            f"| {scenario['id']} | {scenario['evidence_class']} | {primary['http_status']} | "
            f"{primary['outcome']} | {reason} | {scenario['verdict']} |"
        )
    lines.extend(
        [
            "",
            "## Totals",
            "",
            "```json",
            _canonical_json(result["summary"], pretty=True),
            "```",
            "",
            "Independent review remains `INSUFFICIENT_EVIDENCE` until a separate reviewer",
            "checks this bundle against source and tests.",
            "",
        ]
    )
    return "\n".join(lines)


def _write_bundle(result: Mapping[str, Any], bundle_dir: Path) -> None:
    if bundle_dir.exists():
        raise RuntimeError("refusing to overwrite an existing evidence bundle")
    bundle_dir.mkdir(parents=True, exist_ok=False)
    events = _events(result)
    files = {
        "summary.json": _canonical_json(result, pretty=True) + "\n",
        "summary.md": _summary_markdown(result),
        "events.jsonl": "".join(_canonical_json(event, pretty=False) + "\n" for event in events),
        "pytest.txt": "\n".join(
            [
                "SAFE4 FOCUSED TEST TRANSCRIPT (SANITIZED ALLOWLIST)",
                "command=.\\.python313\\python.exe -m pytest -q tests/test_edge_case_evidence.py",
                "pytest_execution=NOT_EXECUTED_BY_RUNNER",
                "runner_execution=COMPLETED",
                f"required_scenarios_passed={result['summary']['required_scenarios_passed']}",
                f"required_scenarios_failed={result['summary']['required_scenarios_failed']}",
                f"settlement_fixtures_passed={result['summary']['settlement_fixtures_passed']}",
                f"known_gap_canaries={result['summary']['known_gap_canaries']}",
                "raw_output_persisted=false",
                "note=Run pytest separately; never append unsanitized process output to this file.",
                "",
            ]
        ),
        "redaction-manifest.md": "\n".join(
            [
                "# Redaction manifest",
                "",
                "The runner never writes values from these categories:",
                "",
                "- OAuth access and refresh tokens",
                "- OAuth authorization codes and authorization header values",
                "- receipt tokens and receipt-signature material",
                "- administrative secrets",
                "- spend authorization tokens",
                "- private keys, one-time passwords, and email addresses",
                "- cookies, wallet sessions, and browser sessions",
                "- environment variable values",
                "- raw HTTP bodies or headers",
                "- raw application logs or database contents",
                "- absolute filesystem paths",
                "- ambient environment dumps",
                "",
                "Application identifiers and synthetic client addresses are mapped to",
                "deterministic per-scenario aliases.",
                "",
            ]
        ),
        "README.md": "\n".join(
            [
                "# Reproducing this local evidence",
                "",
                "From the repository root with Python 3.13:",
                "",
                "```powershell",
                ".\\.python313\\python.exe scripts\\run_edge_case_evidence.py --pretty",
                "```",
                "",
                "Evidence classes are `local_application_authorization`, `red_team_canary`,",
                "and `local_settlement_fixture`. No RPC, wallet, signing, transfer, or broadcast",
                "is performed. `/pay` transaction aliases are local authorization identifiers,",
                "not settlement identifiers. Standard `/pay` rows report settlement executor",
                "evidence as `NOT_OBSERVED`.",
                "",
                "The SQLite database exists only below ignored `.tmp` during execution and is",
                "deleted before this sanitized bundle is written.",
                "",
            ]
        ),
    }
    for name, content in files.items():
        (bundle_dir / name).write_text(content, encoding="utf-8", newline="\n")


def run_matrix(*, run_id: str) -> dict[str, Any]:
    """Execute the complete matrix and return its canonical sanitized structure."""

    if sys.version_info[:2] != (3, 13):
        raise RuntimeError("the evidence runner requires Python 3.13")
    if not re.fullmatch(r"\d{8}T\d{6}Z", run_id):
        raise RuntimeError("run_id must match YYYYMMDDTHHMMSSZ")
    if "app.main" in sys.modules:
        raise RuntimeError("run_matrix must start in a fresh subprocess before app.main is imported")

    repository_root = Path(__file__).resolve().parents[1]
    repository_root_text = str(repository_root)
    if repository_root_text not in sys.path:
        sys.path.insert(0, repository_root_text)
    temporary_parent = repository_root / ".tmp"
    temporary_parent.mkdir(exist_ok=True)
    run_temp = temporary_parent / f"edge-case-evidence-{run_id}"
    if run_temp.exists():
        raise RuntimeError("refusing to reuse an existing temporary evidence directory")
    run_temp.mkdir()
    try:
        state_group = run_temp / "state-group-matrix"
        state_group.mkdir()
        database_path = state_group / "payment-state.db"
        _configure_local_environment(database_path)

        from fastapi.testclient import TestClient
        from app import main as app_main, webhooks_api

        _assert_isolated_sqlite(app_main, database_path, state_group)
        with TestClient(app_main.app) as client:
            with _network_disabled():
                harness = EvidenceHarness(app_main, webhooks_api, client)
                scenarios = _run_transaction_scenarios(harness)
        settlement_fixtures = _run_settlement_fixtures()
    finally:
        resolved_run_temp = run_temp.resolve()
        if resolved_run_temp.parent != temporary_parent.resolve():
            raise RuntimeError("refusing to clean an unexpected temporary path")
        shutil.rmtree(resolved_run_temp)

    summary = _build_summary(scenarios, settlement_fixtures)
    result = {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id,
        "preflight": {
            "run_timestamp_utc": datetime.strptime(run_id, "%Y%m%dT%H%M%SZ")
            .replace(tzinfo=timezone.utc)
            .isoformat()
            .replace("+00:00", "Z"),
            "python_version": platform.python_version(),
            **_source_metadata(repository_root),
        },
        "execution": {
            "mode": "LOCAL_TESTCLIENT_AUTHORIZATION_ONLY",
            "python": "3.13",
            "database_backend": "SQLite",
            "database_location": "EPHEMERAL_IGNORED_TMP",
            "database_deleted_before_bundle_write": True,
            "state_isolation": "ONE_UNIQUE_RUN_DATABASE_RESET_BETWEEN_INDEPENDENT_CASES",
            "network": "BLOCKED",
            "wallet": "NOT_INVOKED",
            "rpc": "NOT_INVOKED",
            "broadcast": "NOT_INVOKED",
        },
        "baseline": {
            "agent": BASE_AGENT,
            "user": BASE_USER,
            "vendor": BASE_VENDOR,
            "amount": "0.001000",
            "currency": "USDC",
            "task_context_trust": "request-supplied-untrusted",
        },
        "scenarios": scenarios,
        "settlement_fixtures": settlement_fixtures,
        "summary": summary,
        "independent_review": {
            "status": "PENDING",
            "verdict": "INSUFFICIENT_EVIDENCE",
        },
        "limitations": [
            "POST /pay authorizes locally and does not expose a settlement executor.",
            "Local transaction aliases are not chain transaction or settlement identifiers.",
            "Idempotency proves one local budget and log write, not exactly-once external settlement.",
            "Request-supplied task context is not principal-bound.",
            "C01-C03 are known-gap canaries and are excluded from positive robustness claims.",
            "T18 currently records an audit but no DENIED payment log and leaves its receipt unconsumed.",
            "The database is unique per run and reset between cases, not a separate process per case.",
        ],
    }
    _assert_sanitized(result)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pretty", action="store_true", help="pretty-print canonical JSON")
    parser.add_argument(
        "--bundle-dir",
        type=Path,
        help=(
            "new bundle directory; defaults to artifacts/transaction-edge-cases/"
            "<UTC-run-id> and is never overwritten"
        ),
    )
    parser.add_argument(
        "--run-id",
        help="sanitized run label; defaults to a unique UTC timestamp",
    )
    parser.add_argument(
        "--fail-on-known-gaps",
        action="store_true",
        help="return non-zero when a red-team canary exposes a known policy gap",
    )
    args = parser.parse_args(argv)
    run_id = args.run_id or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    result = run_matrix(run_id=run_id)
    repository_root = Path(__file__).resolve().parents[1]
    bundle_dir = args.bundle_dir or (
        repository_root / "artifacts" / "transaction-edge-cases" / run_id
    )
    _write_bundle(result, bundle_dir)
    print(_canonical_json(result, pretty=args.pretty))
    baseline_failed = result["summary"]["required_scenarios_failed"] > 0
    fixture_failed = result["summary"]["settlement_fixtures_failed"] > 0
    known_gap_failed = args.fail_on_known_gaps and result["summary"]["known_gap_canaries"] > 0
    return 1 if baseline_failed or fixture_failed or known_gap_failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
