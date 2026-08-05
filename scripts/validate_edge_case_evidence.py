"""Validate a sanitized Safe4 transaction edge-case evidence bundle offline.

The validator deliberately has no application, database, HTTP, or socket imports.
It reads the six public evidence artifacts, validates their closed schemas and
cross-file invariants, and reports every deterministic contract violation.
"""

from __future__ import annotations

import argparse
from collections.abc import Iterable, Mapping
import ipaddress
import json
from pathlib import Path
import re
from typing import Any


SCHEMA_VERSION = "safe4-transaction-evidence/1.0"

REQUIRED_ARTIFACTS = (
    "summary.json",
    "summary.md",
    "events.jsonl",
    "pytest.txt",
    "redaction-manifest.md",
    "README.md",
)

REQUIRED_TRANSACTION_IDS = (
    "T01",
    "T02",
    "T03",
    "T04A",
    "T04B",
    "T05",
    "T06",
    "T07",
    "T08",
    "T09",
    "T10",
    "T11",
    "T12",
    "T13",
    "T14",
    "T15",
    "T16",
    "T17",
    "T18",
    "T19",
    "T20",
    "T21",
)
REQUIRED_CANARY_IDS = ("C01", "C02", "C03")
REQUIRED_SCENARIO_IDS = REQUIRED_TRANSACTION_IDS + REQUIRED_CANARY_IDS
REQUIRED_SETTLEMENT_IDS = tuple(f"S{index:02d}" for index in range(1, 9))

OUTCOMES = {
    "ALLOW",
    "DENY",
    "CHALLENGE",
    "RATE_LIMIT",
    "CONFLICT",
    "VALIDATION_REJECT",
    "PENDING_APPROVAL",
}
VERDICTS = {"PASS", "FAIL"}
OUTCOME_COUNT_FIELDS = {
    "ALLOW": "allowed",
    "DENY": "denied",
    "CHALLENGE": "challenged",
    "PENDING_APPROVAL": "pending_approval",
    "RATE_LIMIT": "rate_limited",
    "CONFLICT": "conflict",
    "VALIDATION_REJECT": "validation_rejected",
}

TOP_LEVEL_FIELDS = {
    "schema_version",
    "run_id",
    "preflight",
    "execution",
    "baseline",
    "scenarios",
    "settlement_fixtures",
    "summary",
    "independent_review",
    "limitations",
}
PREFLIGHT_FIELDS = {
    "run_timestamp_utc",
    "python_version",
    "source",
    "manifest_algorithm",
    "manifest_digest",
    "manifest_files",
}
EXECUTION_FIELDS = {
    "mode",
    "python",
    "database_backend",
    "database_location",
    "database_deleted_before_bundle_write",
    "state_isolation",
    "network",
    "wallet",
    "rpc",
    "broadcast",
}
BASELINE_FIELDS = {
    "agent",
    "user",
    "vendor",
    "amount",
    "currency",
    "task_context_trust",
}
INDEPENDENT_REVIEW_FIELDS = {"status", "verdict"}
SCENARIO_FIELDS = {
    "id",
    "evidence_class",
    "input_delta",
    "expected",
    "actual",
    "assertions",
    "verdict",
    "known_gap",
}
EXPECTED_FIELDS = {
    "ordered_steps",
    "primary_label",
    "user_spend_delta",
    "agent_spend_delta",
    "settlement_executor",
}
ACTUAL_FIELDS = {
    "ordered_steps",
    "primary",
    "state",
    "settlement_executor",
    "observations",
}
STEP_FIELDS = {
    "label",
    "http_status",
    "outcome",
    "response_status",
    "top_level_code",
    "nested_reason_code",
    "intent",
    "policy_details",
    "correlation",
    "retry_after_present",
    "retry_after_seconds",
}
INTENT_FIELDS = {
    "allowed",
    "reason_code",
    "mode",
    "matched_concepts",
    "task_context_trust",
}
CORRELATION_FIELDS = {"request", "local_transaction", "approval_fixture"}
STATE_FIELDS = {
    "before",
    "after",
    "user_spend_delta",
    "agent_spend_delta",
    "payment_log_delta",
    "audit_entry_delta",
}
STATE_SNAPSHOT_FIELDS = {
    "user_configured",
    "user_spend",
    "agent_spend",
    "payment_log_count",
    "payment_log_results",
    "audit_entry_count",
    "audit_reason_codes",
}
SETTLEMENT_EXECUTOR_FIELDS = {"status", "reason"}
FIXTURE_FIELDS = {
    "id",
    "evidence_class",
    "input_delta",
    "expected",
    "actual",
    "verdict",
    "known_gap",
}
FIXTURE_EXPECTED_FIELDS = {"outcome", "error_class", "reason_category"}
FIXTURE_ACTUAL_FIELDS = {
    "outcome",
    "error_class",
    "reason_category_matched",
    "rpc_invoked",
}
SUMMARY_COUNT_FIELDS = {
    "scenario_count",
    "passed",
    "failed",
    "required_scenarios_passed",
    "required_scenarios_failed",
    "known_gap_canaries",
    "coverage_verdicts",
    "allowed",
    "denied",
    "challenged",
    "pending_approval",
    "rate_limited",
    "conflict",
    "validation_rejected",
    "primary_outcomes",
    "challenge_step_count",
    "authorization_only_cases",
    "settlement_fixtures_passed",
    "settlement_fixtures_failed",
    "overall_verdict",
}

SCENARIO_EVENT_FIELDS = {
    "schema_version",
    "run_id",
    "event_index",
    "type",
    "scenario_id",
    "evidence_class",
    "step_index",
    "step_label",
    "http_status",
    "outcome",
    "top_level_code",
    "nested_reason_code",
    "request_alias",
    "local_transaction_alias",
    "scenario_verdict",
    "known_gap",
}
SETTLEMENT_EVENT_FIELDS = {
    "schema_version",
    "run_id",
    "event_index",
    "type",
    "scenario_id",
    "evidence_class",
    "expected",
    "actual",
    "scenario_verdict",
    "known_gap",
}

RUN_ID_PATTERN = re.compile(r"\A\d{8}T\d{6}Z\Z")
DECIMAL_PATTERN = re.compile(r"\A-?(?:0|[1-9]\d*)\.\d{6}\Z")
ALIAS_PATTERNS = {
    "request": re.compile(r"\Arequest-\d+\Z"),
    "local_transaction": re.compile(r"\Alocal-transaction-\d+\Z"),
    "approval_fixture": re.compile(r"\Aapproval-fixture-\d+\Z"),
}
WINDOWS_ABSOLUTE_PATH = re.compile(r"(?i)(?<![A-Za-z0-9_])[A-Z]:[\\/]")
UNC_PATH = re.compile(r"(?<![\\])\\\\[^\\\s]+\\[^\\\s]+")
DSN_PATTERN = re.compile(
    r"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|"
    r"sqlite|mssql|oracle)://[^\s<]+"
)
IPV4_CANDIDATE = re.compile(r"(?<![0-9.])(?:\d{1,3}\.){3}\d{1,3}(?![0-9.])")
IPV6_CANDIDATE = re.compile(
    r"(?i)(?<![0-9A-F:])(?:\[[0-9A-F:]+\]|(?:[0-9A-F]{0,4}:){2,7}[0-9A-F]{0,4})(?![0-9A-F:])"
)
JWT_PATTERN = re.compile(
    r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,}\b"
)
TOKEN_PATTERN = re.compile(
    r"(?i)(?:authorization\s*[:=]\s*bearer\s+|"
    r"(?:access|refresh|receipt|spend|session)[_-]?token\s*[:=]\s*[\"']?)"
    r"(?P<value>[A-Za-z0-9._~+/=-]{12,})"
)
PRIVATE_KEY_PATTERN = re.compile(
    r"(?im)(?:\b(?:private[_-]?key|arc_private_key)\b\s*[:=]\s*[\"']?)"
    r"(?:0x)?[0-9a-f]{64}\b|-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"
)
EMAIL_PATTERN = re.compile(
    r"(?i)(?<![A-Z0-9.!#$%&'*+/=?^_`{|}~-])"
    r"[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?"
    r"(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+"
)

MONEY_KEYS = {
    "amount",
    "agent_transaction_cap",
    "transaction_cap",
    "daily_cap",
    "spent_today",
    "prior_spend",
    "requested_amount",
    "max_cost",
    "budget_before",
    "budget_after",
    "spent_before",
    "spent_after",
    "spend_before",
    "spend_after",
    "spend_delta",
    "user_spend",
    "agent_spend",
    "user_spend_delta",
    "agent_spend_delta",
    "hitl_threshold",
}

MINIMUM_STEP_COUNTS = {
    "T01": 2,
    "T08": 2,
    "T09": 2,
    "T10": 2,
    "T11": 2,
    "T15": 2,
    "T20": 2,
}


class DuplicateKeyError(ValueError):
    """Raised when evidence JSON contains an ambiguous duplicate object key."""


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load_json(text: str, *, source: str) -> Any:
    try:
        return json.loads(text, object_pairs_hook=_object_without_duplicate_keys)
    except (json.JSONDecodeError, DuplicateKeyError) as exc:
        raise ValueError(f"{source}: invalid JSON: {exc}") from exc


def _canonical_summary(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def _canonical_event(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def _field_error(errors: list[str], location: str, actual: Iterable[str], expected: set[str]) -> None:
    actual_set = set(actual)
    missing = sorted(expected - actual_set)
    extra = sorted(actual_set - expected)
    if missing:
        errors.append(f"{location}: missing fields: {', '.join(missing)}")
    if extra:
        errors.append(f"{location}: unexpected fields: {', '.join(extra)}")


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _validate_optional_string(errors: list[str], location: str, value: Any) -> None:
    if value is not None and not isinstance(value, str):
        errors.append(f"{location}: expected string or null")


def _validate_alias(errors: list[str], location: str, kind: str, value: Any) -> None:
    if value is None:
        return
    if not isinstance(value, str) or ALIAS_PATTERNS[kind].fullmatch(value) is None:
        errors.append(f"{location}: expected sanitized {kind.replace('_', '-')} alias or null")


def _validate_decimal_values(value: Any, errors: list[str], location: str) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            child_location = f"{location}.{key}"
            if key in MONEY_KEYS and child is not None:
                if not isinstance(child, str) or DECIMAL_PATTERN.fullmatch(child) is None:
                    errors.append(
                        f"{child_location}: monetary value must be a canonical six-decimal string"
                    )
            _validate_decimal_values(child, errors, child_location)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _validate_decimal_values(child, errors, f"{location}[{index}]")


def _validate_step(step: Any, errors: list[str], location: str) -> None:
    if not isinstance(step, Mapping):
        errors.append(f"{location}: expected object")
        return
    _field_error(errors, location, step, STEP_FIELDS)
    if not isinstance(step.get("label"), str) or not step.get("label"):
        errors.append(f"{location}.label: expected non-empty string")
    status = step.get("http_status")
    if not _is_int(status) or not 100 <= status <= 599:
        errors.append(f"{location}.http_status: expected integer HTTP status")
    if step.get("outcome") not in OUTCOMES:
        errors.append(f"{location}.outcome: expected one of {sorted(OUTCOMES)}")
    for field in ("response_status", "top_level_code", "nested_reason_code"):
        _validate_optional_string(errors, f"{location}.{field}", step.get(field))

    intent = step.get("intent")
    if intent is not None:
        if not isinstance(intent, Mapping):
            errors.append(f"{location}.intent: expected object or null")
        else:
            _field_error(errors, f"{location}.intent", intent, INTENT_FIELDS)
            if not isinstance(intent.get("allowed"), bool):
                errors.append(f"{location}.intent.allowed: expected boolean")
            for field in ("reason_code", "mode", "task_context_trust"):
                _validate_optional_string(errors, f"{location}.intent.{field}", intent.get(field))
            concepts = intent.get("matched_concepts")
            if not isinstance(concepts, list) or not all(isinstance(item, str) for item in concepts):
                errors.append(f"{location}.intent.matched_concepts: expected string array")

    if not isinstance(step.get("policy_details"), Mapping):
        errors.append(f"{location}.policy_details: expected object")
    correlation = step.get("correlation")
    if not isinstance(correlation, Mapping):
        errors.append(f"{location}.correlation: expected object")
    else:
        _field_error(errors, f"{location}.correlation", correlation, CORRELATION_FIELDS)
        for kind in CORRELATION_FIELDS:
            _validate_alias(
                errors,
                f"{location}.correlation.{kind}",
                kind,
                correlation.get(kind),
            )
    if not isinstance(step.get("retry_after_present"), bool):
        errors.append(f"{location}.retry_after_present: expected boolean")
    retry_seconds = step.get("retry_after_seconds")
    if retry_seconds is not None and (not _is_int(retry_seconds) or retry_seconds < 0):
        errors.append(f"{location}.retry_after_seconds: expected non-negative integer or null")
    if step.get("retry_after_present") is False and retry_seconds is not None:
        errors.append(f"{location}.retry_after_seconds: must be null when header is absent")


def _resolve_primary_step(actual: Mapping[str, Any], errors: list[str], location: str) -> Mapping[str, Any] | None:
    steps = actual.get("ordered_steps")
    if not isinstance(steps, list) or not steps:
        return None
    primary = actual.get("primary")
    if isinstance(primary, Mapping):
        if primary in steps:
            return primary
        errors.append(f"{location}.primary: copied primary step is absent from steps")
        return None
    errors.append(f"{location}.primary: expected a copied member of ordered_steps")
    return None


def _validate_expected(
    expected: Mapping[str, Any],
    actual: Mapping[str, Any] | None,
    errors: list[str],
    location: str,
    *,
    require_observation_match: bool,
) -> None:
    ordered = expected.get("ordered_steps")
    if not isinstance(ordered, list) or not ordered:
        errors.append(f"{location}.ordered_steps: expected non-empty array")
        return
    labels: list[Any] = []
    for index, item in enumerate(ordered):
        item_location = f"{location}.ordered_steps[{index}]"
        if not isinstance(item, Mapping):
            errors.append(f"{item_location}: expected object")
            continue
        unexpected = sorted(set(item) - STEP_FIELDS)
        if unexpected:
            errors.append(f"{item_location}: unexpected fields: {', '.join(unexpected)}")
        label = item.get("label")
        labels.append(label)
        if not isinstance(label, str) or not label:
            errors.append(f"{item_location}.label: expected non-empty string")
        if "outcome" in item and item.get("outcome") not in OUTCOMES:
            errors.append(f"{item_location}.outcome: expected one of {sorted(OUTCOMES)}")
        if "http_status" in item:
            status = item.get("http_status")
            if not _is_int(status) or not 100 <= status <= 599:
                errors.append(f"{item_location}.http_status: expected integer HTTP status")
    if len(set(labels)) != len(labels):
        errors.append(f"{location}.ordered_steps: labels must be unique")
    primary_label = expected.get("primary_label")
    if primary_label not in labels:
        errors.append(f"{location}.primary_label: must name an expected ordered step")
    for field in ("user_spend_delta", "agent_spend_delta"):
        value = expected.get(field)
        if value is not None and (
            not isinstance(value, str) or DECIMAL_PATTERN.fullmatch(value) is None
        ):
            errors.append(f"{location}.{field}: expected canonical six-decimal string or null")
    if expected.get("settlement_executor") != "NOT_OBSERVED":
        errors.append(f"{location}.settlement_executor: expected NOT_OBSERVED")

    if not isinstance(actual, Mapping):
        return
    actual_steps = actual.get("ordered_steps")
    if isinstance(actual_steps, list):
        if [item.get("label") if isinstance(item, Mapping) else None for item in actual_steps] != labels:
            errors.append(f"{location}.ordered_steps: labels/order do not match actual ordered_steps")
        for index, item in enumerate(ordered):
            if not isinstance(item, Mapping) or index >= len(actual_steps):
                continue
            actual_item = actual_steps[index]
            if not isinstance(actual_item, Mapping):
                continue
            for field, value in item.items():
                if require_observation_match and actual_item.get(field) != value:
                    errors.append(
                        f"{location}.ordered_steps[{index}].{field}: does not match actual observation"
                    )
    primary = actual.get("primary")
    if isinstance(primary, Mapping) and primary.get("label") != primary_label:
        errors.append(f"{location}.primary_label: does not select actual.primary")


def _validate_state(state: Any, errors: list[str], location: str) -> None:
    if not isinstance(state, Mapping):
        errors.append(f"{location}: expected object")
        return
    _field_error(errors, location, state, STATE_FIELDS)
    for field in ("before", "after"):
        snapshot = state.get(field)
        if not isinstance(snapshot, Mapping):
            errors.append(f"{location}.{field}: expected object")
            continue
        _field_error(errors, f"{location}.{field}", snapshot, STATE_SNAPSHOT_FIELDS)
        if not isinstance(snapshot.get("user_configured"), bool):
            errors.append(f"{location}.{field}.user_configured: expected boolean")
        for money_field in ("user_spend", "agent_spend"):
            money = snapshot.get(money_field)
            if money is not None and (
                not isinstance(money, str) or DECIMAL_PATTERN.fullmatch(money) is None
            ):
                errors.append(
                    f"{location}.{field}.{money_field}: expected six-decimal string or null"
                )
        for count_field in ("payment_log_count", "audit_entry_count"):
            if not _is_int(snapshot.get(count_field)) or snapshot.get(count_field) < 0:
                errors.append(f"{location}.{field}.{count_field}: expected non-negative integer")
        for list_field in ("payment_log_results", "audit_reason_codes"):
            values = snapshot.get(list_field)
            if not isinstance(values, list) or not all(isinstance(item, str) for item in values):
                errors.append(f"{location}.{field}.{list_field}: expected string array")
    for field in ("payment_log_delta", "audit_entry_delta"):
        if not _is_int(state.get(field)):
            errors.append(f"{location}.{field}: expected integer")


def _validate_scenarios(summary: Mapping[str, Any], errors: list[str]) -> tuple[list[Mapping[str, Any]], dict[str, Mapping[str, Any]]]:
    raw = summary.get("scenarios")
    if not isinstance(raw, list):
        errors.append("summary.scenarios: expected array")
        return [], {}
    ids = [item.get("id") if isinstance(item, Mapping) else None for item in raw]
    if ids != list(REQUIRED_SCENARIO_IDS):
        errors.append(
            "summary.scenarios: IDs must appear exactly once in canonical order: "
            + ", ".join(REQUIRED_SCENARIO_IDS)
        )

    valid: list[Mapping[str, Any]] = []
    by_id: dict[str, Mapping[str, Any]] = {}
    for index, scenario in enumerate(raw):
        location = f"summary.scenarios[{index}]"
        if not isinstance(scenario, Mapping):
            errors.append(f"{location}: expected object")
            continue
        valid.append(scenario)
        _field_error(errors, location, scenario, SCENARIO_FIELDS)
        scenario_id = scenario.get("id")
        if isinstance(scenario_id, str):
            by_id[scenario_id] = scenario
        expected_class = (
            "red_team_canary"
            if scenario_id in REQUIRED_CANARY_IDS
            else "local_application_authorization"
        )
        if scenario.get("evidence_class") != expected_class:
            errors.append(f"{location}.evidence_class: expected {expected_class}")
        if scenario.get("verdict") not in VERDICTS:
            errors.append(f"{location}.verdict: expected PASS or FAIL")
        if not isinstance(scenario.get("known_gap"), bool):
            errors.append(f"{location}.known_gap: expected boolean")
        elif scenario_id in REQUIRED_CANARY_IDS:
            if scenario.get("known_gap") is not True or scenario.get("verdict") != "FAIL":
                errors.append(f"{location}: canary must be retained as a failing known gap")
        elif scenario.get("known_gap") is not False:
            errors.append(f"{location}.known_gap: required transaction scenarios are not known gaps")

        for field, allowed_fields in (
            ("expected", EXPECTED_FIELDS),
            ("actual", ACTUAL_FIELDS),
        ):
            value = scenario.get(field)
            if not isinstance(value, Mapping):
                errors.append(f"{location}.{field}: expected object")
            else:
                _field_error(errors, f"{location}.{field}", value, allowed_fields)

        actual = scenario.get("actual")
        if isinstance(actual, Mapping):
            steps = actual.get("ordered_steps")
            if not isinstance(steps, list) or not steps:
                errors.append(f"{location}.actual.ordered_steps: expected non-empty array")
            else:
                for step_index, step in enumerate(steps):
                    _validate_step(
                        step,
                        errors,
                        f"{location}.actual.ordered_steps[{step_index}]",
                    )
                if scenario_id == "T17" and len(steps) != 6:
                    errors.append(
                        f"{location}.actual.ordered_steps: T17 must contain exactly six cases"
                    )
                minimum = MINIMUM_STEP_COUNTS.get(str(scenario_id))
                if minimum is not None and len(steps) < minimum:
                    errors.append(
                        f"{location}.actual.ordered_steps: {scenario_id} must contain at least {minimum} ordered steps"
                    )
            _resolve_primary_step(actual, errors, f"{location}.actual")
            _validate_state(actual.get("state"), errors, f"{location}.actual.state")
            executor = actual.get("settlement_executor")
            if not isinstance(executor, Mapping):
                errors.append(f"{location}.actual.settlement_executor: expected object")
            else:
                _field_error(
                    errors,
                    f"{location}.actual.settlement_executor",
                    executor,
                    SETTLEMENT_EXECUTOR_FIELDS,
                )
                if executor.get("status") != "NOT_OBSERVED":
                    errors.append(
                        f"{location}.actual.settlement_executor.status: expected NOT_OBSERVED"
                    )
                if not isinstance(executor.get("reason"), str) or not executor.get("reason"):
                    errors.append(
                        f"{location}.actual.settlement_executor.reason: expected non-empty string"
                    )
            if not isinstance(actual.get("observations"), Mapping):
                errors.append(f"{location}.actual.observations: expected object")

        expected = scenario.get("expected")
        if isinstance(expected, Mapping):
            _validate_expected(
                expected,
                actual if isinstance(actual, Mapping) else None,
                errors,
                f"{location}.expected",
                require_observation_match=scenario.get("verdict") == "PASS",
            )

        if not isinstance(scenario.get("input_delta"), Mapping):
            errors.append(f"{location}.input_delta: expected object")
        assertions = scenario.get("assertions")
        if not isinstance(assertions, Mapping) or not assertions:
            errors.append(f"{location}.assertions: expected non-empty object")
        elif not all(isinstance(value, bool) for value in assertions.values()):
            errors.append(f"{location}.assertions: every assertion value must be boolean")
        elif scenario.get("verdict") != ("PASS" if all(assertions.values()) else "FAIL"):
            errors.append(f"{location}.verdict: does not reconcile with assertions")
    return valid, by_id


def _validate_fixtures(summary: Mapping[str, Any], errors: list[str]) -> tuple[list[Mapping[str, Any]], dict[str, Mapping[str, Any]]]:
    raw = summary.get("settlement_fixtures")
    if not isinstance(raw, list):
        errors.append("summary.settlement_fixtures: expected array")
        return [], {}
    ids = [item.get("id") if isinstance(item, Mapping) else None for item in raw]
    if ids != list(REQUIRED_SETTLEMENT_IDS):
        errors.append(
            "summary.settlement_fixtures: IDs must appear exactly once in canonical order: "
            + ", ".join(REQUIRED_SETTLEMENT_IDS)
        )
    valid: list[Mapping[str, Any]] = []
    by_id: dict[str, Mapping[str, Any]] = {}
    for index, fixture in enumerate(raw):
        location = f"summary.settlement_fixtures[{index}]"
        if not isinstance(fixture, Mapping):
            errors.append(f"{location}: expected object")
            continue
        valid.append(fixture)
        _field_error(errors, location, fixture, FIXTURE_FIELDS)
        fixture_id = fixture.get("id")
        if isinstance(fixture_id, str):
            by_id[fixture_id] = fixture
        if fixture.get("evidence_class") != "local_settlement_fixture":
            errors.append(
                f"{location}.evidence_class: expected local_settlement_fixture"
            )
        if fixture.get("verdict") not in VERDICTS:
            errors.append(f"{location}.verdict: expected PASS or FAIL")
        if fixture.get("known_gap") is not False:
            errors.append(f"{location}.known_gap: settlement fixtures are not known gaps")
        if not isinstance(fixture.get("input_delta"), Mapping):
            errors.append(f"{location}.input_delta: expected object")
        expected = fixture.get("expected")
        if not isinstance(expected, Mapping):
            errors.append(f"{location}.expected: expected object")
        else:
            _field_error(errors, f"{location}.expected", expected, FIXTURE_EXPECTED_FIELDS)
            if expected.get("outcome") != "REJECT":
                errors.append(f"{location}.expected.outcome: expected REJECT")
            if expected.get("error_class") != "ArcSettlementError":
                errors.append(f"{location}.expected.error_class: expected ArcSettlementError")
            if not isinstance(expected.get("reason_category"), str):
                errors.append(f"{location}.expected.reason_category: expected string")
        actual = fixture.get("actual")
        if not isinstance(actual, Mapping):
            errors.append(f"{location}.actual: expected object")
        else:
            _field_error(errors, f"{location}.actual", actual, FIXTURE_ACTUAL_FIELDS)
            if actual.get("outcome") not in {"REJECT", "ACCEPT"}:
                errors.append(f"{location}.actual.outcome: expected REJECT or ACCEPT")
            _validate_optional_string(
                errors,
                f"{location}.actual.error_class",
                actual.get("error_class"),
            )
            if not isinstance(actual.get("reason_category_matched"), bool):
                errors.append(
                    f"{location}.actual.reason_category_matched: expected boolean"
                )
            if actual.get("rpc_invoked") is not False:
                errors.append(f"{location}.actual.rpc_invoked: must be false")
        if isinstance(expected, Mapping) and isinstance(actual, Mapping):
            passed = (
                actual.get("outcome") == expected.get("outcome")
                and actual.get("error_class") == expected.get("error_class")
                and actual.get("reason_category_matched") is True
                and actual.get("rpc_invoked") is False
            )
            if fixture.get("verdict") != ("PASS" if passed else "FAIL"):
                errors.append(f"{location}.verdict: does not reconcile with fixture result")
    return valid, by_id


def _validate_counts(
    summary: Mapping[str, Any],
    scenarios: list[Mapping[str, Any]],
    fixtures: list[Mapping[str, Any]],
    errors: list[str],
) -> None:
    counts = summary.get("summary")
    if not isinstance(counts, Mapping):
        errors.append("summary.summary: expected object")
        return
    _field_error(errors, "summary.summary", counts, SUMMARY_COUNT_FIELDS)

    expected: dict[str, int] = {
        "scenario_count": len(scenarios),
        "passed": sum(item.get("verdict") == "PASS" for item in scenarios),
        "failed": sum(item.get("verdict") == "FAIL" for item in scenarios),
        "required_scenarios_passed": sum(
            item.get("id") in REQUIRED_TRANSACTION_IDS and item.get("verdict") == "PASS"
            for item in scenarios
        ),
        "required_scenarios_failed": sum(
            item.get("id") in REQUIRED_TRANSACTION_IDS and item.get("verdict") == "FAIL"
            for item in scenarios
        ),
        "known_gap_canaries": sum(
            item.get("id") in REQUIRED_CANARY_IDS and item.get("known_gap") is True
            for item in scenarios
        ),
        "authorization_only_cases": len(scenarios),
        "settlement_fixtures_passed": sum(item.get("verdict") == "PASS" for item in fixtures),
        "settlement_fixtures_failed": sum(item.get("verdict") == "FAIL" for item in fixtures),
    }
    expected.update({field: 0 for field in OUTCOME_COUNT_FIELDS.values()})
    primary_outcomes = {outcome: 0 for outcome in (
        "ALLOW",
        "DENY",
        "CHALLENGE",
        "PENDING_APPROVAL",
        "RATE_LIMIT",
        "CONFLICT",
        "VALIDATION_REJECT",
    )}
    challenge_step_count = 0
    for index, scenario in enumerate(scenarios):
        actual = scenario.get("actual")
        if not isinstance(actual, Mapping):
            continue
        steps = actual.get("ordered_steps")
        if isinstance(steps, list):
            challenge_step_count += sum(
                isinstance(step, Mapping) and step.get("outcome") == "CHALLENGE"
                for step in steps
            )
        primary = _resolve_primary_step(actual, [], f"summary.scenarios[{index}].actual")
        if primary is None:
            continue
        outcome = primary.get("outcome")
        count_field = OUTCOME_COUNT_FIELDS.get(outcome)
        if count_field is not None:
            expected[count_field] += 1
        if outcome in primary_outcomes:
            primary_outcomes[outcome] += 1

    for field, expected_value in expected.items():
        if counts.get(field) != expected_value:
            errors.append(
                f"summary.summary.{field}: expected reconciled count {expected_value}, "
                f"got {counts.get(field)!r}"
            )

    expected_coverage = {"PASS": expected["passed"], "FAIL": expected["failed"]}
    if counts.get("coverage_verdicts") != expected_coverage:
        errors.append(
            f"summary.summary.coverage_verdicts: expected {expected_coverage!r}"
        )
    if counts.get("primary_outcomes") != primary_outcomes:
        errors.append(
            f"summary.summary.primary_outcomes: expected {primary_outcomes!r}"
        )
    if counts.get("challenge_step_count") != challenge_step_count:
        errors.append(
            "summary.summary.challenge_step_count: expected reconciled count "
            f"{challenge_step_count}, got {counts.get('challenge_step_count')!r}"
        )
    if expected["required_scenarios_failed"] or expected["settlement_fixtures_failed"]:
        expected_overall = "FAIL_REQUIRED_EVIDENCE"
    elif expected["known_gap_canaries"]:
        expected_overall = "REQUIRED_PASS_WITH_KNOWN_GAPS"
    else:
        expected_overall = "PASS"
    if counts.get("overall_verdict") != expected_overall:
        errors.append(
            f"summary.summary.overall_verdict: expected {expected_overall}, "
            f"got {counts.get('overall_verdict')!r}"
        )


def _load_events(path: Path, errors: list[str]) -> tuple[list[Mapping[str, Any]], str]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        errors.append(f"events.jsonl: cannot read: {exc}")
        return [], ""
    events: list[Mapping[str, Any]] = []
    lines = text.splitlines()
    if not lines:
        errors.append("events.jsonl: expected at least one event")
        return events, text
    for line_number, line in enumerate(lines, start=1):
        if not line:
            errors.append(f"events.jsonl:{line_number}: blank lines are not allowed")
            continue
        try:
            event = _load_json(line, source=f"events.jsonl:{line_number}")
        except ValueError as exc:
            errors.append(str(exc))
            continue
        if not isinstance(event, Mapping):
            errors.append(f"events.jsonl:{line_number}: expected JSON object")
            continue
        canonical = _canonical_event(event)
        if line != canonical:
            errors.append(f"events.jsonl:{line_number}: event is not canonical compact sorted JSON")
        events.append(event)
    if text and not text.endswith("\n"):
        errors.append("events.jsonl: file must end with a newline")
    return events, text


def _validate_events(
    events: list[Mapping[str, Any]],
    summary: Mapping[str, Any],
    scenarios_by_id: Mapping[str, Mapping[str, Any]],
    fixtures_by_id: Mapping[str, Mapping[str, Any]],
    errors: list[str],
) -> None:
    run_id = summary.get("run_id")
    expected_positions: list[tuple[str, str, int | None]] = []
    for scenario_id in REQUIRED_SCENARIO_IDS:
        scenario = scenarios_by_id.get(scenario_id)
        actual = scenario.get("actual") if isinstance(scenario, Mapping) else None
        steps = actual.get("ordered_steps") if isinstance(actual, Mapping) else None
        if isinstance(steps, list):
            expected_positions.extend(
                ("scenario_step", scenario_id, step_index)
                for step_index in range(len(steps))
            )
    expected_positions.extend(
        ("settlement_fixture", fixture_id, None)
        for fixture_id in REQUIRED_SETTLEMENT_IDS
    )
    actual_positions = [
        (
            event.get("type"),
            event.get("scenario_id"),
            event.get("step_index") if event.get("type") == "scenario_step" else None,
        )
        for event in events
    ]
    if actual_positions != expected_positions:
        errors.append(
            "events.jsonl: events must be grouped in canonical scenario/step order, followed by S01-S08"
        )

    for index, event in enumerate(events):
        location = f"events[{index}]"
        if event.get("event_index") != index:
            errors.append(f"{location}.event_index: expected contiguous index {index}")
        if event.get("schema_version") != SCHEMA_VERSION:
            errors.append(f"{location}.schema_version: must match {SCHEMA_VERSION}")
        if event.get("run_id") != run_id:
            errors.append(f"{location}.run_id: must match summary run_id")
        event_type = event.get("type")
        if event_type == "scenario_step":
            _field_error(errors, location, event, SCENARIO_EVENT_FIELDS)
            scenario_id = event.get("scenario_id")
            scenario = scenarios_by_id.get(str(scenario_id))
            if scenario is None:
                errors.append(f"{location}.scenario_id: unknown scenario")
                continue
            if event.get("evidence_class") != scenario.get("evidence_class"):
                errors.append(f"{location}.evidence_class: does not match summary")
            if event.get("scenario_verdict") != scenario.get("verdict"):
                errors.append(f"{location}.scenario_verdict: does not match summary")
            if event.get("known_gap") != scenario.get("known_gap"):
                errors.append(f"{location}.known_gap: does not match summary")
            step_index = event.get("step_index")
            actual = scenario.get("actual")
            steps = actual.get("ordered_steps") if isinstance(actual, Mapping) else None
            if not _is_int(step_index) or not isinstance(steps, list) or not 0 <= step_index < len(steps):
                errors.append(f"{location}.step_index: expected valid zero-based step index")
                continue
            step = steps[step_index]
            if not isinstance(step, Mapping):
                continue
            comparisons = {
                "step_label": step.get("label"),
                "http_status": step.get("http_status"),
                "outcome": step.get("outcome"),
                "top_level_code": step.get("top_level_code"),
                "nested_reason_code": step.get("nested_reason_code"),
                "request_alias": (
                    step.get("correlation", {}).get("request")
                    if isinstance(step.get("correlation"), Mapping)
                    else None
                ),
                "local_transaction_alias": (
                    step.get("correlation", {}).get("local_transaction")
                    if isinstance(step.get("correlation"), Mapping)
                    else None
                ),
            }
            for field, expected_value in comparisons.items():
                if event.get(field) != expected_value:
                    errors.append(f"{location}.{field}: does not match summary step")
            if event.get("outcome") not in OUTCOMES:
                errors.append(f"{location}.outcome: expected one of {sorted(OUTCOMES)}")
            if event.get("scenario_verdict") not in VERDICTS:
                errors.append(f"{location}.scenario_verdict: expected PASS or FAIL")
            _validate_alias(errors, f"{location}.request_alias", "request", event.get("request_alias"))
            _validate_alias(
                errors,
                f"{location}.local_transaction_alias",
                "local_transaction",
                event.get("local_transaction_alias"),
            )
        elif event_type == "settlement_fixture":
            _field_error(errors, location, event, SETTLEMENT_EVENT_FIELDS)
            scenario_id = event.get("scenario_id")
            fixture = fixtures_by_id.get(str(scenario_id))
            if fixture is None:
                errors.append(f"{location}.scenario_id: unknown settlement fixture")
                continue
            comparisons = {
                "evidence_class": fixture.get("evidence_class"),
                "expected": fixture.get("expected"),
                "actual": fixture.get("actual"),
                "scenario_verdict": fixture.get("verdict"),
                "known_gap": False,
            }
            for field, expected_value in comparisons.items():
                if event.get(field) != expected_value:
                    errors.append(f"{location}.{field}: does not match summary fixture")
            if event.get("scenario_verdict") not in VERDICTS:
                errors.append(f"{location}.scenario_verdict: expected PASS or FAIL")
        else:
            errors.append(f"{location}.type: expected scenario_step or settlement_fixture")


def _valid_ip_literals(text: str) -> set[str]:
    found: set[str] = set()
    for match in IPV4_CANDIDATE.finditer(text):
        candidate = match.group(0)
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        found.add(candidate)
    for match in IPV6_CANDIDATE.finditer(text):
        candidate = match.group(0).strip("[]")
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        found.add(candidate)
    return found


def _scan_artifact_text(name: str, text: str, errors: list[str]) -> None:
    if WINDOWS_ABSOLUTE_PATH.search(text) or UNC_PATH.search(text):
        errors.append(f"{name}: contains an absolute Windows path")
    if DSN_PATTERN.search(text):
        errors.append(f"{name}: contains a database DSN")
    if JWT_PATTERN.search(text):
        errors.append(f"{name}: contains JWT-like security material")
    if TOKEN_PATTERN.search(text):
        errors.append(f"{name}: contains persisted token material")
    if PRIVATE_KEY_PATTERN.search(text):
        errors.append(f"{name}: contains private-key material")
    if EMAIL_PATTERN.search(text):
        errors.append(f"{name}: contains an email address")
    if _valid_ip_literals(text):
        errors.append(f"{name}: contains a raw IP address")


def _validate_metadata(summary: Mapping[str, Any], errors: list[str]) -> None:
    preflight = summary.get("preflight")
    if not isinstance(preflight, Mapping):
        errors.append("summary.preflight: expected object")
    else:
        _field_error(errors, "summary.preflight", preflight, PREFLIGHT_FIELDS)
        if not isinstance(preflight.get("run_timestamp_utc"), str) or not re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z",
            str(preflight.get("run_timestamp_utc")),
        ):
            errors.append("summary.preflight.run_timestamp_utc: expected second-precision UTC")
        if not isinstance(preflight.get("python_version"), str) or not str(
            preflight.get("python_version")
        ).startswith("3.13."):
            errors.append("summary.preflight.python_version: expected Python 3.13 patch version")
        if preflight.get("manifest_algorithm") != "SHA256":
            errors.append("summary.preflight.manifest_algorithm: expected SHA256")
        digest = preflight.get("manifest_digest")
        if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            errors.append("summary.preflight.manifest_digest: expected lowercase SHA256 digest")
        manifest_files = preflight.get("manifest_files")
        if not isinstance(manifest_files, list) or not manifest_files or not all(
            isinstance(path, str)
            and path
            and not Path(path).is_absolute()
            and ".." not in Path(path).parts
            for path in manifest_files
        ):
            errors.append("summary.preflight.manifest_files: expected safe relative paths")
        source = preflight.get("source")
        if not isinstance(source, Mapping):
            errors.append("summary.preflight.source: expected object")
        elif source.get("kind") == "unversioned_snapshot":
            _field_error(errors, "summary.preflight.source", source, {"kind"})
        elif source.get("kind") == "git":
            _field_error(
                errors,
                "summary.preflight.source",
                source,
                {"kind", "revision", "dirty"},
            )
            if not isinstance(source.get("revision"), str) or re.fullmatch(
                r"[0-9a-f]{40}", str(source.get("revision"))
            ) is None:
                errors.append("summary.preflight.source.revision: expected Git object id")
            if not isinstance(source.get("dirty"), bool):
                errors.append("summary.preflight.source.dirty: expected boolean")
        else:
            errors.append("summary.preflight.source.kind: expected git or unversioned_snapshot")

    execution = summary.get("execution")
    if not isinstance(execution, Mapping):
        errors.append("summary.execution: expected object")
    else:
        _field_error(errors, "summary.execution", execution, EXECUTION_FIELDS)
        required_execution = {
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
        }
        for field, expected in required_execution.items():
            if execution.get(field) != expected:
                errors.append(f"summary.execution.{field}: expected {expected!r}")

    baseline = summary.get("baseline")
    if not isinstance(baseline, Mapping):
        errors.append("summary.baseline: expected object")
    else:
        _field_error(errors, "summary.baseline", baseline, BASELINE_FIELDS)
        if baseline.get("amount") != "0.001000":
            errors.append("summary.baseline.amount: expected 0.001000")
        if baseline.get("currency") != "USDC":
            errors.append("summary.baseline.currency: expected USDC")
        if baseline.get("task_context_trust") != "request-supplied-untrusted":
            errors.append(
                "summary.baseline.task_context_trust: expected request-supplied-untrusted"
            )

    review = summary.get("independent_review")
    if not isinstance(review, Mapping):
        errors.append("summary.independent_review: expected object")
    else:
        _field_error(errors, "summary.independent_review", review, INDEPENDENT_REVIEW_FIELDS)
        if review.get("status") not in {"PENDING", "COMPLETED"}:
            errors.append("summary.independent_review.status: invalid review status")
        if review.get("verdict") not in {"PASS", "FAIL", "INSUFFICIENT_EVIDENCE"}:
            errors.append("summary.independent_review.verdict: invalid review verdict")
        if review.get("status") == "PENDING" and review.get("verdict") != "INSUFFICIENT_EVIDENCE":
            errors.append(
                "summary.independent_review: pending review must remain INSUFFICIENT_EVIDENCE"
            )


def validate_bundle(bundle_path: Path) -> list[str]:
    """Return deterministic validation errors; an empty list means PASS."""

    bundle_path = Path(bundle_path)
    errors: list[str] = []
    if not bundle_path.is_dir():
        return [f"bundle: not a directory: {bundle_path}"]

    artifact_text: dict[str, str] = {}
    for name in REQUIRED_ARTIFACTS:
        path = bundle_path / name
        if not path.is_file():
            errors.append(f"bundle: missing required artifact: {name}")
            continue
        try:
            artifact_text[name] = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            errors.append(f"{name}: cannot read as UTF-8 text: {exc}")
    if errors:
        return errors
    for name, text in artifact_text.items():
        if not text.strip():
            errors.append(f"{name}: artifact must not be empty")
        _scan_artifact_text(name, text, errors)

    try:
        summary = _load_json(artifact_text["summary.json"], source="summary.json")
    except ValueError as exc:
        errors.append(str(exc))
        return errors
    if not isinstance(summary, Mapping):
        errors.append("summary.json: top level must be an object")
        return errors
    if artifact_text["summary.json"] != _canonical_summary(summary):
        errors.append("summary.json: must be canonical indented sorted JSON with one trailing newline")
    _field_error(errors, "summary", summary, TOP_LEVEL_FIELDS)
    if summary.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"summary.schema_version: expected {SCHEMA_VERSION}")
    run_id = summary.get("run_id")
    if not isinstance(run_id, str) or RUN_ID_PATTERN.fullmatch(run_id) is None:
        errors.append("summary.run_id: expected UTC run id YYYYMMDDTHHMMSSZ")
    _validate_metadata(summary, errors)
    limitations = summary.get("limitations")
    if not isinstance(limitations, list) or not limitations or not all(
        isinstance(item, str) and item for item in limitations
    ):
        errors.append("summary.limitations: expected non-empty string array")

    scenarios, scenarios_by_id = _validate_scenarios(summary, errors)
    fixtures, fixtures_by_id = _validate_fixtures(summary, errors)
    _validate_counts(summary, scenarios, fixtures, errors)
    _validate_decimal_values(summary, errors, "summary")

    events, _ = _load_events(bundle_path / "events.jsonl", errors)
    _validate_events(events, summary, scenarios_by_id, fixtures_by_id, errors)
    _validate_decimal_values(events, errors, "events")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path, help="completed evidence bundle directory")
    args = parser.parse_args(argv)
    errors = validate_bundle(args.bundle)
    if errors:
        print("EDGE_CASE_EVIDENCE_INVALID")
        for error in errors:
            print(f"- {error}")
        return 1
    print("EDGE_CASE_EVIDENCE_VALID")
    print(f"bundle={args.bundle}")
    print(f"schema={SCHEMA_VERSION}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
