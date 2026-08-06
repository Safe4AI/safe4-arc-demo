from __future__ import annotations

import ast
from copy import deepcopy
import json
from pathlib import Path
from typing import Any

import pytest

from scripts import validate_edge_case_evidence as validator


RUN_ID = "20260805T010203Z"


def _step(label: str, *, outcome: str = "ALLOW", status: int = 200) -> dict[str, Any]:
    authorized = outcome == "ALLOW"
    return {
        "label": label,
        "http_status": status,
        "outcome": outcome,
        "response_status": "AUTHORIZED" if authorized else None,
        "top_level_code": None,
        "nested_reason_code": "TASK_PURCHASE_MATCH" if authorized else None,
        "intent": None,
        "policy_details": {},
        "correlation": {
            "request": "request-1",
            "local_transaction": "local-transaction-1" if authorized else None,
            "approval_fixture": None,
        },
        "retry_after_present": False,
        "retry_after_seconds": None,
    }


def _snapshot() -> dict[str, Any]:
    return {
        "user_configured": True,
        "user_spend": "0.000000",
        "agent_spend": "0.000000",
        "payment_log_count": 0,
        "payment_log_results": [],
        "audit_entry_count": 0,
        "audit_reason_codes": [],
    }


def _scenario(scenario_id: str) -> dict[str, Any]:
    count = 6 if scenario_id == "T17" else validator.MINIMUM_STEP_COUNTS.get(scenario_id, 1)
    steps = [_step(f"step_{index + 1}") for index in range(count)]
    if scenario_id == "T17":
        steps = [
            _step(f"invalid_envelope_{index + 1}", outcome="VALIDATION_REJECT", status=422)
            for index in range(6)
        ]
    is_canary = scenario_id in validator.REQUIRED_CANARY_IDS
    assertions = {"predeclared_expectation_met": not is_canary}
    state_before = _snapshot()
    state_after = _snapshot()
    expected_steps = [
        {
            "label": step["label"],
            "http_status": step["http_status"],
            "outcome": step["outcome"],
        }
        for step in steps
    ]
    return {
        "id": scenario_id,
        "evidence_class": (
            "red_team_canary" if is_canary else "local_application_authorization"
        ),
        "input_delta": {"amount": "0.001000"},
        "expected": {
            "ordered_steps": expected_steps,
            "primary_label": steps[-1]["label"],
            "user_spend_delta": "0.000000",
            "agent_spend_delta": "0.000000",
            "settlement_executor": "NOT_OBSERVED",
        },
        "actual": {
            "ordered_steps": steps,
            "primary": steps[-1],
            "state": {
                "before": state_before,
                "after": state_after,
                "user_spend_delta": "0.000000",
                "agent_spend_delta": "0.000000",
                "payment_log_delta": 0,
                "audit_entry_delta": 0,
            },
            "settlement_executor": {
                "status": "NOT_OBSERVED",
                "reason": "The local authorization path exposes no executor.",
            },
            "observations": {},
        },
        "assertions": assertions,
        "verdict": "FAIL" if is_canary else "PASS",
        "known_gap": is_canary,
    }


def _fixture(fixture_id: str) -> dict[str, Any]:
    category = f"fixture_{fixture_id.lower()}"
    return {
        "id": fixture_id,
        "evidence_class": "local_settlement_fixture",
        "input_delta": {"fixture_case": category},
        "expected": {
            "outcome": "REJECT",
            "error_class": "ArcSettlementError",
            "reason_category": category,
        },
        "actual": {
            "outcome": "REJECT",
            "error_class": "ArcSettlementError",
            "reason_category_matched": True,
            "rpc_invoked": False,
        },
        "verdict": "PASS",
        "known_gap": False,
    }


def _summary() -> dict[str, Any]:
    scenarios = [_scenario(scenario_id) for scenario_id in validator.REQUIRED_SCENARIO_IDS]
    fixtures = [_fixture(fixture_id) for fixture_id in validator.REQUIRED_SETTLEMENT_IDS]
    outcomes = {
        outcome: sum(item["actual"]["primary"]["outcome"] == outcome for item in scenarios)
        for outcome in (
            "ALLOW",
            "DENY",
            "CHALLENGE",
            "PENDING_APPROVAL",
            "RATE_LIMIT",
            "CONFLICT",
            "VALIDATION_REJECT",
        )
    }
    passed = sum(item["verdict"] == "PASS" for item in scenarios)
    failed = len(scenarios) - passed
    counts = {
        "scenario_count": len(scenarios),
        "passed": passed,
        "failed": failed,
        "required_scenarios_passed": len(validator.REQUIRED_TRANSACTION_IDS),
        "required_scenarios_failed": 0,
        "known_gap_canaries": len(validator.REQUIRED_CANARY_IDS),
        "coverage_verdicts": {"PASS": passed, "FAIL": failed},
        "allowed": outcomes["ALLOW"],
        "denied": outcomes["DENY"],
        "challenged": outcomes["CHALLENGE"],
        "pending_approval": outcomes["PENDING_APPROVAL"],
        "rate_limited": outcomes["RATE_LIMIT"],
        "conflict": outcomes["CONFLICT"],
        "validation_rejected": outcomes["VALIDATION_REJECT"],
        "primary_outcomes": outcomes,
        "challenge_step_count": sum(
            step["outcome"] == "CHALLENGE"
            for item in scenarios
            for step in item["actual"]["ordered_steps"]
        ),
        "authorization_only_cases": len(scenarios),
        "settlement_fixtures_passed": len(fixtures),
        "settlement_fixtures_failed": 0,
        "overall_verdict": "REQUIRED_PASS_WITH_KNOWN_GAPS",
    }
    return {
        "schema_version": validator.SCHEMA_VERSION,
        "run_id": RUN_ID,
        "preflight": {
            "run_timestamp_utc": "2026-08-05T01:02:03Z",
            "python_version": "3.13.5",
            "source": {"kind": "unversioned_snapshot"},
            "manifest_algorithm": "SHA256",
            "manifest_digest": "0" * 64,
            "manifest_files": ["app/main.py", "scripts/run_edge_case_evidence.py"],
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
            "agent": "agent_alpha",
            "user": "user_123",
            "vendor": "synthetic_company_research",
            "amount": "0.001000",
            "currency": "USDC",
            "task_context_trust": "request-supplied-untrusted",
        },
        "scenarios": scenarios,
        "settlement_fixtures": fixtures,
        "summary": counts,
        "independent_review": {
            "status": "PENDING",
            "verdict": "INSUFFICIENT_EVIDENCE",
        },
        "limitations": ["Local authorization evidence is not chain settlement evidence."],
    }


def _events(summary: dict[str, Any]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for scenario in summary["scenarios"]:
        for step_index, step in enumerate(scenario["actual"]["ordered_steps"]):
            events.append(
                {
                    "schema_version": summary["schema_version"],
                    "run_id": summary["run_id"],
                    "event_index": len(events),
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
    for fixture in summary["settlement_fixtures"]:
        events.append(
            {
                "schema_version": summary["schema_version"],
                "run_id": summary["run_id"],
                "event_index": len(events),
                "type": "settlement_fixture",
                "scenario_id": fixture["id"],
                "evidence_class": fixture["evidence_class"],
                "expected": fixture["expected"],
                "actual": fixture["actual"],
                "scenario_verdict": fixture["verdict"],
                "known_gap": fixture["known_gap"],
            }
        )
    return events


def _write_bundle(path: Path, summary: dict[str, Any] | None = None) -> dict[str, Any]:
    summary = deepcopy(summary or _summary())
    path.mkdir()
    (path / "summary.json").write_text(
        validator._canonical_summary(summary), encoding="utf-8"
    )
    (path / "events.jsonl").write_text(
        "".join(validator._canonical_event(event) + "\n" for event in _events(summary)),
        encoding="utf-8",
    )
    safe_text = {
        "summary.md": "# Sanitized evidence summary\n",
        "pytest.txt": "focused_tests=PASS\n",
        "redaction-manifest.md": "# Removed categories\n\n- credential values\n",
        "README.md": "# Local evidence reproduction\n\nNo external execution.\n",
    }
    for name, text in safe_text.items():
        (path / name).write_text(text, encoding="utf-8")
    return summary


def _rewrite_summary(path: Path, summary: dict[str, Any]) -> None:
    (path / "summary.json").write_text(
        validator._canonical_summary(summary), encoding="utf-8"
    )


def test_accepts_complete_canonical_offline_bundle(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    _write_bundle(bundle)

    assert validator.validate_bundle(bundle) == []


def test_rejects_missing_artifact(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    _write_bundle(bundle)
    (bundle / "pytest.txt").unlink()

    assert "bundle: missing required artifact: pytest.txt" in validator.validate_bundle(bundle)


def test_rejects_fixed_id_order_and_missing_settlement_event(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    summary = _write_bundle(bundle)
    summary["scenarios"][0], summary["scenarios"][1] = (
        summary["scenarios"][1],
        summary["scenarios"][0],
    )
    _rewrite_summary(bundle, summary)
    lines = (bundle / "events.jsonl").read_text(encoding="utf-8").splitlines()
    (bundle / "events.jsonl").write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")

    errors = validator.validate_bundle(bundle)
    assert any("IDs must appear exactly once in canonical order" in error for error in errors)
    assert any("followed by S01-S08" in error for error in errors)


def test_rejects_noncontiguous_event_and_extra_event_field(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    summary = _write_bundle(bundle)
    events = _events(summary)
    events[1]["event_index"] = 9
    events[1]["raw_response"] = "not allowed"
    (bundle / "events.jsonl").write_text(
        "".join(validator._canonical_event(event) + "\n" for event in events),
        encoding="utf-8",
    )

    errors = validator.validate_bundle(bundle)
    assert any("expected contiguous index 1" in error for error in errors)
    assert any("unexpected fields: raw_response" in error for error in errors)


def test_rejects_count_mismatch_and_canary_relabel(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    summary = _write_bundle(bundle)
    summary["summary"]["allowed"] += 1
    summary["scenarios"][-1]["known_gap"] = False
    summary["scenarios"][-1]["verdict"] = "PASS"
    summary["scenarios"][-1]["assertions"] = {"predeclared_expectation_met": True}
    _rewrite_summary(bundle, summary)

    errors = validator.validate_bundle(bundle)
    assert any("allowed: expected reconciled count" in error for error in errors)
    assert any("canary must be retained as a failing known gap" in error for error in errors)


def test_rejects_extra_scenario_field_and_numeric_money(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    summary = _write_bundle(bundle)
    summary["scenarios"][0]["raw_headers"] = {}
    summary["scenarios"][0]["input_delta"]["amount"] = 0.001
    _rewrite_summary(bundle, summary)

    errors = validator.validate_bundle(bundle)
    assert any("unexpected fields: raw_headers" in error for error in errors)
    assert any("monetary value must be a canonical six-decimal string" in error for error in errors)


@pytest.mark.parametrize(
    ("leak", "message"),
    [
        ("C:" + "\\Users\\" + "Judge\\private.txt", "absolute Windows path"),
        ("10.20.30.40", "raw IP address"),
        ("postgresql://service:password@database/prod", "database DSN"),
        ("Authorization: Bearer abcdefghijklmnopqrstuvwxyz1234", "persisted token material"),
    ],
)
def test_rejects_sensitive_or_identifying_text(
    tmp_path: Path,
    leak: str,
    message: str,
) -> None:
    bundle = tmp_path / "bundle"
    _write_bundle(bundle)
    (bundle / "README.md").write_text(f"# Evidence\n\n{leak}\n", encoding="utf-8")

    assert any(message in error for error in validator.validate_bundle(bundle))


def test_rejects_noncanonical_json_and_duplicate_keys(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    _write_bundle(bundle)
    (bundle / "summary.json").write_text(
        '{"schema_version":"one","schema_version":"two"}\n',
        encoding="utf-8",
    )

    assert any("duplicate JSON key" in error for error in validator.validate_bundle(bundle))


def test_validator_source_has_no_network_database_or_application_import() -> None:
    source_path = Path(validator.__file__)
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    imported_roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_roots.add(node.module.split(".", 1)[0])

    assert imported_roots.isdisjoint(
        {"app", "httpx", "requests", "socket", "sqlite3", "sqlalchemy", "urllib"}
    )
