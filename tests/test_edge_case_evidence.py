from __future__ import annotations

import json
import os
from copy import deepcopy
from pathlib import Path
import re
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts" / "run_edge_case_evidence.py"
EXPECTED_BUNDLE_FILES = {
    "README.md",
    "events.jsonl",
    "pytest.txt",
    "redaction-manifest.md",
    "summary.json",
    "summary.md",
}
EXPECTED_T_IDS = (
    "T01", "T02", "T03", "T04A", "T04B", "T05", "T06", "T07",
    "T08", "T09", "T10", "T11", "T12", "T13", "T14", "T15",
    "T16", "T17", "T18", "T19", "T20", "T21",
)
EXPECTED_C_IDS = ("C01", "C02", "C03")
EXPECTED_S_IDS = tuple(f"S{index:02d}" for index in range(1, 9))


def _run_matrix(
    base: Path,
    name: str,
    run_id: str,
) -> tuple[subprocess.CompletedProcess[str], dict[str, object], Path]:
    bundle = base / "artifacts" / "transaction-edge-cases" / name
    environment = os.environ.copy()
    environment.update(
        {
            "PAYMENT_FIREWALL_POSTGRES_DSN": "postgresql://inherited.invalid/unsafe",
            "PAYMENT_FIREWALL_ENV": "production",
            "PAYMENT_FIREWALL_RATE_LIMIT_REQUESTS": "1",
            "PAYMENT_FIREWALL_WEBHOOK_DISPATCH_ENABLED": "true",
            "PAYMENT_FIREWALL_PHASE3_X402_ADVANCED_ENABLED": "true",
            "PAYMENT_FIREWALL_RECEIPT_SECRET": "inherited-secret-must-not-survive",
            "SAFE4_PROVIDER_RANGE_RISK_API_KEY": "inherited-provider-secret",
            "SAFE4_DEMO_MODE": "circle-live",
        }
    )
    completed = subprocess.run(
        [
            sys.executable,
            str(RUNNER),
            "--run-id",
            run_id,
            "--bundle-dir",
            str(bundle),
        ],
        cwd=ROOT,
        env=environment,
        text=True,
        capture_output=True,
        timeout=180,
        check=False,
    )
    payload = json.loads(completed.stdout) if completed.stdout.strip() else {}
    return completed, payload, bundle


@pytest.fixture(scope="module")
def evidence_runs(tmp_path_factory: pytest.TempPathFactory) -> tuple[dict[str, object], Path, str]:
    first_root = tmp_path_factory.mktemp("edge-evidence-first")
    second_root = tmp_path_factory.mktemp("edge-evidence-second")
    seconds = os.getpid() % 86400
    first_run_id = f"20991231T{seconds // 3600:02d}{(seconds % 3600) // 60:02d}{seconds % 60:02d}Z"
    second_seconds = (seconds + 1) % 86400
    second_run_id = f"20991231T{second_seconds // 3600:02d}{(second_seconds % 3600) // 60:02d}{second_seconds % 60:02d}Z"
    first, payload, bundle = _run_matrix(first_root, "bundle", first_run_id)
    assert first.returncode == 0, first.stderr
    second, repeated, _second_bundle = _run_matrix(second_root, "bundle", second_run_id)
    assert second.returncode == 0, second.stderr
    normalized_first = deepcopy(payload)
    normalized_second = deepcopy(repeated)
    for item in (normalized_first, normalized_second):
        item["run_id"] = "RUN_ID"
        item["preflight"]["run_timestamp_utc"] = "RUN_TIMESTAMP"
    assert normalized_second == normalized_first
    return payload, bundle, first.stdout


def test_edge_case_runner_covers_the_predeclared_contract(
    evidence_runs: tuple[dict[str, object], Path, str],
) -> None:
    payload, _bundle, _stdout = evidence_runs
    assert payload["schema_version"] == "safe4-transaction-evidence/1.0"
    scenarios = payload["scenarios"]
    t_rows = [row for row in scenarios if row["id"].startswith("T")]
    c_rows = [row for row in scenarios if row["id"].startswith("C")]
    assert tuple(row["id"] for row in t_rows) == EXPECTED_T_IDS
    assert tuple(row["id"] for row in c_rows) == EXPECTED_C_IDS
    assert all(row["verdict"] == "PASS" for row in t_rows)
    assert all(row["verdict"] == "FAIL" and row["known_gap"] for row in c_rows)

    fixtures = payload["settlement_fixtures"]
    assert tuple(row["id"] for row in fixtures) == EXPECTED_S_IDS
    assert all(row["verdict"] == "PASS" for row in fixtures)
    assert all(row["evidence_class"] == "local_settlement_fixture" for row in fixtures)


def test_edge_case_runner_preserves_ordered_steps_and_primary_outcomes(
    evidence_runs: tuple[dict[str, object], Path, str],
) -> None:
    payload, _bundle, _stdout = evidence_runs
    by_id = {row["id"]: row for row in payload["scenarios"]}
    assert [step["label"] for step in by_id["T08"]["actual"]["ordered_steps"]] == [
        "first_receipt_challenge",
        "first_authorization",
        "second_receipt_challenge",
        "second_authorization",
    ]
    assert by_id["T08"]["actual"]["primary"]["top_level_code"] == "VELOCITY_LIMIT_EXCEEDED"
    assert by_id["T08"]["assertions"]["second_user_spend_unchanged"] is True
    assert by_id["T08"]["assertions"]["second_agent_spend_unchanged"] is True
    assert by_id["T09"]["assertions"]["identical_response_bodies"] is True
    assert by_id["T09"]["assertions"]["replay_user_spend_unchanged"] is True
    assert by_id["T10"]["actual"]["primary"]["outcome"] == "CONFLICT"
    assert by_id["T10"]["assertions"]["conflict_user_spend_unchanged"] is True
    assert by_id["T11"]["assertions"]["reuse_user_spend_unchanged"] is True
    assert by_id["T17"]["actual"]["ordered_steps"][0]["top_level_code"] is None
    assert by_id["T17"]["actual"]["ordered_steps"][-1]["top_level_code"] == "REQUEST_TOO_LARGE"
    assert by_id["T20"]["actual"]["primary"]["outcome"] == "PENDING_APPROVAL"
    assert by_id["T20"]["assertions"]["pending_spend_unchanged"] is True
    assert by_id["T20"]["actual"]["observations"]["pending_state"]["user_spend"] == "0.000000"
    assert by_id["T20"]["actual"]["state"]["after"]["user_spend"] == "9.990000"
    assert by_id["T15"]["actual"]["primary"]["retry_after_seconds"] > 0
    assert by_id["T16"]["assertions"]["request_agent_budget_unchanged"] is True
    assert by_id["T16"]["assertions"]["no_payment_log"] is True
    assert by_id["T16"]["assertions"]["no_audit_entry"] is True
    assert by_id["T18"]["actual"]["observations"]["receipt_consumed"] is False
    assert by_id["T18"]["actual"]["state"]["payment_log_delta"] == 0
    assert all(
        row["actual"]["settlement_executor"]["status"] == "NOT_OBSERVED"
        for row in payload["scenarios"]
    )


def test_edge_case_bundle_is_complete_canonical_and_allowlisted(
    evidence_runs: tuple[dict[str, object], Path, str],
) -> None:
    payload, bundle, stdout = evidence_runs
    assert {path.name for path in bundle.iterdir()} == EXPECTED_BUNDLE_FILES
    assert json.loads((bundle / "summary.json").read_text(encoding="utf-8")) == payload
    events = [json.loads(line) for line in (bundle / "events.jsonl").read_text(encoding="utf-8").splitlines()]
    assert [event["event_index"] for event in events] == list(range(len(events)))
    assert all(event["schema_version"] == payload["schema_version"] for event in events)
    assert all(event["run_id"] == payload["run_id"] for event in events)
    assert [event["scenario_id"] for event in events[-8:]] == list(EXPECTED_S_IDS)
    assert all(event["type"] == "settlement_fixture" for event in events[-8:])

    persisted = "\n".join(
        path.read_text(encoding="utf-8") for path in sorted(bundle.iterdir())
    )
    forbidden = (
        "Bearer ",
        "X-Payment-Receipt",
        "X-Admin-Secret",
        "X-Spend-Token",
        "access_token",
        "receipt_token",
        "spend_token",
    )
    assert not any(marker.lower() in persisted.lower() for marker in forbidden)
    assert not re.search(r"[A-Za-z]:\\", persisted)
    assert not re.search(r"/(?:home|users|tmp)/", persisted.lower())
    assert "PAYMENT_FIREWALL_POSTGRES_DSN" not in persisted
    assert stdout.strip() == json.dumps(payload, sort_keys=True, separators=(",", ":"))
    assert not (ROOT / ".tmp" / f"edge-case-evidence-{payload['run_id']}").exists()


def test_summary_separates_scenario_verdicts_from_primary_outcomes(
    evidence_runs: tuple[dict[str, object], Path, str],
) -> None:
    payload, _bundle, _stdout = evidence_runs
    summary = payload["summary"]
    assert summary["required_scenarios_passed"] == len(EXPECTED_T_IDS)
    assert summary["required_scenarios_failed"] == 0
    assert summary["failed"] == len(EXPECTED_C_IDS)
    assert summary["known_gap_canaries"] == len(EXPECTED_C_IDS)
    assert sum(summary["primary_outcomes"].values()) == summary["scenario_count"]
    assert summary["settlement_fixtures_passed"] == len(EXPECTED_S_IDS)
    assert summary["settlement_fixtures_failed"] == 0
    assert payload["independent_review"] == {
        "status": "PENDING",
        "verdict": "INSUFFICIENT_EVIDENCE",
    }
    assert payload["preflight"]["source"]["kind"] in {"unversioned_snapshot", "git"}
    assert re.fullmatch(r"[0-9a-f]{64}", payload["preflight"]["manifest_digest"])


def test_sanitizer_rejects_secret_shaped_values_under_innocuous_keys() -> None:
    from scripts import run_edge_case_evidence as runner

    with pytest.raises(RuntimeError, match="three-part credential"):
        runner._assert_sanitized(
            {
                "innocuous": (
                    "eyJhbGciOiJIUzI1NiJ9."
                    "eyJzdWIiOiJzeW50aGV0aWMifQ."
                    "QWxwaGFOdW1lcmljU2lnbmF0dXJlMTIzNDU2"
                )
            }
        )


def test_required_failure_forces_overall_failure(
    evidence_runs: tuple[dict[str, object], Path, str],
) -> None:
    from scripts import run_edge_case_evidence as runner

    payload, _bundle, _stdout = evidence_runs
    scenarios = deepcopy(payload["scenarios"])
    scenarios[0]["verdict"] = "FAIL"
    summary = runner._build_summary(scenarios, deepcopy(payload["settlement_fixtures"]))
    assert summary["required_scenarios_failed"] == 1
    assert summary["overall_verdict"] == "FAIL_REQUIRED_EVIDENCE"
