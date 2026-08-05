from __future__ import annotations

from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
from typing import Any, Iterator, Mapping
from unittest.mock import patch
from uuid import UUID

import pytest

from scripts.demo_live_arc_batch import (
    ARC_CHAIN,
    ARC_CHAIN_ID,
    AuthorizationResult,
    SubmissionResult,
    VerificationResult,
)
from scripts import demo_live_arc_batch_fixed as fixed


SOURCE_REVISION = "a" * 40


class CountingKeyFactory:
    def __init__(self) -> None:
        self.calls = 0

    def __call__(self) -> UUID:
        self.calls += 1
        return UUID(int=self.calls, version=4)


def clean_source() -> fixed.SourceIdentity:
    return fixed.SourceIdentity(
        revision=SOURCE_REVISION,
        worktree_state="CLEAN",
    )


def fixed_clock() -> Any:
    observations = iter(
        (
            datetime(2026, 8, 5, 12, 0, 0, tzinfo=timezone.utc),
            datetime(2026, 8, 5, 12, 0, 9, tzinfo=timezone.utc),
        )
    )
    return lambda: next(observations)


def wallet_preflight() -> dict[str, Any]:
    return {
        "status": "VERIFIED",
        "source": "AUTHENTICATED_CIRCLE_CLI_WALLET_LIST",
        "address": fixed.FIXED_SENDER,
        "blockchain": ARC_CHAIN,
        "raw_command_output_retained": False,
    }


def balance_observation(
    stage: str,
    *,
    sender_balance: int = fixed.MIN_PREFLIGHT_SENDER_BALANCE_BASE_UNITS * 10,
    chain_id: int = ARC_CHAIN_ID,
) -> dict[str, Any]:
    return {
        "status": "OBSERVED",
        "stage": stage,
        "chain_id": chain_id,
        "block_number": 55_500_001 if stage == "PRE" else 55_500_004,
        "block_tag": hex(55_500_001 if stage == "PRE" else 55_500_004),
        "unit": "ARC_NATIVE_USDC_18_DECIMAL_BASE_UNITS",
        "sender_balance_base_units": str(sender_balance),
        "recipient_balance_base_units": "1000000000000000000",
    }


def _phases(state_directory: Path, item_id: str) -> list[str]:
    journal = json.loads(
        (state_directory / fixed.JOURNAL_FILENAME).read_text(encoding="utf-8")
    )
    item = next(
        item
        for item in journal["execution_progress"]["items"]
        if item["item_id"] == item_id
    )
    return [transition["phase"] for transition in item["transitions"]]


def runtime_factory(
    state_directory: Path,
    events: list[str],
    *,
    pre_observation: Mapping[str, Any] | None = None,
    verification_status: str = "VERIFIED",
    runtime_secrets: dict[str, str] | None = None,
    circle_cli_version: str = fixed.SUPPORTED_CIRCLE_CLI_VERSION,
) -> fixed.RuntimeFactory:
    class Authorizer:
        def authorize(self, item: Any) -> AuthorizationResult:
            events.append(f"authorize:{item.sequence}")
            assert _phases(state_directory, item.item_id)[-1] == "AUTHORIZATION_STARTED"
            return AuthorizationResult(
                status="AUTHORIZED",
                binding_hash=item.binding_hash,
                reason_code="TASK_PURCHASE_MATCH",
                safe4_transaction_id=f"{item.sequence:032x}",
            )

    class Submitter:
        def submit(self, item: Any) -> SubmissionResult:
            events.append(f"submit:{item.sequence}")
            phases = _phases(state_directory, item.item_id)
            assert phases[-2:] == ["AUTHORIZATION_RESULT", "SUBMISSION_STARTED"]
            return SubmissionResult(
                status="SUBMITTED",
                binding_hash=item.binding_hash,
                transaction_hash=f"0x{item.sequence:064x}",
            )

    class Verifier:
        def verify(self, item: Any, transaction_hash: str) -> VerificationResult:
            events.append(f"verify:{item.sequence}")
            phases = _phases(state_directory, item.item_id)
            assert phases[-2:] == ["SUBMISSION_RESULT", "VERIFICATION_STARTED"]
            return VerificationResult(
                status=verification_status,
                binding_hash=item.binding_hash,
                transaction_hash=transaction_hash,
                block_number=55_500_000 + item.sequence,
                observed_chain=ARC_CHAIN if verification_status == "VERIFIED" else None,
                observed_sender=item.sender if verification_status == "VERIFIED" else None,
                observed_recipient=(
                    item.recipient if verification_status == "VERIFIED" else None
                ),
                observed_amount_units=(
                    item.amount_units if verification_status == "VERIFIED" else None
                ),
                error_code=(
                    None
                    if verification_status == "VERIFIED"
                    else "RPC_PROPAGATION_EXHAUSTED"
                ),
            )

    def observe(stage: str) -> Mapping[str, Any]:
        events.append(f"balance:{stage}")
        if stage == "PRE" and pre_observation is not None:
            return pre_observation
        return balance_observation(stage)

    @contextmanager
    def factory(plan: Any, database_path: Path) -> Iterator[fixed.RuntimeBundle]:
        events.append("runtime-created")
        journal_path = state_directory / fixed.JOURNAL_FILENAME
        journal = json.loads(journal_path.read_text(encoding="utf-8"))
        assert journal["status"] == "EXECUTION_STARTED_NO_AUTOMATIC_RETRY"
        assert journal["exact_private_plan"]["plan_hash"] == plan.plan_hash
        assert (state_directory / fixed.LOCK_FILENAME).is_file()
        assert os.getenv("PAYMENT_FIREWALL_POSTGRES_DSN") is None
        assert Path(os.environ["PAYMENT_FIREWALL_DB_PATH"]).resolve() == database_path
        assert os.environ["PAYMENT_FIREWALL_PAY_TO"] == fixed.FIXED_RECIPIENT
        assert os.environ["PAYMENT_FIREWALL_WEBHOOK_DISPATCH_ENABLED"] == "false"
        assert os.environ["PAYMENT_FIREWALL_PHASE3_X402_ADVANCED_ENABLED"] == "false"
        assert os.environ["PAYMENT_FIREWALL_PHASE3_AP2_ENABLED"] == "false"
        assert (
            os.environ["PAYMENT_FIREWALL_PHASE3_INFRASTRUCTURE_IDENTITY_ENABLED"]
            == "false"
        )
        assert os.environ["SAFE4_PROVIDER_RANGE_RISK_API_KEY"] == ""
        if runtime_secrets is not None:
            runtime_secrets["receipt"] = os.environ[
                "PAYMENT_FIREWALL_RECEIPT_SECRET"
            ]
            runtime_secrets["admin"] = os.environ[
                "PAYMENT_FIREWALL_ADMIN_SECRET"
            ]
        yield fixed.RuntimeBundle(
            authorizer=Authorizer(),
            submitter=Submitter(),
            verifier=Verifier(),
            circle_cli_version=circle_cli_version,
            circle_wallet_preflight=wallet_preflight(),
            observe_public_balances=observe,
        )

    return factory


def execute_offline(
    private_root: Path,
    state_directory: Path,
    factory: fixed.RuntimeFactory,
    *,
    keys: CountingKeyFactory | None = None,
) -> fixed.FixedRunEvidence:
    with patch.dict(
        os.environ,
        {
            "PAYMENT_FIREWALL_POSTGRES_DSN": "must-be-removed",
            "PAYMENT_FIREWALL_PAY_TO": "0x9999999999999999999999999999999999999999",
            "SAFE4_PROVIDER_UNTRUSTED_API_KEY": "must-be-removed",
            "SAFE4_DEMO_MODE": "circle-live-untrusted",
        },
        clear=False,
    ):
        os.environ.pop("CIRCLE_PROXY_URL", None)
        return fixed.execute_fixed_live_batch(
            confirmation=fixed.LIVE_CONFIRMATION_MARKER,
            state_directory=state_directory,
            private_root=private_root,
            key_factory=keys or CountingKeyFactory(),
            runtime_factory=factory,
            source_identity_factory=clean_source,
            clock=fixed_clock(),
        )


def test_default_preview_is_fixed_and_has_no_side_effects(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert fixed.main([]) == 0
    preview = json.loads(capsys.readouterr().out)
    assert preview["mode"] == "PREVIEW_ONLY_NO_AUTHORIZATION_NO_CLI_NO_NETWORK"
    assert preview["sender"] == fixed.FIXED_SENDER
    assert preview["recipient"] == fixed.FIXED_RECIPIENT
    assert [item["amount_units"] for item in preview["items"]] == [1000, 2000, 3000]
    assert preview["total_amount_units"] == 6000
    assert preview["preflight_arc_rpc"] == {
        "required_chain_id": ARC_CHAIN_ID,
        "required_sender_balance_base_units": str(
            fixed.MIN_PREFLIGHT_SENDER_BALANCE_BASE_UNITS
        ),
        "required_before_first_pay": True,
    }
    assert (
        preview["recipient_policy"]["safe4_payment_policy"]
        == "NOT_A_GENERAL_SAFE4_RECIPIENT_ALLOWLIST_ENFORCEMENT_CLAIM"
    )


def test_direct_script_preview_invocation_is_supported_and_side_effect_free() -> None:
    repository_root = Path(__file__).resolve().parents[1]
    state_directory = repository_root / ".tmp" / "live-arc-fixed-batch-v1"
    existed_before = state_directory.exists()
    completed = subprocess.run(
        [
            sys.executable,
            str(repository_root / "scripts" / "demo_live_arc_batch_fixed.py"),
            "--preview",
        ],
        cwd=repository_root,
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert completed.returncode == 0
    preview = json.loads(completed.stdout)
    assert preview["mode"] == "PREVIEW_ONLY_NO_AUTHORIZATION_NO_CLI_NO_NETWORK"
    assert preview["total_amount_units"] == 6000
    assert not completed.stderr
    assert state_directory.exists() is existed_before


def test_read_only_preflight_has_no_keys_journal_app_pay_or_transfer(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    events: list[str] = []
    state = tmp_path / "private" / "run"
    keys = CountingKeyFactory()
    app_was_imported = "app.main" in sys.modules

    def source() -> fixed.SourceIdentity:
        events.append("source")
        return clean_source()

    def locate(name: str) -> str:
        events.append(f"locate:{name}")
        return "circle-test"

    def version(executable: str) -> str:
        events.append(f"version:{executable}")
        return "0.0.6"

    def wallet(executable: str) -> Mapping[str, Any]:
        events.append(f"wallet:{executable}")
        return wallet_preflight()

    def balances(stage: str) -> Mapping[str, Any]:
        events.append(f"rpc:{stage}")
        return balance_observation(stage)

    with patch.dict(os.environ, {}, clear=True):
        observed = fixed.run_read_only_preflight(
            source_identity_factory=source,
            circle_locator=locate,
            circle_version_observer=version,
            wallet_observer=wallet,
            balance_observer=balances,
            clock=lambda: datetime(
                2026,
                8,
                5,
                11,
                59,
                0,
                tzinfo=timezone.utc,
            ),
        )
    assert events == [
        "source",
        "locate:circle",
        "version:circle-test",
        "wallet:circle-test",
        "rpc:PRE",
    ]
    assert observed["mode"] == "READ_ONLY_NO_KEYS_NO_JOURNAL_NO_APP_NO_PAY_NO_TRANSFER"
    assert observed["go"] is True
    assert observed["fixed_plan"]["amount_units"] == [1000, 2000, 3000]
    assert observed["arc_rpc"]["observation"]["chain_id"] == ARC_CHAIN_ID
    assert keys.calls == 0
    assert ("app.main" in sys.modules) is app_was_imported
    assert not state.exists()

    with patch.object(fixed, "run_read_only_preflight", return_value=observed):
        assert fixed.main(["--preflight"]) == 0
    cli_output = json.loads(capsys.readouterr().out)
    assert cli_output == observed


def test_wrong_confirmation_stops_before_keys_source_state_or_runtime(tmp_path: Path) -> None:
    keys = CountingKeyFactory()
    source_calls = 0
    runtime_calls = 0

    def source() -> fixed.SourceIdentity:
        nonlocal source_calls
        source_calls += 1
        return clean_source()

    @contextmanager
    def never_runtime(plan: Any, database_path: Path) -> Iterator[fixed.RuntimeBundle]:
        nonlocal runtime_calls
        runtime_calls += 1
        raise AssertionError("runtime must not be created")
        yield  # pragma: no cover

    with pytest.raises(fixed.FixedBatchSafetyError, match="LIVE_CONFIRMATION_MISMATCH"):
        fixed.execute_fixed_live_batch(
            confirmation="wrong",
            state_directory=tmp_path / "private" / "run",
            private_root=tmp_path / "private",
            key_factory=keys,
            runtime_factory=never_runtime,
            source_identity_factory=source,
        )
    assert keys.calls == 0
    assert source_calls == 0
    assert runtime_calls == 0
    assert not (tmp_path / "private").exists()


def test_circle_proxy_override_fails_before_source_keys_state_runtime_or_rpc(
    tmp_path: Path,
) -> None:
    keys = CountingKeyFactory()
    calls: list[str] = []

    def source() -> fixed.SourceIdentity:
        calls.append("source")
        return clean_source()

    @contextmanager
    def runtime(plan: Any, database_path: Path) -> Iterator[fixed.RuntimeBundle]:
        calls.append("runtime")
        raise AssertionError("runtime must not be created")
        yield  # pragma: no cover

    state = tmp_path / "private" / "run"
    with patch.dict(
        os.environ,
        {"CIRCLE_PROXY_URL": "https://untrusted.invalid"},
        clear=False,
    ):
        with pytest.raises(
            fixed.FixedBatchSafetyError,
            match="CIRCLE_PROXY_URL_FORBIDDEN",
        ):
            fixed.execute_fixed_live_batch(
                confirmation=fixed.LIVE_CONFIRMATION_MARKER,
                state_directory=state,
                private_root=tmp_path / "private",
                key_factory=keys,
                runtime_factory=runtime,
                source_identity_factory=source,
            )
    assert calls == []
    assert keys.calls == 0
    assert not state.exists()

    with patch.dict(
        os.environ,
        {"CIRCLE_PROXY_URL": "https://untrusted.invalid"},
        clear=False,
    ):
        with pytest.raises(
            fixed.FixedBatchSafetyError,
            match="CIRCLE_PROXY_URL_FORBIDDEN",
        ):
            fixed.run_read_only_preflight(source_identity_factory=source)
    assert calls == []


def test_exact_private_plan_is_journaled_before_ports_and_transitions_are_durable(
    tmp_path: Path,
) -> None:
    private_root = tmp_path / "private"
    state = private_root / "run"
    events: list[str] = []
    keys = CountingKeyFactory()
    runtime_secrets: dict[str, str] = {}
    evidence = execute_offline(
        private_root,
        state,
        runtime_factory(state, events, runtime_secrets=runtime_secrets),
        keys=keys,
    )

    assert keys.calls == 6
    assert events == [
        "runtime-created",
        "balance:PRE",
        "authorize:1",
        "submit:1",
        "verify:1",
        "authorize:2",
        "submit:2",
        "verify:2",
        "authorize:3",
        "submit:3",
        "verify:3",
        "balance:POST",
    ]
    journal_text = (state / fixed.JOURNAL_FILENAME).read_text(encoding="utf-8")
    journal = json.loads(journal_text)
    assert journal["status"] == "COMPLETE_REVIEW_REQUIRED"
    assert journal["execution_progress"]["transition_count"] == 18
    for sequence, item in enumerate(journal["execution_progress"]["items"], start=1):
        assert [transition["phase"] for transition in item["transitions"]] == [
            "AUTHORIZATION_STARTED",
            "AUTHORIZATION_RESULT",
            "SUBMISSION_STARTED",
            "SUBMISSION_RESULT",
            "VERIFICATION_STARTED",
            "VERIFICATION_RESULT",
        ]
        submission = item["transitions"][3]
        assert submission["transaction_hash"] == f"0x{sequence:064x}"
        verification = item["transitions"][5]
        assert verification["block_number"] == 55_500_000 + sequence

    private_items = journal["exact_private_plan"]["items"]
    all_keys = []
    for item in private_items:
        binding = item["binding_document"]
        all_keys.extend(
            [binding["safe4_idempotency_key"], binding["circle_idempotency_key"]]
        )
    assert len(all_keys) == len(set(all_keys)) == 6
    assert runtime_secrets["receipt"] != runtime_secrets["admin"]
    assert runtime_secrets["receipt"] not in journal_text
    assert runtime_secrets["admin"] not in journal_text

    public = evidence.to_public_dict()
    assert public["started_at_utc"] == "2026-08-05T12:00:00Z"
    assert public["ended_at_utc"] == "2026-08-05T12:00:09Z"
    assert public["source"] == {
        "revision": SOURCE_REVISION,
        "worktree_state": "CLEAN",
    }
    assert public["circle_cli"] == {
        "command": "circle --version",
        "command_reported_version": "0.0.6",
        "version_independently_verified": False,
        "raw_command_output_retained": False,
        "authenticated_wallet_preflight": wallet_preflight(),
    }
    assert public["circle_cli"]["authenticated_wallet_preflight"]["address"] == fixed.FIXED_SENDER
    assert public["fixed_settlement"]["recipient"] == fixed.FIXED_RECIPIENT
    assert public["batch"]["terminal_status"] == "COMPLETE"
    serialized_public = evidence.to_sanitized_json()
    assert all(key not in serialized_public for key in all_keys)
    assert str(state) not in serialized_public
    assert runtime_secrets["receipt"] not in serialized_public
    assert runtime_secrets["admin"] not in serialized_public


@pytest.mark.parametrize(
    "pre_observation",
    [
        {
            "status": "NOT_OBSERVED",
            "stage": "PRE",
            "reason_code": "PUBLIC_BALANCE_RPC_UNAVAILABLE",
        },
        balance_observation(
            "PRE",
            sender_balance=fixed.MIN_PREFLIGHT_SENDER_BALANCE_BASE_UNITS - 1,
        ),
        balance_observation("PRE", chain_id=1),
    ],
    ids=("rpc-unavailable", "balance-too-low", "wrong-chain"),
)
def test_required_arc_preflight_stops_before_first_pay(
    tmp_path: Path,
    pre_observation: Mapping[str, Any],
) -> None:
    private_root = tmp_path / "private"
    state = private_root / "run"
    events: list[str] = []
    with pytest.raises(fixed.FixedBatchSafetyError):
        execute_offline(
            private_root,
            state,
            runtime_factory(state, events, pre_observation=pre_observation),
        )
    assert events == ["runtime-created", "balance:PRE"]
    journal = json.loads(
        (state / fixed.JOURNAL_FILENAME).read_text(encoding="utf-8")
    )
    assert journal["status"] == "ABORTED_NO_AUTOMATIC_RESUME"
    assert journal["execution_progress"]["transition_count"] == 0


def test_unsupported_runtime_circle_version_stops_before_balance_or_pay(
    tmp_path: Path,
) -> None:
    private_root = tmp_path / "private"
    state = private_root / "run"
    events: list[str] = []

    with pytest.raises(
        fixed.FixedBatchSafetyError,
        match="CIRCLE_CLI_VERSION_UNSUPPORTED",
    ):
        execute_offline(
            private_root,
            state,
            runtime_factory(
                state,
                events,
                circle_cli_version="0.0.7",
            ),
        )

    assert events == ["runtime-created"]
    journal = json.loads(
        (state / fixed.JOURNAL_FILENAME).read_text(encoding="utf-8")
    )
    assert journal["status"] == "ABORTED_NO_AUTOMATIC_RESUME"
    assert journal["execution_progress"]["transition_count"] == 0


def test_fixed_run_evidence_revalidates_pre_post_stages_and_pre_balance(
    tmp_path: Path,
) -> None:
    private_root = tmp_path / "private"
    state = private_root / "run"
    events: list[str] = []
    valid = execute_offline(
        private_root,
        state,
        runtime_factory(state, events),
    )

    invalid_cases = (
        (
            replace(valid, pre_balances=balance_observation("POST")),
            "PUBLIC_BALANCE_PRE_STAGE_INVALID",
        ),
        (
            replace(valid, post_balances=balance_observation("PRE")),
            "PUBLIC_BALANCE_POST_STAGE_INVALID",
        ),
        (
            replace(
                valid,
                pre_balances=balance_observation(
                    "PRE",
                    sender_balance=(
                        fixed.MIN_PREFLIGHT_SENDER_BALANCE_BASE_UNITS - 1
                    ),
                ),
            ),
            "PREFLIGHT_SENDER_BALANCE_TOO_LOW",
        ),
        (
            replace(
                valid,
                pre_balances={
                    "status": "NOT_OBSERVED",
                    "stage": "PRE",
                    "reason_code": "PUBLIC_BALANCE_RPC_UNAVAILABLE",
                },
            ),
            "PREFLIGHT_ARC_RPC_REQUIRED",
        ),
    )
    for evidence, reason_code in invalid_cases:
        with pytest.raises(fixed.FixedBatchSafetyError, match=reason_code):
            evidence.to_public_dict()


def test_rpc_unknown_is_journaled_and_never_automatically_retried(tmp_path: Path) -> None:
    private_root = tmp_path / "private"
    state = private_root / "run"
    events: list[str] = []
    factory = runtime_factory(state, events, verification_status="UNKNOWN")
    evidence = execute_offline(private_root, state, factory)
    assert evidence.batch.terminal_status == "STOPPED"
    assert events.count("submit:1") == 1
    assert not any(event in events for event in ("authorize:2", "submit:2"))
    journal = json.loads(
        (state / fixed.JOURNAL_FILENAME).read_text(encoding="utf-8")
    )
    assert journal["status"] == "STOPPED_NO_AUTOMATIC_RESUME"
    first = journal["execution_progress"]["items"][0]
    assert first["transitions"][3]["transaction_hash"] == f"0x{1:064x}"
    assert first["transitions"][-1]["status"] == "UNKNOWN"

    second_runtime_calls = 0

    @contextmanager
    def second_runtime(plan: Any, database_path: Path) -> Iterator[fixed.RuntimeBundle]:
        nonlocal second_runtime_calls
        second_runtime_calls += 1
        raise AssertionError("no automatic or implicit resume")
        yield  # pragma: no cover

    with pytest.raises(
        fixed.FixedBatchSafetyError,
        match="PRIOR_OR_INCOMPLETE_PRIVATE_STATE_EXISTS",
    ):
        execute_offline(private_root, state, second_runtime)
    assert second_runtime_calls == 0
    assert events.count("submit:1") == 1


@pytest.mark.parametrize(
    "prior_name",
    (
        fixed.JOURNAL_FILENAME,
        f"{fixed.JOURNAL_FILENAME}.tmp-interrupted",
        fixed.DATABASE_FILENAME,
        "unexpected-private-state",
    ),
)
def test_any_prior_or_incomplete_private_state_fails_before_runtime(
    tmp_path: Path,
    prior_name: str,
) -> None:
    private_root = tmp_path / "private"
    state = private_root / "run"
    state.mkdir(parents=True)
    (state / prior_name).write_text("private", encoding="utf-8")
    runtime_calls = 0

    @contextmanager
    def never_runtime(plan: Any, database_path: Path) -> Iterator[fixed.RuntimeBundle]:
        nonlocal runtime_calls
        runtime_calls += 1
        raise AssertionError("runtime must not be created")
        yield  # pragma: no cover

    with pytest.raises(
        fixed.FixedBatchSafetyError,
        match="PRIOR_OR_INCOMPLETE_PRIVATE_STATE_EXISTS",
    ):
        execute_offline(private_root, state, never_runtime)
    assert runtime_calls == 0


def test_existing_exclusive_lock_fails_closed_before_runtime(tmp_path: Path) -> None:
    private_root = tmp_path / "private"
    state = private_root / "run"
    state.mkdir(parents=True)
    lock = state / fixed.LOCK_FILENAME
    lock.write_text("held", encoding="utf-8")
    runtime_calls = 0

    @contextmanager
    def never_runtime(plan: Any, database_path: Path) -> Iterator[fixed.RuntimeBundle]:
        nonlocal runtime_calls
        runtime_calls += 1
        raise AssertionError("runtime must not be created")
        yield  # pragma: no cover

    with pytest.raises(fixed.FixedBatchSafetyError, match="EXCLUSIVE_BATCH_LOCK_HELD"):
        execute_offline(private_root, state, never_runtime)
    assert runtime_calls == 0
    assert lock.read_text(encoding="utf-8") == "held"


def test_runtime_crash_retains_sanitized_abort_journal_and_blocks_resume(
    tmp_path: Path,
) -> None:
    private_root = tmp_path / "private"
    state = private_root / "run"
    runtime_calls = 0

    @contextmanager
    def crashing_runtime(plan: Any, database_path: Path) -> Iterator[fixed.RuntimeBundle]:
        nonlocal runtime_calls
        runtime_calls += 1
        assert (state / fixed.JOURNAL_FILENAME).is_file()
        raise RuntimeError(
            "Be" + "arer raw-provider-secret " + "private" + " key"
        )
        yield  # pragma: no cover

    with pytest.raises(
        fixed.FixedBatchSafetyError,
        match="LIVE_BATCH_ABORTED_PRIVATE_JOURNAL_RETAINED",
    ):
        execute_offline(private_root, state, crashing_runtime)
    journal_text = (state / fixed.JOURNAL_FILENAME).read_text(encoding="utf-8")
    assert "ABORTED_NO_AUTOMATIC_RESUME" in journal_text
    assert "raw-provider-secret" not in journal_text
    assert "Bearer" not in journal_text
    assert not (state / fixed.LOCK_FILENAME).exists()

    with pytest.raises(
        fixed.FixedBatchSafetyError,
        match="PRIOR_OR_INCOMPLETE_PRIVATE_STATE_EXISTS",
    ):
        execute_offline(private_root, state, crashing_runtime)
    assert runtime_calls == 1


def test_wallet_list_preflight_is_exact_and_retains_no_raw_output() -> None:
    calls: list[list[str]] = []
    raw_secret = "never-retain-this-wallet-session-value"

    def runner(command: list[str], **kwargs: Any) -> Any:
        calls.append(command)
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps(
                {
                    "data": {
                        "wallets": [
                            {
                                "address": fixed.FIXED_SENDER.upper(),
                                "blockchain": "arc-testnet",
                                "type": "agent",
                                "opaqueSession": raw_secret,
                            },
                            {
                                "address": "0x1111111111111111111111111111111111111111",
                                "blockchain": ARC_CHAIN,
                                "type": "agent",
                            },
                        ]
                    }
                }
            ),
            stderr="Be" + "arer another-raw-value",
        )

    observed = fixed.verify_fixed_circle_wallet_preflight(
        "circle-test",
        command_runner=runner,
    )
    assert calls == [
        [
            "circle-test",
            "wallet",
            "list",
            "--chain",
            ARC_CHAIN,
            "--type",
            "agent",
            "--output",
            "json",
        ]
    ]
    assert observed == wallet_preflight()
    assert raw_secret not in json.dumps(observed)


@pytest.mark.parametrize(
    "payload",
    [
        {"data": {"wallets": []}},
        {"data": {"wallets": []}, "extra": True},
        {"data": {"wallets": [], "cursor": "secret"}},
        {
            "data": {
                "wallets": [
                    {
                        "address": "0x1111111111111111111111111111111111111111",
                        "blockchain": ARC_CHAIN,
                        "type": "agent",
                    }
                ]
            }
        },
        {
            "data": {
                "wallets": [
                    {
                        "address": fixed.FIXED_SENDER,
                        "blockchain": ARC_CHAIN,
                        "type": "local",
                    }
                ]
            }
        },
        {
            "data": {
                "wallets": [
                    {
                        "address": fixed.FIXED_SENDER,
                        "blockchain": ARC_CHAIN,
                        "type": "agent",
                    },
                    {
                        "address": fixed.FIXED_SENDER,
                        "blockchain": ARC_CHAIN,
                        "type": "agent",
                    },
                ]
            }
        },
    ],
)
def test_wallet_list_preflight_rejects_nonexact_or_ambiguous_results(
    payload: Mapping[str, Any],
) -> None:
    def runner(command: list[str], **kwargs: Any) -> Any:
        return SimpleNamespace(returncode=0, stdout=json.dumps(payload), stderr="")

    with pytest.raises(fixed.FixedBatchSafetyError):
        fixed.verify_fixed_circle_wallet_preflight(
            "circle-test",
            command_runner=runner,
        )


def test_cli_version_and_source_revision_are_strictly_parsed_offline() -> None:
    def circle_runner(command: list[str], **kwargs: Any) -> Any:
        return SimpleNamespace(
            returncode=0,
            stdout="@circle-fin/cli/0.0.6 win32-x64 node-v22.0.0",
            stderr="raw stderr must not be retained",
        )

    assert fixed.observe_circle_cli_version(
        "circle-test",
        command_runner=circle_runner,
    ) == "0.0.6"

    git_calls = 0

    def git_runner(command: list[str], **kwargs: Any) -> Any:
        nonlocal git_calls
        git_calls += 1
        if "rev-parse" in command:
            return SimpleNamespace(returncode=0, stdout=SOURCE_REVISION + "\n")
        return SimpleNamespace(returncode=0, stdout="")

    assert fixed.observe_clean_source_identity(command_runner=git_runner) == clean_source()
    assert git_calls == 2


def test_circle_version_and_wallet_commands_receive_sanitized_environment() -> None:
    observed_environments: list[dict[str, str]] = []

    def version_runner(command: list[str], **kwargs: Any) -> Any:
        observed_environments.append(kwargs["env"])
        return SimpleNamespace(returncode=0, stdout="0.0.6", stderr="")

    def wallet_runner(command: list[str], **kwargs: Any) -> Any:
        observed_environments.append(kwargs["env"])
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps(
                {
                    "data": {
                        "wallets": [
                            {
                                "address": fixed.FIXED_SENDER,
                                "blockchain": ARC_CHAIN,
                                "type": "agent",
                            }
                        ]
                    }
                }
            ),
            stderr="",
        )

    inherited = {
        "Path": "C:\\Windows\\System32",
        "SystemRoot": "C:\\Windows",
        "APPDATA": "C:\\Users\\demo\\AppData\\Roaming",
        "USERPROFILE": "C:\\Users\\demo",
        "PAYMENT_FIREWALL_ADMIN_SECRET": "unsafe-safe4-secret",
        "SAFE4_PROVIDER_RANGE_RISK_API_KEY": "unsafe-provider-secret",
        "CIRCLE_ACCESS_TOKEN": "unsafe-circle-token",
        "PRIVATE_KEY": "unsafe-private-key",
        "HTTP_PROXY": "http://attacker.invalid",
        "HTTPS_PROXY": "http://attacker.invalid",
        "SSL_CERT_FILE": "C:\\attacker\\ca.pem",
        "NODE_OPTIONS": "--require=C:\\attacker\\inject.js",
        "NODE_EXTRA_CA_CERTS": "C:\\attacker\\ca.pem",
    }
    with patch.dict(os.environ, inherited, clear=True):
        assert fixed.observe_circle_cli_version(
            "circle-test",
            command_runner=version_runner,
        ) == fixed.SUPPORTED_CIRCLE_CLI_VERSION
        assert fixed.verify_fixed_circle_wallet_preflight(
            "circle-test",
            command_runner=wallet_runner,
        ) == wallet_preflight()

    expected = {
        "APPDATA": "C:\\Users\\demo\\AppData\\Roaming",
        "PATH": "C:\\Windows\\System32",
        "SYSTEMROOT": "C:\\Windows",
        "USERPROFILE": "C:\\Users\\demo",
    }
    assert observed_environments == [expected, expected]


@pytest.mark.parametrize(
    "reported_version",
    ("0.0.5", "0.0.7", "1.0.0", "0.0.6-alpha"),
)
def test_circle_version_command_rejects_every_other_semver(
    reported_version: str,
) -> None:
    def runner(command: list[str], **kwargs: Any) -> Any:
        return SimpleNamespace(returncode=0, stdout=reported_version, stderr="")

    with pytest.raises(
        fixed.FixedBatchSafetyError,
        match="CIRCLE_CLI_VERSION_UNSUPPORTED",
    ):
        fixed.observe_circle_cli_version("circle-test", command_runner=runner)


def test_arc_public_balance_observer_disables_ambient_http_environment() -> None:
    class FakeHttpClient:
        def __enter__(self) -> "FakeHttpClient":
            return self

        def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> bool:
            return False

    observer = fixed.ArcPublicBalanceObserver()
    with (
        patch("httpx.Client", return_value=FakeHttpClient()) as client_factory,
        patch.object(
            observer,
            "_rpc",
            side_effect=(
                hex(ARC_CHAIN_ID),
                hex(55_500_001),
                hex(fixed.MIN_PREFLIGHT_SENDER_BALANCE_BASE_UNITS * 10),
                hex(1_000_000_000_000_000_000),
            ),
        ),
    ):
        observed = observer("PRE")

    assert observed["status"] == "OBSERVED"
    assert observed["stage"] == "PRE"
    client_factory.assert_called_once_with(timeout=15.0, trust_env=False)


def test_local_fixture_secrets_are_fresh_ephemeral_and_not_static(tmp_path: Path) -> None:
    with patch.dict(os.environ, {}, clear=True):
        fixed.configure_isolated_environment(tmp_path / "first.sqlite3")
        first = (
            os.environ["PAYMENT_FIREWALL_RECEIPT_SECRET"],
            os.environ["PAYMENT_FIREWALL_ADMIN_SECRET"],
        )
        fixed.configure_isolated_environment(tmp_path / "second.sqlite3")
        second = (
            os.environ["PAYMENT_FIREWALL_RECEIPT_SECRET"],
            os.environ["PAYMENT_FIREWALL_ADMIN_SECRET"],
        )
    assert len(set(first + second)) == 4
    assert all(len(value) >= 48 for value in first + second)
    assert all("fixed-live-local" not in value for value in first + second)
