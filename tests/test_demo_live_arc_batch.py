from __future__ import annotations

from dataclasses import replace
from decimal import Decimal
import hashlib
import json
import os
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch
from uuid import UUID

import pytest

from scripts.demo_live_arc_batch import (
    ARC_CHAIN,
    ARC_CHAIN_ID,
    ARC_ENTRYPOINT_ADDRESS,
    ARC_NATIVE_USDC_ADDRESS,
    MAX_BATCH_AMOUNT_UNITS,
    MAX_BATCH_ITEMS,
    MAX_ITEM_AMOUNT_UNITS,
    ArcRpcVerificationPort,
    AuthorizationResult,
    BatchItemInput,
    BatchValidationError,
    BindingIntegrityError,
    CircleCliSubmissionPort,
    LiveArcBatchCoordinator,
    LocalSafe4AuthorizationPort,
    SubmissionResult,
    VerificationResult,
    assert_single_bound_outgoing_transfer,
    assert_single_successful_bound_user_operation,
    build_circle_transfer_command,
    prepare_batch,
)
from scripts.verify_arc_settlement import (
    TRANSFER_TOPIC,
    USER_OPERATION_EVENT_TOPIC,
    address_topic,
    parse_hex_int,
)


SENDER = "0x1111111111111111111111111111111111111111"
RECIPIENT_A = "0x530271da8cc4e44375f22ad9632bc61a55382f88"
RECIPIENT_B = "0x3333333333333333333333333333333333333333"
RECIPIENT_C = "0x4444444444444444444444444444444444444444"
NATIVE_USDC = "0xfffffffffffffffffffffffffffffffffffffffe"


def item(
    item_id: str,
    *,
    recipient: str = RECIPIENT_A,
    amount_units: int = 1_000,
) -> BatchItemInput:
    return BatchItemInput(
        item_id=item_id,
        recipient=recipient,
        amount_units=amount_units,
        vendor=f"synthetic_{item_id}",
        description=f"Generate competitor pricing research for {item_id} company data.",
        task="Research competitor pricing using paid company data services.",
        service_category="company-research",
    )


def make_plan(
    *items: BatchItemInput,
    allowlist: tuple[str, ...] = (RECIPIENT_A,),
):
    selected = items or (item("item-1"), item("item-2", amount_units=2_000))
    return prepare_batch(
        batch_id="judge-batch-001",
        sender=SENDER,
        recipient_allowlist=allowlist,
        items=selected,
    )


def circle_cli_json(bound, transaction_hash: str, **overrides: Any) -> str:
    """Mirror Circle CLI 0.0.6's ``{"data": result}`` JSON envelope."""

    result: dict[str, Any] = {
        "idempotencyKey": bound.circle_idempotency_key,
        "id": "circle-transaction-id",
        "state": "COMPLETE",
        "blockchain": ARC_CHAIN,
        "txHash": transaction_hash,
        "sourceAddress": bound.sender,
        "destinationAddress": bound.recipient,
        "amounts": [bound.amount_usdc],
        "operation": "TRANSFER",
        "transactionType": "OUTBOUND",
        "errorReason": None,
        "errorDetails": None,
    }
    result.update(overrides)
    return json.dumps({"data": result})


class CountingKeyFactory:
    def __init__(self) -> None:
        self.calls = 0

    def __call__(self) -> UUID:
        self.calls += 1
        return UUID(int=self.calls, version=4)


def test_invalid_batches_fail_preflight_before_keys_or_ports() -> None:
    cases: list[dict[str, Any]] = [
        {
            "recipient_allowlist": (RECIPIENT_A,),
            "items": tuple(item(f"item-{index}") for index in range(MAX_BATCH_ITEMS + 1)),
        },
        {
            "recipient_allowlist": (RECIPIENT_A,),
            "items": (item("too-large", amount_units=MAX_ITEM_AMOUNT_UNITS + 1),),
        },
        {
            "recipient_allowlist": (RECIPIENT_A,),
            "items": (
                item("one", amount_units=4_000),
                item("two", amount_units=4_000),
                item(
                    "three",
                    amount_units=MAX_BATCH_AMOUNT_UNITS - 8_000 + 1,
                ),
            ),
        },
        {
            "recipient_allowlist": (),
            "items": (item("no-allowlist"),),
        },
        {
            "recipient_allowlist": (RECIPIENT_A,),
            "items": (item("outside", recipient=RECIPIENT_B),),
        },
        {
            # Supplying an arbitrary address in both the caller-authored list
            # and item cannot expand the code-reviewed destination set.
            "recipient_allowlist": (RECIPIENT_B,),
            "items": (item("untrusted-list", recipient=RECIPIENT_B),),
        },
        {
            # The invalid second item proves the first item does not cause keys
            # to be generated before the complete batch has passed preflight.
            "recipient_allowlist": (RECIPIENT_A,),
            "items": (item("valid-first"), item("invalid-second", amount_units=0)),
        },
    ]

    for case in cases:
        keys = CountingKeyFactory()
        with pytest.raises(BatchValidationError):
            prepare_batch(
                batch_id="invalid-batch",
                sender=SENDER,
                recipient_allowlist=case["recipient_allowlist"],
                items=case["items"],
                key_factory=keys,
            )
        assert keys.calls == 0

    self_transfer_keys = CountingKeyFactory()
    with pytest.raises(BatchValidationError, match="sender cannot"):
        prepare_batch(
            batch_id="self-transfer",
            sender=RECIPIENT_A,
            recipient_allowlist=(RECIPIENT_A,),
            items=(item("self-transfer", recipient=RECIPIENT_A),),
            key_factory=self_transfer_keys,
        )
    assert self_transfer_keys.calls == 0


def test_keys_are_uuid4_unique_across_items_and_separate_between_systems() -> None:
    plan = make_plan(
        item("one", amount_units=1_000),
        item("two", amount_units=2_000),
        item("three", amount_units=3_000),
    )

    keys = [
        key
        for bound in plan.items
        for key in (bound.safe4_idempotency_key, bound.circle_idempotency_key)
    ]
    assert len(keys) == 6
    assert len(set(keys)) == 6
    assert all(UUID(key).version == 4 and str(UUID(key)) == key for key in keys)
    assert all(
        bound.safe4_idempotency_key != bound.circle_idempotency_key
        for bound in plan.items
    )
    for bound in plan.items:
        settlement_intent = bound.payment_payload()["context"]["settlement_intent"]
        assert settlement_intent["binding_hash"] == bound.binding_hash
        assert settlement_intent["recipient"] == bound.recipient
        assert settlement_intent["amount_units"] == bound.amount_units


class FakeAuthorizer:
    def __init__(
        self,
        events: list[str],
        *,
        denied_item: str | None = None,
        raise_item: str | None = None,
        binding_mismatch_item: str | None = None,
    ) -> None:
        self.events = events
        self.denied_item = denied_item
        self.raise_item = raise_item
        self.binding_mismatch_item = binding_mismatch_item
        self.calls: list[str] = []

    def authorize(self, bound) -> AuthorizationResult:
        self.calls.append(bound.item_id)
        self.events.append(f"authorize:{bound.item_id}")
        if bound.item_id == self.raise_item:
            raise RuntimeError(
                "Bearer test-only-access-token receipt_token=unsafe operator@example.com"
            )
        if bound.item_id == self.denied_item:
            return AuthorizationResult(
                status="DENIED",
                binding_hash=bound.binding_hash,
                reason_code="PURCHASE_PURPOSE_MISMATCH",
            )
        return AuthorizationResult(
            status="AUTHORIZED",
            binding_hash=(
                "f" * 64
                if bound.item_id == self.binding_mismatch_item
                else bound.binding_hash
            ),
            reason_code="TASK_PURCHASE_MATCH",
            safe4_transaction_id=f"{bound.sequence:032x}",
        )


class FakeSubmitter:
    def __init__(
        self,
        events: list[str],
        *,
        status_by_item: dict[str, str] | None = None,
    ) -> None:
        self.events = events
        self.status_by_item = status_by_item or {}
        self.calls: list[str] = []

    def submit(self, bound) -> SubmissionResult:
        self.calls.append(bound.item_id)
        self.events.append(f"submit:{bound.item_id}")
        status = self.status_by_item.get(bound.item_id, "SUBMITTED")
        return SubmissionResult(
            status=status,
            binding_hash=bound.binding_hash,
            transaction_hash=(
                "0x" + f"{bound.sequence:064x}" if status == "SUBMITTED" else None
            ),
            error_code=None if status == "SUBMITTED" else "CIRCLE_SUBMISSION_TIMEOUT",
        )


class FakeVerifier:
    def __init__(
        self,
        events: list[str],
        *,
        mismatch_item: str | None = None,
    ) -> None:
        self.events = events
        self.mismatch_item = mismatch_item
        self.calls: list[str] = []

    def verify(self, bound, transaction_hash: str) -> VerificationResult:
        self.calls.append(bound.item_id)
        self.events.append(f"verify:{bound.item_id}")
        return VerificationResult(
            status="VERIFIED",
            binding_hash=bound.binding_hash,
            transaction_hash=transaction_hash,
            block_number=100 + bound.sequence,
            observed_chain=ARC_CHAIN,
            observed_sender=bound.sender,
            observed_recipient=(
                RECIPIENT_C
                if bound.item_id == self.mismatch_item
                else bound.recipient
            ),
            observed_amount_units=bound.amount_units,
        )


def coordinator(
    *,
    denied_item: str | None = None,
    raise_item: str | None = None,
    binding_mismatch_item: str | None = None,
    status_by_item: dict[str, str] | None = None,
    verifier_mismatch_item: str | None = None,
):
    events: list[str] = []
    authorizer = FakeAuthorizer(
        events,
        denied_item=denied_item,
        raise_item=raise_item,
        binding_mismatch_item=binding_mismatch_item,
    )
    submitter = FakeSubmitter(events, status_by_item=status_by_item)
    verifier = FakeVerifier(events, mismatch_item=verifier_mismatch_item)
    runner = LiveArcBatchCoordinator(
        authorizer=authorizer,
        submitter=submitter,
        verifier=verifier,
    )
    return runner, authorizer, submitter, verifier, events


def test_success_is_strictly_authorize_submit_verify_per_item() -> None:
    plan = make_plan(
        item("one", amount_units=1_000),
        item("two", amount_units=2_000),
        item("three", amount_units=3_000),
    )
    runner, _, _, _, events = coordinator()

    evidence = runner.run(plan)

    assert events == [
        "authorize:one",
        "submit:one",
        "verify:one",
        "authorize:two",
        "submit:two",
        "verify:two",
        "authorize:three",
        "submit:three",
        "verify:three",
    ]
    public = evidence.to_public_dict()
    assert evidence.terminal_status == "COMPLETE"
    assert [entry["outcome"] for entry in public["items"]] == [
        "VERIFIED",
        "VERIFIED",
        "VERIFIED",
    ]
    assert public["atomic"] is False
    assert public["execution_model"] == "SEQUENTIAL_NON_ATOMIC_STOP_ON_FIRST_FAILURE"
    assert public["counts"] == {
        "planned": 3,
        "authorized": 3,
        "submitted": 3,
        "verified": 3,
        "denied": 0,
        "failed": 0,
        "unknown": 0,
        "skipped": 0,
    }
    assert public["totals"]["verified_amount_units"] == 6_000


def test_unknown_submission_stops_non_atomically_before_next_authorization() -> None:
    plan = make_plan(item("one"), item("two"), item("three"))
    runner, authorizer, submitter, verifier, events = coordinator(
        status_by_item={"two": "UNKNOWN"}
    )

    evidence = runner.run(plan)

    assert events == [
        "authorize:one",
        "submit:one",
        "verify:one",
        "authorize:two",
        "submit:two",
    ]
    assert authorizer.calls == ["one", "two"]
    assert submitter.calls == ["one", "two"]
    assert verifier.calls == ["one"]
    assert evidence.terminal_status == "PARTIAL_STOPPED"
    assert [entry.outcome for entry in evidence.items] == [
        "VERIFIED",
        "UNKNOWN",
        "SKIPPED",
    ]
    assert evidence.items[1].safe4_status == "AUTHORIZED"
    assert evidence.items[1].error_code == "CIRCLE_SUBMISSION_TIMEOUT"


def test_reused_transaction_hash_is_not_verified_or_counted_twice() -> None:
    plan = make_plan(item("one"), item("two"), item("three"))
    events: list[str] = []
    authorizer = FakeAuthorizer(events)
    reused_hash = "0x" + ("a" * 64)

    class ReusingSubmitter:
        def __init__(self) -> None:
            self.calls: list[str] = []

        def submit(self, bound) -> SubmissionResult:
            self.calls.append(bound.item_id)
            events.append(f"submit:{bound.item_id}")
            return SubmissionResult(
                status="SUBMITTED",
                binding_hash=bound.binding_hash,
                transaction_hash=reused_hash,
            )

    submitter = ReusingSubmitter()
    verifier = FakeVerifier(events)
    runner = LiveArcBatchCoordinator(
        authorizer=authorizer,
        submitter=submitter,
        verifier=verifier,
    )

    evidence = runner.run(plan)
    public = evidence.to_public_dict()

    assert authorizer.calls == ["one", "two"]
    assert submitter.calls == ["one", "two"]
    assert verifier.calls == ["one"]
    assert [entry.outcome for entry in evidence.items] == [
        "VERIFIED",
        "UNKNOWN",
        "SKIPPED",
    ]
    assert evidence.items[1].error_code == "TRANSACTION_HASH_REUSED"
    assert public["counts"]["submitted"] == 1
    assert public["counts"]["verified"] == 1


def test_denial_stops_without_submitting_denied_or_later_items() -> None:
    plan = make_plan(item("one"), item("two"), item("three"))
    runner, authorizer, submitter, verifier, events = coordinator(denied_item="two")

    evidence = runner.run(plan)

    assert events == [
        "authorize:one",
        "submit:one",
        "verify:one",
        "authorize:two",
    ]
    assert authorizer.calls == ["one", "two"]
    assert submitter.calls == ["one"]
    assert verifier.calls == ["one"]
    assert [entry.outcome for entry in evidence.items] == [
        "VERIFIED",
        "DENIED",
        "SKIPPED",
    ]


def test_verification_binding_mismatch_stops_remaining_items() -> None:
    plan = make_plan(item("one"), item("two"), item("three"))
    runner, authorizer, submitter, verifier, events = coordinator(
        verifier_mismatch_item="two"
    )

    evidence = runner.run(plan)

    assert events[-1] == "verify:two"
    assert authorizer.calls == ["one", "two"]
    assert submitter.calls == ["one", "two"]
    assert verifier.calls == ["one", "two"]
    assert [entry.outcome for entry in evidence.items] == [
        "VERIFIED",
        "FAILED",
        "SKIPPED",
    ]
    assert evidence.items[1].error_code == "VERIFICATION_BINDING_MISMATCH"


def test_mutated_plan_and_item_fail_before_any_port_or_cli_call() -> None:
    plan = make_plan(item("one", recipient=RECIPIENT_A))
    mutated_item = replace(plan.items[0], recipient=RECIPIENT_B)
    mutated_plan = replace(plan, items=(mutated_item,))
    runner, authorizer, submitter, verifier, _ = coordinator()

    with pytest.raises(BindingIntegrityError):
        runner.run(mutated_plan)

    assert authorizer.calls == []
    assert submitter.calls == []
    assert verifier.calls == []

    cli_calls: list[Any] = []

    def command_runner(*args, **kwargs):
        cli_calls.append((args, kwargs))
        raise AssertionError("CLI must not be reached")

    port = CircleCliSubmissionPort(
        circle_executable="circle",
        command_runner=command_runner,
    )
    with pytest.raises(BindingIntegrityError):
        port.submit(mutated_item)
    assert cli_calls == []

    # Recomputing the unkeyed binding hash cannot bypass the deployment-owned
    # destination set enforced by item integrity itself.
    outsider = replace(plan.items[0], recipient=RECIPIENT_B)
    outsider_hash = hashlib.sha256(
        json.dumps(
            outsider.binding_document(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()
    rehashed_outsider = replace(outsider, binding_hash=outsider_hash)
    with pytest.raises(BindingIntegrityError, match="code-reviewed"):
        port.submit(rehashed_outsider)
    assert cli_calls == []


def test_authorization_binding_mismatch_blocks_submission() -> None:
    plan = make_plan(item("one"), item("two"))
    runner, authorizer, submitter, verifier, _ = coordinator(
        binding_mismatch_item="one"
    )

    evidence = runner.run(plan)

    assert authorizer.calls == ["one"]
    assert submitter.calls == []
    assert verifier.calls == []
    assert [entry.outcome for entry in evidence.items] == ["UNKNOWN", "SKIPPED"]
    assert evidence.items[0].reason_code == "AUTHORIZATION_BINDING_MISMATCH"


def test_opaque_authorization_identifier_cannot_enter_evidence() -> None:
    plan = make_plan(item("one"), item("two"))
    events: list[str] = []

    class OpaqueIdAuthorizer:
        def authorize(self, bound) -> AuthorizationResult:
            events.append(f"authorize:{bound.item_id}")
            return AuthorizationResult(
                status="AUTHORIZED",
                binding_hash=bound.binding_hash,
                reason_code="TASK_PURCHASE_MATCH",
                # Deliberately attempt to reuse an idempotency key as an ID.
                safe4_transaction_id=bound.safe4_idempotency_key,
            )

    submitter = FakeSubmitter(events)
    verifier = FakeVerifier(events)
    runner = LiveArcBatchCoordinator(
        authorizer=OpaqueIdAuthorizer(),
        submitter=submitter,
        verifier=verifier,
    )

    evidence = runner.run(plan)
    serialized = evidence.to_sanitized_json()

    assert submitter.calls == []
    assert verifier.calls == []
    assert [entry.outcome for entry in evidence.items] == ["UNKNOWN", "SKIPPED"]
    assert plan.items[0].safe4_idempotency_key not in serialized
    assert evidence.items[0].safe4_transaction_id is None


def test_circle_command_uses_only_bound_item_not_settlement_environment() -> None:
    bound = make_plan(item("one", recipient=RECIPIENT_A, amount_units=1_234)).items[0]
    calls: list[tuple[list[str], dict[str, Any]]] = []
    transaction_hash = "0x" + ("a" * 64)

    def command_runner(command: list[str], **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(
            returncode=0,
            stdout=circle_cli_json(bound, transaction_hash),
            stderr="",
        )

    port = CircleCliSubmissionPort(
        circle_executable="C:\\tools\\circle.cmd",
        command_runner=command_runner,
    )
    with patch.dict(
        os.environ,
        {
            "SETTLEMENT_TO": RECIPIENT_C,
            "SETTLEMENT_AMOUNT_UNITS": "999999999",
            "SETTLEMENT_IDEMPOTENCY_KEY": str(UUID(int=999, version=4)),
        },
    ):
        result = port.submit(bound)

    assert result.status == "SUBMITTED"
    assert result.transaction_hash == transaction_hash
    assert len(calls) == 1
    command, kwargs = calls[0]
    assert command == list(
        build_circle_transfer_command(
            bound,
            circle_executable="C:\\tools\\circle.cmd",
        )
    )
    assert command[command.index("transfer") + 1] == bound.recipient
    assert command[command.index("--amount") + 1] == "0.001234"
    assert command[command.index("--address") + 1] == bound.sender
    assert command[command.index("--idempotency-key") + 1] == bound.circle_idempotency_key
    assert bound.safe4_idempotency_key not in command
    assert RECIPIENT_C not in command
    assert kwargs["check"] is False
    assert kwargs["capture_output"] is True
    assert kwargs["text"] is True


def test_circle_confirmed_state_proceeds_to_rpc_verification() -> None:
    """Circle CLI 0.0.6 treats CONFIRMED as a successful terminal state."""

    bound = make_plan(item("one")).items[0]
    transaction_hash = "0x" + ("a" * 64)
    completed = SimpleNamespace(
        returncode=0,
        stdout=circle_cli_json(
            bound,
            transaction_hash,
            state="CONFIRMED",
        ),
        stderr="",
    )
    port = CircleCliSubmissionPort(
        circle_executable="circle",
        command_runner=lambda *args, **kwargs: completed,
    )

    result = port.submit(bound)

    assert result.status == "SUBMITTED"
    assert result.transaction_hash == transaction_hash


@pytest.mark.parametrize(
    "state",
    ["INITIATED", "PENDING", "FAILED", "CANCELLED", "DENIED"],
)
def test_circle_non_success_states_stop_before_rpc_verification(state: str) -> None:
    bound = make_plan(item("one")).items[0]
    completed = SimpleNamespace(
        returncode=0,
        stdout=circle_cli_json(
            bound,
            "0x" + ("a" * 64),
            state=state,
        ),
        stderr="",
    )
    port = CircleCliSubmissionPort(
        circle_executable="circle",
        command_runner=lambda *args, **kwargs: completed,
    )

    result = port.submit(bound)

    assert result.status == "UNKNOWN"
    assert result.transaction_hash is None
    assert result.error_code == "CIRCLE_STATE_NOT_SUCCESS"


def test_circle_rejects_legacy_unwrapped_transfer_output() -> None:
    """A tx hash alone is ambiguous even when it may follow a broadcast."""

    bound = make_plan(item("one")).items[0]
    completed = SimpleNamespace(
        returncode=0,
        stdout=json.dumps({"txHash": "0x" + ("a" * 64)}),
        stderr="",
    )
    port = CircleCliSubmissionPort(
        circle_executable="circle",
        command_runner=lambda *args, **kwargs: completed,
    )

    result = port.submit(bound)

    assert result.status == "UNKNOWN"
    assert result.transaction_hash is None
    assert result.error_code == "CIRCLE_OUTPUT_ENVELOPE_INVALID"


@pytest.mark.parametrize(
    ("override", "untrusted_value"),
    [
        ("idempotencyKey", "00000000-0000-4000-8000-000000000099"),
        ("blockchain", "BASE"),
        ("sourceAddress", RECIPIENT_C),
        ("destinationAddress", RECIPIENT_C),
        ("amounts", ["0.004999"]),
        ("operation", "CONTRACT_EXECUTION"),
        ("transactionType", "INBOUND"),
    ],
)
def test_circle_requires_every_installed_cli_binding_field(
    override: str,
    untrusted_value: Any,
) -> None:
    bound = make_plan(item("one")).items[0]
    completed = SimpleNamespace(
        returncode=0,
        stdout=circle_cli_json(
            bound,
            "0x" + ("a" * 64),
            **{override: untrusted_value},
        ),
        stderr="",
    )
    port = CircleCliSubmissionPort(
        circle_executable="circle",
        command_runner=lambda *args, **kwargs: completed,
    )

    result = port.submit(bound)

    assert result.status == "UNKNOWN"
    assert result.transaction_hash is None
    assert result.error_code == "CIRCLE_OUTPUT_BINDING_MISMATCH"


@pytest.mark.parametrize(
    ("error_field", "error_value"),
    [
        ("errorReason", "provider-secret-details"),
        ("errorDetails", ["operator@example.com"]),
    ],
)
def test_circle_complete_output_with_error_is_unknown_and_sanitized(
    error_field: str,
    error_value: Any,
) -> None:
    bound = make_plan(item("one")).items[0]
    completed = SimpleNamespace(
        returncode=0,
        stdout=circle_cli_json(
            bound,
            "0x" + ("a" * 64),
            **{error_field: error_value},
        ),
        stderr="",
    )
    port = CircleCliSubmissionPort(
        circle_executable="circle",
        command_runner=lambda *args, **kwargs: completed,
    )

    result = port.submit(bound)

    assert result.status == "UNKNOWN"
    assert result.transaction_hash is None
    assert result.error_code == "CIRCLE_OUTPUT_CONTAINS_ERROR"
    serialized = json.dumps(
        {
            "status": result.status,
            "transaction_hash": result.transaction_hash,
            "error_code": result.error_code,
        }
    )
    assert "provider-secret-details" not in serialized
    assert "operator@example.com" not in serialized


@pytest.mark.parametrize(
    ("completed", "expected_code"),
    [
        (
            SimpleNamespace(
                returncode=1,
                stdout="Bearer test-only-token",
                stderr="operator@example.com receipt_token=raw",
            ),
            "CIRCLE_CLI_NONZERO",
        ),
        (
            SimpleNamespace(returncode=0, stdout="not-json", stderr="private key"),
            "CIRCLE_OUTPUT_INVALID",
        ),
    ],
)
def test_circle_failures_return_only_sanitized_codes(completed, expected_code) -> None:
    bound = make_plan(item("one")).items[0]
    port = CircleCliSubmissionPort(
        circle_executable="circle",
        command_runner=lambda *args, **kwargs: completed,
    )

    result = port.submit(bound)

    assert result.status == "UNKNOWN"
    assert result.error_code == expected_code
    serialized = json.dumps(result.__dict__ if hasattr(result, "__dict__") else {
        "status": result.status,
        "binding_hash": result.binding_hash,
        "transaction_hash": result.transaction_hash,
        "error_code": result.error_code,
    })
    assert "test-only-token" not in serialized
    assert "operator@example.com" not in serialized
    assert "private key" not in serialized


def test_circle_rejects_ambiguous_hashes_in_installed_cli_envelope() -> None:
    bound = make_plan(item("one")).items[0]
    completed = SimpleNamespace(
        returncode=0,
        stdout=circle_cli_json(
            bound,
            "0x" + ("a" * 64),
            transactionHash="0x" + ("b" * 64),
        ),
        stderr="",
    )
    port = CircleCliSubmissionPort(
        circle_executable="circle",
        command_runner=lambda *args, **kwargs: completed,
    )

    result = port.submit(bound)

    assert result.status == "UNKNOWN"
    assert result.error_code == "CIRCLE_OUTPUT_AMBIGUOUS"


def test_circle_failed_state_with_old_hash_is_not_treated_as_submitted() -> None:
    bound = make_plan(item("one")).items[0]
    old_hash = "0x" + ("a" * 64)
    completed = SimpleNamespace(
        returncode=0,
        stdout=circle_cli_json(
            bound,
            old_hash,
            state="FAILED",
            error={"txHash": old_hash},
        ),
        stderr="",
    )
    port = CircleCliSubmissionPort(
        circle_executable="circle",
        command_runner=lambda *args, **kwargs: completed,
    )

    result = port.submit(bound)

    assert result.status == "UNKNOWN"
    assert result.transaction_hash is None
    assert result.error_code == "CIRCLE_STATE_NOT_SUCCESS"


def test_exception_text_and_idempotency_keys_never_enter_public_evidence() -> None:
    plan = make_plan(item("one"), item("two"))
    runner, authorizer, submitter, verifier, _ = coordinator(raise_item="one")

    evidence = runner.run(plan)
    serialized = evidence.to_sanitized_json()

    assert authorizer.calls == ["one"]
    assert submitter.calls == []
    assert verifier.calls == []
    assert "test-only-access-token" not in serialized
    assert "operator@example.com" not in serialized
    assert "receipt_token" not in serialized
    assert "synthetic_one" not in serialized
    assert "Generate competitor" not in serialized
    for bound in plan.items:
        assert bound.safe4_idempotency_key not in serialized
        assert bound.circle_idempotency_key not in serialized
    public = json.loads(serialized)
    assert [entry["outcome"] for entry in public["items"]] == [
        "UNKNOWN",
        "SKIPPED",
    ]


class FakeResponse:
    def __init__(self, status_code: int, body: dict[str, Any]) -> None:
        self.status_code = status_code
        self._body = body

    def json(self) -> dict[str, Any]:
        return self._body


class FakeSafe4Client:
    def __init__(self, bound) -> None:
        self.bound = bound
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def post(self, path: str, **kwargs):
        self.calls.append((path, kwargs))
        pay_calls = [call for call in self.calls if call[0] == "/pay"]
        if path == "/pay" and len(pay_calls) == 1:
            return FakeResponse(
                402,
                {"details": {"amount_due": "0.000003", "currency": "USDC"}},
            )
        if path == "/receipts/issue":
            return FakeResponse(200, {"receipt_token": "fixture-receipt-secret"})
        if path == "/pay" and len(pay_calls) == 2:
            return FakeResponse(
                200,
                {
                    "status": "AUTHORIZED",
                    "transaction_id": "a" * 32,
                    "intent_decision": {"reason_code": "TASK_PURCHASE_MATCH"},
                },
            )
        raise AssertionError(f"unexpected call: {path}")


def test_local_safe4_adapter_uses_safe4_key_only_on_receipt_retry() -> None:
    bound = make_plan(item("one", amount_units=1_000)).items[0]
    client = FakeSafe4Client(bound)

    class PaymentRequest:
        @classmethod
        def model_validate(cls, payload):
            return payload

    class Store:
        @staticmethod
        def list_audit_entries():
            return [
                {
                    "action": "payment_authorize",
                    "decision": "authorized",
                    "transaction_id": "a" * 32,
                    "request_payload_hash": "canonical-request-hash",
                    "transaction_amount": Decimal("0.001000"),
                    "transaction_currency": "USDC",
                }
            ]

    main_module = SimpleNamespace(
        RECEIPT_ADMIN_SECRET="test-only-admin-secret",
        PaymentRequest=PaymentRequest,
        build_request_hash=lambda payload: "canonical-request-hash",
        store=Store(),
    )
    adapter = LocalSafe4AuthorizationPort(
        client=client,
        main_module=main_module,
        access_token="test-only-oauth-token",
    )

    result = adapter.authorize(bound)

    assert result.status == "AUTHORIZED"
    assert result.binding_hash == bound.binding_hash
    first_pay = client.calls[0]
    receipt_issue = client.calls[1]
    final_pay = client.calls[2]
    assert first_pay[0] == "/pay"
    assert "Idempotency-Key" not in first_pay[1]["headers"]
    assert receipt_issue[0] == "/receipts/issue"
    assert final_pay[0] == "/pay"
    assert final_pay[1]["headers"]["Idempotency-Key"] == bound.safe4_idempotency_key
    assert final_pay[1]["headers"]["X-Payment-Receipt"] == "fixture-receipt-secret"
    assert bound.circle_idempotency_key not in json.dumps(client.calls)


def test_strict_receipt_check_rejects_extra_outgoing_transfer() -> None:
    bound = make_plan(item("one", amount_units=1_000)).items[0]
    native_amount_units = 1_000 * (10**12)

    def transfer_log(recipient: str, amount: int) -> dict[str, Any]:
        return {
            "address": NATIVE_USDC,
            "topics": [
                TRANSFER_TOPIC,
                address_topic(bound.sender),
                address_topic(recipient),
            ],
            "data": hex(amount),
        }

    receipt = {"logs": [transfer_log(bound.recipient, native_amount_units)]}
    assert_single_bound_outgoing_transfer(
        item=bound,
        receipt=receipt,
        native_usdc_address=NATIVE_USDC,
        transfer_topic=TRANSFER_TOPIC,
        address_topic=address_topic,
        parse_hex_int=parse_hex_int,
        native_amount_units=native_amount_units,
    )

    receipt["logs"].append(transfer_log(RECIPIENT_B, 1))
    with pytest.raises(BindingIntegrityError, match="exactly one outgoing"):
        assert_single_bound_outgoing_transfer(
            item=bound,
            receipt=receipt,
            native_usdc_address=NATIVE_USDC,
            transfer_topic=TRANSFER_TOPIC,
            address_topic=address_topic,
            parse_hex_int=parse_hex_int,
            native_amount_units=native_amount_units,
        )


def test_strict_receipt_check_requires_one_successful_bound_user_operation() -> None:
    bound = make_plan(item("one")).items[0]
    entrypoint = ARC_ENTRYPOINT_ADDRESS

    def user_operation_log(success: int) -> dict[str, Any]:
        return {
            "address": entrypoint,
            "topics": [
                USER_OPERATION_EVENT_TOPIC,
                "0x" + ("4" * 64),
                address_topic(bound.sender),
            ],
            "data": "0x" + ("0" * 64) + f"{success:064x}" + ("0" * 128),
        }

    receipt = {"logs": [user_operation_log(1)]}
    assert_single_successful_bound_user_operation(
        item=bound,
        receipt=receipt,
        entrypoint_address=entrypoint,
        user_operation_event_topic=USER_OPERATION_EVENT_TOPIC,
        address_topic=address_topic,
        parse_hex_int=parse_hex_int,
    )

    receipt["logs"].append(user_operation_log(1))
    with pytest.raises(BindingIntegrityError, match="exactly one ERC-4337"):
        assert_single_successful_bound_user_operation(
            item=bound,
            receipt=receipt,
            entrypoint_address=entrypoint,
            user_operation_event_topic=USER_OPERATION_EVENT_TOPIC,
            address_topic=address_topic,
            parse_hex_int=parse_hex_int,
        )


def test_rpc_propagation_poll_returns_unknown_without_resubmission() -> None:
    bound = make_plan(item("one")).items[0]
    sleeps: list[float] = []

    class FakeHttpClient:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            return False

    def fake_rpc(client, rpc_url, method, params):
        if method == "eth_chainId":
            return hex(ARC_CHAIN_ID)
        return None

    verifier = ArcRpcVerificationPort(
        rpc_url="https://rpc.invalid.example",
        poll_attempts=3,
        poll_interval_seconds=0.25,
        sleeper=sleeps.append,
    )
    transaction_hash = "0x" + ("a" * 64)
    with (
        patch("httpx.Client", return_value=FakeHttpClient()),
        patch("scripts.verify_arc_settlement.rpc", side_effect=fake_rpc) as rpc_call,
    ):
        result = verifier.verify(bound, transaction_hash)

    assert result.status == "UNKNOWN"
    assert result.error_code == "UNKNOWN_AFTER_SUBMISSION"
    assert result.transaction_hash == transaction_hash
    assert sleeps == [0.25, 0.25]
    assert rpc_call.call_count == 7  # chain plus two reads for each of 3 attempts


def test_arc_verifier_constructor_hardens_chain_specific_inputs() -> None:
    verifier = ArcRpcVerificationPort(
        rpc_url="https://rpc.invalid.example",
    )
    assert verifier.entrypoint_address == ARC_ENTRYPOINT_ADDRESS
    assert verifier.native_usdc_address == ARC_NATIVE_USDC_ADDRESS
    assert ARC_CHAIN_ID == 5_042_002

    with pytest.raises(BatchValidationError):
        ArcRpcVerificationPort(
            rpc_url="https://rpc.invalid.example",
            entrypoint_address="not-an-address",
        )

    with pytest.raises(BatchValidationError, match="hard-coded Arc Testnet"):
        ArcRpcVerificationPort(
            rpc_url="https://rpc.invalid.example",
            entrypoint_address="0x5555555555555555555555555555555555555555",
        )
