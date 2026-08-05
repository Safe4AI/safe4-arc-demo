"""Guarded fixed-plan wrapper for the sequential Arc Testnet demo batch.

The default command is a read-only preview.  Live execution requires both
``--execute-live`` and the exact confirmation marker printed by the preview.
Before importing ``app.main`` or invoking any authorization/submission port,
the wrapper durably records the complete immutable plan (including both UUIDv4
idempotency keys) in a private, git-ignored journal and acquires an exclusive
lock.

The journal is deliberately never deleted automatically.  Any existing
journal, incomplete atomic-write file, database, or lock causes a fail-closed
stop.  There is no automatic crash recovery, resume, or retry: an operator must
inspect the private state and the external provider/chain state first.

This wrapper fixes the sender, recipient, chain, RPC endpoint, three amounts,
and purchase intents in source.  Adding a runtime flag for any of those values
would weaken the review boundary and is intentionally unsupported.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import errno
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
from typing import Any, Callable, ContextManager, Iterator, Mapping
from uuid import UUID, uuid4

# Support the documented/operator-friendly direct path invocation in addition
# to ``python -m scripts.demo_live_arc_batch_fixed``. This changes import
# resolution only; it performs no app import, journal write, CLI, or network IO.
if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.demo_live_arc_batch import (
    ARC_CHAIN,
    ARC_CHAIN_ID,
    BatchEvidence,
    BatchItemInput,
    BoundBatchItem,
    BoundBatchPlan,
    CircleCliSubmissionPort,
    LocalSafe4AuthorizationPort,
    LiveArcBatchCoordinator,
    ArcRpcVerificationPort,
    prepare_batch,
)


FIXED_BATCH_ID = "safe4-fixed-x402-demo-v1"
FIXED_SENDER = "0x3985a31e4e42a31e437c1099306decbe2f08da4d"
FIXED_RECIPIENT = "0x530271da8cc4e44375f22ad9632bc61a55382f88"
FIXED_RPC_URL = "https://rpc.testnet.arc.network"
FIXED_AMOUNT_UNITS = (1_000, 2_000, 3_000)
FIXED_TOTAL_UNITS = sum(FIXED_AMOUNT_UNITS)
FIXED_TASK = "Research competitor pricing using paid company data services."
MIN_PREFLIGHT_SENDER_BALANCE_BASE_UNITS = 100_000_000_000_000_000

# The long, exact string makes accidental execution from copied flags less
# likely.  It confirms only this source-reviewed plan; it is not a secret.
LIVE_CONFIRMATION_MARKER = (
    "EXECUTE_SAFE4_FIXED_ARC_TESTNET_0.001_0.002_0.003_USDC_SEQUENTIAL_NON_ATOMIC"
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_PRIVATE_ROOT = (REPOSITORY_ROOT / ".tmp").resolve()
DEFAULT_STATE_DIRECTORY = (
    REPOSITORY_PRIVATE_ROOT / "live-arc-fixed-batch-v1"
).resolve()
JOURNAL_FILENAME = "private-journal.json"
LOCK_FILENAME = "batch.lock"
DATABASE_FILENAME = "safe4-live.sqlite3"
JOURNAL_SCHEMA = "safe4-live-arc-private-journal-v1"

_PREPARED_STATUS = "PREPARED_BEFORE_ANY_AUTHORIZATION_OR_SUBMISSION"
_STARTED_STATUS = "EXECUTION_STARTED_NO_AUTOMATIC_RETRY"
_COMPLETE_STATUS = "COMPLETE_REVIEW_REQUIRED"
_STOPPED_STATUS = "STOPPED_NO_AUTOMATIC_RESUME"
_ABORTED_STATUS = "ABORTED_NO_AUTOMATIC_RESUME"

_SOURCE_REVISION_PATTERN = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
_CLI_VERSION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")
_UTC_PATTERN = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:"
    r"[0-9]{2}(?:\.[0-9]{1,6})?Z$"
)
_TRANSACTION_HASH_PATTERN = re.compile(r"^0x[0-9a-f]{64}$")
_SAFE4_TRANSACTION_ID_PATTERN = re.compile(r"^[0-9a-f]{32}$")
_REASON_CODE_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_PUBLIC_SECRET_PATTERNS = (
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]+=*"),
    re.compile(r"(?i)\b(?:access|refresh|receipt|spend)[_-]?token\b"),
    re.compile(r"(?i)\b(?:private[_ -]?key|mnemonic|admin[_ -]?secret|otp)\b"),
    re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"),
)


class FixedBatchSafetyError(RuntimeError):
    """A fail-closed operational guard prevented or stopped live execution."""



@dataclass(frozen=True, slots=True)
class SourceIdentity:
    revision: str
    worktree_state: str


@dataclass(frozen=True, slots=True)
class RuntimeBundle:
    authorizer: Any
    submitter: Any
    verifier: Any
    circle_cli_version: str
    circle_wallet_preflight: Mapping[str, Any]
    observe_public_balances: Callable[[str], Mapping[str, Any]]


@dataclass(frozen=True, slots=True)
class FixedRunEvidence:
    started_at_utc: str
    ended_at_utc: str
    source_revision: str
    source_worktree_state: str
    circle_cli_version: str
    circle_wallet_preflight: Mapping[str, Any]
    pre_balances: Mapping[str, Any]
    post_balances: Mapping[str, Any]
    batch: BatchEvidence

    def to_public_dict(self) -> dict[str, Any]:
        if not _UTC_PATTERN.fullmatch(self.started_at_utc):
            raise FixedBatchSafetyError("START_TIMESTAMP_INVALID")
        if not _UTC_PATTERN.fullmatch(self.ended_at_utc):
            raise FixedBatchSafetyError("END_TIMESTAMP_INVALID")
        if not _SOURCE_REVISION_PATTERN.fullmatch(self.source_revision):
            raise FixedBatchSafetyError("SOURCE_REVISION_INVALID")
        if self.source_worktree_state != "CLEAN":
            raise FixedBatchSafetyError("SOURCE_WORKTREE_NOT_CLEAN")
        if not _CLI_VERSION_PATTERN.fullmatch(self.circle_cli_version):
            raise FixedBatchSafetyError("CIRCLE_CLI_VERSION_INVALID")
        wallet_preflight = _validated_wallet_preflight(
            self.circle_wallet_preflight
        )
        pre = _validated_public_balance_observation(self.pre_balances)
        post = _validated_public_balance_observation(self.post_balances)
        return {
            "schema_version": "safe4-live-arc-fixed-run-evidence-v1",
            "started_at_utc": self.started_at_utc,
            "ended_at_utc": self.ended_at_utc,
            "source": {
                "revision": self.source_revision,
                "worktree_state": self.source_worktree_state,
            },
            "circle_cli": {
                "package": "@circle-fin/cli",
                "version": self.circle_cli_version,
                "raw_command_output_retained": False,
                "authenticated_wallet_preflight": wallet_preflight,
            },
            "fixed_settlement": {
                "chain": ARC_CHAIN,
                "chain_id": ARC_CHAIN_ID,
                "rpc_url": FIXED_RPC_URL,
                "sender": FIXED_SENDER,
                "recipient": FIXED_RECIPIENT,
                "amount_units": list(FIXED_AMOUNT_UNITS),
                "total_amount_units": FIXED_TOTAL_UNITS,
                "currency": "USDC",
            },
            "recipient_policy": {
                "coordinator": (
                    "FIXED_CODE_REVIEWED_ALLOWLIST_ENFORCED_BEFORE_EACH_SUBMISSION"
                ),
                "safe4_payment_policy": (
                    "NOT_A_GENERAL_SAFE4_RECIPIENT_ALLOWLIST_ENFORCEMENT_CLAIM"
                ),
            },
            "public_balance_observations": {
                "pre": pre,
                "post": post,
                "required_pre_sender_balance_base_units": str(
                    MIN_PREFLIGHT_SENDER_BALANCE_BASE_UNITS
                ),
                "interpretation": (
                    "PRE_IS_A_REQUIRED_GO_GATE_POST_IS_OPTIONAL_CONTEXT_NOT_SETTLEMENT_PROOF"
                ),
            },
            "x402_boundary": (
                "LOCAL_SAFE4_RECEIPT_FIXTURE_FOR_AUTHORIZATION_NOT_AN_EXTERNAL_X402_PAYMENT"
            ),
            "batch": self.batch.to_public_dict(),
        }

    def to_sanitized_json(self) -> str:
        # Run the underlying evidence sanitizer first, then scan only the
        # explicit wrapper allowlist above. Raw subprocess/RPC output is never
        # passed to this object.
        self.batch.to_sanitized_json()
        serialized = json.dumps(
            self.to_public_dict(),
            sort_keys=True,
            indent=2,
            ensure_ascii=True,
        )
        for pattern in _PUBLIC_SECRET_PATTERNS:
            if pattern.search(serialized):
                raise FixedBatchSafetyError("PUBLIC_EVIDENCE_SANITIZATION_FAILED")
        return serialized + "\n"


RuntimeFactory = Callable[
    [BoundBatchPlan, Path],
    ContextManager[RuntimeBundle],
]


def fixed_batch_inputs() -> tuple[BatchItemInput, ...]:
    """Return the only three purchase intents this wrapper may execute."""

    return (
        BatchItemInput(
            item_id="market-data",
            recipient=FIXED_RECIPIENT,
            amount_units=FIXED_AMOUNT_UNITS[0],
            vendor="synthetic_market_data",
            description=(
                "Generate competitor pricing research from paid company data "
                "for the market-data demo item."
            ),
            task=FIXED_TASK,
            service_category="market-data",
            task_id="safe4-demo-market-data",
        ),
        BatchItemInput(
            item_id="compute",
            recipient=FIXED_RECIPIENT,
            amount_units=FIXED_AMOUNT_UNITS[1],
            vendor="synthetic_compute",
            description=(
                "Analyze competitor pricing from paid company data for the "
                "compute demo item."
            ),
            task=FIXED_TASK,
            service_category="compute",
            task_id="safe4-demo-compute",
        ),
        BatchItemInput(
            item_id="agent-memory",
            recipient=FIXED_RECIPIENT,
            amount_units=FIXED_AMOUNT_UNITS[2],
            vendor="synthetic_agent_memory",
            description=(
                "Store competitor pricing research from paid company data for "
                "the agent-memory demo item."
            ),
            task=FIXED_TASK,
            service_category="agent-memory",
            task_id="safe4-demo-agent-memory",
        ),
    )


def build_fixed_plan(
    *,
    key_factory: Callable[[], UUID | str] = uuid4,
) -> BoundBatchPlan:
    """Build the source-fixed plan and bind six distinct UUIDv4 keys."""

    plan = prepare_batch(
        batch_id=FIXED_BATCH_ID,
        sender=FIXED_SENDER,
        recipient_allowlist=(FIXED_RECIPIENT,),
        items=fixed_batch_inputs(),
        key_factory=key_factory,
    )
    plan.assert_integrity()
    if tuple(item.amount_units for item in plan.items) != FIXED_AMOUNT_UNITS:
        raise FixedBatchSafetyError("FIXED_PLAN_INTEGRITY_FAILED")
    if any(item.recipient != FIXED_RECIPIENT for item in plan.items):
        raise FixedBatchSafetyError("FIXED_PLAN_INTEGRITY_FAILED")
    if plan.sender != FIXED_SENDER:
        raise FixedBatchSafetyError("FIXED_PLAN_INTEGRITY_FAILED")
    return plan


def public_preview() -> dict[str, Any]:
    """Return an allowlisted preview without generating keys or touching disk."""

    inputs = fixed_batch_inputs()
    return {
        "schema_version": "safe4-live-arc-fixed-preview-v1",
        "mode": "PREVIEW_ONLY_NO_AUTHORIZATION_NO_CLI_NO_NETWORK",
        "execution_enabled": False,
        "confirmation_required": LIVE_CONFIRMATION_MARKER,
        "chain": ARC_CHAIN,
        "chain_id": ARC_CHAIN_ID,
        "rpc_url": FIXED_RPC_URL,
        "sender": FIXED_SENDER,
        "recipient": FIXED_RECIPIENT,
        "currency": "USDC",
        "execution_model": "SEQUENTIAL_NON_ATOMIC_STOP_ON_FIRST_FAILURE",
        "automatic_resume": False,
        "automatic_retry_after_unknown": False,
        "source_revision": "CAPTURED_FROM_CLEAN_WORKTREE_AT_EXECUTION",
        "circle_cli_version": "STRICTLY_PARSED_AT_EXECUTION",
        "preflight_arc_rpc": {
            "required_chain_id": ARC_CHAIN_ID,
            "required_sender_balance_base_units": str(
                MIN_PREFLIGHT_SENDER_BALANCE_BASE_UNITS
            ),
            "required_before_first_pay": True,
        },
        "post_public_balance_observation": "OPTIONAL_READ_ONLY_RPC_CONTEXT",
        "journal_policy": (
            "PRIVATE_DURABLE_PLAN_BEFORE_AUTHORIZATION_AND_SUBMISSION"
        ),
        "recipient_policy": {
            "coordinator": "FIXED_CODE_REVIEWED_ALLOWLIST_ENFORCED",
            "safe4_payment_policy": (
                "NOT_A_GENERAL_SAFE4_RECIPIENT_ALLOWLIST_ENFORCEMENT_CLAIM"
            ),
        },
        "items": [
            {
                "sequence": sequence,
                "item_id": item.item_id,
                "vendor": item.vendor,
                "service_category": item.service_category,
                "amount_units": item.amount_units,
                "amount_usdc": f"{item.amount_units / 1_000_000:.6f}",
            }
            for sequence, item in enumerate(inputs, start=1)
        ],
        "total_amount_units": FIXED_TOTAL_UNITS,
        "total_amount_usdc": f"{FIXED_TOTAL_UNITS / 1_000_000:.6f}",
        "limitations": [
            "Three sequential transfers to one approved recipient; not an atomic multi-send.",
            "A crash or UNKNOWN result requires manual provider and chain review.",
            (
                "Safe4 local receipt issuance is an authorization fixture, "
                "not an external x402 settlement."
            ),
        ],
    }


def _plan_journal_payload(plan: BoundBatchPlan) -> dict[str, Any]:
    """Return the exact private plan, including both keys for every item."""

    plan.assert_integrity()
    return {
        "plan_hash": plan.plan_hash,
        "plan_document": plan.plan_document(),
        "items": [
            {
                "binding_hash": item.binding_hash,
                "binding_document": item.binding_document(),
            }
            for item in plan.items
        ],
    }


def _journal_document(
    plan: BoundBatchPlan,
    *,
    status: str,
    started_at_utc: str,
    source_identity: SourceIdentity,
    runtime_metadata: Mapping[str, Any] | None = None,
    execution_progress: Mapping[str, Any] | None = None,
    evidence: FixedRunEvidence | None = None,
) -> dict[str, Any]:
    document: dict[str, Any] = {
        "schema_version": JOURNAL_SCHEMA,
        "status": status,
        "resume_policy": "NEVER_AUTOMATICALLY_RESUME_OR_RETRY",
        "execution_confirmation": LIVE_CONFIRMATION_MARKER,
        "fixed_rpc_url": FIXED_RPC_URL,
        "started_at_utc": started_at_utc,
        "source": {
            "revision": source_identity.revision,
            "worktree_state": source_identity.worktree_state,
        },
        "exact_private_plan": _plan_journal_payload(plan),
        "execution_progress": dict(
            execution_progress or _initial_execution_progress(plan)
        ),
    }
    if runtime_metadata is not None:
        document["runtime_metadata"] = dict(runtime_metadata)
    if evidence is not None:
        # FixedRunEvidence constructs this from an allowlist and performs its
        # own sanitization check. UUID keys and tokens are not public fields.
        evidence.to_sanitized_json()
        document["sanitized_public_evidence"] = evidence.to_public_dict()
    return document


def _canonical_json_bytes(document: dict[str, Any]) -> bytes:
    return (
        json.dumps(
            document,
            sort_keys=True,
            indent=2,
            ensure_ascii=True,
        )
        + "\n"
    ).encode("utf-8")


def _fsync_directory(directory: Path) -> None:
    """Best-effort parent-directory flush; unsupported on some Windows APIs."""

    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    try:
        descriptor = os.open(str(directory), flags)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    except OSError:
        pass
    finally:
        os.close(descriptor)


def _atomic_write_private_json(
    path: Path,
    document: dict[str, Any],
    *,
    replacing: bool,
) -> None:
    """Durably replace one private JSON file without deleting crash remnants."""

    if replacing and not path.is_file():
        raise FixedBatchSafetyError("PRIVATE_JOURNAL_MISSING")
    if not replacing and path.exists():
        raise FixedBatchSafetyError("PRIVATE_JOURNAL_ALREADY_EXISTS")

    temporary = path.with_name(f"{path.name}.tmp-{uuid4().hex}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        descriptor = os.open(str(temporary), flags, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(_canonical_json_bytes(document))
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        # For the initial write, re-check immediately before the atomic rename.
        if not replacing and path.exists():
            raise FixedBatchSafetyError("PRIVATE_JOURNAL_ALREADY_EXISTS")
        os.replace(temporary, path)
        os.chmod(path, 0o600)
        _fsync_directory(path.parent)
    except FixedBatchSafetyError:
        # Keep the temporary file as an incomplete-journal canary.  The next
        # invocation must stop for manual inspection.
        raise
    except OSError as exc:
        # Do not leak filesystem or user details through the public error.
        raise FixedBatchSafetyError("PRIVATE_JOURNAL_WRITE_FAILED") from exc


def _load_private_journal(path: Path) -> dict[str, Any]:
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise FixedBatchSafetyError("PRIVATE_JOURNAL_INVALID") from exc
    if not isinstance(loaded, dict):
        raise FixedBatchSafetyError("PRIVATE_JOURNAL_INVALID")
    return loaded


def _assert_journal_matches(
    path: Path,
    plan: BoundBatchPlan,
    *,
    expected_status: str,
) -> None:
    loaded = _load_private_journal(path)
    if loaded.get("schema_version") != JOURNAL_SCHEMA:
        raise FixedBatchSafetyError("PRIVATE_JOURNAL_INVALID")
    if loaded.get("status") != expected_status:
        raise FixedBatchSafetyError("PRIVATE_JOURNAL_STATUS_MISMATCH")
    if loaded.get("exact_private_plan") != _plan_journal_payload(plan):
        raise FixedBatchSafetyError("PRIVATE_JOURNAL_PLAN_MISMATCH")


def _initial_execution_progress(plan: BoundBatchPlan) -> dict[str, Any]:
    return {
        "transition_count": 0,
        "items": [
            {
                "sequence": item.sequence,
                "item_id": item.item_id,
                "binding_hash": item.binding_hash,
                "latest_phase": "NOT_STARTED",
                "transitions": [],
            }
            for item in plan.items
        ],
    }


def _transition_reason_code(value: Any, *, fallback: str) -> str:
    candidate = str(value or "").strip().upper()
    return candidate if _REASON_CODE_PATTERN.fullmatch(candidate) else fallback


def _validated_transition_details(details: Mapping[str, Any]) -> dict[str, Any]:
    allowed = {
        "status",
        "reason_code",
        "error_code",
        "safe4_transaction_id",
        "transaction_hash",
        "block_number",
        "binding_hash_matches",
    }
    if not isinstance(details, Mapping) or not set(details).issubset(allowed):
        raise FixedBatchSafetyError("PRIVATE_JOURNAL_TRANSITION_INVALID")
    sanitized: dict[str, Any] = {}
    if "status" in details:
        status = str(details.get("status") or "").strip().upper()
        sanitized["status"] = status if status in {
            "AUTHORIZED",
            "DENIED",
            "SUBMITTED",
            "VERIFIED",
            "FAILED",
            "UNKNOWN",
        } else "UNKNOWN"
    if "reason_code" in details:
        sanitized["reason_code"] = _transition_reason_code(
            details.get("reason_code"),
            fallback="UNCLASSIFIED_REASON",
        )
    if "error_code" in details and details.get("error_code"):
        sanitized["error_code"] = _transition_reason_code(
            details.get("error_code"),
            fallback="UNCLASSIFIED_ERROR",
        )
    safe4_id = str(details.get("safe4_transaction_id") or "").strip()
    if safe4_id and _SAFE4_TRANSACTION_ID_PATTERN.fullmatch(safe4_id):
        sanitized["safe4_transaction_id"] = safe4_id
    transaction_hash = str(details.get("transaction_hash") or "").strip().lower()
    if transaction_hash and _TRANSACTION_HASH_PATTERN.fullmatch(transaction_hash):
        sanitized["transaction_hash"] = transaction_hash
    if "block_number" in details:
        block_number = details.get("block_number")
        if (
            not isinstance(block_number, bool)
            and isinstance(block_number, int)
            and block_number >= 0
        ):
            sanitized["block_number"] = block_number
    if "binding_hash_matches" in details:
        sanitized["binding_hash_matches"] = details.get("binding_hash_matches") is True
    return sanitized


class _DurableProgressJournal:
    """Synchronously persist every settlement-bound execution transition."""

    _PHASES = frozenset(
        {
            "AUTHORIZATION_STARTED",
            "AUTHORIZATION_RESULT",
            "AUTHORIZATION_EXCEPTION",
            "SUBMISSION_STARTED",
            "SUBMISSION_RESULT",
            "SUBMISSION_EXCEPTION",
            "VERIFICATION_STARTED",
            "VERIFICATION_RESULT",
            "VERIFICATION_EXCEPTION",
        }
    )

    def __init__(
        self,
        *,
        journal_path: Path,
        plan: BoundBatchPlan,
        started_at_utc: str,
        source_identity: SourceIdentity,
        runtime_metadata: Mapping[str, Any],
    ) -> None:
        self.journal_path = journal_path
        self.plan = plan
        self.started_at_utc = started_at_utc
        self.source_identity = source_identity
        self.runtime_metadata = dict(runtime_metadata)
        self.progress = _initial_execution_progress(plan)
        self._healthy = True

    def record(
        self,
        item: BoundBatchItem,
        phase: str,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        if phase not in self._PHASES:
            raise FixedBatchSafetyError("PRIVATE_JOURNAL_TRANSITION_INVALID")
        item.assert_integrity()
        planned = next(
            (
                planned_item
                for planned_item in self.plan.items
                if planned_item.item_id == item.item_id
            ),
            None,
        )
        if planned is None or planned != item:
            raise FixedBatchSafetyError("PRIVATE_JOURNAL_ITEM_MISMATCH")
        entry = self.progress["items"][item.sequence - 1]
        if entry["binding_hash"] != item.binding_hash:
            raise FixedBatchSafetyError("PRIVATE_JOURNAL_ITEM_MISMATCH")
        self.progress["transition_count"] += 1
        transition: dict[str, Any] = {
            "ordinal": self.progress["transition_count"],
            "phase": phase,
        }
        transition.update(_validated_transition_details(details or {}))
        entry["latest_phase"] = phase
        entry["transitions"].append(transition)
        document = _journal_document(
            self.plan,
            status=_STARTED_STATUS,
            started_at_utc=self.started_at_utc,
            source_identity=self.source_identity,
            runtime_metadata=self.runtime_metadata,
            execution_progress=self.progress,
        )
        try:
            _atomic_write_private_json(
                self.journal_path,
                document,
                replacing=True,
            )
            _assert_journal_matches(
                self.journal_path,
                self.plan,
                expected_status=_STARTED_STATUS,
            )
        except Exception:
            self._healthy = False
            raise

    def assert_healthy(self) -> None:
        if not self._healthy:
            raise FixedBatchSafetyError("PRIVATE_JOURNAL_TRANSITION_WRITE_FAILED")


class _JournaledAuthorizationPort:
    def __init__(self, wrapped: Any, progress: _DurableProgressJournal) -> None:
        self.wrapped = wrapped
        self.progress = progress

    def authorize(self, item: BoundBatchItem) -> Any:
        self.progress.record(item, "AUTHORIZATION_STARTED")
        try:
            result = self.wrapped.authorize(item)
        except Exception:
            self.progress.record(
                item,
                "AUTHORIZATION_EXCEPTION",
                {"status": "UNKNOWN", "error_code": "AUTHORIZATION_EXCEPTION"},
            )
            raise
        self.progress.record(
            item,
            "AUTHORIZATION_RESULT",
            {
                "status": getattr(result, "status", "UNKNOWN"),
                "reason_code": getattr(
                    result,
                    "reason_code",
                    "AUTHORIZATION_RESULT_INVALID",
                ),
                "safe4_transaction_id": getattr(
                    result,
                    "safe4_transaction_id",
                    None,
                ),
                "binding_hash_matches": (
                    getattr(result, "binding_hash", None) == item.binding_hash
                ),
            },
        )
        return result


class _JournaledSubmissionPort:
    def __init__(self, wrapped: Any, progress: _DurableProgressJournal) -> None:
        self.wrapped = wrapped
        self.progress = progress

    def submit(self, item: BoundBatchItem) -> Any:
        self.progress.record(item, "SUBMISSION_STARTED")
        try:
            result = self.wrapped.submit(item)
        except Exception:
            # Once the CLI call starts, absence of a returned hash is UNKNOWN,
            # never evidence that no provider request was accepted.
            self.progress.record(
                item,
                "SUBMISSION_EXCEPTION",
                {"status": "UNKNOWN", "error_code": "SUBMISSION_EXCEPTION"},
            )
            raise
        self.progress.record(
            item,
            "SUBMISSION_RESULT",
            {
                "status": getattr(result, "status", "UNKNOWN"),
                "transaction_hash": getattr(result, "transaction_hash", None),
                "error_code": getattr(result, "error_code", None),
                "binding_hash_matches": (
                    getattr(result, "binding_hash", None) == item.binding_hash
                ),
            },
        )
        return result


class _JournaledVerificationPort:
    def __init__(self, wrapped: Any, progress: _DurableProgressJournal) -> None:
        self.wrapped = wrapped
        self.progress = progress

    def verify(self, item: BoundBatchItem, transaction_hash: str) -> Any:
        self.progress.record(
            item,
            "VERIFICATION_STARTED",
            {"transaction_hash": transaction_hash},
        )
        try:
            result = self.wrapped.verify(item, transaction_hash)
        except Exception:
            self.progress.record(
                item,
                "VERIFICATION_EXCEPTION",
                {
                    "status": "UNKNOWN",
                    "transaction_hash": transaction_hash,
                    "error_code": "VERIFICATION_EXCEPTION",
                },
            )
            raise
        self.progress.record(
            item,
            "VERIFICATION_RESULT",
            {
                "status": getattr(result, "status", "UNKNOWN"),
                "transaction_hash": getattr(
                    result,
                    "transaction_hash",
                    transaction_hash,
                ),
                "block_number": getattr(result, "block_number", None),
                "error_code": getattr(result, "error_code", None),
                "binding_hash_matches": (
                    getattr(result, "binding_hash", None) == item.binding_hash
                ),
            },
        )
        return result


class _ExclusiveFileLock:
    """Crash-sticky lock: normal exit removes it, process death leaves it."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._descriptor: int | None = None

    def __enter__(self) -> "_ExclusiveFileLock":
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        try:
            self._descriptor = os.open(str(self.path), flags, 0o600)
        except OSError as exc:
            if exc.errno == errno.EEXIST:
                raise FixedBatchSafetyError("EXCLUSIVE_BATCH_LOCK_HELD") from exc
            raise FixedBatchSafetyError("EXCLUSIVE_BATCH_LOCK_FAILED") from exc
        try:
            os.write(self._descriptor, b"SAFE4_FIXED_LIVE_BATCH_LOCK\n")
            os.fsync(self._descriptor)
            os.chmod(self.path, 0o600)
            _fsync_directory(self.path.parent)
        except OSError as exc:
            os.close(self._descriptor)
            self._descriptor = None
            # Retain the partially created lock as a crash/incomplete-state
            # canary; never guess that execution can safely restart.
            raise FixedBatchSafetyError("EXCLUSIVE_BATCH_LOCK_FAILED") from exc
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        if self._descriptor is not None:
            os.close(self._descriptor)
            self._descriptor = None
        try:
            self.path.unlink()
            _fsync_directory(self.path.parent)
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise FixedBatchSafetyError("EXCLUSIVE_BATCH_LOCK_RELEASE_FAILED") from exc


def _resolve_private_state_directory(
    state_directory: Path | None,
    *,
    private_root: Path,
) -> Path:
    resolved_root = private_root.resolve()
    resolved_state = (state_directory or DEFAULT_STATE_DIRECTORY).resolve()
    if resolved_state == resolved_root or resolved_root not in resolved_state.parents:
        raise FixedBatchSafetyError("PRIVATE_STATE_DIRECTORY_OUTSIDE_APPROVED_ROOT")
    return resolved_state


def _prepare_private_directory(state_directory: Path) -> None:
    try:
        state_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(state_directory, 0o700)
    except OSError as exc:
        raise FixedBatchSafetyError("PRIVATE_STATE_DIRECTORY_UNAVAILABLE") from exc


def _refuse_prior_or_incomplete_state(
    state_directory: Path,
    *,
    lock_path: Path,
) -> None:
    allowed_during_lock = {lock_path.name}
    try:
        unexpected = [
            entry
            for entry in state_directory.iterdir()
            if entry.name not in allowed_during_lock
        ]
    except OSError as exc:
        raise FixedBatchSafetyError("PRIVATE_STATE_DIRECTORY_UNAVAILABLE") from exc
    if unexpected:
        raise FixedBatchSafetyError("PRIOR_OR_INCOMPLETE_PRIVATE_STATE_EXISTS")


def _utc_timestamp(clock: Callable[[], datetime]) -> str:
    observed = clock()
    if observed.tzinfo is None:
        raise FixedBatchSafetyError("UTC_CLOCK_INVALID")
    normalized = observed.astimezone(timezone.utc)
    return normalized.isoformat(timespec="seconds").replace("+00:00", "Z")


def _assert_circle_proxy_disabled() -> None:
    # @circle-fin/cli 0.0.6 treats this as an alternate API transport for both
    # wallet-list and transfer requests. Even an empty ambient override is
    # refused so the authenticated CLI boundary cannot be silently rerouted.
    if "CIRCLE_PROXY_URL" in os.environ:
        raise FixedBatchSafetyError("CIRCLE_PROXY_URL_FORBIDDEN")


def observe_clean_source_identity(
    *,
    command_runner: Callable[..., Any] = subprocess.run,
) -> SourceIdentity:
    """Read a strict local Git identity without retaining command output."""

    try:
        revision_process = command_runner(
            [
                "git",
                "-C",
                str(REPOSITORY_ROOT),
                "rev-parse",
                "--verify",
                "HEAD",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if getattr(revision_process, "returncode", 1) != 0:
            raise FixedBatchSafetyError("SOURCE_REVISION_UNAVAILABLE")
        revision = str(getattr(revision_process, "stdout", "")).strip().lower()
        if not _SOURCE_REVISION_PATTERN.fullmatch(revision):
            raise FixedBatchSafetyError("SOURCE_REVISION_INVALID")

        status_process = command_runner(
            [
                "git",
                "-C",
                str(REPOSITORY_ROOT),
                "status",
                "--porcelain=v1",
                "--untracked-files=normal",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if getattr(status_process, "returncode", 1) != 0:
            raise FixedBatchSafetyError("SOURCE_WORKTREE_STATE_UNAVAILABLE")
        # Filenames in porcelain output are intentionally neither returned nor
        # persisted. A live run is allowed only when there are none.
        if str(getattr(status_process, "stdout", "")).strip():
            raise FixedBatchSafetyError("SOURCE_WORKTREE_NOT_CLEAN")
    except FixedBatchSafetyError:
        raise
    except (OSError, subprocess.SubprocessError) as exc:
        raise FixedBatchSafetyError("SOURCE_IDENTITY_UNAVAILABLE") from exc
    return SourceIdentity(revision=revision, worktree_state="CLEAN")


def _parse_circle_cli_version(raw_output: str) -> str:
    """Extract only one semver from a bounded Circle CLI version response."""

    candidate = raw_output.strip()
    if len(candidate) > 1_000:
        raise FixedBatchSafetyError("CIRCLE_CLI_VERSION_INVALID")
    try:
        payload = json.loads(candidate)
    except json.JSONDecodeError:
        payload = None
    if isinstance(payload, Mapping):
        json_version = payload.get("version")
        if isinstance(json_version, str) and _CLI_VERSION_PATTERN.fullmatch(
            json_version.strip()
        ):
            return json_version.strip()

    exact = candidate.removeprefix("v")
    if _CLI_VERSION_PATTERN.fullmatch(exact):
        return exact
    version_text = r"([0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?)"
    matches = re.findall(
        rf"(?i)(?:@circle-fin/cli|circle)(?:/|\s+version\s+|\s+v?){version_text}",
        candidate,
    )
    unique = {match for match in matches if _CLI_VERSION_PATTERN.fullmatch(match)}
    if len(unique) != 1:
        raise FixedBatchSafetyError("CIRCLE_CLI_VERSION_INVALID")
    return unique.pop()


def observe_circle_cli_version(
    circle_executable: str,
    *,
    command_runner: Callable[..., Any] = subprocess.run,
) -> str:
    """Run a non-transfer version command and immediately discard raw output."""

    try:
        completed = command_runner(
            [circle_executable, "--version"],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise FixedBatchSafetyError("CIRCLE_CLI_VERSION_UNAVAILABLE") from exc
    if getattr(completed, "returncode", 1) != 0:
        raise FixedBatchSafetyError("CIRCLE_CLI_VERSION_UNAVAILABLE")
    return _parse_circle_cli_version(str(getattr(completed, "stdout", "")))


def _validated_wallet_preflight(observation: Mapping[str, Any]) -> dict[str, Any]:
    expected = {
        "status",
        "source",
        "address",
        "blockchain",
        "raw_command_output_retained",
    }
    if not isinstance(observation, Mapping) or set(observation) != expected:
        raise FixedBatchSafetyError("CIRCLE_WALLET_PREFLIGHT_INVALID")
    if observation.get("status") != "VERIFIED":
        raise FixedBatchSafetyError("CIRCLE_WALLET_PREFLIGHT_FAILED")
    if observation.get("source") != "AUTHENTICATED_CIRCLE_CLI_WALLET_LIST":
        raise FixedBatchSafetyError("CIRCLE_WALLET_PREFLIGHT_INVALID")
    if str(observation.get("address", "")).lower() != FIXED_SENDER:
        raise FixedBatchSafetyError("CIRCLE_WALLET_PREFLIGHT_SENDER_MISMATCH")
    if str(observation.get("blockchain", "")).upper() != ARC_CHAIN:
        raise FixedBatchSafetyError("CIRCLE_WALLET_PREFLIGHT_CHAIN_MISMATCH")
    if observation.get("raw_command_output_retained") is not False:
        raise FixedBatchSafetyError("CIRCLE_WALLET_PREFLIGHT_INVALID")
    return {
        "status": "VERIFIED",
        "source": "AUTHENTICATED_CIRCLE_CLI_WALLET_LIST",
        "address": FIXED_SENDER,
        "blockchain": ARC_CHAIN,
        "raw_command_output_retained": False,
    }


def verify_fixed_circle_wallet_preflight(
    circle_executable: str,
    *,
    command_runner: Callable[..., Any] = subprocess.run,
) -> dict[str, Any]:
    """Require the authenticated CLI to list the exact fixed Arc wallet.

    Only the exact ``{"data": {"wallets": [...]}}`` envelope is accepted.
    Wallet identifiers and all raw stdout/stderr are discarded immediately.
    A successful list command is the authentication observation; the fixed
    address and Arc Testnet fields bind it to this wrapper's source wallet.
    """

    try:
        completed = command_runner(
            [
                circle_executable,
                "wallet",
                "list",
                "--chain",
                ARC_CHAIN,
                "--type",
                "agent",
                "--output",
                "json",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise FixedBatchSafetyError("CIRCLE_WALLET_PREFLIGHT_UNAVAILABLE") from exc
    if getattr(completed, "returncode", 1) != 0:
        raise FixedBatchSafetyError("CIRCLE_WALLET_PREFLIGHT_UNAVAILABLE")
    raw_output = str(getattr(completed, "stdout", ""))
    if len(raw_output) > 1_000_000:
        raise FixedBatchSafetyError("CIRCLE_WALLET_PREFLIGHT_INVALID")
    try:
        payload = json.loads(raw_output)
    except (json.JSONDecodeError, TypeError) as exc:
        raise FixedBatchSafetyError("CIRCLE_WALLET_PREFLIGHT_INVALID") from exc
    if not isinstance(payload, Mapping) or set(payload) != {"data"}:
        raise FixedBatchSafetyError("CIRCLE_WALLET_PREFLIGHT_INVALID")
    data = payload.get("data")
    if not isinstance(data, Mapping) or set(data) != {"wallets"}:
        raise FixedBatchSafetyError("CIRCLE_WALLET_PREFLIGHT_INVALID")
    wallets = data.get("wallets")
    if not isinstance(wallets, list) or not wallets or len(wallets) > 1_000:
        raise FixedBatchSafetyError("CIRCLE_WALLET_PREFLIGHT_INVALID")

    matching = []
    for wallet in wallets:
        if not isinstance(wallet, Mapping):
            raise FixedBatchSafetyError("CIRCLE_WALLET_PREFLIGHT_INVALID")
        address = wallet.get("address")
        blockchain = wallet.get("blockchain")
        wallet_type = wallet.get("type")
        if (
            isinstance(address, str)
            and isinstance(blockchain, str)
            and wallet_type == "agent"
            and address.lower() == FIXED_SENDER
            and blockchain.upper() == ARC_CHAIN
        ):
            matching.append(wallet)
    if len(matching) != 1:
        raise FixedBatchSafetyError("CIRCLE_WALLET_PREFLIGHT_FIXED_WALLET_NOT_FOUND")
    # Return only public allowlisted facts, never the wallet object itself.
    return _validated_wallet_preflight(
        {
            "status": "VERIFIED",
            "source": "AUTHENTICATED_CIRCLE_CLI_WALLET_LIST",
            "address": FIXED_SENDER,
            "blockchain": ARC_CHAIN,
            "raw_command_output_retained": False,
        }
    )


def _validated_public_balance_observation(
    observation: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(observation, Mapping):
        raise FixedBatchSafetyError("PUBLIC_BALANCE_OBSERVATION_INVALID")
    status = observation.get("status")
    stage = observation.get("stage")
    if stage not in {"PRE", "POST"}:
        raise FixedBatchSafetyError("PUBLIC_BALANCE_OBSERVATION_INVALID")
    if status == "NOT_OBSERVED":
        if set(observation) != {"status", "stage", "reason_code"}:
            raise FixedBatchSafetyError("PUBLIC_BALANCE_OBSERVATION_INVALID")
        if observation.get("reason_code") != "PUBLIC_BALANCE_RPC_UNAVAILABLE":
            raise FixedBatchSafetyError("PUBLIC_BALANCE_OBSERVATION_INVALID")
        return dict(observation)
    expected_keys = {
        "status",
        "stage",
        "chain_id",
        "block_number",
        "block_tag",
        "unit",
        "sender_balance_base_units",
        "recipient_balance_base_units",
    }
    if status != "OBSERVED" or set(observation) != expected_keys:
        raise FixedBatchSafetyError("PUBLIC_BALANCE_OBSERVATION_INVALID")
    if observation.get("chain_id") != ARC_CHAIN_ID:
        raise FixedBatchSafetyError("PUBLIC_BALANCE_CHAIN_ID_MISMATCH")
    block_number = observation.get("block_number")
    block_tag = observation.get("block_tag")
    if isinstance(block_number, bool) or not isinstance(block_number, int):
        raise FixedBatchSafetyError("PUBLIC_BALANCE_OBSERVATION_INVALID")
    if block_number < 0 or block_tag != hex(block_number):
        raise FixedBatchSafetyError("PUBLIC_BALANCE_OBSERVATION_INVALID")
    if observation.get("unit") != "ARC_NATIVE_USDC_18_DECIMAL_BASE_UNITS":
        raise FixedBatchSafetyError("PUBLIC_BALANCE_OBSERVATION_INVALID")
    for key in ("sender_balance_base_units", "recipient_balance_base_units"):
        value = observation.get(key)
        if not isinstance(value, str) or not re.fullmatch(r"[0-9]{1,80}", value):
            raise FixedBatchSafetyError("PUBLIC_BALANCE_OBSERVATION_INVALID")
    return dict(observation)


class ArcPublicBalanceObserver:
    """Read-only Arc chain and balance context at one fixed block.

    The wrapper treats the PRE observation as a mandatory GO gate and the POST
    observation as best-effort context.
    """

    def __init__(self, *, rpc_url: str = FIXED_RPC_URL) -> None:
        if rpc_url != FIXED_RPC_URL:
            raise FixedBatchSafetyError("FIXED_RPC_URL_MISMATCH")
        self.rpc_url = rpc_url

    @staticmethod
    def _rpc(client: Any, method: str, params: list[Any], request_id: int) -> Any:
        response = client.post(
            FIXED_RPC_URL,
            json={
                "jsonrpc": "2.0",
                "id": request_id,
                "method": method,
                "params": params,
            },
        )
        response.raise_for_status()
        payload = response.json()
        if (
            not isinstance(payload, Mapping)
            or payload.get("id") != request_id
            or "error" in payload
            or "result" not in payload
        ):
            raise ValueError("invalid RPC response")
        return payload["result"]

    def __call__(self, stage: str) -> Mapping[str, Any]:
        normalized_stage = str(stage).upper()
        if normalized_stage not in {"PRE", "POST"}:
            raise FixedBatchSafetyError("PUBLIC_BALANCE_STAGE_INVALID")
        try:
            import httpx

            with httpx.Client(timeout=15.0) as client:
                chain_raw = self._rpc(client, "eth_chainId", [], 1)
                if not isinstance(chain_raw, str) or not re.fullmatch(
                    r"0x[0-9a-fA-F]+", chain_raw
                ):
                    raise ValueError("invalid chain ID")
                if int(chain_raw, 16) != ARC_CHAIN_ID:
                    raise ValueError("unexpected chain ID")
                block_raw = self._rpc(client, "eth_blockNumber", [], 2)
                if not isinstance(block_raw, str) or not re.fullmatch(
                    r"0x[0-9a-fA-F]+", block_raw
                ):
                    raise ValueError("invalid block number")
                block_number = int(block_raw, 16)
                block_tag = hex(block_number)
                sender_raw = self._rpc(
                    client,
                    "eth_getBalance",
                    [FIXED_SENDER, block_tag],
                    3,
                )
                recipient_raw = self._rpc(
                    client,
                    "eth_getBalance",
                    [FIXED_RECIPIENT, block_tag],
                    4,
                )
                for value in (sender_raw, recipient_raw):
                    if not isinstance(value, str) or not re.fullmatch(
                        r"0x[0-9a-fA-F]+", value
                    ):
                        raise ValueError("invalid balance")
                observed = {
                    "status": "OBSERVED",
                    "stage": normalized_stage,
                    "chain_id": ARC_CHAIN_ID,
                    "block_number": block_number,
                    "block_tag": block_tag,
                    "unit": "ARC_NATIVE_USDC_18_DECIMAL_BASE_UNITS",
                    "sender_balance_base_units": str(int(sender_raw, 16)),
                    "recipient_balance_base_units": str(int(recipient_raw, 16)),
                }
                return _validated_public_balance_observation(observed)
        except Exception:
            return {
                "status": "NOT_OBSERVED",
                "stage": normalized_stage,
                "reason_code": "PUBLIC_BALANCE_RPC_UNAVAILABLE",
            }


def _observe_balances_safely(
    observer: Callable[[str], Mapping[str, Any]],
    stage: str,
) -> dict[str, Any]:
    try:
        return _validated_public_balance_observation(observer(stage))
    except Exception:
        return {
            "status": "NOT_OBSERVED",
            "stage": stage,
            "reason_code": "PUBLIC_BALANCE_RPC_UNAVAILABLE",
        }


def _assert_required_preflight_balance(observation: Mapping[str, Any]) -> None:
    if observation.get("status") != "OBSERVED":
        raise FixedBatchSafetyError("PREFLIGHT_ARC_RPC_REQUIRED")
    validated = _validated_public_balance_observation(observation)
    if validated["stage"] != "PRE" or validated["chain_id"] != ARC_CHAIN_ID:
        raise FixedBatchSafetyError("PREFLIGHT_ARC_CHAIN_ID_MISMATCH")
    sender_balance = int(validated["sender_balance_base_units"])
    if sender_balance < MIN_PREFLIGHT_SENDER_BALANCE_BASE_UNITS:
        raise FixedBatchSafetyError("PREFLIGHT_SENDER_BALANCE_TOO_LOW")


def run_read_only_preflight(
    *,
    source_identity_factory: Callable[[], SourceIdentity] = observe_clean_source_identity,
    circle_locator: Callable[[str], str | None] = shutil.which,
    circle_version_observer: Callable[[str], str] = observe_circle_cli_version,
    wallet_observer: Callable[[str], Mapping[str, Any]] = (
        verify_fixed_circle_wallet_preflight
    ),
    balance_observer: Callable[[str], Mapping[str, Any]] | None = None,
    clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> dict[str, Any]:
    """Check external prerequisites without creating executable private state."""

    _assert_circle_proxy_disabled()
    source = source_identity_factory()
    if not _SOURCE_REVISION_PATTERN.fullmatch(source.revision):
        raise FixedBatchSafetyError("SOURCE_REVISION_INVALID")
    if source.worktree_state != "CLEAN":
        raise FixedBatchSafetyError("SOURCE_WORKTREE_NOT_CLEAN")
    circle_executable = circle_locator("circle")
    if not circle_executable:
        raise FixedBatchSafetyError("CIRCLE_CLI_NOT_FOUND")
    circle_version = circle_version_observer(circle_executable)
    if not _CLI_VERSION_PATTERN.fullmatch(circle_version):
        raise FixedBatchSafetyError("CIRCLE_CLI_VERSION_INVALID")
    wallet = _validated_wallet_preflight(wallet_observer(circle_executable))
    observer = balance_observer or ArcPublicBalanceObserver()
    pre_balance = _observe_balances_safely(observer, "PRE")
    _assert_required_preflight_balance(pre_balance)

    public = {
        "schema_version": "safe4-live-arc-read-only-preflight-v1",
        "mode": "READ_ONLY_NO_KEYS_NO_JOURNAL_NO_APP_NO_PAY_NO_TRANSFER",
        "observed_at_utc": _utc_timestamp(clock),
        "go": True,
        "source": {
            "revision": source.revision,
            "worktree_state": source.worktree_state,
        },
        "circle_cli": {
            "package": "@circle-fin/cli",
            "version": circle_version,
            "authenticated_wallet": wallet,
            "raw_command_output_retained": False,
        },
        "arc_rpc": {
            "rpc_url": FIXED_RPC_URL,
            "required_chain_id": ARC_CHAIN_ID,
            "required_sender_balance_base_units": str(
                MIN_PREFLIGHT_SENDER_BALANCE_BASE_UNITS
            ),
            "observation": pre_balance,
        },
        "fixed_plan": {
            "sender": FIXED_SENDER,
            "recipient": FIXED_RECIPIENT,
            "amount_units": list(FIXED_AMOUNT_UNITS),
            "total_amount_units": FIXED_TOTAL_UNITS,
            "currency": "USDC",
            "execution_model": "SEQUENTIAL_NON_ATOMIC_STOP_ON_FIRST_FAILURE",
        },
        "recipient_policy": {
            "coordinator": "FIXED_CODE_REVIEWED_ALLOWLIST_ENFORCED",
            "safe4_payment_policy": (
                "NOT_A_GENERAL_SAFE4_RECIPIENT_ALLOWLIST_ENFORCEMENT_CLAIM"
            ),
        },
    }
    serialized = json.dumps(public, sort_keys=True, ensure_ascii=True)
    for pattern in _PUBLIC_SECRET_PATTERNS:
        if pattern.search(serialized):
            raise FixedBatchSafetyError("PUBLIC_EVIDENCE_SANITIZATION_FAILED")
    return public


def configure_isolated_environment(database_path: Path) -> None:
    """Discard ambient Safe4 config and install fixed local app settings."""

    _assert_circle_proxy_disabled()
    for name in tuple(os.environ):
        if (
            name.startswith("PAYMENT_FIREWALL_")
            or name.startswith("SAFE4_PROVIDER_")
            or name == "SAFE4_DEMO_MODE"
        ):
            os.environ.pop(name, None)
    # These local fixture credentials exist only in this process environment.
    # They are generated after the private plan journal and are never added to
    # that journal or to public evidence.
    receipt_secret = secrets.token_urlsafe(48)
    admin_secret = secrets.token_urlsafe(48)
    if not receipt_secret or not admin_secret or receipt_secret == admin_secret:
        raise FixedBatchSafetyError("EPHEMERAL_LOCAL_SECRET_GENERATION_FAILED")
    os.environ.update(
        {
            "PAYMENT_FIREWALL_ENV": "development",
            "PAYMENT_FIREWALL_DB_PATH": str(database_path),
            "PAYMENT_FIREWALL_PAY_TO": FIXED_RECIPIENT,
            "PAYMENT_FIREWALL_RECEIPT_SECRET": receipt_secret,
            "PAYMENT_FIREWALL_ADMIN_SECRET": admin_secret,
            "PAYMENT_FIREWALL_WEBHOOK_DISPATCH_ENABLED": "false",
            "PAYMENT_FIREWALL_PHASE3_X402_ADVANCED_ENABLED": "false",
            "PAYMENT_FIREWALL_PHASE3_AP2_ENABLED": "false",
            "PAYMENT_FIREWALL_PHASE3_INFRASTRUCTURE_IDENTITY_ENABLED": "false",
            "PAYMENT_FIREWALL_DEMO_X402_RECEIPT_ENABLED": "false",
            "PAYMENT_FIREWALL_RATE_LIMIT_REQUESTS": "1000",
            "PAYMENT_FIREWALL_RATE_LIMIT_WINDOW_SECONDS": "60",
            "PAYMENT_FIREWALL_VELOCITY_LIMIT": "3",
            "PAYMENT_FIREWALL_VELOCITY_WINDOW_SECONDS": "60",
            "PAYMENT_FIREWALL_AP2_FEDERATION_DISCOVERY_POLL_URL": "",
            "SAFE4_PROVIDER_RANGE_RISK_API_KEY": "",
            "SAFE4_PROVIDER_RANGE_RISK_BASE_URL": "http://127.0.0.1:9",
            "SAFE4_DEMO_MODE": "fixed-live-arc-batch",
        }
    )


def _issue_local_oauth_token(client: Any, main: Any) -> str:
    verifier = "a" * 43
    authorization = client.post(
        "/oauth/authorize",
        json={
            "client_id": "dev-public-client",
            "redirect_uri": "https://localhost/callback",
            "scope": (
                "payment:read payment:authorize budget:manage "
                "audit:read admin:all"
            ),
            "code_challenge": main.compute_code_challenge(verifier),
            "code_challenge_method": "S256",
            "subject": "safe4_fixed_arc_demo_operator",
            "agent_id": "agent_alpha",
        },
    )
    authorization.raise_for_status()
    token = client.post(
        "/oauth/token",
        json={
            "grant_type": "authorization_code",
            "client_id": "dev-public-client",
            "code": authorization.json()["code"],
            "redirect_uri": "https://localhost/callback",
            "code_verifier": verifier,
        },
    )
    token.raise_for_status()
    return str(token.json()["access_token"])


@contextmanager
def _real_runtime_factory(
    plan: BoundBatchPlan,
    database_path: Path,
) -> Iterator[RuntimeBundle]:
    """Import the isolated app, then construct the three fixed live ports."""

    _assert_circle_proxy_disabled()
    plan.assert_integrity()
    if "app.main" in sys.modules or "app.webhooks_api" in sys.modules:
        raise FixedBatchSafetyError("SAFE4_APP_IMPORTED_BEFORE_ISOLATION")

    # These imports occur only after configure_isolated_environment and the
    # durable journal assertion in execute_fixed_live_batch.
    from fastapi.testclient import TestClient
    from app import main, webhooks_api

    if main.POSTGRES_DSN:
        raise FixedBatchSafetyError("POSTGRES_NOT_DISABLED")
    if Path(str(main.DB_URL)).resolve() != database_path.resolve():
        raise FixedBatchSafetyError("SQLITE_ISOLATION_CHECK_FAILED")
    if any(
        (
            main.WEBHOOK_DISPATCH_ENABLED,
            main.PHASE3_ADVANCED_X402_ENABLED,
            main.PHASE3_AP2_ENABLED,
            main.PHASE3_INFRASTRUCTURE_IDENTITY_ENABLED,
            main.DEMO_X402_RECEIPT_ENABLED,
        )
    ):
        raise FixedBatchSafetyError("EXTERNAL_SAFE4_PATH_NOT_DISABLED")
    if main.get_range_api_key() is not None:
        raise FixedBatchSafetyError("EXTERNAL_PROVIDER_CREDENTIAL_PRESENT")
    if main.RANGE_PROVIDER_CONFIG.endpoint.base_url != "http://127.0.0.1:9":
        raise FixedBatchSafetyError("EXTERNAL_PROVIDER_ENDPOINT_NOT_DISABLED")

    circle_executable = shutil.which("circle")
    if not circle_executable:
        raise FixedBatchSafetyError("CIRCLE_CLI_NOT_FOUND")
    circle_cli_version = observe_circle_cli_version(circle_executable)
    circle_wallet_preflight = verify_fixed_circle_wallet_preflight(
        circle_executable
    )

    main.reset_runtime_state()
    webhooks_api.reset_webhook_sender_for_tests()
    with TestClient(main.app) as client:
        access_token = _issue_local_oauth_token(client, main)
        yield RuntimeBundle(
            authorizer=LocalSafe4AuthorizationPort(
                client=client,
                main_module=main,
                access_token=access_token,
            ),
            submitter=CircleCliSubmissionPort(circle_executable=circle_executable),
            verifier=ArcRpcVerificationPort(rpc_url=FIXED_RPC_URL),
            circle_cli_version=circle_cli_version,
            circle_wallet_preflight=circle_wallet_preflight,
            observe_public_balances=ArcPublicBalanceObserver(),
        )


def execute_fixed_live_batch(
    *,
    confirmation: str,
    state_directory: Path | None = None,
    private_root: Path = REPOSITORY_PRIVATE_ROOT,
    key_factory: Callable[[], UUID | str] = uuid4,
    runtime_factory: RuntimeFactory = _real_runtime_factory,
    source_identity_factory: Callable[[], SourceIdentity] = observe_clean_source_identity,
    clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> FixedRunEvidence:
    """Execute once after persisting a crash-safe private plan journal.

    ``state_directory``, ``private_root``, ``key_factory``, and
    ``runtime_factory``, ``source_identity_factory``, and ``clock`` exist for
    offline dependency-injected tests. The CLI exposes none of them and always
    uses the fixed repository-private path and real adapters.
    """

    if confirmation != LIVE_CONFIRMATION_MARKER:
        raise FixedBatchSafetyError("LIVE_CONFIRMATION_MISMATCH")

    _assert_circle_proxy_disabled()
    started_at_utc = _utc_timestamp(clock)
    source_identity = source_identity_factory()
    if not _SOURCE_REVISION_PATTERN.fullmatch(source_identity.revision):
        raise FixedBatchSafetyError("SOURCE_REVISION_INVALID")
    if source_identity.worktree_state != "CLEAN":
        raise FixedBatchSafetyError("SOURCE_WORKTREE_NOT_CLEAN")

    resolved_state = _resolve_private_state_directory(
        state_directory,
        private_root=private_root,
    )
    _prepare_private_directory(resolved_state)
    lock_path = resolved_state / LOCK_FILENAME
    journal_path = resolved_state / JOURNAL_FILENAME
    database_path = (resolved_state / DATABASE_FILENAME).resolve()
    plan = build_fixed_plan(key_factory=key_factory)

    with _ExclusiveFileLock(lock_path):
        _refuse_prior_or_incomplete_state(resolved_state, lock_path=lock_path)

        prepared = _journal_document(
            plan,
            status=_PREPARED_STATUS,
            started_at_utc=started_at_utc,
            source_identity=source_identity,
        )
        _atomic_write_private_json(journal_path, prepared, replacing=False)
        _assert_journal_matches(
            journal_path,
            plan,
            expected_status=_PREPARED_STATUS,
        )

        # Only now may application configuration/import or any port creation
        # happen.  Port calls remain later still, inside coordinator.run().
        configure_isolated_environment(database_path)
        started = _journal_document(
            plan,
            status=_STARTED_STATUS,
            started_at_utc=started_at_utc,
            source_identity=source_identity,
        )
        _atomic_write_private_json(journal_path, started, replacing=True)
        _assert_journal_matches(
            journal_path,
            plan,
            expected_status=_STARTED_STATUS,
        )

        runtime_metadata: dict[str, Any] | None = None
        progress_journal: _DurableProgressJournal | None = None
        try:
            with runtime_factory(plan, database_path) as runtime:
                if not isinstance(runtime, RuntimeBundle):
                    raise FixedBatchSafetyError("LIVE_RUNTIME_INVALID")
                if not _CLI_VERSION_PATTERN.fullmatch(runtime.circle_cli_version):
                    raise FixedBatchSafetyError("CIRCLE_CLI_VERSION_INVALID")
                wallet_preflight = _validated_wallet_preflight(
                    runtime.circle_wallet_preflight
                )
                pre_balances = _observe_balances_safely(
                    runtime.observe_public_balances,
                    "PRE",
                )
                _assert_required_preflight_balance(pre_balances)
                runtime_metadata = {
                    "circle_cli_version": runtime.circle_cli_version,
                    "circle_wallet_preflight": wallet_preflight,
                    "pre_public_balances": pre_balances,
                    "raw_command_output_retained": False,
                }
                # Persist observed runtime identity/context before the first
                # transaction authorization. Failure here stops execution.
                started_with_runtime = _journal_document(
                    plan,
                    status=_STARTED_STATUS,
                    started_at_utc=started_at_utc,
                    source_identity=source_identity,
                    runtime_metadata=runtime_metadata,
                )
                _atomic_write_private_json(
                    journal_path,
                    started_with_runtime,
                    replacing=True,
                )
                _assert_journal_matches(
                    journal_path,
                    plan,
                    expected_status=_STARTED_STATUS,
                )
                progress_journal = _DurableProgressJournal(
                    journal_path=journal_path,
                    plan=plan,
                    started_at_utc=started_at_utc,
                    source_identity=source_identity,
                    runtime_metadata=runtime_metadata,
                )
                coordinator = LiveArcBatchCoordinator(
                    authorizer=_JournaledAuthorizationPort(
                        runtime.authorizer,
                        progress_journal,
                    ),
                    submitter=_JournaledSubmissionPort(
                        runtime.submitter,
                        progress_journal,
                    ),
                    verifier=_JournaledVerificationPort(
                        runtime.verifier,
                        progress_journal,
                    ),
                )
                batch_evidence = coordinator.run(plan)
                progress_journal.assert_healthy()
                post_balances = _observe_balances_safely(
                    runtime.observe_public_balances,
                    "POST",
                )

            evidence = FixedRunEvidence(
                started_at_utc=started_at_utc,
                ended_at_utc=_utc_timestamp(clock),
                source_revision=source_identity.revision,
                source_worktree_state=source_identity.worktree_state,
                circle_cli_version=runtime.circle_cli_version,
                circle_wallet_preflight=wallet_preflight,
                pre_balances=pre_balances,
                post_balances=post_balances,
                batch=batch_evidence,
            )
            evidence.to_sanitized_json()

            final_status = (
                _COMPLETE_STATUS
                if batch_evidence.terminal_status == "COMPLETE"
                else _STOPPED_STATUS
            )
            final = _journal_document(
                plan,
                status=final_status,
                started_at_utc=started_at_utc,
                source_identity=source_identity,
                runtime_metadata=runtime_metadata,
                execution_progress=(
                    progress_journal.progress if progress_journal else None
                ),
                evidence=evidence,
            )
            _atomic_write_private_json(journal_path, final, replacing=True)
            _assert_journal_matches(
                journal_path,
                plan,
                expected_status=final_status,
            )
            return evidence
        except Exception as exc:
            try:
                aborted = _journal_document(
                    plan,
                    status=_ABORTED_STATUS,
                    started_at_utc=started_at_utc,
                    source_identity=source_identity,
                    runtime_metadata=runtime_metadata,
                    execution_progress=(
                        progress_journal.progress if progress_journal else None
                    ),
                )
                _atomic_write_private_json(journal_path, aborted, replacing=True)
            except Exception:
                # The PREPARED/STARTED journal or an atomic-write remnant still
                # blocks another run.  Never delete either automatically.
                pass
            if isinstance(exc, FixedBatchSafetyError):
                raise
            raise FixedBatchSafetyError(
                "LIVE_BATCH_ABORTED_PRIVATE_JOURNAL_RETAINED"
            ) from None


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Preview or explicitly execute the fixed Arc Testnet demo batch."
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--preview",
        action="store_true",
        help="print the fixed sanitized plan without side effects (default)",
    )
    mode.add_argument(
        "--preflight",
        action="store_true",
        help=(
            "read-only source/Circle wallet/Arc balance checks; no keys, "
            "journal, app import, payment, or transfer"
        ),
    )
    mode.add_argument(
        "--execute-live",
        action="store_true",
        help="authorize and submit the fixed sequential Arc Testnet batch",
    )
    parser.add_argument(
        "--confirm",
        default="",
        help="exact non-secret confirmation marker printed by preview",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.preflight:
        try:
            preflight = run_read_only_preflight()
        except FixedBatchSafetyError as exc:
            print(
                json.dumps(
                    {"status": "STOPPED", "reason_code": str(exc)},
                    sort_keys=True,
                ),
                file=sys.stderr,
            )
            return 1
        print(json.dumps(preflight, sort_keys=True, indent=2))
        return 0
    if not args.execute_live:
        print(json.dumps(public_preview(), sort_keys=True, indent=2))
        return 0
    if args.confirm != LIVE_CONFIRMATION_MARKER:
        print(
            json.dumps(
                {
                    "status": "REFUSED",
                    "reason_code": "LIVE_CONFIRMATION_MISMATCH",
                    "required_confirmation": LIVE_CONFIRMATION_MARKER,
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2
    try:
        evidence = execute_fixed_live_batch(confirmation=args.confirm)
    except FixedBatchSafetyError as exc:
        # All wrapper exceptions use bounded reason codes; no raw provider,
        # token, environment, CLI, or path output is printed.
        print(
            json.dumps(
                {"status": "STOPPED", "reason_code": str(exc)},
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1
    print(evidence.to_sanitized_json(), end="")
    return 0 if evidence.batch.terminal_status == "COMPLETE" else 1


if __name__ == "__main__":
    raise SystemExit(main())
