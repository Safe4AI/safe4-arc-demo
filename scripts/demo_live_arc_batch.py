"""Fail-closed coordinator for a bounded sequential Arc Testnet demo batch.

This module deliberately does not execute anything at import time and does not
provide an unguarded command-line entry point.  A caller must explicitly build
an allowlisted :class:`BoundBatchPlan` and inject authorization, submission,
and verification ports.

The execution model is sequential and non-atomic::

    Safe4 authorize item -> Circle submit item -> Arc RPC verify item

The next item is not authorized until the preceding item is RPC verified.  A
denial, failure, or unknown state stops the batch.  Previously verified chain
transactions cannot be rolled back.

The local Safe4 authorization adapter below uses the repository's development
receipt fixture.  It is authorization evidence, not proof of a paid external
x402 service endpoint.  The Circle submission and Arc verification ports are
separate so tests can prove the coordinator's behavior without a wallet,
network access, signing, or broadcasting.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from decimal import Decimal
import hashlib
import json
import re
import subprocess
import time
from typing import Any, Callable, Mapping, Protocol, Sequence
from uuid import UUID, uuid4


ARC_CHAIN = "ARC-TESTNET"
ARC_CHAIN_ID = 5_042_002
USDC_CURRENCY = "USDC"
USDC_DECIMALS = 6
ARC_ENTRYPOINT_ADDRESS = "0x5ff137d4b0fdcd49dca30c7cf57e578a026d2789"
ARC_NATIVE_USDC_ADDRESS = "0xfffffffffffffffffffffffffffffffffffffffe"
ARC_NATIVE_USDC_DECIMALS = 18
# A caller must still pass an explicit allowlist, and every supplied address
# must be drawn from this code-reviewed demo destination set. Adding another
# destination therefore requires a source change and review, not a runtime flag.
PREDECLARED_ARC_TESTNET_RECIPIENTS = frozenset(
    {"0x530271da8cc4e44375f22ad9632bc61a55382f88"}
)
MAX_BATCH_ITEMS = 3
MAX_ITEM_AMOUNT_UNITS = 5_000
MAX_BATCH_AMOUNT_UNITS = 10_000
EXECUTION_MODEL = "SEQUENTIAL_NON_ATOMIC_STOP_ON_FIRST_FAILURE"

_ADDRESS_PATTERN = re.compile(r"^0x[0-9a-fA-F]{40}$")
_TX_HASH_PATTERN = re.compile(r"^0x[0-9a-fA-F]{64}$")
_HEX_HASH_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_SAFE4_TRANSACTION_ID_PATTERN = re.compile(r"^[0-9a-f]{32}$")
_REASON_CODE_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_EMAIL_PATTERN = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
_SECRET_VALUE_PATTERNS = (
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]+=*"),
    re.compile(r"(?i)\b(?:access|refresh|receipt|spend|authorization)[_-]?token\b"),
    re.compile(r"(?i)\b(?:private[_ -]?key|mnemonic|admin[_ -]?secret|otp)\b"),
    _EMAIL_PATTERN,
)
_TRANSACTION_HASH_KEYS = frozenset(
    {"txHash", "transactionHash", "transaction_hash", "tx_hash"}
)


class BatchValidationError(ValueError):
    """Raised before any port is invoked when a batch is unsafe or invalid."""


class BindingIntegrityError(RuntimeError):
    """Raised when immutable batch data no longer matches its canonical hash."""


class EvidenceSanitizationError(RuntimeError):
    """Raised when public evidence contains a prohibited value."""


def _canonical_hash(document: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _normalize_address(value: str, *, label: str) -> str:
    if not isinstance(value, str) or not _ADDRESS_PATTERN.fullmatch(value.strip()):
        raise BatchValidationError(f"{label} must be a 20-byte 0x-prefixed address")
    return value.strip().lower()


def _validated_text(value: str, *, label: str, maximum: int) -> str:
    if not isinstance(value, str):
        raise BatchValidationError(f"{label} must be a string")
    normalized = " ".join(value.split())
    if not normalized:
        raise BatchValidationError(f"{label} cannot be empty")
    if len(normalized) > maximum:
        raise BatchValidationError(f"{label} exceeds {maximum} characters")
    if any(ord(character) < 32 for character in normalized):
        raise BatchValidationError(f"{label} contains control characters")
    return normalized


def _validated_identifier(value: str, *, label: str) -> str:
    normalized = _validated_text(value, label=label, maximum=128)
    if not _IDENTIFIER_PATTERN.fullmatch(normalized):
        raise BatchValidationError(f"{label} contains unsupported characters")
    return normalized


def _uuid4_text(value: UUID | str, *, label: str) -> str:
    try:
        parsed = value if isinstance(value, UUID) else UUID(str(value))
    except (ValueError, AttributeError) as exc:
        raise BatchValidationError(f"{label} must be a UUIDv4") from exc
    canonical = str(parsed)
    if parsed.version != 4 or str(value).lower() != canonical:
        raise BatchValidationError(f"{label} must be a canonical UUIDv4")
    return canonical


def _safe_reason_code(value: Any, *, fallback: str) -> str:
    candidate = str(value or "").strip().upper()
    return candidate if _REASON_CODE_PATTERN.fullmatch(candidate) else fallback


def _safe_safe4_transaction_id(value: Any) -> str | None:
    candidate = str(value or "").strip()
    return candidate if _SAFE4_TRANSACTION_ID_PATTERN.fullmatch(candidate) else None


def _safe_transaction_hash(value: Any) -> str | None:
    candidate = str(value or "").strip().lower()
    return candidate if _TX_HASH_PATTERN.fullmatch(candidate) else None


@dataclass(frozen=True, slots=True)
class BatchItemInput:
    """Untrusted preflight input for one synthetic demo purchase."""

    item_id: str
    recipient: str
    amount_units: int
    vendor: str
    description: str
    task: str
    service_category: str
    task_id: str | None = None


@dataclass(frozen=True, slots=True)
class BoundBatchItem:
    """Immutable item used by authorization, submission, and verification."""

    batch_id: str
    item_id: str
    sequence: int
    sender: str
    recipient: str
    amount_units: int
    vendor: str
    description: str
    task: str
    service_category: str
    task_id: str
    safe4_idempotency_key: str
    circle_idempotency_key: str
    binding_hash: str

    def binding_document(self) -> dict[str, Any]:
        return {
            "schema_version": "safe4-live-arc-batch-item-v1",
            "batch_id": self.batch_id,
            "item_id": self.item_id,
            "sequence": self.sequence,
            "agent_id": "agent_alpha",
            "user_id": "user_123",
            "chain": ARC_CHAIN,
            "chain_id": ARC_CHAIN_ID,
            "currency": USDC_CURRENCY,
            "sender": self.sender,
            "recipient": self.recipient,
            "amount_units": self.amount_units,
            "vendor": self.vendor,
            "description": self.description,
            "task": self.task,
            "service_category": self.service_category,
            "task_id": self.task_id,
            "safe4_idempotency_key": self.safe4_idempotency_key,
            "circle_idempotency_key": self.circle_idempotency_key,
        }

    def assert_integrity(self) -> None:
        if _canonical_hash(self.binding_document()) != self.binding_hash:
            raise BindingIntegrityError(
                f"batch item {self.item_id} no longer matches its binding hash"
            )
        if not _HEX_HASH_PATTERN.fullmatch(self.binding_hash):
            raise BindingIntegrityError("binding hash is not canonical SHA-256 hex")
        try:
            normalized_sender = _normalize_address(self.sender, label="sender")
            normalized_recipient = _normalize_address(self.recipient, label="recipient")
            safe4_key = _uuid4_text(
                self.safe4_idempotency_key,
                label="safe4_idempotency_key",
            )
            circle_key = _uuid4_text(
                self.circle_idempotency_key,
                label="circle_idempotency_key",
            )
        except BatchValidationError as exc:
            raise BindingIntegrityError(str(exc)) from exc
        if normalized_sender != self.sender or normalized_recipient != self.recipient:
            raise BindingIntegrityError("bound addresses must be normalized")
        if normalized_recipient == normalized_sender:
            raise BindingIntegrityError("sender cannot also be a settlement recipient")
        if normalized_recipient not in PREDECLARED_ARC_TESTNET_RECIPIENTS:
            raise BindingIntegrityError(
                "bound recipient is outside the code-reviewed Arc Testnet destinations"
            )
        if safe4_key == circle_key:
            raise BindingIntegrityError("Safe4 and Circle idempotency keys must differ")
        if (
            isinstance(self.amount_units, bool)
            or not isinstance(self.amount_units, int)
            or self.amount_units <= 0
            or self.amount_units > MAX_ITEM_AMOUNT_UNITS
        ):
            raise BindingIntegrityError("bound amount exceeds the live item cap")

    @property
    def amount_usdc(self) -> str:
        return f"{Decimal(self.amount_units) / (10 ** USDC_DECIMALS):.6f}"

    def payment_payload(self) -> dict[str, Any]:
        """Return a new `/pay` payload containing the exact settlement binding."""

        self.assert_integrity()
        return {
            "agent_id": "agent_alpha",
            "user_id": "user_123",
            "vendor": self.vendor,
            # Safe4 intentionally requires a JSON number, not a decimal string.
            "amount": float(Decimal(self.amount_units) / (10 ** USDC_DECIMALS)),
            "currency": USDC_CURRENCY,
            "description": self.description,
            "context": {
                "payment_intent": {
                    "task_id": self.task_id,
                    "task": self.task,
                    "allowed_service_categories": [self.service_category],
                    "service_category": self.service_category,
                    "purchase_purpose": self.description,
                },
                "settlement_intent": {
                    "schema_version": "safe4-arc-settlement-v1",
                    "batch_id": self.batch_id,
                    "item_id": self.item_id,
                    "sequence": self.sequence,
                    "chain": ARC_CHAIN,
                    "chain_id": ARC_CHAIN_ID,
                    "currency": USDC_CURRENCY,
                    "sender": self.sender,
                    "recipient": self.recipient,
                    "amount_units": self.amount_units,
                    "binding_hash": self.binding_hash,
                },
            },
        }


@dataclass(frozen=True, slots=True)
class BoundBatchPlan:
    batch_id: str
    sender: str
    recipient_allowlist: tuple[str, ...]
    items: tuple[BoundBatchItem, ...]
    plan_hash: str

    def plan_document(self) -> dict[str, Any]:
        return {
            "schema_version": "safe4-live-arc-batch-plan-v1",
            "batch_id": self.batch_id,
            "chain": ARC_CHAIN,
            "chain_id": ARC_CHAIN_ID,
            "currency": USDC_CURRENCY,
            "sender": self.sender,
            "recipient_allowlist": list(self.recipient_allowlist),
            "hard_caps": {
                "max_items": MAX_BATCH_ITEMS,
                "max_item_amount_units": MAX_ITEM_AMOUNT_UNITS,
                "max_batch_amount_units": MAX_BATCH_AMOUNT_UNITS,
            },
            "item_binding_hashes": [item.binding_hash for item in self.items],
        }

    def assert_integrity(self) -> None:
        if _canonical_hash(self.plan_document()) != self.plan_hash:
            raise BindingIntegrityError("batch plan no longer matches its binding hash")
        if not self.items or len(self.items) > MAX_BATCH_ITEMS:
            raise BindingIntegrityError("batch item count violates the hard cap")
        if sum(item.amount_units for item in self.items) > MAX_BATCH_AMOUNT_UNITS:
            raise BindingIntegrityError("batch total violates the hard cap")
        if not self.recipient_allowlist:
            raise BindingIntegrityError("recipient allowlist is required")
        if self.sender in self.recipient_allowlist:
            raise BindingIntegrityError("sender cannot be present in the recipient allowlist")
        if not set(self.recipient_allowlist).issubset(
            PREDECLARED_ARC_TESTNET_RECIPIENTS
        ):
            raise BindingIntegrityError(
                "plan allowlist exceeds the code-reviewed Arc Testnet destinations"
            )

        item_ids: set[str] = set()
        idempotency_keys: set[str] = set()
        for expected_sequence, item in enumerate(self.items, start=1):
            item.assert_integrity()
            if item.batch_id != self.batch_id or item.sender != self.sender:
                raise BindingIntegrityError("item is bound to a different batch or sender")
            if item.sequence != expected_sequence:
                raise BindingIntegrityError("batch item sequence is not canonical")
            if item.recipient not in self.recipient_allowlist:
                raise BindingIntegrityError("item recipient is outside the bound allowlist")
            if item.item_id in item_ids:
                raise BindingIntegrityError("batch item IDs must be unique")
            item_ids.add(item.item_id)
            for key in (item.safe4_idempotency_key, item.circle_idempotency_key):
                if key in idempotency_keys:
                    raise BindingIntegrityError(
                        "all Safe4 and Circle idempotency keys must be unique"
                    )
                idempotency_keys.add(key)


def _item_binding_document(
    *,
    batch_id: str,
    item_id: str,
    sequence: int,
    sender: str,
    recipient: str,
    amount_units: int,
    vendor: str,
    description: str,
    task: str,
    service_category: str,
    task_id: str,
    safe4_idempotency_key: str,
    circle_idempotency_key: str,
) -> dict[str, Any]:
    provisional = BoundBatchItem(
        batch_id=batch_id,
        item_id=item_id,
        sequence=sequence,
        sender=sender,
        recipient=recipient,
        amount_units=amount_units,
        vendor=vendor,
        description=description,
        task=task,
        service_category=service_category,
        task_id=task_id,
        safe4_idempotency_key=safe4_idempotency_key,
        circle_idempotency_key=circle_idempotency_key,
        binding_hash="0" * 64,
    )
    return provisional.binding_document()


def prepare_batch(
    *,
    batch_id: str,
    sender: str,
    recipient_allowlist: Sequence[str] | None,
    items: Sequence[BatchItemInput],
    key_factory: Callable[[], UUID | str] = uuid4,
) -> BoundBatchPlan:
    """Validate the complete batch before generating any executable plan."""

    normalized_batch_id = _validated_identifier(batch_id, label="batch_id")
    normalized_sender = _normalize_address(sender, label="sender")
    if recipient_allowlist is None or not recipient_allowlist:
        raise BatchValidationError("an explicit recipient allowlist is required")
    normalized_allowlist = tuple(
        _normalize_address(address, label="recipient allowlist entry")
        for address in recipient_allowlist
    )
    if len(set(normalized_allowlist)) != len(normalized_allowlist):
        raise BatchValidationError("recipient allowlist entries must be unique")
    if normalized_sender in normalized_allowlist:
        raise BatchValidationError("sender cannot also be a settlement recipient")
    unsupported_recipients = set(normalized_allowlist) - set(
        PREDECLARED_ARC_TESTNET_RECIPIENTS
    )
    if unsupported_recipients:
        raise BatchValidationError(
            "recipient allowlist contains an address outside the code-reviewed "
            "Arc Testnet demo destinations"
        )
    normalized_allowlist = tuple(sorted(normalized_allowlist))

    raw_items = tuple(items)
    if not raw_items:
        raise BatchValidationError("batch must contain at least one item")
    if len(raw_items) > MAX_BATCH_ITEMS:
        raise BatchValidationError(
            f"batch cannot contain more than {MAX_BATCH_ITEMS} items"
        )

    validated: list[dict[str, Any]] = []
    item_ids: set[str] = set()
    total_units = 0
    for sequence, raw in enumerate(raw_items, start=1):
        item_id = _validated_identifier(raw.item_id, label="item_id")
        if item_id in item_ids:
            raise BatchValidationError("batch item IDs must be unique")
        item_ids.add(item_id)
        recipient = _normalize_address(raw.recipient, label="recipient")
        if recipient not in normalized_allowlist:
            raise BatchValidationError(
                f"recipient for {item_id} is outside the explicit allowlist"
            )
        if (
            isinstance(raw.amount_units, bool)
            or not isinstance(raw.amount_units, int)
            or raw.amount_units <= 0
        ):
            raise BatchValidationError("amount_units must be a positive integer")
        if raw.amount_units > MAX_ITEM_AMOUNT_UNITS:
            raise BatchValidationError(
                f"item {item_id} exceeds {MAX_ITEM_AMOUNT_UNITS} USDC base units"
            )
        total_units += raw.amount_units
        if total_units > MAX_BATCH_AMOUNT_UNITS:
            raise BatchValidationError(
                f"batch exceeds {MAX_BATCH_AMOUNT_UNITS} USDC base units"
            )
        service_category = _validated_identifier(
            raw.service_category,
            label="service_category",
        )
        validated.append(
            {
                "batch_id": normalized_batch_id,
                "item_id": item_id,
                "sequence": sequence,
                "sender": normalized_sender,
                "recipient": recipient,
                "amount_units": raw.amount_units,
                "vendor": _validated_identifier(raw.vendor, label="vendor"),
                "description": _validated_text(
                    raw.description,
                    label="description",
                    maximum=1_000,
                ),
                "task": _validated_text(raw.task, label="task", maximum=1_000),
                "service_category": service_category,
                "task_id": _validated_identifier(
                    raw.task_id or f"{normalized_batch_id}-{item_id}",
                    label="task_id",
                ),
            }
        )

    # Generate keys only after every non-random input has passed preflight.
    all_keys: set[str] = set()
    bound_items: list[BoundBatchItem] = []
    for values in validated:
        safe4_key = _uuid4_text(key_factory(), label="safe4_idempotency_key")
        circle_key = _uuid4_text(key_factory(), label="circle_idempotency_key")
        for key in (safe4_key, circle_key):
            if key in all_keys:
                raise BatchValidationError(
                    "idempotency key factory produced a duplicate UUIDv4"
                )
            all_keys.add(key)
        binding_document = _item_binding_document(
            **values,
            safe4_idempotency_key=safe4_key,
            circle_idempotency_key=circle_key,
        )
        bound_items.append(
            BoundBatchItem(
                **values,
                safe4_idempotency_key=safe4_key,
                circle_idempotency_key=circle_key,
                binding_hash=_canonical_hash(binding_document),
            )
        )

    provisional = BoundBatchPlan(
        batch_id=normalized_batch_id,
        sender=normalized_sender,
        recipient_allowlist=normalized_allowlist,
        items=tuple(bound_items),
        plan_hash="0" * 64,
    )
    plan = replace(provisional, plan_hash=_canonical_hash(provisional.plan_document()))
    plan.assert_integrity()
    return plan


@dataclass(frozen=True, slots=True)
class AuthorizationResult:
    status: str
    binding_hash: str
    reason_code: str
    safe4_transaction_id: str | None = None


@dataclass(frozen=True, slots=True)
class SubmissionResult:
    status: str
    binding_hash: str
    transaction_hash: str | None = None
    error_code: str | None = None


@dataclass(frozen=True, slots=True)
class VerificationResult:
    status: str
    binding_hash: str
    transaction_hash: str
    block_number: int | None = None
    observed_chain: str | None = None
    observed_sender: str | None = None
    observed_recipient: str | None = None
    observed_amount_units: int | None = None
    error_code: str | None = None


class AuthorizationPort(Protocol):
    def authorize(self, item: BoundBatchItem) -> AuthorizationResult: ...


class SubmissionPort(Protocol):
    def submit(self, item: BoundBatchItem) -> SubmissionResult: ...


class VerificationPort(Protocol):
    def verify(
        self,
        item: BoundBatchItem,
        transaction_hash: str,
    ) -> VerificationResult: ...


@dataclass(frozen=True, slots=True)
class ItemEvidence:
    sequence: int
    item_id: str
    binding_hash: str
    recipient: str
    amount_units: int
    amount_usdc: str
    outcome: str
    safe4_status: str
    reason_code: str
    safe4_transaction_id: str | None = None
    submission_status: str = "NOT_INVOKED"
    verification_status: str = "NOT_INVOKED"
    transaction_hash: str | None = None
    block_number: int | None = None
    error_code: str | None = None

    def to_public_dict(self) -> dict[str, Any]:
        """Serialize from a fixed allowlist; no port response is forwarded."""

        return {
            "sequence": self.sequence,
            "item_id": self.item_id,
            "binding_hash": self.binding_hash,
            "chain": ARC_CHAIN,
            "chain_id": ARC_CHAIN_ID,
            "currency": USDC_CURRENCY,
            "recipient": self.recipient,
            "amount_units": self.amount_units,
            "amount_usdc": self.amount_usdc,
            "outcome": self.outcome,
            "safe4_status": self.safe4_status,
            "reason_code": self.reason_code,
            "safe4_transaction_id": _safe_safe4_transaction_id(
                self.safe4_transaction_id
            ),
            "submission_status": self.submission_status,
            "verification_status": self.verification_status,
            "transaction_hash": _safe_transaction_hash(self.transaction_hash),
            "block_number": self.block_number
            if isinstance(self.block_number, int) and self.block_number > 0
            else None,
            "error_code": _safe_reason_code(
                self.error_code,
                fallback="UNCLASSIFIED_ERROR",
            )
            if self.error_code
            else None,
        }


@dataclass(frozen=True, slots=True)
class BatchEvidence:
    batch_id: str
    plan_hash: str
    terminal_status: str
    items: tuple[ItemEvidence, ...]

    def to_public_dict(self) -> dict[str, Any]:
        public_items = [item.to_public_dict() for item in self.items]
        return {
            "schema_version": "safe4-live-arc-batch-evidence-v1",
            "batch_id": self.batch_id,
            "plan_hash": self.plan_hash,
            "chain": ARC_CHAIN,
            "chain_id": ARC_CHAIN_ID,
            "currency": USDC_CURRENCY,
            "execution_model": EXECUTION_MODEL,
            "atomic": False,
            "terminal_status": self.terminal_status,
            "hard_caps": {
                "max_items": MAX_BATCH_ITEMS,
                "max_item_amount_units": MAX_ITEM_AMOUNT_UNITS,
                "max_batch_amount_units": MAX_BATCH_AMOUNT_UNITS,
            },
            "counts": {
                "planned": len(public_items),
                "authorized": sum(
                    item["safe4_status"] == "AUTHORIZED" for item in public_items
                ),
                "submitted": sum(
                    item["submission_status"] == "SUBMITTED" for item in public_items
                ),
                "verified": sum(item["outcome"] == "VERIFIED" for item in public_items),
                "denied": sum(item["outcome"] == "DENIED" for item in public_items),
                "failed": sum(item["outcome"] == "FAILED" for item in public_items),
                "unknown": sum(item["outcome"] == "UNKNOWN" for item in public_items),
                "skipped": sum(item["outcome"] == "SKIPPED" for item in public_items),
            },
            "totals": {
                "planned_amount_units": sum(item["amount_units"] for item in public_items),
                "verified_amount_units": sum(
                    item["amount_units"]
                    for item in public_items
                    if item["outcome"] == "VERIFIED"
                ),
            },
            "items": public_items,
        }

    def to_sanitized_json(self) -> str:
        serialized = json.dumps(
            self.to_public_dict(),
            sort_keys=True,
            indent=2,
            ensure_ascii=True,
        )
        for pattern in _SECRET_VALUE_PATTERNS:
            if pattern.search(serialized):
                raise EvidenceSanitizationError(
                    "public evidence matched a prohibited secret or PII pattern"
                )
        return serialized + "\n"


def _skipped_evidence(item: BoundBatchItem) -> ItemEvidence:
    return ItemEvidence(
        sequence=item.sequence,
        item_id=item.item_id,
        binding_hash=item.binding_hash,
        recipient=item.recipient,
        amount_units=item.amount_units,
        amount_usdc=item.amount_usdc,
        outcome="SKIPPED",
        safe4_status="NOT_INVOKED",
        reason_code="BATCH_STOPPED_BEFORE_ITEM",
    )


class LiveArcBatchCoordinator:
    def __init__(
        self,
        *,
        authorizer: AuthorizationPort,
        submitter: SubmissionPort,
        verifier: VerificationPort,
    ) -> None:
        self.authorizer = authorizer
        self.submitter = submitter
        self.verifier = verifier

    def run(self, plan: BoundBatchPlan) -> BatchEvidence:
        # This assertion occurs before the first call to any injected port.
        plan.assert_integrity()
        observations: list[ItemEvidence] = []
        stopped = False
        observed_transaction_hashes: set[str] = set()

        for item in plan.items:
            if stopped:
                observations.append(_skipped_evidence(item))
                continue
            item.assert_integrity()

            try:
                authorization = self.authorizer.authorize(item)
            except Exception:
                observations.append(
                    ItemEvidence(
                        sequence=item.sequence,
                        item_id=item.item_id,
                        binding_hash=item.binding_hash,
                        recipient=item.recipient,
                        amount_units=item.amount_units,
                        amount_usdc=item.amount_usdc,
                        outcome="UNKNOWN",
                        safe4_status="UNKNOWN",
                        reason_code="AUTHORIZATION_EXCEPTION",
                        error_code="AUTHORIZATION_EXCEPTION",
                    )
                )
                stopped = True
                continue

            auth_reason = _safe_reason_code(
                authorization.reason_code,
                fallback="AUTHORIZATION_RESULT_INVALID",
            )
            if authorization.binding_hash != item.binding_hash:
                observations.append(
                    ItemEvidence(
                        sequence=item.sequence,
                        item_id=item.item_id,
                        binding_hash=item.binding_hash,
                        recipient=item.recipient,
                        amount_units=item.amount_units,
                        amount_usdc=item.amount_usdc,
                        outcome="UNKNOWN",
                        safe4_status="UNKNOWN",
                        reason_code="AUTHORIZATION_BINDING_MISMATCH",
                        error_code="AUTHORIZATION_BINDING_MISMATCH",
                    )
                )
                stopped = True
                continue
            if authorization.status != "AUTHORIZED":
                denied = authorization.status == "DENIED"
                observations.append(
                    ItemEvidence(
                        sequence=item.sequence,
                        item_id=item.item_id,
                        binding_hash=item.binding_hash,
                        recipient=item.recipient,
                        amount_units=item.amount_units,
                        amount_usdc=item.amount_usdc,
                        outcome="DENIED" if denied else "UNKNOWN",
                        safe4_status="DENIED" if denied else "UNKNOWN",
                        reason_code=auth_reason,
                        safe4_transaction_id=authorization.safe4_transaction_id,
                        error_code=None if denied else "AUTHORIZATION_UNKNOWN",
                    )
                )
                stopped = True
                continue

            safe4_transaction_id = _safe_safe4_transaction_id(
                authorization.safe4_transaction_id
            )
            if safe4_transaction_id is None:
                observations.append(
                    ItemEvidence(
                        sequence=item.sequence,
                        item_id=item.item_id,
                        binding_hash=item.binding_hash,
                        recipient=item.recipient,
                        amount_units=item.amount_units,
                        amount_usdc=item.amount_usdc,
                        outcome="UNKNOWN",
                        safe4_status="UNKNOWN",
                        reason_code="AUTHORIZATION_RESULT_INVALID",
                        error_code="AUTHORIZATION_RESULT_INVALID",
                    )
                )
                stopped = True
                continue

            try:
                submission = self.submitter.submit(item)
            except Exception:
                observations.append(
                    ItemEvidence(
                        sequence=item.sequence,
                        item_id=item.item_id,
                        binding_hash=item.binding_hash,
                        recipient=item.recipient,
                        amount_units=item.amount_units,
                        amount_usdc=item.amount_usdc,
                        outcome="UNKNOWN",
                        safe4_status="AUTHORIZED",
                        reason_code=auth_reason,
                        safe4_transaction_id=safe4_transaction_id,
                        submission_status="UNKNOWN",
                        error_code="SUBMISSION_EXCEPTION",
                    )
                )
                stopped = True
                continue

            transaction_hash = _safe_transaction_hash(submission.transaction_hash)
            if submission.binding_hash != item.binding_hash:
                submission_status = "UNKNOWN"
                submission_error = "SUBMISSION_BINDING_MISMATCH"
            elif submission.status != "SUBMITTED" and transaction_hash is not None:
                # Any observed hash makes a nominal FAILED result ambiguous.
                submission_status = "UNKNOWN"
                submission_error = "SUBMISSION_STATE_AMBIGUOUS"
            elif submission.status != "SUBMITTED" or transaction_hash is None:
                submission_status = (
                    submission.status
                    if submission.status in {"FAILED", "UNKNOWN"}
                    else "UNKNOWN"
                )
                submission_error = _safe_reason_code(
                    submission.error_code,
                    fallback="SUBMISSION_RESULT_INVALID",
                )
            else:
                submission_status = "SUBMITTED"
                submission_error = None

            if submission_status != "SUBMITTED" or transaction_hash is None:
                observations.append(
                    ItemEvidence(
                        sequence=item.sequence,
                        item_id=item.item_id,
                        binding_hash=item.binding_hash,
                        recipient=item.recipient,
                        amount_units=item.amount_units,
                        amount_usdc=item.amount_usdc,
                        outcome="FAILED"
                        if submission_status == "FAILED"
                        else "UNKNOWN",
                        safe4_status="AUTHORIZED",
                        reason_code=auth_reason,
                        safe4_transaction_id=safe4_transaction_id,
                        submission_status=submission_status,
                        transaction_hash=transaction_hash,
                        error_code=submission_error,
                    )
                )
                stopped = True
                continue

            if transaction_hash in observed_transaction_hashes:
                observations.append(
                    ItemEvidence(
                        sequence=item.sequence,
                        item_id=item.item_id,
                        binding_hash=item.binding_hash,
                        recipient=item.recipient,
                        amount_units=item.amount_units,
                        amount_usdc=item.amount_usdc,
                        outcome="UNKNOWN",
                        safe4_status="AUTHORIZED",
                        reason_code=auth_reason,
                        safe4_transaction_id=safe4_transaction_id,
                        submission_status="UNKNOWN",
                        transaction_hash=transaction_hash,
                        error_code="TRANSACTION_HASH_REUSED",
                    )
                )
                stopped = True
                continue
            observed_transaction_hashes.add(transaction_hash)

            try:
                verification = self.verifier.verify(item, transaction_hash)
            except Exception:
                observations.append(
                    ItemEvidence(
                        sequence=item.sequence,
                        item_id=item.item_id,
                        binding_hash=item.binding_hash,
                        recipient=item.recipient,
                        amount_units=item.amount_units,
                        amount_usdc=item.amount_usdc,
                        outcome="UNKNOWN",
                        safe4_status="AUTHORIZED",
                        reason_code=auth_reason,
                        safe4_transaction_id=safe4_transaction_id,
                        submission_status="SUBMITTED",
                        verification_status="UNKNOWN",
                        transaction_hash=transaction_hash,
                        error_code="VERIFICATION_EXCEPTION",
                    )
                )
                stopped = True
                continue

            verification_hash = _safe_transaction_hash(
                verification.transaction_hash
            )
            exact_match = (
                verification.status == "VERIFIED"
                and verification.binding_hash == item.binding_hash
                and verification_hash == transaction_hash
                and verification.observed_chain == ARC_CHAIN
                and str(verification.observed_sender or "").lower() == item.sender
                and str(verification.observed_recipient or "").lower()
                == item.recipient
                and verification.observed_amount_units == item.amount_units
                and isinstance(verification.block_number, int)
                and verification.block_number > 0
            )
            if exact_match:
                observations.append(
                    ItemEvidence(
                        sequence=item.sequence,
                        item_id=item.item_id,
                        binding_hash=item.binding_hash,
                        recipient=item.recipient,
                        amount_units=item.amount_units,
                        amount_usdc=item.amount_usdc,
                        outcome="VERIFIED",
                        safe4_status="AUTHORIZED",
                        reason_code=auth_reason,
                        safe4_transaction_id=safe4_transaction_id,
                        submission_status="SUBMITTED",
                        verification_status="VERIFIED",
                        transaction_hash=transaction_hash,
                        block_number=verification.block_number,
                    )
                )
                continue

            verification_status = (
                verification.status
                if verification.status in {"FAILED", "UNKNOWN"}
                else "FAILED"
            )
            observations.append(
                ItemEvidence(
                    sequence=item.sequence,
                    item_id=item.item_id,
                    binding_hash=item.binding_hash,
                    recipient=item.recipient,
                    amount_units=item.amount_units,
                    amount_usdc=item.amount_usdc,
                    outcome="UNKNOWN"
                    if verification_status == "UNKNOWN"
                    else "FAILED",
                    safe4_status="AUTHORIZED",
                    reason_code=auth_reason,
                    safe4_transaction_id=safe4_transaction_id,
                    submission_status="SUBMITTED",
                    verification_status=verification_status,
                    transaction_hash=transaction_hash,
                    error_code=_safe_reason_code(
                        verification.error_code,
                        fallback="VERIFICATION_BINDING_MISMATCH",
                    ),
                )
            )
            stopped = True

        verified_count = sum(item.outcome == "VERIFIED" for item in observations)
        if verified_count == len(plan.items):
            terminal_status = "COMPLETE"
        elif verified_count:
            terminal_status = "PARTIAL_STOPPED"
        else:
            terminal_status = "STOPPED"
        return BatchEvidence(
            batch_id=plan.batch_id,
            plan_hash=plan.plan_hash,
            terminal_status=terminal_status,
            items=tuple(observations),
        )


def build_circle_transfer_command(
    item: BoundBatchItem,
    *,
    circle_executable: str,
) -> tuple[str, ...]:
    """Build a single-recipient CLI command solely from a bound item."""

    item.assert_integrity()
    if not circle_executable or not str(circle_executable).strip():
        raise BatchValidationError("Circle CLI executable path is required")
    return (
        str(circle_executable),
        "wallet",
        "transfer",
        item.recipient,
        "--amount",
        item.amount_usdc,
        "--address",
        item.sender,
        "--chain",
        ARC_CHAIN,
        "--idempotency-key",
        item.circle_idempotency_key,
        "--output",
        "json",
    )


class CircleCliSubmissionPort:
    """Submit exactly one bound transfer and retain no raw CLI output."""

    def __init__(
        self,
        *,
        circle_executable: str,
        command_runner: Callable[..., Any] = subprocess.run,
        timeout_seconds: int = 180,
    ) -> None:
        self.circle_executable = circle_executable
        self.command_runner = command_runner
        self.timeout_seconds = timeout_seconds

    def submit(self, item: BoundBatchItem) -> SubmissionResult:
        command = build_circle_transfer_command(
            item,
            circle_executable=self.circle_executable,
        )
        try:
            completed = self.command_runner(
                list(command),
                check=False,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
            )
        except subprocess.TimeoutExpired:
            return SubmissionResult(
                status="UNKNOWN",
                binding_hash=item.binding_hash,
                error_code="CIRCLE_SUBMISSION_TIMEOUT",
            )
        except OSError:
            return SubmissionResult(
                status="FAILED",
                binding_hash=item.binding_hash,
                error_code="CIRCLE_CLI_UNAVAILABLE",
            )

        if getattr(completed, "returncode", 1) != 0:
            # A nonzero exit does not prove that no provider request was accepted.
            return SubmissionResult(
                status="UNKNOWN",
                binding_hash=item.binding_hash,
                error_code="CIRCLE_CLI_NONZERO",
            )
        try:
            payload = json.loads(str(getattr(completed, "stdout", "")))
        except (json.JSONDecodeError, TypeError):
            return SubmissionResult(
                status="UNKNOWN",
                binding_hash=item.binding_hash,
                error_code="CIRCLE_OUTPUT_INVALID",
            )
        # Circle CLI 0.0.6's JSON formatter wraps command results in exactly
        # one top-level ``data`` object. Validate that installed contract
        # narrowly so a post-broadcast parser mismatch cannot be mistaken for
        # a safe retry condition.
        if not isinstance(payload, Mapping) or set(payload) != {"data"}:
            return SubmissionResult(
                status="UNKNOWN",
                binding_hash=item.binding_hash,
                error_code="CIRCLE_OUTPUT_ENVELOPE_INVALID",
            )
        result = payload.get("data")
        if not isinstance(result, Mapping) or result.get("state") not in {
            "CONFIRMED",
            "COMPLETE",
        }:
            return SubmissionResult(
                status="UNKNOWN",
                binding_hash=item.binding_hash,
                error_code="CIRCLE_STATE_NOT_SUCCESS",
            )
        if result.get("error") not in (None, "") or result.get("errorReason") not in (
            None,
            "",
        ) or result.get("errorDetails") not in (None, "", []):
            return SubmissionResult(
                status="UNKNOWN",
                binding_hash=item.binding_hash,
                error_code="CIRCLE_OUTPUT_CONTAINS_ERROR",
            )
        try:
            observed_amounts = result.get("amounts")
            amount_matches = (
                isinstance(observed_amounts, list)
                and len(observed_amounts) == 1
                and Decimal(str(observed_amounts[0])) == Decimal(item.amount_usdc)
            )
        except Exception:
            amount_matches = False
        bound_fields_match = (
            result.get("idempotencyKey") == item.circle_idempotency_key
            and str(result.get("blockchain", "")).upper() == ARC_CHAIN
            and str(result.get("sourceAddress", "")).lower() == item.sender
            and str(result.get("destinationAddress", "")).lower() == item.recipient
            and str(result.get("operation", "")).upper() == "TRANSFER"
            and str(result.get("transactionType", "")).upper() == "OUTBOUND"
            and amount_matches
        )
        if not bound_fields_match:
            return SubmissionResult(
                status="UNKNOWN",
                binding_hash=item.binding_hash,
                error_code="CIRCLE_OUTPUT_BINDING_MISMATCH",
            )
        hashes = {
            candidate
            for key in _TRANSACTION_HASH_KEYS
            if (candidate := _safe_transaction_hash(result.get(key))) is not None
        }
        if len(hashes) != 1:
            return SubmissionResult(
                status="UNKNOWN",
                binding_hash=item.binding_hash,
                error_code="CIRCLE_OUTPUT_AMBIGUOUS",
            )
        return SubmissionResult(
            status="SUBMITTED",
            binding_hash=item.binding_hash,
            transaction_hash=next(iter(hashes)),
        )


def assert_single_bound_outgoing_transfer(
    *,
    item: BoundBatchItem,
    receipt: Mapping[str, Any],
    native_usdc_address: str,
    transfer_topic: str,
    address_topic: Callable[[str], str],
    parse_hex_int: Callable[..., int],
    native_amount_units: int,
) -> None:
    """Reject extra native-USDC transfers originating from the bound wallet."""

    item.assert_integrity()
    native_address = _normalize_address(
        native_usdc_address,
        label="Arc native USDC address",
    )
    sender_topic = address_topic(item.sender).lower()
    recipient_topic = address_topic(item.recipient).lower()
    outgoing: list[Mapping[str, Any]] = []
    for raw_entry in receipt.get("logs", []):
        if not isinstance(raw_entry, Mapping):
            continue
        topics = [str(topic).lower() for topic in raw_entry.get("topics", [])]
        if (
            str(raw_entry.get("address", "")).lower() == native_address
            and len(topics) >= 3
            and topics[0] == transfer_topic.lower()
            and topics[1] == sender_topic
        ):
            outgoing.append(raw_entry)
    if len(outgoing) != 1:
        raise BindingIntegrityError(
            "expected exactly one outgoing Arc native-USDC transfer from the bound wallet"
        )
    topics = [str(topic).lower() for topic in outgoing[0].get("topics", [])]
    if topics[2] != recipient_topic:
        raise BindingIntegrityError("outgoing transfer recipient does not match binding")
    observed_units = parse_hex_int(
        outgoing[0].get("data", "0x0"),
        label="Arc native USDC Transfer amount",
    )
    if observed_units != native_amount_units:
        raise BindingIntegrityError("outgoing transfer amount does not match binding")


def assert_single_successful_bound_user_operation(
    *,
    item: BoundBatchItem,
    receipt: Mapping[str, Any],
    entrypoint_address: str,
    user_operation_event_topic: str,
    address_topic: Callable[[str], str],
    parse_hex_int: Callable[..., int],
) -> None:
    """Require exactly one successful UserOperation event for the bound wallet."""

    item.assert_integrity()
    normalized_entrypoint = _normalize_address(
        entrypoint_address,
        label="ERC-4337 EntryPoint address",
    )
    sender_topic = address_topic(item.sender).lower()
    matching_operations: list[Mapping[str, Any]] = []
    for raw_entry in receipt.get("logs", []):
        if not isinstance(raw_entry, Mapping):
            continue
        topics = [str(topic).lower() for topic in raw_entry.get("topics", [])]
        if (
            str(raw_entry.get("address", "")).lower() == normalized_entrypoint
            and len(topics) >= 3
            and topics[0] == user_operation_event_topic.lower()
            and topics[2] == sender_topic
        ):
            matching_operations.append(raw_entry)
    if len(matching_operations) != 1:
        raise BindingIntegrityError(
            "expected exactly one ERC-4337 UserOperation for the bound wallet"
        )
    data = str(matching_operations[0].get("data", "0x0")).lower()
    if len(data) < 130:
        raise BindingIntegrityError("UserOperation event data is incomplete")
    success = parse_hex_int("0x" + data[66:130], label="UserOperation success")
    if success != 1:
        raise BindingIntegrityError("bound wallet UserOperation was not successful")


class ArcRpcVerificationPort:
    """Read-only exact verifier for one bound Circle Agent Wallet transfer."""

    def __init__(
        self,
        *,
        rpc_url: str,
        entrypoint_address: str = ARC_ENTRYPOINT_ADDRESS,
        native_usdc_address: str = ARC_NATIVE_USDC_ADDRESS,
        native_usdc_decimals: int = ARC_NATIVE_USDC_DECIMALS,
        poll_attempts: int = 6,
        poll_interval_seconds: float = 2.0,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        if not rpc_url or not rpc_url.strip():
            raise BatchValidationError("Arc RPC URL is required")
        self.rpc_url = rpc_url.strip()
        self.entrypoint_address = _normalize_address(
            entrypoint_address,
            label="ERC-4337 EntryPoint address",
        )
        self.native_usdc_address = _normalize_address(
            native_usdc_address,
            label="Arc native USDC address",
        )
        if self.entrypoint_address != ARC_ENTRYPOINT_ADDRESS:
            raise BatchValidationError(
                "batch verifier must use the hard-coded Arc Testnet EntryPoint"
            )
        if self.native_usdc_address != ARC_NATIVE_USDC_ADDRESS:
            raise BatchValidationError(
                "batch verifier must use the hard-coded Arc native USDC address"
            )
        if native_usdc_decimals != ARC_NATIVE_USDC_DECIMALS:
            raise BatchValidationError("batch verifier requires 18-decimal Arc native USDC")
        if isinstance(poll_attempts, bool) or not isinstance(poll_attempts, int):
            raise BatchValidationError("poll_attempts must be an integer")
        if poll_attempts < 1 or poll_attempts > 10:
            raise BatchValidationError("poll_attempts must be between 1 and 10")
        if poll_interval_seconds < 0 or poll_interval_seconds > 5:
            raise BatchValidationError(
                "poll_interval_seconds must be between zero and five"
            )
        self.native_usdc_decimals = native_usdc_decimals
        self.poll_attempts = poll_attempts
        self.poll_interval_seconds = poll_interval_seconds
        self.sleeper = sleeper

    def verify(
        self,
        item: BoundBatchItem,
        transaction_hash: str,
    ) -> VerificationResult:
        item.assert_integrity()
        normalized_hash = _safe_transaction_hash(transaction_hash)
        if normalized_hash is None:
            return VerificationResult(
                status="FAILED",
                binding_hash=item.binding_hash,
                transaction_hash=str(transaction_hash),
                error_code="TRANSACTION_HASH_INVALID",
            )

        import httpx

        from scripts.verify_arc_settlement import (
            ArcSettlementError,
            TRANSFER_TOPIC,
            USER_OPERATION_EVENT_TOPIC,
            address_topic,
            parse_hex_int,
            rpc,
            scale_amount_units,
            verify_circle_agent_wallet_payloads,
        )

        native_amount_units = scale_amount_units(
            item.amount_units,
            USDC_DECIMALS,
            self.native_usdc_decimals,
        )
        with httpx.Client(timeout=15.0) as client:
            try:
                actual_chain_id = parse_hex_int(
                    rpc(client, self.rpc_url, "eth_chainId", []),
                    label="chain ID",
                )
            except (httpx.HTTPError, ArcSettlementError, ValueError):
                return VerificationResult(
                    status="UNKNOWN",
                    binding_hash=item.binding_hash,
                    transaction_hash=normalized_hash,
                    error_code="ARC_RPC_UNAVAILABLE",
                )
            if actual_chain_id != ARC_CHAIN_ID:
                return VerificationResult(
                    status="FAILED",
                    binding_hash=item.binding_hash,
                    transaction_hash=normalized_hash,
                    error_code="ARC_CHAIN_MISMATCH",
                )

            transaction: Any = None
            receipt: Any = None
            for attempt in range(self.poll_attempts):
                try:
                    transaction = rpc(
                        client,
                        self.rpc_url,
                        "eth_getTransactionByHash",
                        [normalized_hash],
                    )
                    receipt = rpc(
                        client,
                        self.rpc_url,
                        "eth_getTransactionReceipt",
                        [normalized_hash],
                    )
                except (httpx.HTTPError, ArcSettlementError, ValueError):
                    return VerificationResult(
                        status="UNKNOWN",
                        binding_hash=item.binding_hash,
                        transaction_hash=normalized_hash,
                        error_code="ARC_RPC_UNAVAILABLE",
                    )
                if transaction is not None and receipt is not None:
                    break
                if attempt + 1 < self.poll_attempts:
                    self.sleeper(self.poll_interval_seconds)

        if transaction is None or receipt is None:
            return VerificationResult(
                status="UNKNOWN",
                binding_hash=item.binding_hash,
                transaction_hash=normalized_hash,
                error_code="UNKNOWN_AFTER_SUBMISSION",
            )

        try:
            if not isinstance(receipt, Mapping):
                raise ArcSettlementError("transaction receipt not found")
            assert_single_bound_outgoing_transfer(
                item=item,
                receipt=receipt,
                native_usdc_address=self.native_usdc_address,
                transfer_topic=TRANSFER_TOPIC,
                address_topic=address_topic,
                parse_hex_int=parse_hex_int,
                native_amount_units=native_amount_units,
            )
            assert_single_successful_bound_user_operation(
                item=item,
                receipt=receipt,
                entrypoint_address=self.entrypoint_address,
                user_operation_event_topic=USER_OPERATION_EVENT_TOPIC,
                address_topic=address_topic,
                parse_hex_int=parse_hex_int,
            )
            block_number = verify_circle_agent_wallet_payloads(
                transaction,
                receipt,
                transaction_hash=normalized_hash,
                entrypoint_address=self.entrypoint_address,
                native_usdc_address=self.native_usdc_address,
                sender=item.sender,
                recipient=item.recipient,
                native_amount_units=native_amount_units,
            )
        except (ArcSettlementError, BindingIntegrityError, ValueError):
            return VerificationResult(
                status="FAILED",
                binding_hash=item.binding_hash,
                transaction_hash=normalized_hash,
                error_code="ARC_SETTLEMENT_MISMATCH",
            )
        return VerificationResult(
            status="VERIFIED",
            binding_hash=item.binding_hash,
            transaction_hash=normalized_hash,
            block_number=block_number,
            observed_chain=ARC_CHAIN,
            observed_sender=item.sender,
            observed_recipient=item.recipient,
            observed_amount_units=item.amount_units,
        )


class LocalSafe4AuthorizationPort:
    """Authorize through local `/pay` and bind the result to its audit hash.

    The initial 402 request intentionally has no idempotency header because
    Safe4 stores 402 responses by idempotency key.  The receipt-bearing retry
    uses the item's distinct Safe4 UUIDv4 key.
    """

    def __init__(self, *, client: Any, main_module: Any, access_token: str) -> None:
        self.client = client
        self.main = main_module
        self.access_token = access_token

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.access_token}"}

    @staticmethod
    def _reason(response: Any) -> str:
        try:
            body = response.json()
        except Exception:
            return "AUTHORIZATION_RESPONSE_INVALID"
        if not isinstance(body, Mapping):
            return "AUTHORIZATION_RESPONSE_INVALID"
        details = body.get("details")
        nested = details.get("intent_decision") if isinstance(details, Mapping) else None
        candidate = (
            nested.get("reason_code")
            if isinstance(nested, Mapping)
            else body.get("code")
        )
        return _safe_reason_code(candidate, fallback="AUTHORIZATION_RESPONSE_INVALID")

    def authorize(self, item: BoundBatchItem) -> AuthorizationResult:
        item.assert_integrity()
        payload = item.payment_payload()
        headers = self._headers()
        challenge = self.client.post("/pay", json=payload, headers=headers)
        if challenge.status_code != 402:
            return AuthorizationResult(
                status="DENIED" if 400 <= challenge.status_code < 500 else "UNKNOWN",
                binding_hash=item.binding_hash,
                reason_code=self._reason(challenge),
            )
        try:
            details = challenge.json()["details"]
            amount_due = float(details["amount_due"])
            currency = str(details["currency"])
        except (KeyError, TypeError, ValueError):
            return AuthorizationResult(
                status="UNKNOWN",
                binding_hash=item.binding_hash,
                reason_code="PAYMENT_CHALLENGE_INVALID",
            )
        issued = self.client.post(
            "/receipts/issue",
            json={
                "amount_due": amount_due,
                "currency": currency,
                "expires_in_seconds": 300,
            },
            headers=headers | {"X-Admin-Secret": self.main.RECEIPT_ADMIN_SECRET},
        )
        if issued.status_code != 200:
            return AuthorizationResult(
                status="UNKNOWN",
                binding_hash=item.binding_hash,
                reason_code="LOCAL_RECEIPT_ISSUE_FAILED",
            )
        try:
            receipt_token = str(issued.json()["receipt_token"])
        except (KeyError, TypeError, ValueError):
            return AuthorizationResult(
                status="UNKNOWN",
                binding_hash=item.binding_hash,
                reason_code="LOCAL_RECEIPT_RESPONSE_INVALID",
            )
        response = self.client.post(
            "/pay",
            json=payload,
            headers=headers
            | {
                "X-Payment-Receipt": receipt_token,
                "Idempotency-Key": item.safe4_idempotency_key,
            },
        )
        if response.status_code != 200:
            return AuthorizationResult(
                status="DENIED" if response.status_code < 500 else "UNKNOWN",
                binding_hash=item.binding_hash,
                reason_code=self._reason(response),
            )
        try:
            body = response.json()
            if body.get("status") != "AUTHORIZED":
                raise ValueError("authorization status is not AUTHORIZED")
            transaction_id = _safe_safe4_transaction_id(body["transaction_id"])
            reason_code = _safe_reason_code(
                body["intent_decision"]["reason_code"],
                fallback="AUTHORIZATION_RESPONSE_INVALID",
            )
            validated_payment = self.main.PaymentRequest.model_validate(payload)
            request_hash = self.main.build_request_hash(validated_payment)
        except (KeyError, TypeError, ValueError):
            return AuthorizationResult(
                status="UNKNOWN",
                binding_hash=item.binding_hash,
                reason_code="AUTHORIZATION_RESPONSE_INVALID",
            )
        if transaction_id is None:
            return AuthorizationResult(
                status="UNKNOWN",
                binding_hash=item.binding_hash,
                reason_code="AUTHORIZATION_RESPONSE_INVALID",
            )
        if reason_code != "TASK_PURCHASE_MATCH":
            return AuthorizationResult(
                status="UNKNOWN",
                binding_hash=item.binding_hash,
                reason_code="AUTHORIZATION_REASON_UNEXPECTED",
            )
        matching_audits = [
            audit
            for audit in self.main.store.list_audit_entries()
            if audit.get("action") == "payment_authorize"
            and audit.get("decision") == "authorized"
            and audit.get("transaction_id") == transaction_id
        ]
        if len(matching_audits) != 1:
            return AuthorizationResult(
                status="UNKNOWN",
                binding_hash=item.binding_hash,
                reason_code="AUTHORIZATION_AUDIT_MISSING",
            )
        audit = matching_audits[0]
        try:
            audit_amount = Decimal(str(audit.get("transaction_amount")))
        except Exception:
            audit_amount = Decimal("-1")
        expected_amount = Decimal(item.amount_units) / (10 ** USDC_DECIMALS)
        if (
            audit.get("request_payload_hash") != request_hash
            or audit_amount != expected_amount
            or audit.get("transaction_currency") != USDC_CURRENCY
        ):
            return AuthorizationResult(
                status="UNKNOWN",
                binding_hash=item.binding_hash,
                reason_code="AUTHORIZATION_AUDIT_BINDING_MISMATCH",
            )
        return AuthorizationResult(
            status="AUTHORIZED",
            binding_hash=item.binding_hash,
            reason_code=reason_code,
            safe4_transaction_id=transaction_id,
        )


__all__ = [
    "ARC_CHAIN",
    "ARC_CHAIN_ID",
    "ARC_ENTRYPOINT_ADDRESS",
    "ARC_NATIVE_USDC_ADDRESS",
    "ARC_NATIVE_USDC_DECIMALS",
    "PREDECLARED_ARC_TESTNET_RECIPIENTS",
    "USDC_CURRENCY",
    "MAX_BATCH_ITEMS",
    "MAX_ITEM_AMOUNT_UNITS",
    "MAX_BATCH_AMOUNT_UNITS",
    "BatchValidationError",
    "BindingIntegrityError",
    "EvidenceSanitizationError",
    "BatchItemInput",
    "BoundBatchItem",
    "BoundBatchPlan",
    "AuthorizationResult",
    "SubmissionResult",
    "VerificationResult",
    "ItemEvidence",
    "BatchEvidence",
    "AuthorizationPort",
    "SubmissionPort",
    "VerificationPort",
    "LiveArcBatchCoordinator",
    "CircleCliSubmissionPort",
    "ArcRpcVerificationPort",
    "LocalSafe4AuthorizationPort",
    "prepare_batch",
    "build_circle_transfer_command",
    "assert_single_bound_outgoing_transfer",
    "assert_single_successful_bound_user_operation",
]
