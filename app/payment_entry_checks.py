from __future__ import annotations

import time
from decimal import Decimal
from typing import Any, Callable

from fastapi.responses import JSONResponse


_store = None
_metrics = None
_error_payload: Callable[..., dict[str, Any]] | None = None
_decimal_to_text: Callable[[Decimal], str] | None = None
_payment_required_response: Callable[..., JSONResponse] | None = None
_deny_payment: Callable[..., JSONResponse] | None = None
_verify_x402_receipt: Callable[..., Any] | None = None
_append_audit_entry: Callable[..., None] | None = None


def setup_payment_entry_checks(
    *,
    store: Any,
    metrics: Any,
    append_audit_entry: Callable[..., None],
    error_payload: Callable[..., dict[str, Any]],
    decimal_to_text: Callable[[Decimal], str],
    payment_required_response: Callable[..., JSONResponse],
    deny_payment: Callable[..., JSONResponse],
    verify_x402_receipt: Callable[..., Any],
) -> None:
    global _store, _metrics, _append_audit_entry, _error_payload, _decimal_to_text
    global _payment_required_response, _deny_payment, _verify_x402_receipt
    _store = store
    _metrics = metrics
    _append_audit_entry = append_audit_entry
    _error_payload = error_payload
    _decimal_to_text = decimal_to_text
    _payment_required_response = payment_required_response
    _deny_payment = deny_payment
    _verify_x402_receipt = verify_x402_receipt


def _request_infrastructure_identity_fields(request: Any) -> dict[str, Any]:
    identity = getattr(request.state, "current_identity", None)
    infra = None if identity is None else getattr(identity, "infrastructure_identity", None)
    return {
        "infrastructure_provider_name": None if infra is None else infra.provider_name,
        "infrastructure_subject": None if infra is None else infra.subject,
        "infrastructure_trust_tier": None if infra is None else infra.trust_tier,
    }


def _append_x402_verification_audit_entry(
    *,
    request: Any,
    payment: Any,
    request_hash: str,
    verification: Any,
    verification_latency_ms: int,
) -> None:
    if _append_audit_entry is None:
        return

    receipt = verification.receipt
    receipt_id = verification.receipt_id
    decision_details: dict[str, Any] = {
        "reason_code": verification.reason_code or (
            "X402_RECEIPT_ACCEPTED" if verification.status == "accepted" else "X402_RECEIPT_UNSPECIFIED"
        ),
        "receipt_id": receipt_id,
        "receipt_source": getattr(verification, "receipt_source", "signed_receipt_fallback"),
        "verifier_name": getattr(verification, "verifier_name", "unknown"),
        "verification_latency_ms": verification_latency_ms,
    }
    if isinstance(receipt, dict):
        for field in (
            "provider_name",
            "network",
            "currency",
            "status",
            "verification_status",
            "verification_reason_code",
            "issuer_url",
            "key_id",
            "settlement_reference",
            "expires_at",
            "used_at",
        ):
            if field in receipt:
                decision_details[field] = receipt.get(field)

    _append_audit_entry(
        actor_type="agent",
        actor_id=payment.agent_id,
        action="x402_verify",
        request_path="/pay",
        request_payload_hash=request_hash,
        request_payload_summary={
            "user_id": payment.user_id,
            "vendor": payment.vendor,
            "currency": payment.currency,
            "receipt_source": getattr(verification, "receipt_source", "signed_receipt_fallback"),
        },
        decision="accepted" if verification.status == "accepted" else verification.status,
        decision_reason=verification.reason_code,
        decision_details=decision_details,
        transaction_amount=payment.amount,
        transaction_currency=payment.currency,
        mcp_tool_id=payment.mcp_tool_id,
        **_request_infrastructure_identity_fields(request),
    )


def check_payment_idempotency(
    *,
    request: Any,
    idempotency_key: str | None,
    request_hash: str,
) -> JSONResponse | None:
    if not idempotency_key:
        return None
    existing = _store.get_idempotency(idempotency_key)
    if existing is None:
        return None
    stored_request_hash, stored_record = existing
    if stored_request_hash != request_hash:
        _metrics.increment("payment_idempotency_conflict_total")
        return JSONResponse(
            status_code=409,
            content=_error_payload(
                request,
                "IDEMPOTENCY_KEY_REUSED",
                "Idempotency key was already used for a different request body.",
                {"idempotency_key": idempotency_key},
            ),
        )
    _metrics.increment("payment_idempotency_replay_total")
    return JSONResponse(status_code=stored_record.status_code, content=stored_record.response_body)


def validate_payment_receipt(
    *,
    request: Any,
    payment: Any,
    request_hash: str,
    amount_due: Decimal,
    started_at: float,
    idempotency_key: str | None,
    x_payment_receipt: str | None,
) -> tuple[JSONResponse | None, str | None, dict[str, Any] | None, str]:
    verification_started_at = time.perf_counter()
    verification = _verify_x402_receipt(payment=payment, amount_due=amount_due, receipt_token=x_payment_receipt)
    verification_latency_ms = int((time.perf_counter() - verification_started_at) * 1000)
    receipt_id = verification.receipt_id
    receipt = verification.receipt
    receipt_source = getattr(verification, "receipt_source", "signed_receipt_fallback")
    _append_x402_verification_audit_entry(
        request=request,
        payment=payment,
        request_hash=request_hash,
        verification=verification,
        verification_latency_ms=verification_latency_ms,
    )

    if verification.status == "payment_required":
        return (
            _payment_required_response(
                request=request,
                payment=payment,
                request_hash=request_hash,
                amount_due=amount_due,
                idempotency_key=idempotency_key,
            ),
            receipt_id,
            receipt,
            receipt_source,
        )

    if verification.status == "already_used":
        return (
            _deny_payment(
                request=request,
                payment=payment,
                request_hash=request_hash,
                amount_due=amount_due,
                started_at=started_at,
                idempotency_key=idempotency_key,
                status_code=402,
                error_code=verification.reason_code or "PAYMENT_RECEIPT_ALREADY_USED",
                message="Payment receipt has already been consumed by a previous authorization attempt.",
                details={"receipt": receipt_id, "amount_due": _decimal_to_text(amount_due)},
                metric_name="payment_receipt_reused_total",
                audit_reason="Payment receipt has already been consumed by a previous authorization attempt.",
                audit_reason_code=verification.reason_code or "PAYMENT_RECEIPT_ALREADY_USED",
                extra_audit_details={"receipt": receipt_id, "receipt_source": receipt_source},
            ),
            receipt_id,
            receipt,
            receipt_source,
        )

    if verification.status == "expired":
        return (
            _deny_payment(
                request=request,
                payment=payment,
                request_hash=request_hash,
                amount_due=amount_due,
                started_at=started_at,
                idempotency_key=idempotency_key,
                status_code=402,
                error_code=verification.reason_code or "PAYMENT_RECEIPT_EXPIRED",
                message="Payment receipt has expired and can no longer authorize a request.",
                details={"receipt": receipt_id, "expires_at": receipt["expires_at"]},
                metric_name="payment_receipt_expired_total",
                audit_reason="Payment receipt has expired and can no longer authorize a request.",
                audit_reason_code=verification.reason_code or "PAYMENT_RECEIPT_EXPIRED",
                extra_audit_details={"receipt": receipt_id, "receipt_source": receipt_source},
            ),
            receipt_id,
            receipt,
            receipt_source,
        )

    if verification.status == "mismatch":
        amount_field = "amount_due" if receipt is not None and "amount_due" in receipt else "amount_paid"
        receipt_amount = Decimal(str(receipt[amount_field])) if receipt is not None else Decimal("0")
        return (
            _deny_payment(
                request=request,
                payment=payment,
                request_hash=request_hash,
                amount_due=amount_due,
                started_at=started_at,
                idempotency_key=idempotency_key,
                status_code=402,
                error_code=verification.reason_code or "PAYMENT_RECEIPT_MISMATCH",
                message="Payment receipt does not match the required fee for this request.",
                details={
                    "receipt": receipt_id,
                    "expected_amount_due": _decimal_to_text(amount_due),
                    "receipt_amount_due": _decimal_to_text(receipt_amount),
                    "expected_currency": payment.currency,
                    "receipt_currency": receipt["currency"],
                },
                metric_name="payment_receipt_mismatch_total",
                audit_reason="Payment receipt does not match the required fee for this request.",
                audit_reason_code=verification.reason_code or "PAYMENT_RECEIPT_MISMATCH",
                extra_audit_details={"receipt": receipt_id, "receipt_source": receipt_source},
            ),
            receipt_id,
            receipt,
            receipt_source,
        )

    if verification.status == "invalid":
        return (
            _deny_payment(
                request=request,
                payment=payment,
                request_hash=request_hash,
                amount_due=amount_due,
                started_at=started_at,
                idempotency_key=idempotency_key,
                status_code=402,
                error_code=verification.reason_code or "PAYMENT_RECEIPT_INVALID",
                message="Payment receipt could not be verified.",
                details={"receipt": receipt_id, "receipt_source": receipt_source},
                metric_name="payment_receipt_invalid_total",
                audit_reason="Payment receipt could not be verified.",
                audit_reason_code=verification.reason_code or "PAYMENT_RECEIPT_INVALID",
                extra_audit_details={"receipt": receipt_id, "receipt_source": receipt_source},
            ),
            receipt_id,
            receipt,
            receipt_source,
        )

    if verification.status == "provider_disabled":
        return (
            _deny_payment(
                request=request,
                payment=payment,
                request_hash=request_hash,
                amount_due=amount_due,
                started_at=started_at,
                idempotency_key=idempotency_key,
                status_code=403,
                error_code=verification.reason_code or "ADVANCED_X402_DISABLED",
                message="Provider-backed x402 receipts are disabled by the active policy.",
                details={"receipt_source": receipt_source},
                metric_name="payment_provider_receipt_disabled_total",
                audit_reason="Provider-backed x402 receipts are disabled by the active policy.",
                audit_reason_code=verification.reason_code or "ADVANCED_X402_DISABLED",
                extra_audit_details={"receipt_source": receipt_source},
            ),
            receipt_id,
            receipt,
            receipt_source,
        )

    return None, receipt_id, receipt, receipt_source
