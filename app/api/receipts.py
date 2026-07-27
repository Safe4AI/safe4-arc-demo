from __future__ import annotations

import hashlib
import json
from decimal import Decimal
from typing import Any, Callable

from fastapi import APIRouter, Header, Request, status
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..auth import (
    audit_infrastructure_identity_fields,
    capture_infrastructure_identity_profile,
    require_trusted_infrastructure_identity_for_admin,
)


router = APIRouter()

_store = None
_append_audit_entry: Callable[..., None] | None = None
_issue_receipt: Callable[..., dict[str, Any]] | None = None
_decimal_to_text: Callable[[Any], str] | None = None
_sanitize_text: Callable[[str, int], str] | None = None
_parse_decimal_input: Callable[[Any, str], Any] | None = None
_normalize_money: Callable[[Any], Any] | None = None
_error_payload: Callable[..., dict[str, Any]] | None = None
_get_current_identity = None
_ensure_scope: Callable[[Any, list[str]], Any] | None = None
_metrics = None
_max_amount = None
_default_receipt_ttl_seconds = 0
_pay_to_address = ""
_receipt_admin_secret = ""
_allowed_currencies: set[str] = set()


def setup_receipts_api(
    *,
    store: Any,
    append_audit_entry: Callable[..., None],
    issue_receipt: Callable[..., dict[str, Any]],
    decimal_to_text: Callable[[Any], str],
    sanitize_text: Callable[[str, int], str],
    parse_decimal_input: Callable[[Any, str], Any],
    normalize_money: Callable[[Any], Any],
    error_payload: Callable[..., dict[str, Any]],
    get_current_identity: Callable[..., Any],
    ensure_scope: Callable[[Any, list[str]], Any],
    metrics: Any,
    max_amount: Any,
    default_receipt_ttl_seconds: int,
    pay_to_address: str,
    receipt_admin_secret: str,
    allowed_currencies: set[str],
) -> None:
    global _store, _append_audit_entry, _issue_receipt, _decimal_to_text, _sanitize_text, _parse_decimal_input
    global _normalize_money, _error_payload, _get_current_identity, _ensure_scope, _metrics, _max_amount
    global _default_receipt_ttl_seconds, _pay_to_address, _receipt_admin_secret, _allowed_currencies
    _store = store
    _append_audit_entry = append_audit_entry
    _issue_receipt = issue_receipt
    _decimal_to_text = decimal_to_text
    _sanitize_text = sanitize_text
    _parse_decimal_input = parse_decimal_input
    _normalize_money = normalize_money
    _error_payload = error_payload
    _get_current_identity = get_current_identity
    _ensure_scope = ensure_scope
    _metrics = metrics
    _max_amount = max_amount
    _default_receipt_ttl_seconds = default_receipt_ttl_seconds
    _pay_to_address = pay_to_address
    _receipt_admin_secret = receipt_admin_secret
    _allowed_currencies = allowed_currencies


class ReceiptIssueRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    amount_due: Any = Field(..., gt=0)
    currency: str = Field(..., min_length=1)
    expires_in_seconds: int = Field(300, ge=1, le=3600)
    pay_to: str | None = Field(default=None)

    @field_validator("amount_due", mode="before")
    @classmethod
    def parse_amount_due(cls, value: Any) -> Any:
        return _parse_decimal_input(value, "amount_due")

    @field_validator("amount_due")
    @classmethod
    def normalize_amount(cls, value: Any) -> Any:
        normalized = _normalize_money(value)
        if normalized > _max_amount:
            raise ValueError("amount_due must be less than or equal to 1000000.000000")
        if value != normalized:
            raise ValueError("amount_due must have at most 6 decimal places")
        return normalized

    @field_validator("currency")
    @classmethod
    def normalize_currency(cls, value: str) -> str:
        normalized = value.upper()
        if normalized not in _allowed_currencies:
            raise ValueError("currency must be one of USD, EUR, GBP, USDC")
        return normalized

    @field_validator("pay_to")
    @classmethod
    def sanitize_pay_to(cls, value: str | None) -> str | None:
        if value is None:
            return None
        sanitized = _sanitize_text(value, max_length=255)
        if not sanitized:
            raise ValueError("pay_to cannot be empty")
        return sanitized


def _require_admin_identity(
    authorization: str | None,
    infrastructure_assertion: str | None = None,
    infrastructure_signature: str | None = None,
) -> Any:
    if _get_current_identity is None or _ensure_scope is None:
        raise RuntimeError("Receipts API not configured")
    identity = _get_current_identity(authorization, infrastructure_assertion, infrastructure_signature)
    return _ensure_scope(identity, ["admin:all"])


@router.post("/receipts/issue")
def issue_payment_receipt(
    request: Request,
    receipt_request: ReceiptIssueRequest,
    x_admin_secret: str | None = Header(default=None, alias="X-Admin-Secret"),
    authorization: str | None = Header(default=None, alias="Authorization"),
    infrastructure_assertion: str | None = Header(default=None, alias="X-Infrastructure-Assertion"),
    infrastructure_signature: str | None = Header(default=None, alias="X-Infrastructure-Signature"),
) -> JSONResponse:
    identity = _require_admin_identity(authorization, infrastructure_assertion, infrastructure_signature)
    require_trusted_infrastructure_identity_for_admin(identity)
    if x_admin_secret != _receipt_admin_secret:
        _metrics.increment("receipt_issue_denied_total")
        body = _error_payload(
            request,
            "ADMIN_AUTH_REQUIRED",
            "Valid admin authorization is required to issue receipts.",
        )
        return JSONResponse(status_code=status.HTTP_403_FORBIDDEN, content=body)

    receipt = _issue_receipt(
        amount_due=receipt_request.amount_due,
        currency=receipt_request.currency,
        expires_in_seconds=receipt_request.expires_in_seconds,
        pay_to=receipt_request.pay_to or _pay_to_address,
    )
    _append_audit_entry(
        actor_type="admin",
        actor_id=identity.oauth_subject,
        action="receipt_issue",
        request_path="/receipts/issue",
        request_payload_hash=hashlib.sha256(
            json.dumps(
                {
                    "amount_due": _decimal_to_text(receipt_request.amount_due),
                    "currency": receipt_request.currency,
                    "expires_in_seconds": receipt_request.expires_in_seconds,
                    "pay_to": receipt_request.pay_to or _pay_to_address,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest(),
        request_payload_summary={
            "currency": receipt_request.currency,
            "pay_to": receipt_request.pay_to or _pay_to_address,
            "expires_in_seconds": receipt_request.expires_in_seconds,
        },
        decision="issued",
        decision_reason=None,
        decision_details={"status": "issued"},
        transaction_amount=receipt_request.amount_due,
        transaction_currency=receipt_request.currency,
        **audit_infrastructure_identity_fields(identity),
    )
    capture_infrastructure_identity_profile(
        store=_store,
        identity=identity,
        actor_type="admin",
        actor_id=identity.oauth_subject,
        event_type="admin_mutation",
        action="receipt_issue",
        transaction_amount=receipt_request.amount_due,
        transaction_currency=receipt_request.currency,
        request_path="/receipts/issue",
    )
    _metrics.increment("receipt_issue_total")
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=jsonable_encoder(
            {
                "status": "issued",
                "pay_to": receipt["pay_to"],
                "amount_due": Decimal(str(receipt["amount_due"])),
                "currency": receipt["currency"],
                "expires_at": receipt["expires_at"],
                "receipt_token": receipt["token"],
                "request_id": request.state.request_id,
            }
        ),
    )
