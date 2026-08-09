"""Admin-gated live Arc Testnet settlement lane for presentation use.

This lane exists so a presenter can show one real on-chain transfer that only
happens after Safe4 authorizes it. It is deliberately separate from the public
browser lab, which remains authorization-only and never broadcasts.

Every one of the following must hold before a transaction is constructed:

* ``ARC_PRIVATE_KEY`` is present. Without it the lane is inert and returns 503,
  so a deployment that has not deliberately opted in can never settle.
* ``PAYMENT_FIREWALL_LIVE_ADMIN_SECRET`` is present and the caller presents it.
* The recipient is taken from configuration, never from the request, so a
  compromised caller cannot redirect funds.
* The amount is at or below the per-transaction cap and the running daily total
  stays at or below the daily cap.
* Safe4's real intent evaluator returns ALLOW. On DENY the handler returns
  before any transaction is built, signed, or sent.

The signing and verification steps mirror ``scripts/arc_testnet_transfer.py``.
"""

from __future__ import annotations

from datetime import date
from decimal import Decimal
import os
import threading
from typing import Any

import httpx
from fastapi import APIRouter, Header, HTTPException, status
from pydantic import BaseModel, Field

from ..core.intent import evaluate_payment_intent


router = APIRouter()

ARC_CHAIN_ID = 5_042_002
USDC_DECIMALS = 6
TRANSFER_SELECTOR = "a9059cbb"
TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
EXPLORER = "https://testnet.arcscan.app"

# Hard ceilings. These bound the loss if the admin secret ever leaks.
MAX_PER_TRANSACTION = Decimal("0.01")
MAX_PER_DAY = Decimal("0.10")

_spend_lock = threading.Lock()
_spend_day: date | None = None
_spend_total = Decimal("0")


class LiveSettleRequest(BaseModel):
    task: str = Field(min_length=1, max_length=500)
    purpose: str = Field(min_length=1, max_length=500)
    amount: Decimal = Field(default=Decimal("0.001"))
    service_category: str = Field(default="company-research", max_length=80)


def _rpc_url() -> str:
    return os.getenv("ARC_RPC_URL", "https://rpc.testnet.arc.network")


def _usdc_address() -> str:
    return os.getenv("ARC_USDC_ADDRESS", "0x3600000000000000000000000000000000000000")


def _recipient() -> str | None:
    """Settlement destination. Configuration only; never request-supplied."""
    return os.getenv("ARC_LIVE_RECIPIENT") or os.getenv("PAYMENT_FIREWALL_PAY_TO")


def _rpc(client: httpx.Client, method: str, params: list[Any]) -> Any:
    response = client.post(
        _rpc_url(), json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    )
    response.raise_for_status()
    body = response.json()
    if "error" in body:
        raise RuntimeError(f"{method} failed: {body['error'].get('message')}")
    return body["result"]


def _units(amount: Decimal) -> int:
    scaled = amount * (10**USDC_DECIMALS)
    if scaled != scaled.to_integral_value():
        raise ValueError("amount supports at most 6 decimal places")
    return int(scaled)


def _encode_transfer(recipient: str, amount_units: int) -> str:
    return (
        "0x"
        + TRANSFER_SELECTOR
        + recipient[2:].lower().rjust(64, "0")
        + f"{amount_units:064x}"
    )


def _reserve_daily_budget(amount: Decimal) -> None:
    """Reserve against the daily cap before any transaction is constructed."""
    global _spend_day, _spend_total
    today = date.today()
    with _spend_lock:
        if _spend_day != today:
            _spend_day = today
            _spend_total = Decimal("0")
        if _spend_total + amount > MAX_PER_DAY:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail={
                    "code": "LIVE_DAILY_CAP_EXCEEDED",
                    "spent_today": str(_spend_total),
                    "daily_cap": str(MAX_PER_DAY),
                },
            )
        _spend_total += amount


def _release_daily_budget(amount: Decimal) -> None:
    global _spend_total
    with _spend_lock:
        _spend_total = max(Decimal("0"), _spend_total - amount)


def _verify_transfer_log(receipt: dict, sender: str, recipient: str, units: int) -> bool:
    """Confirm the receipt contains the exact ERC-20 Transfer we intended."""
    for log in receipt.get("logs", []):
        topics = log.get("topics") or []
        if len(topics) < 3 or topics[0].lower() != TRANSFER_TOPIC:
            continue
        log_from = "0x" + topics[1][-40:]
        log_to = "0x" + topics[2][-40:]
        if log_from.lower() != sender.lower() or log_to.lower() != recipient.lower():
            continue
        if int(log.get("data", "0x0"), 16) == units:
            return True
    return False


@router.post("/demo/live/settle")
def live_settle(
    payload: LiveSettleRequest,
    live_admin: str | None = Header(default=None, alias="X-Live-Admin"),
) -> dict[str, Any]:
    admin_secret = os.getenv("PAYMENT_FIREWALL_LIVE_ADMIN_SECRET")
    private_key = os.getenv("ARC_PRIVATE_KEY")

    # Inert unless this deployment deliberately opted in.
    if not private_key or not admin_secret:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "LIVE_SETTLEMENT_NOT_CONFIGURED"},
        )
    if not live_admin or not _constant_time_equals(live_admin, admin_secret):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "LIVE_ADMIN_REQUIRED"},
        )

    recipient = _recipient()
    if not recipient:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "LIVE_RECIPIENT_NOT_CONFIGURED"},
        )

    if payload.amount <= 0 or payload.amount > MAX_PER_TRANSACTION:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "code": "LIVE_AMOUNT_CAP_EXCEEDED",
                "requested": str(payload.amount),
                "per_transaction_cap": str(MAX_PER_TRANSACTION),
            },
        )

    # Safe4's real evaluator, the same one POST /pay uses.
    decision = evaluate_payment_intent(
        description=payload.purpose,
        context={
            "payment_intent": {
                "task": payload.task,
                "purchase_purpose": payload.purpose,
                "service_category": payload.service_category,
                "allowed_service_categories": [payload.service_category],
            }
        },
        legacy_minimum_words=8,
    )

    if not decision.allowed:
        # Nothing is constructed, signed, or sent on this path.
        return {
            "settled": False,
            "executor_invoked": False,
            "decision": decision.public_details(),
            "note": "Safe4 denied the request. No transaction was built or broadcast.",
        }

    _reserve_daily_budget(payload.amount)
    units = _units(payload.amount)
    try:
        from eth_account import Account

        account = Account.from_key(private_key)
        sender = account.address
        data = _encode_transfer(recipient, units)

        with httpx.Client(timeout=30.0) as client:
            balance = int(
                _rpc(
                    client,
                    "eth_call",
                    [
                        {
                            "to": _usdc_address(),
                            "data": "0x70a08231" + sender[2:].lower().rjust(64, "0"),
                        },
                        "latest",
                    ],
                ),
                16,
            )
            if balance < units:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail={
                        "code": "LIVE_WALLET_UNDERFUNDED",
                        "balance_usdc": str(Decimal(balance) / 10**USDC_DECIMALS),
                    },
                )

            estimate = {
                "from": sender,
                "to": _usdc_address(),
                "value": "0x0",
                "data": data,
            }
            gas = int(_rpc(client, "eth_estimateGas", [estimate]), 16)
            transaction = {
                "chainId": ARC_CHAIN_ID,
                "nonce": int(
                    _rpc(client, "eth_getTransactionCount", [sender, "pending"]), 16
                ),
                "to": _usdc_address(),
                "value": 0,
                "data": data,
                "gasPrice": int(_rpc(client, "eth_gasPrice", []), 16),
                "gas": max(gas * 12 // 10, gas + 1_000),
            }
            signed = account.sign_transaction(transaction)
            tx_hash = _rpc(
                client, "eth_sendRawTransaction", ["0x" + signed.raw_transaction.hex()]
            )

        # Return as soon as the transaction is accepted by the node. Confirmation
        # is observed separately through /demo/live/status so the caller can show
        # real chain progress instead of blocking on one long request.
        _remember_pending(tx_hash, sender, recipient, units)
        return {
            "settled": True,
            "executor_invoked": True,
            "broadcast": True,
            "confirmed": False,
            "decision": decision.public_details(),
            "network": "arc-testnet",
            "chain_id": ARC_CHAIN_ID,
            "from": sender,
            "to": recipient,
            "amount_usdc": str(payload.amount),
            "transaction": tx_hash,
            "explorer": f"{EXPLORER}/tx/{tx_hash}",
        }
    except HTTPException:
        _release_daily_budget(payload.amount)
        raise
    except Exception as exc:  # fail closed, and never leak key material
        _release_daily_budget(payload.amount)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={"code": "LIVE_SETTLEMENT_FAILED", "error": type(exc).__name__},
        ) from exc


def _constant_time_equals(left: str, right: str) -> bool:
    import hmac

    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


_pending_lock = threading.Lock()
_pending: dict[str, tuple[str, str, int]] = {}


def _remember_pending(tx_hash: str, sender: str, recipient: str, units: int) -> None:
    """Record what a broadcast transaction is expected to contain.

    The status endpoint verifies against this rather than trusting its caller,
    so a status query cannot be used to assert an unrelated transaction.
    """
    with _pending_lock:
        if len(_pending) > 256:
            _pending.clear()
        _pending[tx_hash.lower()] = (sender, recipient, units)


@router.get("/demo/live/status")
def live_status(
    tx: str,
    live_admin: str | None = Header(default=None, alias="X-Live-Admin"),
) -> dict[str, Any]:
    admin_secret = os.getenv("PAYMENT_FIREWALL_LIVE_ADMIN_SECRET")
    if not admin_secret:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "LIVE_SETTLEMENT_NOT_CONFIGURED"},
        )
    if not live_admin or not _constant_time_equals(live_admin, admin_secret):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "LIVE_ADMIN_REQUIRED"},
        )

    with _pending_lock:
        expected = _pending.get(tx.lower())
    if expected is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "LIVE_TRANSACTION_NOT_FROM_THIS_LANE"},
        )
    sender, recipient, units = expected

    with httpx.Client(timeout=20.0) as client:
        receipt = _rpc(client, "eth_getTransactionReceipt", [tx])

    if not receipt:
        return {
            "transaction": tx,
            "confirmed": False,
            "pending": True,
            "explorer": f"{EXPLORER}/tx/{tx}",
        }

    succeeded = int(receipt.get("status", "0x0"), 16) == 1
    return {
        "transaction": tx,
        "confirmed": True,
        "pending": False,
        "succeeded": succeeded,
        "block": int(receipt.get("blockNumber", "0x0"), 16),
        "gas_used": int(receipt.get("gasUsed", "0x0"), 16),
        "rpc_verified_transfer_event": (
            _verify_transfer_log(receipt, sender, recipient, units)
            if succeeded
            else False
        ),
        "explorer": f"{EXPLORER}/tx/{tx}",
    }
