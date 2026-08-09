"""Additive browser-wallet-signing lane for the x402 judge lab.

This lane is deliberately separate from the two lanes that already exist:

* The authorization-only browser lab (``app/api/demo_x402_ui.py``) never
  connects a wallet and never broadcasts.
* The presenter live settlement lane (``app/api/demo_live.py``) broadcasts
  from a server-held hot wallet, gated by an admin secret.

Here, a visitor connects their *own* wallet (an EIP-1193 provider such as
MetaMask) on Arc Testnet and signs the USDC transfer themselves. Safe4 never
holds or sees a wallet key for this lane -- there is no private key on this
server for it at all. The recipient address is always read from server
configuration, never from the request, so a compromised caller cannot
redirect funds. Safe4 still sits between decision and execution: the wallet
only has something to sign after ``/demo/wallet/evaluate`` returns ALLOW.

``/demo/wallet/status`` is a public, read-only RPC lookup (no admin secret):
it reports whether a given transaction hash is confirmed and whether its
ERC-20 Transfer event actually paid the configured recipient. It does not
trust its caller's claims -- every fact reported comes from an independent
RPC call.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Any

import httpx
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from ..core.intent import evaluate_payment_intent
from .demo_live import (
    ARC_CHAIN_ID,
    EXPLORER,
    TRANSFER_TOPIC,
    USDC_DECIMALS,
    _recipient,
    _rpc,
    _rpc_url,
    _usdc_address,
)

router = APIRouter()

ARC_CHAIN_ID_HEX = hex(ARC_CHAIN_ID)

# Same order-of-magnitude ceiling as the presenter live lane. This bounds
# what the *evaluate* endpoint will approve; the visitor's own wallet still
# decides whether to actually sign and broadcast.
MAX_PER_TRANSACTION = Decimal("0.01")


class WalletEvaluateRequest(BaseModel):
    task: str = Field(min_length=1, max_length=500)
    purpose: str = Field(min_length=1, max_length=500)
    amount: Decimal = Field(default=Decimal("0.001"))
    service_category: str = Field(default="company-research", max_length=80)


@router.get("/demo/wallet/config")
def wallet_config() -> dict[str, Any]:
    recipient = _recipient()
    if not recipient:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "WALLET_RECIPIENT_NOT_CONFIGURED"},
        )
    return {
        "chain_id": ARC_CHAIN_ID,
        "chain_id_hex": ARC_CHAIN_ID_HEX,
        "chain_name": "Arc Testnet",
        "rpc_url": _rpc_url(),
        "usdc_address": _usdc_address(),
        "usdc_decimals": USDC_DECIMALS,
        "recipient": recipient,
        "max_per_transaction": str(MAX_PER_TRANSACTION),
        "explorer": EXPLORER,
    }


@router.post("/demo/wallet/evaluate")
def wallet_evaluate(payload: WalletEvaluateRequest) -> dict[str, Any]:
    """Return Safe4's real decision. Never signs, broadcasts, or holds a key.

    On ALLOW, the response includes everything the caller's own wallet needs
    to construct the transfer -- amount and recipient, both server-derived,
    never echoing anything the caller could use to redirect funds.
    """
    recipient = _recipient()
    if not recipient:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "WALLET_RECIPIENT_NOT_CONFIGURED"},
        )
    if payload.amount <= 0 or payload.amount > MAX_PER_TRANSACTION:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "code": "WALLET_AMOUNT_CAP_EXCEEDED",
                "requested": str(payload.amount),
                "per_transaction_cap": str(MAX_PER_TRANSACTION),
            },
        )

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

    response: dict[str, Any] = {
        "allowed": decision.allowed,
        "decision": decision.public_details(),
    }
    if decision.allowed:
        response.update(
            {
                "recipient": recipient,
                "amount_usdc": str(payload.amount),
                "usdc_address": _usdc_address(),
                "chain_id": ARC_CHAIN_ID,
                "chain_id_hex": ARC_CHAIN_ID_HEX,
            }
        )
    return response


@router.get("/demo/wallet/status")
def wallet_status(tx: str) -> dict[str, Any]:
    """Public, read-only RPC verification of a visitor-broadcast transaction.

    Reports independently observed facts only -- confirmation state and
    whether the transaction's Transfer event actually paid the configured
    recipient. Trusts nothing the caller claims about the transaction.
    """
    recipient = _recipient()
    if not recipient:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "WALLET_RECIPIENT_NOT_CONFIGURED"},
        )

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
    verified = False
    amount_usdc: str | None = None
    if succeeded:
        for log in receipt.get("logs", []):
            topics = log.get("topics") or []
            if len(topics) < 3 or topics[0].lower() != TRANSFER_TOPIC:
                continue
            log_to = "0x" + topics[2][-40:]
            if log_to.lower() != recipient.lower():
                continue
            units = int(log.get("data", "0x0"), 16)
            amount_usdc = str(Decimal(units) / 10**USDC_DECIMALS)
            verified = True
            break

    return {
        "transaction": tx,
        "confirmed": True,
        "pending": False,
        "succeeded": succeeded,
        "block": int(receipt.get("blockNumber", "0x0"), 16),
        "rpc_verified_transfer_to_configured_recipient": verified,
        "amount_usdc": amount_usdc,
        "explorer": f"{EXPLORER}/tx/{tx}",
    }
