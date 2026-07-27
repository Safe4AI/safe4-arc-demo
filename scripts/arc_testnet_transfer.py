"""Send and RPC-confirm a standalone USDC transfer on Arc Testnet.

This script is intentionally outside Safe4's payment path. It proves the chain,
wallet, gas, and USDC contract path in isolation before the D2 integration.

Never put a private key in the repository. Set ARC_PRIVATE_KEY only in the
process environment and pass the recipient explicitly.
"""

from __future__ import annotations

import argparse
from decimal import Decimal, InvalidOperation
import os
import re
import sys
import time
from typing import Any

import httpx


ARC_RPC_URL = os.getenv("ARC_RPC_URL", "https://rpc.testnet.arc.io")
ARC_CHAIN_ID = 5_042_002
ARC_USDC_ADDRESS = os.getenv(
    "ARC_USDC_ADDRESS",
    "0x3600000000000000000000000000000000000000",
)
ARC_EXPLORER_URL = "https://testnet.arcscan.app"
USDC_DECIMALS = 6
TRANSFER_SELECTOR = "a9059cbb"
BALANCE_OF_SELECTOR = "70a08231"
DECIMALS_SELECTOR = "313ce567"
TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
ADDRESS_PATTERN = re.compile(r"^0x[0-9a-fA-F]{40}$")


class ArcTransferError(RuntimeError):
    """Raised when the standalone transfer cannot be proven successful."""


def validate_address(value: str, *, label: str) -> str:
    if not ADDRESS_PATTERN.fullmatch(value):
        raise ArcTransferError(f"{label} must be a 20-byte 0x-prefixed address")
    return value


def usdc_units(value: str) -> int:
    try:
        amount = Decimal(value)
    except InvalidOperation as exc:
        raise ArcTransferError(f"invalid USDC amount: {value}") from exc
    if amount <= 0:
        raise ArcTransferError("USDC amount must be positive")
    scaled = amount * (10**USDC_DECIMALS)
    if scaled != scaled.to_integral_value():
        raise ArcTransferError("USDC amount supports at most 6 decimal places")
    return int(scaled)


def encode_transfer(recipient: str, amount_units: int) -> str:
    address = validate_address(recipient, label="recipient")[2:].lower()
    return "0x" + TRANSFER_SELECTOR + address.rjust(64, "0") + f"{amount_units:064x}"


def encode_balance_of(address: str) -> str:
    normalized = validate_address(address, label="wallet")[2:].lower()
    return "0x" + BALANCE_OF_SELECTOR + normalized.rjust(64, "0")


def rpc(client: httpx.Client, method: str, params: list[Any]) -> Any:
    response = client.post(
        ARC_RPC_URL,
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
    )
    response.raise_for_status()
    payload = response.json()
    if "error" in payload:
        raise ArcTransferError(f"{method} failed: {payload['error']}")
    if "result" not in payload:
        raise ArcTransferError(f"{method} returned no result")
    return payload["result"]


def verify_network(client: httpx.Client) -> None:
    chain_id = int(rpc(client, "eth_chainId", []), 16)
    if chain_id != ARC_CHAIN_ID:
        raise ArcTransferError(
            f"wrong chain: expected {ARC_CHAIN_ID}, RPC returned {chain_id}"
        )
    code = rpc(client, "eth_getCode", [ARC_USDC_ADDRESS, "latest"])
    if code in {"0x", "0x0", None}:
        raise ArcTransferError(f"no contract code at USDC address {ARC_USDC_ADDRESS}")
    decimals = int(
        rpc(
            client,
            "eth_call",
            [{"to": ARC_USDC_ADDRESS, "data": "0x" + DECIMALS_SELECTOR}, "latest"],
        ),
        16,
    )
    if decimals != USDC_DECIMALS:
        raise ArcTransferError(
            f"USDC decimals mismatch: expected {USDC_DECIMALS}, got {decimals}"
        )
    print(
        f"RPC_OK rpc={ARC_RPC_URL} chain_id={chain_id} "
        f"usdc={ARC_USDC_ADDRESS} decimals={decimals}"
    )


def matching_transfer_log(receipt: dict[str, Any]) -> bool:
    for entry in receipt.get("logs", []):
        topics = [str(topic).lower() for topic in entry.get("topics", [])]
        if (
            str(entry.get("address", "")).lower() == ARC_USDC_ADDRESS.lower()
            and topics
            and topics[0] == TRANSFER_TOPIC
        ):
            return True
    return False


def wait_for_receipt(
    client: httpx.Client,
    transaction_hash: str,
    *,
    timeout_seconds: float = 30.0,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        receipt = rpc(client, "eth_getTransactionReceipt", [transaction_hash])
        if receipt is not None:
            return receipt
        time.sleep(0.5)
    raise ArcTransferError(
        f"transaction was not confirmed within {timeout_seconds:.0f}s: {transaction_hash}"
    )


def send_transfer(client: httpx.Client, recipient: str, amount: str) -> str:
    try:
        from eth_account import Account
    except ImportError as exc:
        raise ArcTransferError(
            "eth-account is required; install requirements-arc.txt"
        ) from exc

    private_key = os.getenv("ARC_PRIVATE_KEY")
    if not private_key:
        raise ArcTransferError(
            "ARC_PRIVATE_KEY is unset; provide it only in the process environment"
        )

    account = Account.from_key(private_key)
    sender = account.address
    amount_units = usdc_units(amount)
    data = encode_transfer(recipient, amount_units)
    balance = int(
        rpc(
            client,
            "eth_call",
            [{"to": ARC_USDC_ADDRESS, "data": encode_balance_of(sender)}, "latest"],
        ),
        16,
    )
    if balance < amount_units:
        raise ArcTransferError(
            f"insufficient USDC: balance={balance / 10**USDC_DECIMALS:.6f}, "
            f"requested={amount_units / 10**USDC_DECIMALS:.6f}"
        )

    transaction: dict[str, Any] = {
        "chainId": ARC_CHAIN_ID,
        "nonce": int(rpc(client, "eth_getTransactionCount", [sender, "pending"]), 16),
        "to": ARC_USDC_ADDRESS,
        "value": 0,
        "data": data,
        "gasPrice": int(rpc(client, "eth_gasPrice", []), 16),
    }
    estimate_request = {
        "from": sender,
        "to": ARC_USDC_ADDRESS,
        "value": "0x0",
        "data": data,
    }
    estimated_gas = int(rpc(client, "eth_estimateGas", [estimate_request]), 16)
    transaction["gas"] = max(estimated_gas * 12 // 10, estimated_gas + 1_000)

    signed = account.sign_transaction(transaction)
    transaction_hash = rpc(
        client,
        "eth_sendRawTransaction",
        ["0x" + signed.raw_transaction.hex()],
    )
    print(f"SUBMITTED tx={transaction_hash}")

    receipt = wait_for_receipt(client, transaction_hash)
    if int(receipt.get("status", "0x0"), 16) != 1:
        raise ArcTransferError(f"transaction reverted: {transaction_hash}")
    if not matching_transfer_log(receipt):
        raise ArcTransferError(
            f"transaction succeeded without a USDC Transfer log: {transaction_hash}"
        )

    print(f"CONFIRMED tx={transaction_hash} block={int(receipt['blockNumber'], 16)}")
    print(f"EXPLORER={ARC_EXPLORER_URL}/tx/{transaction_hash}")
    print(f"SETTLEMENT_FROM={sender}")
    print(f"SETTLEMENT_TO={recipient}")
    print(f"SETTLEMENT_AMOUNT_UNITS={amount_units}")
    print(f"SETTLEMENT_TX={transaction_hash}")
    return transaction_hash


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="verify Arc chain ID, USDC bytecode, and decimals without signing",
    )
    parser.add_argument(
        "--recipient",
        default=os.getenv("ARC_RECIPIENT"),
        help="recipient address (or set ARC_RECIPIENT)",
    )
    parser.add_argument(
        "--amount",
        default=os.getenv("ARC_TRANSFER_AMOUNT_USDC", "0.01"),
        help="USDC amount, up to 6 decimal places (default: 0.01)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        validate_address(ARC_USDC_ADDRESS, label="ARC_USDC_ADDRESS")
        with httpx.Client(timeout=15.0) as client:
            verify_network(client)
            if args.check_only:
                return 0
            if not args.recipient:
                raise ArcTransferError(
                    "--recipient or ARC_RECIPIENT is required; no implicit destination is used"
                )
            send_transfer(client, args.recipient, args.amount)
        return 0
    except (ArcTransferError, httpx.HTTPError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
