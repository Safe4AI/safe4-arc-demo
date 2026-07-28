"""Verify that an Arc Testnet transaction is the exact expected USDC transfer."""

from __future__ import annotations

import argparse
import re
import sys
from typing import Any

import httpx


TRANSFER_SELECTOR = "a9059cbb"
TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
USER_OPERATION_EVENT_TOPIC = (
    "0x49628fd1471006c1482da88028e9ce4dbb080b815c9b0344d39e5a8e6ec1419f"
)
ADDRESS_PATTERN = re.compile(r"^0x[0-9a-fA-F]{40}$")
TX_HASH_PATTERN = re.compile(r"^0x[0-9a-fA-F]{64}$")


class ArcSettlementError(RuntimeError):
    """Raised when onchain evidence does not match the expected settlement."""


def validate_address(value: str, *, label: str) -> str:
    if not ADDRESS_PATTERN.fullmatch(value):
        raise ArcSettlementError(f"{label} must be a 20-byte 0x-prefixed address")
    return value.lower()


def validate_transaction_hash(value: str) -> str:
    if not TX_HASH_PATTERN.fullmatch(value):
        raise ArcSettlementError("transaction hash must be 32-byte 0x-prefixed hex")
    return value.lower()


def parse_hex_int(value: Any, *, label: str) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 16)
        except ValueError as exc:
            raise ArcSettlementError(f"{label} is not a hex integer") from exc
    raise ArcSettlementError(f"{label} is missing or not an integer")


def encode_transfer(recipient: str, amount_units: int) -> str:
    normalized = validate_address(recipient, label="recipient")[2:]
    if amount_units <= 0:
        raise ArcSettlementError("amount_units must be positive")
    return (
        "0x"
        + TRANSFER_SELECTOR
        + normalized.rjust(64, "0")
        + f"{amount_units:064x}"
    )


def address_topic(address: str) -> str:
    return "0x" + validate_address(address, label="topic address")[2:].rjust(64, "0")


def rpc(
    client: httpx.Client,
    rpc_url: str,
    method: str,
    params: list[Any],
) -> Any:
    response = client.post(
        rpc_url,
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
    )
    response.raise_for_status()
    payload = response.json()
    if "error" in payload:
        raise ArcSettlementError(f"{method} failed: {payload['error']}")
    if "result" not in payload:
        raise ArcSettlementError(f"{method} returned no result")
    return payload["result"]


def verify_settlement_payloads(
    transaction: dict[str, Any] | None,
    receipt: dict[str, Any] | None,
    *,
    transaction_hash: str,
    usdc_address: str,
    sender: str,
    recipient: str,
    amount_units: int,
) -> int:
    expected_hash = validate_transaction_hash(transaction_hash)
    expected_usdc = validate_address(usdc_address, label="USDC address")
    expected_sender = validate_address(sender, label="sender")
    expected_recipient = validate_address(recipient, label="recipient")
    expected_input = encode_transfer(expected_recipient, amount_units)

    if transaction is None:
        raise ArcSettlementError("transaction not found")
    if receipt is None:
        raise ArcSettlementError("transaction receipt not found")
    if str(transaction.get("hash", "")).lower() != expected_hash:
        raise ArcSettlementError("transaction hash does not match RPC payload")
    if str(receipt.get("transactionHash", "")).lower() != expected_hash:
        raise ArcSettlementError("receipt hash does not match expected transaction")
    if parse_hex_int(receipt.get("status"), label="receipt status") != 1:
        raise ArcSettlementError("transaction receipt status is not successful")
    if str(transaction.get("to", "")).lower() != expected_usdc:
        raise ArcSettlementError("transaction target is not the configured USDC contract")
    if str(transaction.get("from", "")).lower() != expected_sender:
        raise ArcSettlementError("transaction sender does not match SETTLEMENT_FROM")
    if parse_hex_int(transaction.get("value", "0x0"), label="transaction value") != 0:
        raise ArcSettlementError("USDC ERC-20 transfer must have zero native value")
    if str(transaction.get("input", "")).lower() != expected_input.lower():
        raise ArcSettlementError("transaction calldata does not match recipient and amount")

    sender_topic = address_topic(expected_sender)
    recipient_topic = address_topic(expected_recipient)
    matching_log = False
    for entry in receipt.get("logs", []):
        topics = [str(topic).lower() for topic in entry.get("topics", [])]
        if (
            str(entry.get("address", "")).lower() == expected_usdc
            and len(topics) >= 3
            and topics[0] == TRANSFER_TOPIC
            and topics[1] == sender_topic
            and topics[2] == recipient_topic
            and parse_hex_int(entry.get("data", "0x0"), label="Transfer amount")
            == amount_units
        ):
            matching_log = True
            break
    if not matching_log:
        raise ArcSettlementError(
            "receipt has no matching USDC Transfer(sender, recipient, amount) event"
        )

    return parse_hex_int(receipt.get("blockNumber"), label="receipt block number")


def verify_circle_agent_wallet_payloads(
    transaction: dict[str, Any] | None,
    receipt: dict[str, Any] | None,
    *,
    transaction_hash: str,
    entrypoint_address: str,
    native_usdc_address: str,
    sender: str,
    recipient: str,
    native_amount_units: int,
) -> int:
    """Verify an ERC-4337 Agent Wallet transfer from its receipt evidence."""

    expected_hash = validate_transaction_hash(transaction_hash)
    expected_entrypoint = validate_address(
        entrypoint_address,
        label="ERC-4337 EntryPoint address",
    )
    expected_native_usdc = validate_address(
        native_usdc_address,
        label="Arc native USDC event address",
    )
    expected_sender = validate_address(sender, label="Agent Wallet sender")
    expected_recipient = validate_address(recipient, label="recipient")
    if native_amount_units <= 0:
        raise ArcSettlementError("native_amount_units must be positive")

    if transaction is None:
        raise ArcSettlementError("transaction not found")
    if receipt is None:
        raise ArcSettlementError("transaction receipt not found")
    if str(transaction.get("hash", "")).lower() != expected_hash:
        raise ArcSettlementError("transaction hash does not match RPC payload")
    if str(receipt.get("transactionHash", "")).lower() != expected_hash:
        raise ArcSettlementError("receipt hash does not match expected transaction")
    if parse_hex_int(receipt.get("status"), label="receipt status") != 1:
        raise ArcSettlementError("transaction receipt status is not successful")
    if str(transaction.get("to", "")).lower() != expected_entrypoint:
        raise ArcSettlementError(
            "Agent Wallet transaction target is not the configured ERC-4337 EntryPoint"
        )
    if parse_hex_int(transaction.get("value", "0x0"), label="transaction value") != 0:
        raise ArcSettlementError("ERC-4337 settlement transaction must have zero value")

    sender_topic = address_topic(expected_sender)
    recipient_topic = address_topic(expected_recipient)
    transfer_seen = False
    successful_user_operation_seen = False
    for entry in receipt.get("logs", []):
        address = str(entry.get("address", "")).lower()
        topics = [str(topic).lower() for topic in entry.get("topics", [])]
        data = str(entry.get("data", "0x0")).lower()
        if (
            address == expected_native_usdc
            and len(topics) >= 3
            and topics[0] == TRANSFER_TOPIC
            and topics[1] == sender_topic
            and topics[2] == recipient_topic
            and parse_hex_int(data, label="Arc native USDC Transfer amount")
            == native_amount_units
        ):
            transfer_seen = True
        if (
            address == expected_entrypoint
            and len(topics) >= 3
            and topics[0] == USER_OPERATION_EVENT_TOPIC
            and topics[2] == sender_topic
            and len(data) >= 130
            and parse_hex_int("0x" + data[66:130], label="UserOperation success") == 1
        ):
            successful_user_operation_seen = True

    if not transfer_seen:
        raise ArcSettlementError(
            "receipt has no matching Arc native USDC "
            "Transfer(Agent Wallet, recipient, amount) event"
        )
    if not successful_user_operation_seen:
        raise ArcSettlementError(
            "receipt has no successful ERC-4337 UserOperation for the Agent Wallet"
        )

    return parse_hex_int(receipt.get("blockNumber"), label="receipt block number")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rpc-url", required=True)
    parser.add_argument("--chain-id", required=True, type=int)
    parser.add_argument("--usdc-address", required=True)
    parser.add_argument("--tx-hash", required=True)
    parser.add_argument("--sender", required=True)
    parser.add_argument("--recipient", required=True)
    parser.add_argument("--amount-units", required=True, type=int)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        with httpx.Client(timeout=15.0) as client:
            actual_chain_id = parse_hex_int(
                rpc(client, args.rpc_url, "eth_chainId", []),
                label="chain ID",
            )
            if actual_chain_id != args.chain_id:
                raise ArcSettlementError(
                    f"wrong chain: expected {args.chain_id}, RPC returned {actual_chain_id}"
                )
            transaction = rpc(
                client,
                args.rpc_url,
                "eth_getTransactionByHash",
                [args.tx_hash],
            )
            receipt = rpc(
                client,
                args.rpc_url,
                "eth_getTransactionReceipt",
                [args.tx_hash],
            )
        block_number = verify_settlement_payloads(
            transaction,
            receipt,
            transaction_hash=args.tx_hash,
            usdc_address=args.usdc_address,
            sender=args.sender,
            recipient=args.recipient,
            amount_units=args.amount_units,
        )
        print(
            "ARC_SETTLEMENT_OK "
            f"tx={args.tx_hash} from={args.sender} to={args.recipient} "
            f"amount_units={args.amount_units} block={block_number}"
        )
        return 0
    except (ArcSettlementError, httpx.HTTPError, ValueError) as exc:
        print(f"ARC_SETTLEMENT_FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
