"""Run Safe4's judge-facing allow/deny payment path.

The default mode replays an existing Arc Testnet settlement, but verifies the
transaction against live RPC before presenting it as evidence.  The optional
``circle-live`` mode submits a fresh testnet USDC transfer with Circle Agent
Stack only after Safe4 authorizes the payment.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Any

import httpx
from fastapi.testclient import TestClient

from scripts.verify_arc_settlement import (
    ArcSettlementError,
    parse_hex_int,
    rpc,
    verify_settlement_payloads,
)


ARC_CHAIN = "ARC-TESTNET"
ARC_EXPLORER_TX = "https://testnet.arcscan.app/tx/"
TX_HASH_PATTERN = re.compile(r"0x[0-9a-fA-F]{64}")

TASK = "Research competitor pricing using a paid company data service."
ALLOWED_PURCHASE = "Generate a competitor pricing research brief from company data."
DENIED_PURCHASE = "Purchase a gift card for an unrelated entertainment giveaway."
SERVICE_CATEGORY = "company-research"


def _required_env(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


def _verify_arc_transaction(transaction_hash: str) -> dict[str, Any]:
    rpc_url = _required_env("RPC_URL")
    chain_id = int(_required_env("CHAIN_ID"))
    usdc_address = _required_env("USDC_ADDRESS")
    sender = _required_env("SETTLEMENT_FROM")
    recipient = _required_env("SETTLEMENT_TO")
    amount_units = int(_required_env("SETTLEMENT_AMOUNT_UNITS"))

    with httpx.Client(timeout=15.0) as client:
        actual_chain_id = parse_hex_int(
            rpc(client, rpc_url, "eth_chainId", []),
            label="chain ID",
        )
        if actual_chain_id != chain_id:
            raise ArcSettlementError(
                f"wrong chain: expected {chain_id}, RPC returned {actual_chain_id}"
            )
        transaction = rpc(
            client,
            rpc_url,
            "eth_getTransactionByHash",
            [transaction_hash],
        )
        receipt = rpc(
            client,
            rpc_url,
            "eth_getTransactionReceipt",
            [transaction_hash],
        )

    block_number = verify_settlement_payloads(
        transaction,
        receipt,
        transaction_hash=transaction_hash,
        usdc_address=usdc_address,
        sender=sender,
        recipient=recipient,
        amount_units=amount_units,
    )
    return {
        "transaction_hash": transaction_hash,
        "chain_id": chain_id,
        "chain": ARC_CHAIN,
        "token": usdc_address,
        "sender": sender,
        "recipient": recipient,
        "amount_units": amount_units,
        "amount_usdc": f"{amount_units / 1_000_000:.6f}",
        "block_number": block_number,
        "explorer_url": f"{ARC_EXPLORER_TX}{transaction_hash}",
        "rpc_verified": True,
    }


class SettlementExecutor:
    def __init__(self, mode: str) -> None:
        self.mode = mode
        self.calls = 0

    def settle(self) -> dict[str, Any]:
        self.calls += 1
        if self.mode == "rpc-replay":
            transaction_hash = _required_env("SETTLEMENT_TX")
            evidence = _verify_arc_transaction(transaction_hash)
            return evidence | {
                "mode": "RPC_VERIFIED_REPLAY",
                "broadcast": "EXISTING_CHAIN_EVIDENCE",
            }
        if self.mode != "circle-live":
            raise RuntimeError("SAFE4_DEMO_MODE must be rpc-replay or circle-live")

        circle = shutil.which("circle")
        if circle is None:
            raise RuntimeError(
                "Circle CLI is required for circle-live mode; install @circle-fin/cli"
            )
        sender = _required_env("SETTLEMENT_FROM")
        recipient = _required_env("SETTLEMENT_TO")
        amount_units = int(_required_env("SETTLEMENT_AMOUNT_UNITS"))
        amount = f"{amount_units / 1_000_000:.6f}"
        command = [
            circle,
            "wallet",
            "transfer",
            recipient,
            "--amount",
            amount,
            "--address",
            sender,
            "--chain",
            ARC_CHAIN,
            "--output",
            "json",
        ]
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=180,
        )
        if completed.returncode != 0:
            detail = completed.stderr.strip() or completed.stdout.strip()
            raise RuntimeError(f"Circle Agent Wallet transfer failed: {detail}")
        match = TX_HASH_PATTERN.search(completed.stdout)
        if match is None:
            raise RuntimeError(
                "Circle transfer completed without a transaction hash in JSON output"
            )
        transaction_hash = match.group(0)
        evidence = _verify_arc_transaction(transaction_hash)
        return evidence | {
            "mode": "CIRCLE_AGENT_WALLET_LIVE",
            "broadcast": "SUBMITTED_AFTER_SAFE4_ALLOW",
        }


def _issue_oauth_token(client: TestClient, main: Any) -> str:
    verifier = "a" * 43
    authorization = client.post(
        "/oauth/authorize",
        json={
            "client_id": "dev-public-client",
            "redirect_uri": "https://localhost/callback",
            "scope": "payment:read payment:authorize budget:manage audit:read admin:all",
            "code_challenge": main.compute_code_challenge(verifier),
            "code_challenge_method": "S256",
            "subject": "safe4_arc_demo_operator",
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


def _payment_payload(*, description: str) -> dict[str, Any]:
    return {
        "agent_id": "agent_alpha",
        "user_id": "user_123",
        "vendor": "circle_marketplace_company_research",
        "amount": 0.01,
        "currency": "USDC",
        "description": description,
        "context": {
            "payment_intent": {
                "task_id": "task_competitor_pricing_001",
                "task": TASK,
                "allowed_service_categories": [SERVICE_CATEGORY],
                "service_category": SERVICE_CATEGORY,
                "purchase_purpose": description,
            }
        },
    }


def _receipt_for(
    client: TestClient,
    main: Any,
    access_token: str,
    payload: dict[str, Any],
) -> str:
    headers = {"Authorization": f"Bearer {access_token}"}
    challenge = client.post("/pay", json=payload, headers=headers)
    if challenge.status_code != 402:
        raise RuntimeError(
            f"expected x402 challenge, received {challenge.status_code}: {challenge.text}"
        )
    details = challenge.json()["details"]
    issued = client.post(
        "/receipts/issue",
        json={
            "amount_due": float(details["amount_due"]),
            "currency": details["currency"],
            "expires_in_seconds": 300,
        },
        headers=headers | {"X-Admin-Secret": main.RECEIPT_ADMIN_SECRET},
    )
    issued.raise_for_status()
    return str(issued.json()["receipt_token"])


def _authorize(
    client: TestClient,
    main: Any,
    access_token: str,
    payload: dict[str, Any],
) -> Any:
    receipt = _receipt_for(client, main, access_token, payload)
    return client.post(
        "/pay",
        json=payload,
        headers={
            "Authorization": f"Bearer {access_token}",
            "X-Payment-Receipt": receipt,
        },
    )


def _print_scenario(
    *,
    marker: str,
    payload: dict[str, Any],
    status: str,
    reason: str,
    reason_code: str,
) -> None:
    print(f"SCENARIO={marker}")
    print(f"task={TASK}")
    print(f"proposed_purchase={payload['description']}")
    print(f"amount={payload['amount']} {payload['currency']}")
    print(f"counterparty={payload['vendor']}")
    print("task_context_trust=request-supplied-untrusted")
    print(f"VERDICT={status}")
    print(f"reason_code={reason_code}")
    print(f"reason={reason}")


def run() -> int:
    mode = os.getenv("SAFE4_DEMO_MODE", "rpc-replay").strip().lower()
    settlement = SettlementExecutor(mode)

    # Import after isolating the demo database and setting a real, validated
    # public routing address. No secret material is read or persisted.
    with tempfile.TemporaryDirectory(prefix="safe4-golden-path-") as temp_dir:
        os.environ["PAYMENT_FIREWALL_DB_PATH"] = str(Path(temp_dir) / "safe4-demo.db")
        os.environ["PAYMENT_FIREWALL_PAY_TO"] = _required_env("SETTLEMENT_TO")
        from app import main, webhooks_api

        main.reset_runtime_state()
        webhooks_api.reset_webhook_sender_for_tests()

        print("SAFE4_GOLDEN_PATH_START")
        print(
            "MODE="
            + (
                "RPC_VERIFIED_REPLAY"
                if mode == "rpc-replay"
                else "CIRCLE_AGENT_WALLET_LIVE"
            )
        )
        print(
            "Circle Agent Stack execution boundary: "
            "settlement is invoked only after Safe4 returns ALLOWED."
        )

        with TestClient(main.app) as client:
            access_token = _issue_oauth_token(client, main)

            allowed_payload = _payment_payload(description=ALLOWED_PURCHASE)
            allowed_response = _authorize(
                client,
                main,
                access_token,
                allowed_payload,
            )
            if allowed_response.status_code != 200:
                raise RuntimeError(
                    "allowed scenario failed: "
                    f"{allowed_response.status_code} {allowed_response.text}"
                )
            allowed_body = allowed_response.json()
            allowed_intent = allowed_body["intent_decision"]
            _print_scenario(
                marker="TASK_MATCH",
                payload=allowed_payload,
                status="ALLOWED",
                reason=allowed_intent["reason"],
                reason_code=allowed_intent["reason_code"],
            )

            chain_evidence = settlement.settle()
            demo_evidence_bundle = {
                "safe4_transaction_id": allowed_body["transaction_id"],
                "decision": "ALLOWED",
                "intent_decision": allowed_intent,
                "settlement": chain_evidence,
            }
            print("settlement=RPC_VERIFIED")
            print(f"transaction_hash={chain_evidence['transaction_hash']}")
            print(f"explorer_url={chain_evidence['explorer_url']}")
            print(
                "historical_replay_notice="
                "RPC_VERIFIED_TRANSACTION_NOT_BROADCAST_BY_THIS_DEMO"
            )
            print(
                f"demo_evidence_bundle={json.dumps(demo_evidence_bundle, sort_keys=True)}"
            )

            denied_payload = _payment_payload(description=DENIED_PURCHASE)
            print(
                "UNCHANGED_INPUTS "
                f"amount={denied_payload['amount'] == allowed_payload['amount']} "
                f"category={denied_payload['context']['payment_intent']['service_category'] == allowed_payload['context']['payment_intent']['service_category']} "
                f"counterparty={denied_payload['vendor'] == allowed_payload['vendor']}"
            )
            print("CIRCLE_POLICY=NOT_INVOKED_IN_RPC_REPLAY")
            calls_before_denial = settlement.calls
            denied_response = _authorize(
                client,
                main,
                access_token,
                denied_payload,
            )
            if denied_response.status_code != 403:
                raise RuntimeError(
                    "denied scenario did not fail closed: "
                    f"{denied_response.status_code} {denied_response.text}"
                )
            denied_body = denied_response.json()
            denied_intent = denied_body["details"]["intent_decision"]
            _print_scenario(
                marker="TASK_MISMATCH",
                payload=denied_payload,
                status="DENIED",
                reason=denied_intent["reason"],
                reason_code=denied_intent["reason_code"],
            )
            print("demo_orchestrator_broadcast=NOT_INVOKED_AFTER_SAFE4_DENIED")
            print(f"settlement_executor_calls_before={calls_before_denial}")
            print(f"settlement_executor_calls_after={settlement.calls}")
            if settlement.calls != calls_before_denial:
                raise RuntimeError("denied scenario reached the settlement executor")
            print("DENIED_DEMO_EXECUTOR_NOT_INVOKED=PASS")

        print("SAFE4_GOLDEN_PATH_OK")
    return 0


def main() -> int:
    try:
        return run()
    except (ArcSettlementError, httpx.HTTPError, RuntimeError, ValueError) as exc:
        print(f"SAFE4_GOLDEN_PATH_FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
