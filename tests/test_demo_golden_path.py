from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from scripts.demo_golden_path import SettlementExecutor


def test_rpc_replay_verifies_existing_chain_evidence_without_broadcast() -> None:
    evidence = {"transaction_hash": "0x" + ("a" * 64), "rpc_verified": True}
    with (
        patch.dict(os.environ, {"SETTLEMENT_TX": evidence["transaction_hash"]}),
        patch(
            "scripts.demo_golden_path._verify_arc_transaction",
            return_value=evidence,
        ) as verify,
    ):
        executor = SettlementExecutor("rpc-replay")
        result = executor.settle()

    assert executor.calls == 1
    assert result["mode"] == "RPC_VERIFIED_REPLAY"
    assert result["broadcast"] == "EXISTING_CHAIN_EVIDENCE"
    verify.assert_called_once_with(evidence["transaction_hash"])


def test_unknown_mode_fails_closed() -> None:
    executor = SettlementExecutor("mock")

    with pytest.raises(RuntimeError, match="circle-rpc-replay"):
        executor.settle()


def test_circle_live_requires_cli_before_attempting_transfer() -> None:
    executor = SettlementExecutor("circle-live")

    with patch("scripts.demo_golden_path.shutil.which", return_value=None):
        with pytest.raises(RuntimeError, match="Circle CLI is required"):
            executor.settle()


def test_circle_live_verifies_agent_wallet_receipt_after_transfer() -> None:
    transaction_hash = "0x" + ("b" * 64)
    evidence = {"transaction_hash": transaction_hash, "rpc_verified": True}
    completed = type(
        "Completed",
        (),
        {"returncode": 0, "stdout": f'{{"txHash":"{transaction_hash}"}}', "stderr": ""},
    )()
    env = {
        "SETTLEMENT_FROM": "0x1111111111111111111111111111111111111111",
        "SETTLEMENT_TO": "0x2222222222222222222222222222222222222222",
        "SETTLEMENT_AMOUNT_UNITS": "10000",
    }
    with (
        patch.dict(os.environ, env),
        patch("scripts.demo_golden_path.shutil.which", return_value="circle"),
        patch("scripts.demo_golden_path.subprocess.run", return_value=completed),
        patch(
            "scripts.demo_golden_path._verify_circle_agent_wallet_transaction",
            return_value=evidence,
        ) as verify,
    ):
        result = SettlementExecutor("circle-live").settle()

    assert result["mode"] == "CIRCLE_AGENT_WALLET_LIVE"
    assert result["broadcast"] == "SUBMITTED_AFTER_SAFE4_ALLOW"
    verify.assert_called_once_with(transaction_hash)


def test_circle_rpc_replay_verifies_existing_agent_wallet_evidence() -> None:
    transaction_hash = "0x" + ("c" * 64)
    evidence = {"transaction_hash": transaction_hash, "rpc_verified": True}
    with (
        patch.dict(os.environ, {"SETTLEMENT_TX": transaction_hash}),
        patch(
            "scripts.demo_golden_path._verify_circle_agent_wallet_transaction",
            return_value=evidence,
        ) as verify,
    ):
        result = SettlementExecutor("circle-rpc-replay").settle()

    assert result["mode"] == "CIRCLE_AGENT_WALLET_RPC_VERIFIED_REPLAY"
    assert result["broadcast"] == "EXISTING_CHAIN_EVIDENCE"
    verify.assert_called_once_with(transaction_hash)


def test_task_bound_output_discloses_request_supplied_trust_boundary() -> None:
    from app.core.intent import evaluate_payment_intent

    decision = evaluate_payment_intent(
        description="Generate a competitor pricing research brief from company data.",
        context={
            "payment_intent": {
                "task": "Research competitor pricing using a paid company data service.",
                "allowed_service_categories": ["company-research"],
                "service_category": "company-research",
            }
        },
        legacy_minimum_words=10,
    )

    assert decision.public_details()["task_context_trust"] == "request-supplied-untrusted"
