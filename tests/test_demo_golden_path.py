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

    with pytest.raises(RuntimeError, match="rpc-replay or circle-live"):
        executor.settle()


def test_circle_live_requires_cli_before_attempting_transfer() -> None:
    executor = SettlementExecutor("circle-live")

    with patch("scripts.demo_golden_path.shutil.which", return_value=None):
        with pytest.raises(RuntimeError, match="Circle CLI is required"):
            executor.settle()


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
