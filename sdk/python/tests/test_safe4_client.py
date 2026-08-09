"""Tests for sdk/python/safe4_client.py against a mocked transport.

Uses httpx.MockTransport (built into httpx, no extra dependency) so these
tests exercise the SDK's request/response handling without a live server.
End-to-end verification against a real deployment lives in
examples/third_party_agent_demo.py and is run manually / documented in
docs/x402/CONTRACT.md, not as part of this offline suite.
"""

from __future__ import annotations

import sys
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from safe4_client import Safe4Client, Safe4Error  # noqa: E402

BASE_URL = "https://safe4.example.test"


def _oauth_responses(request: httpx.Request) -> httpx.Response | None:
    if request.url.path == "/oauth/authorize":
        return httpx.Response(200, json={"code": "auth-code-123"})
    if request.url.path == "/oauth/token":
        return httpx.Response(200, json={"access_token": "test-bearer-token"})
    return None


def make_client(handler, **kwargs) -> Safe4Client:
    client = Safe4Client(base_url=BASE_URL, **kwargs)
    client._client = httpx.Client(base_url=BASE_URL, transport=httpx.MockTransport(handler))
    return client


def test_connect_completes_pkce_and_caches_token() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        response = _oauth_responses(request)
        assert response is not None
        return response

    client = make_client(handler)
    token = client.connect()
    assert token == "test-bearer-token"
    assert client._access_token == "test-bearer-token"


def test_authorize_allow_flow_uses_demo_receipt_and_returns_typed_decision() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        oauth = _oauth_responses(request)
        if oauth is not None:
            return oauth
        if request.url.path == "/pay" and "X-Payment-Receipt" not in request.headers:
            return httpx.Response(
                402,
                json={
                    "error": "PAYMENT_REQUIRED",
                    "details": {
                        "pay_to": "0xRecipient",
                        "amount_due": "0.010000",
                        "x402_challenge": {
                            "amount": "0.010000",
                            "currency": "USDC",
                            "receipt_header": "X-Payment-Receipt",
                            "settlement_method": "signed_receipt_fallback",
                        },
                    },
                },
            )
        if request.url.path == "/demo/x402/receipt":
            assert request.headers["X-Demo-Access"] == "demo-token"
            return httpx.Response(200, json={"receipt_token": "test-fixture-receipt-abc"})
        if request.url.path == "/pay" and request.headers.get("X-Payment-Receipt") == "test-fixture-receipt-abc":
            return httpx.Response(
                200,
                json={
                    "status": "AUTHORIZED",
                    "receipt_id": "rcpt_1",
                    "intent_decision": {
                        "allowed": True,
                        "reason_code": "TASK_PURCHASE_MATCH",
                        "matched_concepts": ["company-research"],
                    },
                },
            )
        raise AssertionError(f"unexpected request: {request.method} {request.url}")

    client = make_client(handler, demo_access_token="demo-token")
    decision = client.authorize(
        task="Research competitor pricing.",
        purchase_purpose="Generate a competitor pricing research brief.",
        amount="0.01",
    )

    assert decision.allowed is True
    assert decision.http_status == 200
    assert decision.reason_code == "TASK_PURCHASE_MATCH"
    assert decision.matched_concepts == ("company-research",)
    assert decision.receipt_id == "rcpt_1"
    assert "/demo/x402/receipt" in calls


def test_authorize_deny_flow_returns_denied_decision_not_exception() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        oauth = _oauth_responses(request)
        if oauth is not None:
            return oauth
        if request.url.path == "/pay" and "X-Payment-Receipt" not in request.headers:
            return httpx.Response(
                402,
                json={
                    "details": {
                        "pay_to": "0xRecipient",
                        "x402_challenge": {
                            "amount": "0.010000",
                            "currency": "USDC",
                            "receipt_header": "X-Payment-Receipt",
                        },
                    }
                },
            )
        if request.url.path == "/demo/x402/receipt":
            return httpx.Response(200, json={"receipt_token": "test-fixture-receipt-xyz"})
        if request.url.path == "/pay":
            return httpx.Response(
                403,
                json={
                    "error": "PURCHASE_PURPOSE_MISMATCH",
                    "details": {
                        "intent_decision": {
                            "allowed": False,
                            "reason_code": "PURCHASE_PURPOSE_MISMATCH",
                        }
                    },
                },
            )
        raise AssertionError(f"unexpected request: {request.method} {request.url}")

    client = make_client(handler, demo_access_token="demo-token")
    decision = client.authorize(
        task="Research competitor pricing.",
        purchase_purpose="Buy a gift card, unrelated to the task.",
        amount="0.01",
    )

    assert decision.allowed is False
    assert decision.denied is True
    assert decision.http_status == 403
    assert decision.reason_code == "PURCHASE_PURPOSE_MISMATCH"


def test_authorize_without_proof_source_raises_safe4_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        oauth = _oauth_responses(request)
        if oauth is not None:
            return oauth
        if request.url.path == "/pay":
            return httpx.Response(
                402,
                json={
                    "details": {
                        "x402_challenge": {
                            "amount": "0.010000",
                            "currency": "USDC",
                            "receipt_header": "X-Payment-Receipt",
                        }
                    }
                },
            )
        raise AssertionError(f"unexpected request: {request.method} {request.url}")

    client = make_client(handler)  # no demo_access_token, no receipt_token
    with pytest.raises(Safe4Error, match="No proof available"):
        client.authorize(task="t", purchase_purpose="p", amount="0.01")


def test_authorize_accepts_caller_supplied_receipt_token() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        oauth = _oauth_responses(request)
        if oauth is not None:
            return oauth
        if request.url.path == "/pay" and request.headers.get("X-Payment-Receipt") == "test-fixture-provider-receipt":
            return httpx.Response(200, json={"status": "AUTHORIZED", "receipt_id": "rcpt_2"})
        if request.url.path == "/pay":
            return httpx.Response(
                402,
                json={"details": {"x402_challenge": {"receipt_header": "X-Payment-Receipt"}}},
            )
        raise AssertionError(f"unexpected request: {request.method} {request.url}")

    client = make_client(handler)  # no demo_access_token
    decision = client.authorize(
        task="t", purchase_purpose="p", amount="0.01", receipt_token="test-fixture-provider-receipt"
    )
    assert decision.allowed is True


def test_challenge_without_x402_challenge_raises_safe4_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        oauth = _oauth_responses(request)
        if oauth is not None:
            return oauth
        return httpx.Response(402, json={"details": {}})

    client = make_client(handler)
    with pytest.raises(Safe4Error, match="advanced x402 may be disabled"):
        client.challenge(task="t", purchase_purpose="p", amount="0.01")


def test_context_manager_connects_and_closes() -> None:
    closed = {"value": False}

    def handler(request: httpx.Request) -> httpx.Response:
        response = _oauth_responses(request)
        assert response is not None
        return response

    client = make_client(handler)
    original_close = client._client.close

    def tracking_close() -> None:
        closed["value"] = True
        original_close()

    client._client.close = tracking_close  # type: ignore[method-assign]

    with client as ctx:
        assert ctx._access_token == "test-bearer-token"

    assert closed["value"] is True
