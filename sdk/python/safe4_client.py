"""Safe4 x402 client SDK.

Wraps the OAuth PKCE session, the ``POST /pay`` 402 challenge, and the proof
retry described in ``docs/x402/CONTRACT.md`` into a small, dependency-light
(``httpx`` only) client, promoted from ``examples/safe4_quickstart.py``.

This is not a certified x402-specification client and does not sign,
broadcast, or verify any blockchain transaction: Safe4 returns an
authorization decision only. See ``docs/x402/CONTRACT.md`` for the full
protocol, especially section 4 ("Proof: which kind is real") before using
``demo_access_token`` for anything beyond exercising the decision loop.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import uuid
from dataclasses import dataclass
from decimal import Decimal
from typing import Any

import httpx

CLIENT_ID = "dev-public-client"
REDIRECT_URI = "https://localhost/callback"
SCOPE = "payment:authorize audit:read"


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


class Safe4Error(RuntimeError):
    """Transport- or protocol-shape failure. Not raised for an ordinary DENY."""


@dataclass(frozen=True, slots=True)
class Safe4Decision:
    """A typed Safe4 authorization decision.

    ``allowed`` is the only field that means ALLOW; every other outcome
    (including transport-level denials with no ``intent_decision``) is a
    DENY, with ``reason_code`` carrying whatever code Safe4 returned.
    """

    allowed: bool
    http_status: int
    reason_code: str | None
    matched_concepts: tuple[str, ...]
    receipt_id: str | None
    raw: dict[str, Any]

    @property
    def denied(self) -> bool:
        return not self.allowed


class Safe4Client:
    """Minimal client for Safe4's x402 challenge/proof/decision loop.

    Example::

        with Safe4Client(
            base_url="https://demo.safe4.ai",
            demo_access_token="safe4-judge-...",
        ) as client:
            decision = client.authorize(
                task="Research competitor pricing using a paid company data service.",
                purchase_purpose="Generate a competitor pricing research brief from company data.",
                amount="0.01",
            )
            print(decision.allowed, decision.reason_code)

    ``demo_access_token`` unlocks Safe4's guarded demo receipt fixture so the
    full loop can be exercised against a hosted deployment without prior
    provider coordination -- see ``docs/x402/CONTRACT.md`` section 4 for what
    that fixture does and does not prove. To use your own proof (e.g. a
    provider-signed receipt), omit it and pass ``receipt_token=`` to
    :meth:`authorize` instead.
    """

    def __init__(
        self,
        *,
        base_url: str,
        demo_access_token: str | None = None,
        agent_id: str = "agent_alpha",
        user_id: str = "user_123",
        timeout: float = 30.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.demo_access_token = demo_access_token
        self.agent_id = agent_id
        self.user_id = user_id
        self._client = httpx.Client(base_url=self.base_url, timeout=timeout)
        self._access_token: str | None = None

    def __enter__(self) -> Safe4Client:
        self.connect()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def close(self) -> None:
        self._client.close()

    def connect(self) -> str:
        """Complete OAuth authorization-code + PKCE and cache the bearer token."""
        verifier = _b64url(secrets.token_bytes(32))
        challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())

        authorize = self._post_expecting_success(
            "/oauth/authorize",
            json={
                "client_id": CLIENT_ID,
                "redirect_uri": REDIRECT_URI,
                "scope": SCOPE,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "subject": "safe4_client_sdk",
                "agent_id": self.agent_id,
            },
        )
        token = self._post_expecting_success(
            "/oauth/token",
            json={
                "grant_type": "authorization_code",
                "client_id": CLIENT_ID,
                "code": authorize.json()["code"],
                "redirect_uri": REDIRECT_URI,
                "code_verifier": verifier,
            },
        )
        self._access_token = token.json()["access_token"]
        return self._access_token

    def capabilities(self) -> dict[str, Any]:
        """``GET /x402/capabilities`` -- what this deployment currently supports."""
        return self._authed_get("/x402/capabilities").json()

    def providers(self) -> dict[str, Any]:
        """``GET /x402/providers`` -- registered provider adapters."""
        return self._authed_get("/x402/providers").json()

    def challenge(
        self,
        *,
        task: str,
        purchase_purpose: str,
        amount: str | Decimal,
        service_category: str = "company-research",
        vendor: str = "demo_company_research_api",
        currency: str = "USDC",
        task_id: str | None = None,
    ) -> dict[str, Any]:
        """Send an unproven ``POST /pay`` and return the raw 402 ``details``.

        Raises :class:`Safe4Error` if the deployment does not answer 402 with
        an ``x402_challenge`` (advanced x402 may be disabled).
        """
        if self._access_token is None:
            self.connect()
        payload = self._payment_payload(
            task=task,
            purchase_purpose=purchase_purpose,
            amount=amount,
            service_category=service_category,
            vendor=vendor,
            currency=currency,
            task_id=task_id,
        )
        response = self._client.post("/pay", json=payload, headers=self._auth_header())
        if response.status_code != 402:
            raise Safe4Error(
                f"Expected 402 challenge, got {response.status_code}: {response.text[:500]}"
            )
        details = response.json().get("details", {})
        if "x402_challenge" not in details:
            raise Safe4Error(
                "Deployment returned 402 without an x402_challenge; "
                "advanced x402 may be disabled on this deployment."
            )
        return details

    def authorize(
        self,
        *,
        task: str,
        purchase_purpose: str,
        amount: str | Decimal,
        service_category: str = "company-research",
        vendor: str = "demo_company_research_api",
        currency: str = "USDC",
        task_id: str | None = None,
        receipt_token: str | None = None,
    ) -> Safe4Decision:
        """Run the full 402 -> proof -> decision loop and return a typed decision.

        Pass ``receipt_token`` to supply your own proof (e.g. a provider
        receipt). Otherwise this uses the guarded demo receipt fixture, which
        requires ``demo_access_token`` to have been set on the client.
        """
        if self._access_token is None:
            self.connect()

        payment_kwargs = dict(
            task=task,
            purchase_purpose=purchase_purpose,
            amount=amount,
            service_category=service_category,
            vendor=vendor,
            currency=currency,
            task_id=task_id,
        )
        payload = self._payment_payload(**payment_kwargs)

        challenge_response = self._client.post("/pay", json=payload, headers=self._auth_header())
        if challenge_response.status_code != 402:
            # Already decided without proof (e.g. denied on an earlier check).
            return _decision_from_response(challenge_response)

        details = challenge_response.json().get("details", {})
        x402_challenge = details.get("x402_challenge")
        if x402_challenge is None:
            raise Safe4Error(
                "Deployment returned 402 without an x402_challenge; "
                "advanced x402 may be disabled on this deployment."
            )

        proof = receipt_token
        if proof is None:
            if self.demo_access_token is None:
                raise Safe4Error(
                    "No proof available. Construct Safe4Client(demo_access_token=...) "
                    "to use the guarded demo fixture, or pass authorize(receipt_token=...) "
                    "with your own proof. See docs/x402/CONTRACT.md section 4."
                )
            proof = self._demo_receipt(details, x402_challenge)

        decision_response = self._client.post(
            "/pay",
            json=payload,
            headers={
                **self._auth_header(),
                x402_challenge.get("receipt_header", "X-Payment-Receipt"): proof,
                "Idempotency-Key": str(uuid.uuid4()),
            },
        )
        return _decision_from_response(decision_response)

    def _demo_receipt(self, details: dict[str, Any], x402_challenge: dict[str, Any]) -> str:
        if self.demo_access_token is None:
            raise Safe4Error("demo_access_token is required to use the guarded demo fixture.")
        receipt = self._post_expecting_success(
            "/demo/x402/receipt",
            json={
                "amount_due": x402_challenge["amount"],
                "currency": x402_challenge["currency"],
                "pay_to": details["pay_to"],
            },
            headers={**self._auth_header(), "X-Demo-Access": self.demo_access_token},
        )
        return receipt.json()["receipt_token"]

    def _payment_payload(
        self,
        *,
        task: str,
        purchase_purpose: str,
        amount: str | Decimal,
        service_category: str,
        vendor: str,
        currency: str,
        task_id: str | None,
    ) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "user_id": self.user_id,
            "vendor": vendor,
            "amount": float(amount),
            "currency": currency,
            "description": purchase_purpose,
            "context": {
                "payment_intent": {
                    "task_id": task_id or f"sdk_{uuid.uuid4().hex[:8]}",
                    "task": task,
                    "allowed_service_categories": [service_category],
                    "service_category": service_category,
                    "purchase_purpose": purchase_purpose,
                }
            },
        }

    def _auth_header(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._access_token}"}

    def _authed_get(self, path: str) -> httpx.Response:
        if self._access_token is None:
            self.connect()
        response = self._client.get(path, headers=self._auth_header())
        return _expect_status(response, {200})

    def _post_expecting_success(self, path: str, **kwargs: Any) -> httpx.Response:
        response = self._client.post(path, **kwargs)
        return _expect_status(response, {200, 201})


def _expect_status(response: httpx.Response, expected: set[int]) -> httpx.Response:
    if response.status_code not in expected:
        raise Safe4Error(
            f"{response.request.method} {response.request.url} returned "
            f"{response.status_code}: {response.text[:500]}"
        )
    return response


def _decision_from_response(response: httpx.Response) -> Safe4Decision:
    try:
        body = response.json()
    except ValueError as exc:
        raise Safe4Error(
            f"Non-JSON response (HTTP {response.status_code}): {response.text[:500]}"
        ) from exc

    allowed = response.status_code == 200 and body.get("status") == "AUTHORIZED"
    intent = body.get("intent_decision") or (body.get("details") or {}).get("intent_decision") or {}
    reason_code = intent.get("reason_code") or body.get("error")
    matched = tuple(intent.get("matched_concepts") or ())
    return Safe4Decision(
        allowed=allowed,
        http_status=response.status_code,
        reason_code=reason_code,
        matched_concepts=matched,
        receipt_id=body.get("receipt_id"),
        raw=body,
    )
