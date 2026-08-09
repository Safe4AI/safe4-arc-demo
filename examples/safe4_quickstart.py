"""Minimal end-to-end Safe4 integration example.

Runs the complete agent-payment authorization sequence against a live Safe4
deployment:

    OAuth PKCE  ->  POST /pay (402 challenge)  ->  payment proof  ->  POST /pay

Nothing here signs, broadcasts, or settles a blockchain transaction. Safe4
returns an authorization decision; execution is the caller's responsibility and
must only happen after ALLOW.

Usage:

    python examples/safe4_quickstart.py \
        --base-url https://demo.safe4.ai \
        --access-token <demo access token> \
        --task "Research competitor pricing using a paid company data service." \
        --purpose "Generate a competitor pricing research brief from company data."

Try changing only ``--purpose`` to something unrelated and re-running. The
amount, service category and counterparty stay identical; the decision flips.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import sys
import uuid

import httpx


CLIENT_ID = "dev-public-client"
REDIRECT_URI = "https://localhost/callback"
SCOPE = "payment:authorize audit:read"


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Safe4 quickstart")
    parser.add_argument("--base-url", default=os.getenv("SAFE4_BASE_URL", "http://127.0.0.1:8090"))
    parser.add_argument("--access-token", default=os.getenv("SAFE4_DEMO_ACCESS_TOKEN", "safe4-local-demo"))
    parser.add_argument("--task", default="Research competitor pricing using a paid company data service.")
    parser.add_argument(
        "--purpose",
        default="Generate a competitor pricing research brief from company data.",
    )
    parser.add_argument("--amount", default="0.01")
    parser.add_argument("--category", default="company-research")
    parser.add_argument("--vendor", default="demo_company_research_api")
    return parser.parse_args()


def connect(client: httpx.Client) -> str:
    """Complete the OAuth authorization-code + PKCE flow and return a token."""
    verifier = b64url(secrets.token_bytes(32))
    challenge = b64url(hashlib.sha256(verifier.encode("ascii")).digest())

    authorize = client.post(
        "/oauth/authorize",
        json={
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "scope": SCOPE,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "subject": "safe4_quickstart",
            "agent_id": "agent_alpha",
        },
    )
    authorize.raise_for_status()

    token = client.post(
        "/oauth/token",
        json={
            "grant_type": "authorization_code",
            "client_id": CLIENT_ID,
            "code": authorize.json()["code"],
            "redirect_uri": REDIRECT_URI,
            "code_verifier": verifier,
        },
    )
    token.raise_for_status()
    return token.json()["access_token"]


def payment_payload(args: argparse.Namespace) -> dict:
    return {
        "agent_id": "agent_alpha",
        "user_id": "user_123",
        "vendor": args.vendor,
        # Safe4 requires the amount as a JSON number, not a quoted string.
        "amount": float(args.amount),
        "currency": "USDC",
        "description": args.purpose,
        "context": {
            "payment_intent": {
                "task_id": f"quickstart_{uuid.uuid4().hex[:8]}",
                "task": args.task,
                "allowed_service_categories": [args.category],
                "service_category": args.category,
                "purchase_purpose": args.purpose,
            }
        },
    }


def main() -> int:
    args = parse_args()
    with httpx.Client(base_url=args.base_url, timeout=30.0) as client:
        bearer = connect(client)
        auth_header = {"Authorization": f"Bearer {bearer}"}
        payload = payment_payload(args)

        # 1. Unproven request. Safe4 answers with a machine-readable x402 challenge.
        challenge_response = client.post("/pay", json=payload, headers=auth_header)
        if challenge_response.status_code != 402:
            print(f"Expected a 402 challenge, got {challenge_response.status_code}.")
            print(json.dumps(challenge_response.json(), indent=2))
            return 1
        details = challenge_response.json()["details"]
        challenge = details["x402_challenge"]
        print(f"402 challenge  amount={challenge['amount']} {challenge['currency']}")

        # 2. Obtain payment proof. This demo deployment issues a guarded, fixed-fee,
        #    short-lived receipt fixture; it does not broadcast anything. A real
        #    integration presents its own settlement proof here.
        receipt = client.post(
            "/demo/x402/receipt",
            json={
                "amount_due": challenge["amount"],
                "currency": challenge["currency"],
                "pay_to": details["pay_to"],
            },
            headers={**auth_header, "X-Demo-Access": args.access_token},
        )
        receipt.raise_for_status()
        proof = receipt.json()

        # 3. Retry with proof. This is the authorization decision.
        decision = client.post(
            "/pay",
            json=payload,
            headers={
                **auth_header,
                "X-Payment-Receipt": proof["receipt_token"],
                "Idempotency-Key": str(uuid.uuid4()),
            },
        )
        body = decision.json()
        allowed = decision.status_code == 200 and body.get("status") == "AUTHORIZED"
        intent = body.get("intent_decision") or (body.get("details") or {}).get("intent_decision") or {}

        print()
        print(f"  task     : {args.task}")
        print(f"  purchase : {args.purpose}")
        print(f"  amount   : {args.amount} USDC")
        print()
        print(f"  VERDICT  : {'ALLOW' if allowed else 'DENY'}  (HTTP {decision.status_code})")
        print(f"  reason   : {intent.get('reason_code') or body.get('code')}")
        matched = intent.get("matched_concepts")
        if matched:
            print(f"  matched  : {', '.join(matched)}")
        print()
        print("  Safe4 returned a decision only. No transaction was signed or broadcast.")
        return 0 if allowed else 2


if __name__ == "__main__":
    raise SystemExit(main())
