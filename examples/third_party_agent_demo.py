"""Worked example: a third-party agent calling Safe4 through the SDK.

This is not the Safe4 team's own demo -- it plays the role of *someone
else's* agent that has decided to make a purchase and checks with Safe4
before spending, using nothing but ``sdk/python/safe4_client.py`` and the
public contract in ``docs/x402/CONTRACT.md``. It never signs, broadcasts, or
verifies a blockchain transaction; Safe4 returns an authorization decision
only.

It runs the same purchase twice: once with a purpose that matches the
agent's stated task (expect ALLOW), and once with a purpose that does not
(expect DENY) -- the same verdict flip the browser demo shows, driven here
entirely by an external HTTP client.

Usage:

    python examples/third_party_agent_demo.py \\
        --base-url https://demo.safe4.ai \\
        --demo-access-token <demo access token>

Exit code is 0 if both the ALLOW and the DENY happened as expected, 1
otherwise -- suitable for a CI smoke check.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "sdk" / "python"))

from safe4_client import Safe4Client, Safe4Decision  # noqa: E402


class ResearchAgent:
    """A toy stand-in for a third party's autonomous agent.

    It has one job -- research competitor pricing -- and, before spending
    any money, it always checks with Safe4 first via the SDK. It never
    talks to Safe4's HTTP API directly; that is the SDK's job.
    """

    def __init__(self, safe4: Safe4Client, task: str) -> None:
        self._safe4 = safe4
        self._task = task

    def propose_purchase(self, *, purchase_purpose: str, amount: str) -> Safe4Decision:
        print(f"  agent proposes: \"{purchase_purpose}\" for {amount} USDC")
        decision = self._safe4.authorize(
            task=self._task,
            purchase_purpose=purchase_purpose,
            amount=amount,
        )
        verdict = "ALLOW" if decision.allowed else "DENY"
        print(f"  Safe4 verdict : {verdict}  (HTTP {decision.http_status}, reason={decision.reason_code})")
        if decision.allowed:
            print("  agent proceeds with its own settlement (Safe4 did not do this for it)")
        else:
            print("  agent stops -- no settlement is attempted after a DENY")
        return decision


def main() -> int:
    parser = argparse.ArgumentParser(description="Third-party agent using the Safe4 SDK")
    parser.add_argument("--base-url", default=os.getenv("SAFE4_BASE_URL", "https://demo.safe4.ai"))
    parser.add_argument(
        "--demo-access-token",
        default=os.getenv("SAFE4_DEMO_ACCESS_TOKEN"),
        help=(
            "Unlocks Safe4's guarded demo receipt fixture so this example can "
            "run without prior provider coordination. See docs/x402/CONTRACT.md "
            "section 4 -- this is not proof of a real payment."
        ),
    )
    args = parser.parse_args()

    if not args.demo_access_token:
        print(
            "No --demo-access-token / SAFE4_DEMO_ACCESS_TOKEN given. Without a "
            "proof source this example cannot complete the 402 retry -- see "
            "docs/x402/CONTRACT.md section 4 for the available proof types.",
            file=sys.stderr,
        )
        return 1

    task = "Research competitor pricing using a paid company data service."
    print(f"Third-party agent task: {task}\n")

    with Safe4Client(
        base_url=args.base_url,
        demo_access_token=args.demo_access_token,
    ) as safe4:
        agent = ResearchAgent(safe4, task=task)

        print("Attempt 1 -- purchase matches the stated task:")
        matching = agent.propose_purchase(
            purchase_purpose="Generate a competitor pricing research brief from company data.",
            amount="0.01",
        )

        print("\nAttempt 2 -- same amount and vendor, unrelated purpose:")
        mismatched = agent.propose_purchase(
            purchase_purpose="Buy a gift card for a colleague's birthday.",
            amount="0.01",
        )

    print()
    if matching.allowed and mismatched.denied:
        print("OK: Safe4 allowed the matching purchase and denied the mismatched one.")
        return 0
    print(
        "UNEXPECTED: expected ALLOW then DENY, got "
        f"{matching.allowed=} {mismatched.allowed=}."
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
