# Safe4 judge demo runbook

This walkthrough shows Safe4's local payment-authorization controls in about
90 seconds. It does not broadcast a blockchain transaction.

## Start the isolated demo

From the repository root, run:

```powershell
.\.python313\python.exe scripts\run_local_demo.py
```

Open the protected URL printed by the runner and select **Connect demo
agent**. The runner uses temporary SQLite state and deliberately enables only
the guarded browser receipt fixture.

## Recommended judge path

1. **3-call agent batch** — show three sequential requests for market data,
   hosted compute, and agent memory. Point to `3 ALLOWED`, three independent
   402 challenges, and `Browser broadcasts 0`.
2. **Wrong purchase purpose** — keep the service category and amount while
   changing the purpose to an unrelated gift card. Show
   `PURCHASE_PURPOSE_MISMATCH` and zero local authorizations for that request.
3. **Scope cap exceeded** — show a matching `0.01 USDC` request rejected by a
   presented `0.005 USDC` autonomy limit with
   `SCOPE_OF_AUTONOMY_MAX_COST_EXCEEDED`.
4. **Used receipt replay** — show one local authorization followed by
   `PAYMENT_RECEIPT_ALREADY_USED` when its consumed proof is reused for a
   different request.
5. **Idempotent duplicate** — show the identical initial and cached HTTP 200
   response bodies. Explain that the separately cited regression test verifies
   one local budget/log write; the browser does not query the database count.
   This is a local replay guarantee, not exactly-once external settlement.

If time permits, start with **Task-matched purchase** to show the complete
`402 -> guarded proof -> 200` baseline before the controls.

## What the screen proves

- The browser invokes the real local `/pay` application path.
- Each fixture-backed receipt is short-lived, exact-fee, exact-recipient,
  scoped to the seeded demo agent, rate-limited, and audited.
- The observed local outcomes cover task matching, fan-out, intent, autonomy
  scope, proof replay, and request idempotency.
- The browser never receives a wallet key and has no settlement executor.

## Evidence boundary

The three-call scenario is three independent, sequential authorizations. It is
not an atomic multisend. The page does not prove a paid production x402 service,
Circle Gateway settlement, principal-bound task context, exactly-once external
execution, or a fresh Arc transaction.

The Arcscan links at the bottom are separately labelled historical Arc Testnet
evidence. Opening a link is read-only and running any browser scenario does not
create another transfer.

## Judge-safe narration

> Safe4 just evaluated three independent service-payment requests through the
> real local authorization path. It allowed the task-matched requests and
> exposed the exact denial or replay reason for each control. The browser made
> zero broadcasts; the Arc links are separate historical testnet evidence.

Avoid the phrases "native multisend," "atomic batch," "Circle Gateway
integration," "live x402 settlement," and "exactly-once settlement."
