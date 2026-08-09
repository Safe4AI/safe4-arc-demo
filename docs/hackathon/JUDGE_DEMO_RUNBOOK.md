# Safe4 judge demo runbook

This walkthrough shows Safe4's local payment-authorization controls in about
90 seconds. It does not broadcast a blockchain transaction.

## Hosted demo

No install needed: <https://demo.safe4.ai/demo/x402?access_token=safe4-judge-ad9eb36b6f57>
runs the same authorization-only scenarios described below against the
judged deployment. It never receives a wallet key and never broadcasts.

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
6. **Open challenge** — let the judge type their own task and purchase. The
   lane reports Safe4's real decision live; no outcome is predeclared or
   asserted, so this is the closest thing to letting a judge probe the
   evaluator directly.

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

### Optional independently reviewed live evidence

If a judge asks whether the three-service shape has also been exercised on
chain, open the read-only
[`20260805T123013Z` evidence bundle](../../artifacts/live-arc-batch/20260805T123013Z/README.md).
It records three sequential, non-atomic Arc Testnet USDC transfers to one
reviewed recipient after three local Safe4 `/pay` authorizations:

- `0.001 USDC`, block `55439625`,
  [`0x0f15d296afbefcd20c0b074c36f6ccc914020825af125c6f2e8b9af97a066145`](https://testnet.arcscan.app/tx/0x0f15d296afbefcd20c0b074c36f6ccc914020825af125c6f2e8b9af97a066145)
- `0.002 USDC`, block `55439642`,
  [`0x29df57bf6ca1520034f22b6137c9f027c2f7610aebb0067ff6784593665bce4d`](https://testnet.arcscan.app/tx/0x29df57bf6ca1520034f22b6137c9f027c2f7610aebb0067ff6784593665bce4d)
- `0.003 USDC`, block `55439658`,
  [`0x80cb6d59bcbdd9f25ab7bdd41816febd041cc6bb353c7216dddf6b3c7cfc4a27`](https://testnet.arcscan.app/tx/0x80cb6d59bcbdd9f25ab7bdd41816febd041cc6bb353c7216dddf6b3c7cfc4a27)

The independently reproduced verdict is `PASS` for this bounded `0.006 USDC`
run only. The local receipt route was a fixture and task context was
request-supplied. Do not present it as a native multisend, Circle Gateway
integration, three paid external x402 endpoints, or exactly-once settlement.
The verifier did not decode complete UserOperation calldata. The execution
revision also retained environment-hardening limitations documented in the
bundle; later hardening is not evidence about that earlier execution.

### Optional: presenter live settlement lane (not part of this build)

`demo-day/live-lane` is a separate, not-yet-merged branch deployed at
<https://safe4-demoday-production.up.railway.app>. It adds a presenter-operated,
admin-gated lane (`POST /demo/live/settle`) that runs Safe4's real evaluator
and only on ALLOW broadcasts one real Arc Testnet USDC transfer from a
server-held hot wallet. It is inert without a live admin secret the browser
never holds. On 9 August 2026 it produced transaction
[`0xacd1f38ba411e4596c0039bfe438c4b5f41ae0c31227ae6fc770ffcd68be1540`](https://testnet.arcscan.app/tx/0xacd1f38ba411e4596c0039bfe438c4b5f41ae0c31227ae6fc770ffcd68be1540),
block `56147830`, `0.001 USDC`, RPC-verified. This lane is not present on the
judged `main` deployment (`GET /demo/live/status` there returns `404`); see
`docs/hackathon/CLAIM_LEDGER.md` and `docs/hackathon/VERIFICATION_EVIDENCE.md`
for the current boundary between the two.

## Judge-safe narration

> Safe4 just evaluated three independent service-payment requests through the
> real local authorization path. It allowed the task-matched requests and
> exposed the exact denial or replay reason for each control. The browser made
> zero broadcasts; the Arc links are separate historical testnet evidence.

For the optional live evidence, say:

> Separately, an independently reviewed historical run recorded three
> sequential, non-atomic Arc Testnet transfers totaling 0.006 USDC to one
> reviewed recipient after three local Safe4 authorizations.

Avoid the phrases "native multisend," "atomic batch," "Circle Gateway
integration," "live x402 settlement," and "exactly-once settlement."
