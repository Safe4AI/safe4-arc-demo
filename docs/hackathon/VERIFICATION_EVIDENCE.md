# Verification evidence

Observed in the public submission worktree on 28 July 2026 with Python 3.13.14.

## Current local expansion candidate

After adding the fail-closed Circle Marketplace admission probe and its
adversarial command-safety tests:

```text
332 passed, 7 warnings in 106.23s (0:01:46)
```

The Marketplace-focused gate passed `39` tests. The prepared 122-file public
package then passed:

```text
332 passed, 7 warnings in 99.43s (0:01:39)
PUBLIC_AUDIT_OK files=122 required=9 secrets=0 forbidden=0
```

The final network-enabled shipline verifier independently repeated the source
gate as `332 passed, 8 warnings in 104.23s` and kept C0–C5 and C7 green.

These local results are not attributed to the published public commit until a
separately authorized push and CI run.

## Full regression gate

Command:

```text
python -m pytest -q
```

Raw final line after the Circle Agent Wallet/ERC-4337 update:

```text
293 passed, 7 warnings in 114.04s (0:01:54)
```

## Fast gate

Command:

```text
python -m pytest -q -m "not slow"
```

Raw final line after the C8 wording/test update:

```text
67 passed, 226 deselected, 7 warnings in 1.64s
```

## Documentation check

Command:

```text
python scripts/check_docs.py
```

Raw result:

```text
Documentation check summary
- issues found: 0
No issues found.
```

## Public candidate audit

```text
PUBLIC_AUDIT_OK files=116 required=9 secrets=0 forbidden=0
```

Deployment source commit:
`804149c081ee990e6f3634e7f38d8da7fee87524`

GitHub Actions:
<https://github.com/Safe4AI/safe4-arc-demo/actions/runs/30322024446>
(`success`)

Railway deployment:
`97ca4dfa-1581-449f-a748-9d99388f4899` (`SUCCESS`)

Live verification:

```text
health_status=ok
database=postgresql
docs_http=200
agent_demo_http=200
console_demo_http=200
x402_enabled=true
x402_status=development_provider_plus_fallback
x402_builder=stub
x402_supported_networks=arc-testnet
x402_arc_recipient=0x530271DA8CC4e44375f22ad9632bC61A55382f88
payment_http=402
challenge_status=scaffolded
challenge_builder=stub
```

## Fresh Circle Agent Wallet settlement

Observed after Safe4 returned `ALLOWED` on 28 July 2026:

```text
transaction_hash=0x648ef14e4da7c6bfecce0017d19280ed51fb12635bea94712de926d9f967752c
chain_id=5042002
block_number=54014886
sender=0x3985a31e4e42a31e437c1099306decbe2f08da4d
recipient=0x530271DA8CC4e44375f22ad9632bC61A55382f88
amount=0.010000 USDC
execution_path=ERC_4337_AGENT_WALLET
rpc_verified=true
```

Explorer:
<https://testnet.arcscan.app/tx/0x648ef14e4da7c6bfecce0017d19280ed51fb12635bea94712de926d9f967752c>

Circle CLI's authenticated transaction history independently returned:

```text
state=COMPLETE
blockchain=ARC-TESTNET
operation=TRANSFER
transactionType=OUTBOUND
txHash=0x648ef14e4da7c6bfecce0017d19280ed51fb12635bea94712de926d9f967752c
sourceAddress=0x3985a31e4e42a31e437c1099306decbe2f08da4d
destinationAddress=0x530271da8cc4e44375f22ad9632bc61a55382f88
amount=0.01
blockHeight=54014886
firstConfirmDate=2026-07-28T01:43:15Z
```

The initial live verification failed closed because the existing verifier
expected a direct EOA-to-ERC-20 transaction. The transfer had succeeded through
Circle's ERC-4337 EntryPoint. The corrected verifier requires both the
successful wallet `UserOperationEvent` and the exact recipient/amount transfer
event. The no-broadcast `circle-rpc-replay` run then finished with:

```text
VERDICT=ALLOWED
reason_code=TASK_PURCHASE_MATCH
settlement=RPC_VERIFIED
VERDICT=DENIED
reason_code=PURCHASE_PURPOSE_MISMATCH
DENIED_DEMO_EXECUTOR_NOT_INVOKED=PASS
SAFE4_GOLDEN_PATH_OK
```

## 5 August 2026 live Circle Agent Wallet follow-up

This later run completed the current live coordinator end to end. The
allowlisted transcript records Safe4's `ALLOWED` decision before settlement,
one live Circle submission, successful Arc RPC verification, and a paired
denial with the executor count unchanged:

```text
MODE=CIRCLE_AGENT_WALLET_LIVE
VERDICT=ALLOWED
reason_code=TASK_PURCHASE_MATCH
transaction_hash=0xf9d665cf0eb663e33703826ca599d526718042781860faeec5e7ad089fde775d
block_number=55411369
amount_usdc=0.010000
broadcast=SUBMITTED_AFTER_SAFE4_ALLOW
VERDICT=DENIED
reason_code=PURCHASE_PURPOSE_MISMATCH
settlement_executor_calls_before=1
settlement_executor_calls_after=1
SAFE4_GOLDEN_PATH_OK
```

Authenticated Circle transaction history separately returned `COMPLETE` and
`TRANSFER` for that hash. A second focused read-only verifier returned:

```text
ARC_SETTLEMENT_OK mode=circle-agent-wallet tx=0xf9d665cf0eb663e33703826ca599d526718042781860faeec5e7ad089fde775d from=0x3985a31e4e42a31e437c1099306decbe2f08da4d to=0x530271DA8CC4e44375f22ad9632bC61A55382f88 amount_units=10000 block=55411369
```

Independent artifact review returned `PASS`; focused tests reported `18
passed, 1 warning`, and the repository secret scanner found zero findings. See
`artifacts/live-arc-transaction/20260805T083114Z/` and
`docs/hackathon/LIVE_CIRCLE_EXECUTION_TRANSCRIPT_20260805.txt`. This evidence is
Arc Testnet only and does not establish principal-bound task context,
exactly-once external settlement, production readiness, or chain-wide
prevention.

## Browser x402 decision lab candidate

Observed locally on 28 July 2026 after the presentation frontend and its
security hardening were added:

```text
source_full=338 passed, 8 warnings in 110.15s
source_fast=112 passed, 226 deselected
frontend_focused=10 passed
public_export_files=124
public_export_secrets=0
public_export_forbidden=0
docs_issues=0
```

The real API and browser click-through both produced:

```text
connect=scoped PKCE session
x402_network=arc-testnet
challenge_http=402
challenge_status=scaffolded
challenge_builder=stub
challenge_method=signed_receipt_fallback
allow_http=200
allow_reason_code=TASK_PURCHASE_MATCH
deny_http=403
deny_reason_code=PURCHASE_PURPOSE_MISMATCH
execution=No broadcast
```

The guarded adapter is separately feature-flagged, fixed to `agent_alpha` and
the `0.000025 USDC` demo fee, exact-recipient, short-lived, rate-limited, and
audited without recording its receipt token. The local runner was also started
with deliberately wrong inherited PostgreSQL, database-path, and demo-token
settings; it ignored them and served from isolated temporary SQLite at the
printed URL.

## Transaction edge-case evidence candidate

Observed locally on 5 August 2026 from an explicitly labelled unversioned
snapshot. The sanitized bundle is
`artifacts/transaction-edge-cases/20260805T011517Z/`; its allowlisted source
manifest SHA-256 is
`8cffd331084696cb54499b67743d2b3bd89c99973c6d0df8cbd5958116569dec`.

```text
required_authorization_scenarios=22/22 PASS
adversarial_canaries_desired_deny=0/3
settlement_verifier_fixtures=8/8 PASS
independent_verdict=PASS_WITH_KNOWN_GAPS
rpc=NOT_INVOKED
wallet=NOT_INVOKED
broadcast=NOT_INVOKED
bundle_files=6
bundle_secret_findings=0
bundle_forbidden_paths=0
source_full=437 passed, 7 warnings, 8 subtests passed
prepared_public_full=370 passed, 7 warnings
prepared_public_files=148
prepared_public_secrets=0
prepared_public_forbidden=0
```

All required denied, invalid, challenged, conflicting, and rate-limited steps
added no recorded spend. T08, T10, and T11 each include an earlier successful
authorization; explicit intermediate snapshots show that the rejected
follow-up added no further spend or authorization log. T20's pending phase also
added no spend or payment log; its later authorization used a synthetic local
approval fixture.

C01-C03 each returned HTTP 200 `AUTHORIZED`, increased local user and agent
spend by `0.001000`, and matched request-supplied task concepts. They remain
failed known-gap canaries and block any unqualified claim that Safe4 is robust
against intent laundering, spoofed purpose text, or counterparty substitution.
The S01-S08 results are deterministic local fixture evidence, not live chain
events. No Arc RPC replay was run for this matrix.
