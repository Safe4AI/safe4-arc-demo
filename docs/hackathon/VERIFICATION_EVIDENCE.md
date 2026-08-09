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

## 5 August 2026 independently reviewed sequential live batch

The sanitized
[`20260805T123013Z` evidence bundle](../../artifacts/live-arc-batch/20260805T123013Z/README.md)
records three sequential, non-atomic Arc Testnet USDC transfers to one reviewed
recipient after three local Safe4 `/pay` authorizations. Each transfer was Arc
RPC verified before the next request was authorized:

| Item | Safe4 result | Amount | Arc block | Transaction |
|---|---|---:|---:|---|
| market-data | `AUTHORIZED` / `TASK_PURCHASE_MATCH` | 0.001 USDC | `55439625` | [`0x0f15d296afbefcd20c0b074c36f6ccc914020825af125c6f2e8b9af97a066145`](https://testnet.arcscan.app/tx/0x0f15d296afbefcd20c0b074c36f6ccc914020825af125c6f2e8b9af97a066145) |
| compute | `AUTHORIZED` / `TASK_PURCHASE_MATCH` | 0.002 USDC | `55439642` | [`0x29df57bf6ca1520034f22b6137c9f027c2f7610aebb0067ff6784593665bce4d`](https://testnet.arcscan.app/tx/0x29df57bf6ca1520034f22b6137c9f027c2f7610aebb0067ff6784593665bce4d) |
| agent-memory | `AUTHORIZED` / `TASK_PURCHASE_MATCH` | 0.003 USDC | `55439658` | [`0x80cb6d59bcbdd9f25ab7bdd41816febd041cc6bb353c7216dddf6b3c7cfc4a27`](https://testnet.arcscan.app/tx/0x80cb6d59bcbdd9f25ab7bdd41816febd041cc6bb353c7216dddf6b3c7cfc4a27) |

```text
run_id=20260805T123013Z
source_revision=a2831a76e37e0e45e1d3e5d142484af5d2d12c63
execution_model=SEQUENTIAL_NON_ATOMIC_STOP_ON_FIRST_FAILURE
amounts_usdc=0.001,0.002,0.003
total_amount_usdc=0.006
planned=3
authorized=3
submitted=3
rpc_verified=3
failed=0
unknown=0
independent_verdict=PASS_BOUNDED_CLAIM
bundle_secret_findings=0
```

The independent reviewer reproduced all three exact-hash RPC verifications,
matched authenticated Circle history in `COMPLETE` state, confirmed the exact
`0.006 USDC` sender/recipient balance deltas, and found zero bundle secrets.
The verdict is limited to the bounded result above.

The Safe4 receipt route was a local fixture and task context was
request-supplied. This is not evidence of a native multisend, Circle Gateway
integration, three paid external x402 endpoints, or exactly-once settlement.
The verifier did not decode complete UserOperation calldata, so the bundle does
not prove the absence of unrelated non-USDC effects inside an operation.

At execution revision `a2831a76e37e0e45e1d3e5d142484af5d2d12c63`, Circle
child processes inherited the wrapper's ephemeral fixture environment and
HTTPX used default environment trust. The bundle records a post-run name-only
check that found no proxy, custom-CA, or Circle-proxy variable in the parent
environment. Later source hardening is not attributed retroactively to this
execution.

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

### 5 August judge-lab expansion

The browser interface was expanded to six predeclared local authorization
scenarios and rendered at 1440 pixels in a real headless Edge session. The
browser driver connected through OAuth PKCE, selected each visible scenario,
clicked the same controls a judge uses, and observed:

```text
single_allow=Allow/TASK_PURCHASE_MATCH
batch_allow=3 Allowed/INDEPENDENT_AUTHORIZATIONS
intent_deny=Deny/PURCHASE_PURPOSE_MISMATCH
scope_deny=Deny/SCOPE_OF_AUTONOMY_MAX_COST_EXCEEDED
receipt_replay=Blocked/PAYMENT_RECEIPT_ALREADY_USED
idempotent_retry=Safe Retry/OBSERVED: TASK_PURCHASE_MATCH
```

Focused Python 3.13 verification reported:

```text
16 passed, 7 warnings, 24 subtests passed in 14.64s
```

The six backend cases each ran in a fresh subprocess with an isolated SQLite
database and external paths disabled. The browser result is captured in
`artifacts/safe4-x402-demo.png`. It remains authorization-only: the three-call
case is sequential and non-atomic, every guarded receipt audit recorded
`broadcast=false` and `rpc_verified=false`, and no wallet or settlement
executor was connected.

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

After adding the independently reviewed sequential batch, its post-run source
hardening, and the refreshed judge UI, the exact prepared publication package
was rebuilt and checked again:

```text
prepared_public_full=447 passed, 7 warnings, 27 subtests passed
prepared_public_markdown=29 files, 0 issues
prepared_public_files=175
prepared_public_secrets=0
prepared_public_forbidden=0
```

This is the local publication-candidate gate, not a GitHub Actions result.

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

## 9 August 2026 regression baseline

```text
python -m pytest -q
524 passed, 7 warnings, 35 subtests passed in 164.35s (0:02:44)
```

`python scripts/check_docs.py` reported `0 issues` across `122` markdown
files. The only forbidden-pattern matches were two known local-only working
docs (`docs/hackathon/NEXT_SESSION_PROMPT.md`,
`docs/hackathon/VIDEO_RECORDING_GUIDE.md`, both absent from the
`docs/hackathon` allowlist in `scripts/prepare_public_demo.ps1`), which
`scripts/check_docs.py` now exempts by name for the same reason they are
already excluded from the public export.

## 9 August 2026 presenter live settlement lane

`app/api/demo_live.py` adds an admin-gated live settlement lane
(`POST /demo/live/settle`, `GET /demo/live/status`), merged into the judged
`main` build and deployed to `safe4-arc-demo` the same day (see the task-2
merge entry in `SHIPLINE.md`). The lane runs Safe4's real evaluator and only
broadcasts on ALLOW; it is inert (returns `503
LIVE_SETTLEMENT_NOT_CONFIGURED`) on any deployment missing either
`ARC_PRIVATE_KEY` or `PAYMENT_FIREWALL_LIVE_ADMIN_SECRET` — confirmed against
the judged `safe4-arc-demo` deployment itself, which has neither configured.

Independently RPC-verified against `https://rpc.testnet.arc.network` on 9
August 2026:

```text
transaction_hash=0xacd1f38ba411e4596c0039bfe438c4b5f41ae0c31227ae6fc770ffcd68be1540
chain_id=5042002
block_number=56147830
status=success (0x1)
from=0xCb034Cc0ca5C3415B6a543c9f260CAA5199b1D0e
to=0x530271DA8CC4e44375f22ad9632bC61A55382f88
token=0x3600000000000000000000000000000000000000
amount=0.001000 USDC
```

Explorer:
<https://testnet.arcscan.app/tx/0xacd1f38ba411e4596c0039bfe438c4b5f41ae0c31227ae6fc770ffcd68be1540>

This is testnet-only, presenter-operated evidence: the transaction was
broadcast by a server-held hot wallet (`0xCb034Cc0ca5C3415B6a543c9f260CAA5199b1D0e`)
after an admin-secret-gated request, not by a connected visitor wallet. Task
context was request-supplied. It does not establish principal-bound intent,
exactly-once external settlement, or chain-wide prevention, and it is
separate from the browser lab's guarded `signed_receipt_fallback` evidence
above.

## 9 August 2026 additive browser wallet-signing lane

`app/api/demo_wallet.py` adds a third, distinctly labelled lane ("Connect
your wallet · experimental") where a visitor's own EIP-1193 wallet signs and
broadcasts the transfer after Safe4 returns ALLOW. Unlike the presenter lane
above, there is no private key for this lane anywhere on the server; the
recipient and per-transaction cap still come only from server configuration
(`GET /demo/wallet/config`), never from the request.

Tested end-to-end in a real Chrome session with a connected MetaMask wallet
(`0xCb034Cc0ca5C3415B6a543c9f260CAA5199b1D0e`) against the local dev server:

```text
scenario=Task-matched API purchase (ALLOW expected)
decision=ALLOWED reason_code=TASK_PURCHASE_MATCH
wallet_signed=true
transaction_hash=0xe150f78b0f30cddfc04598f6173d5afa33d64bae9a0752b822b65e5729ce2ace
chain_id=5042002
block_number=56176225
status=success (0x1)
from=0xCb034Cc0ca5C3415B6a543c9f260CAA5199b1D0e
to=0x530271DA8CC4e44375f22ad9632bC61A55382f88
token=0x3600000000000000000000000000000000000000
amount=0.001000 USDC
```

Independently RPC-verified against `https://rpc.testnet.arc.network`: status
`0x1`, exact ERC-20 Transfer log matching the amount and configured
recipient. Explorer:
<https://testnet.arcscan.app/tx/0xe150f78b0f30cddfc04598f6173d5afa33d64bae9a0752b822b65e5729ce2ace>

The paired DENY scenario ("Wrong purchase purpose") returned
`PURCHASE_PURPOSE_MISMATCH` and produced no wallet signing prompt and no
transaction — verified by inspecting the connected page's DOM state
directly, not just its rendered text. `tests/test_demo_wallet.py` (11 tests)
covers the same recipient-is-configuration-only, amount-cap, and DENY-never-
signs guarantees offline.

This directly narrows the browser lab's older blanket claim that "the
browser never receives a wallet key" to the seven predeclared/open
scenarios only; this additive lane is the one exception, and it uses a
visitor-held key, never Safe4's. Testnet only; the visitor must hold their
own testnet USDC, so this lane cannot replace the presenter lane for a room
of unfunded judges. Not yet independently re-verified against the deployed
`demo.safe4.ai` URL as of this writing — see `SHIPLINE.md` for that status.
