# Safe4 Arc + Circle expansion goal

Use this prompt with `$shipline` and `$maximize-circle-fit`.

## Product-fit decision

Safe4 already has a verified, coherent path:

```text
Safe4 task-purpose ALLOW
  -> Circle Agent Wallet transfer
  -> Arc Testnet USDC settlement
  -> ERC-4337-aware RPC verification

Safe4 task-purpose DENY
  -> explicit PURCHASE_PURPOSE_MISMATCH
  -> settlement executor not called
```

The best incremental integration is not another independent transaction. It is a
drop-in replacement for the ALLOW executor:

```text
Circle Marketplace service discovery + x402 offer
  -> Safe4 decision
  -> Circle services payment with a hard maximum
  -> Gateway Nanopayment settlement evidence + paid response
```

If successful, this single flow can honestly cover Arc, USDC, Agent Stack, Agent
Wallets, Agent Marketplace, x402, Gateway, and Nanopayments. The current transfer
and replay remain the recording-safe fallback.

| Product | Current decision | Reason |
|---|---|---|
| Arc + USDC | Keep; verified | Core settlement and evidence layer |
| Agent Stack + Agent Wallets | Keep; verified | Authenticated Circle CLI execution after Safe4 ALLOW |
| Marketplace + x402 + Gateway Nanopayments | Current NO-GO; recheck later | Highest potential gain, but no Marketplace offer currently advertises exact Arc Testnet terms |
| ERC-8004 | Current NO-GO; re-open with trusted data | Deployed v2 contracts are live, but the payment-path wallets own no identities and public feedback lacks attributable trusted reviewers |
| App Kit | Defer | Send duplicates the transfer; bridge/swap/unified balance are not needed |
| Circle Contracts | Defer | Requires a separate API key/Entity Secret and a useful attestation contract |
| Paymaster | Reject for submission | Redundant on native-USDC Arc and gas-sponsored Agent Wallets; docs conflict |
| ERC-8183 | Reject for submission | Creates a different escrow/job product story |
| Whole starter-kit fork | Reject | Current shared wrappers and OpenAI example are Base-oriented |

## Current Marketplace admission result — NO-GO

On 28 July 2026, an initial read-only Circle CLI 0.0.6 probe scanned all 150
Marketplace services:

```json
{
  "TotalItems": 150,
  "GatewayItems": 94,
  "ArcItems": 0,
  "ArcGatewayItems": 0
}
```

The catalog later grew to 470 entries. A complete second scan observed:

```json
{
  "TotalItems": 470,
  "GatewayItems": 245,
  "ArcItems": 0,
  "ArcGatewayItems": 0
}
```

The growth was material, but it did not change the admission result.

`scripts/probe_circle_marketplace.py` now makes this gate reproducible. It
paginates structured CLI output, requires exact Arc and USDC terms, inspects
candidate schemas/recipient/price, and permits only two repeated
`services pay --estimate` calls under a hard `0.01 USDC` ceiling. Its direct
command validator rejects deposit, missing or duplicate safety flags, option
tokens used as values, wrong chains, and over-cap estimates. The live run
returned `NO_EXACT_ARC_GATEWAY_SERVICE`; the sanitized result is preserved in
`docs/hackathon/CIRCLE_MARKETPLACE_PROBE.json`. No payment or deposit occurred.

The gate required the exact Arc Testnet CAIP-2 network `eip155:5042002`.
One public `$0.0024` Gateway service advertised `eip155:5042`, not the
required network. More importantly, an estimate explicitly requested with
`--chain ARC-TESTNET` returned:

```json
{
  "price": "$0.0024 USDC",
  "chain": "Ethereum",
  "scheme": "GatewayWalletBatched"
}
```

No deposit or payment was made. Do not implement or claim this path until a
later read-only scan finds a service whose structured terms use exact Arc
Testnet and whose estimate preserves that network.

## ERC-8004 admission result — NO-GO

A separate read-only Arc Testnet probe verified the documented ERC-8004 v2
Identity and Reputation Registry proxies, their implementations, registry
linkage, and sub-second query feasibility. It also found that the Safe4
deployer, Circle Agent Wallet, and current settlement recipient each own zero
ERC-8004 identities, so the payment counterparty cannot be bound to an agent.

The latest 1,000-block sample contained 1,409 `NewFeedback` events with
bulk-generated patterns and no externally attributable reviewer set. Because
`getSummary` requires explicitly supplied client addresses to mitigate
Sybil/spam risk, Safe4 will not convert arbitrary public scores into ALLOW or
DENY decisions.

Re-open this candidate only when the exact `payTo` address is bound through
`getAgentWallet(agentId)` and at least two independently attributable reviewers
with documented scoring methods can be configured outside request input. No
identity registration, feedback write, or other contract transaction occurred.

## Copy/paste goal prompt

```text
You are Codex operating in the Safe4 repository root.
Use $shipline first and $maximize-circle-fit second.

GOAL
Improve Safe4's Encode x Arc Agentic Economy submission by replacing the current
generic ALLOW transfer with one real, repeatable Circle Marketplace x402 payment
on Arc Testnet, gated by Safe4 before any Circle payment command. Preserve the
existing Circle Agent Wallet transfer and RPC replay as the immutable fallback.
Do not broaden the use case or add products whose effect is not visible in the
same <=3-minute ALLOW/DENY story.

BASELINE TO PRESERVE
- Python 3.13 full regression gate: 338 tests passing in the current local
  candidate; the published public head remains the independently verified
  293-test baseline until an authorized push.
- Public runnable repository and CI remain green.
- Existing Arc Testnet USDC and Circle Agent Wallet transactions remain
  independently RPC-verifiable.
- ALLOW reason remains explicit.
- DENY remains a purpose mismatch that Circle's documented static controls do not
  evaluate, and the payment executor is provably not called.
- Deck/video claims stay narrower than observed evidence.
- No secret, private key, Circle session, OTP, or local credential enters the repo,
  output, transcript, or chat.

PRIMARY HYPOTHESIS
A real Marketplace payment can replace the current settlement executor and prove
Agent Stack + Agent Wallets + Marketplace + x402 + Gateway Nanopayments + USDC +
Arc without adding a second demo flow. This hypothesis is currently NO-GO:
Circle CLI 0.0.6 found no exact Arc Testnet Marketplace offer on 28 July 2026.

PHASE 0 — LOCK THE SUBMISSION
1. Read SHIPLINE.md, shipline/log.md, shipline/signals.md, the claim ledger, and
   the recording package.
2. Run shipline/verify.sh with network access and print the raw verdict block.
3. Preserve every current PASS. The human-recorded <=3-minute video remains the
   highest-priority missing artifact; do not make its verified fallback path less
   reliable.

PHASE 1 — READ-ONLY FEASIBILITY
1. Fetch the current official Arc and Circle llms.txt indexes and relevant pages.
2. Inspect the installed Circle CLI and authenticated testnet session without
   printing credentials.
3. Search Marketplace services, inspect candidate 402 requirements, and use
   circle services pay --estimate. Do not deposit or pay.
   Require `eip155:5042002` in the structured offer and require the estimate
   result to remain on Arc Testnet; never accept an automatic network fallback.
4. Select one stable service only if:
   - it supports the intended Circle/Gateway payment method on Arc Testnet;
   - price, recipient, network, URL, and request schema are machine-readable;
   - its response is useful enough to make the agent's task concrete;
   - it succeeds twice during read-only inspection;
   - it can be capped at <=0.01 testnet USDC;
   - it requires no OTP, Terms, or manual interaction during recording.
5. If no service passes, record a NO-GO signal and retain the current demo.

PHASE 2 — SURGICAL IMPLEMENTATION
1. Add one new settlement-executor mode behind the existing demo boundary.
2. Bind Safe4's submitted task context to the inspected purchase: service URL,
   purpose, recipient, network, amount, and max amount.
3. Run Safe4 before invoking Circle.
4. ALLOW invokes exactly one Circle services payment with a hard --max-amount.
5. DENY invokes no payment command; print the unchanged executor-call count.
6. Fail closed on unavailable service, changed 402 terms, price/recipient/network
   mismatch, malformed Circle output, Gateway failure, or unverifiable evidence.
7. Keep the current Circle transfer and both RPC replay modes unchanged.

PHASE 3 — AUTHORIZED TESTNET PROOF
Prepare the exact deposit/payment commands, resolved wallet, service URL, network,
maximum amount, and expected evidence. Ask Bryn once for permission before any
testnet deposit or payment. Never touch mainnet or real-value funds.

After approval:
- use the minimum practical Gateway deposit;
- make at most a 0.01 testnet-USDC service payment;
- capture sanitized live stdout, authenticated transaction/transfer history,
  balances before/after, paid response, and identifiers;
- do not claim that a batched Nanopayment has a unique immediate onchain
  transaction unless the returned evidence proves it.

PHASE 4 — VERIFICATION
1. Add adversarial tests for ALLOW, DENY/no executor call, changed 402 terms,
   over-max price, wrong network, malformed output, and provider outage.
2. Run focused tests, fast tests, and the complete Python 3.13 suite with a
   unique temporary PAYMENT_FIREWALL_DB_PATH; never use the local application
   database as a test database. Then run docs checks, secret audit, and the
   public clean-clone demo.
3. Run the live/replay path twice unattended.
4. Re-run shipline/verify.sh; no green criterion may regress.
5. Give the raw artifacts to a fresh read-only claim verifier.

CONDITIONAL STRETCH
Only after the video-safe path is locked and all gates remain green, consider a
read-only ERC-8004 provider under app/integrations. It must read a live Arc value
that changes ALLOW/DENY and must fail closed. Display-only identity/reputation is
not an integration.

EXPLICIT CUTS
Do not add App Kit, Circle Contracts, Paymaster, ERC-8183, CCTP, swap/bridge,
another agent framework, or a wholesale starter-kit fork unless a newly observed
requirement makes it necessary for the same payment. Log the signal first.

DONE
- The original verified demo remains available and green.
- One command shows real x402 terms -> Safe4 ALLOW -> one Circle/Gateway payment
  -> paid response/evidence, then Safe4 DENY -> zero payment command.
- The path succeeds twice, unattended, and remains within the <=3-minute story.
- Full tests, public CI, clean-clone, secret audit, and independent claim audit pass.
- Every new product claim maps to distinct observed evidence.
- All human boundaries and the final Encode submission remain Bryn-controlled.
```

## Official source anchors

- <https://docs.arc.io/llms.txt>
- <https://developers.circle.com/llms.txt>
- <https://developers.circle.com/agent-stack>
- <https://developers.circle.com/agent-stack/circle-cli/command-reference>
- <https://developers.circle.com/gateway/nanopayments>
- <https://developers.circle.com/gateway/references/supported-blockchains>
- <https://docs.arc.io/app-kit/references/supported-blockchains>
- <https://developers.circle.com/paymaster/addresses-and-events>
- <https://developers.circle.com/contracts/supported-blockchains>
- <https://docs.arc.io/arc/tutorials/register-your-first-ai-agent>
- <https://github.com/circlefin/agent-stack-starter-kits>
