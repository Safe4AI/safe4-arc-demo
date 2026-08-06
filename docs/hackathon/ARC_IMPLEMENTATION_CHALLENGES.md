# Arc implementation challenges overcome

This is the engineering record behind the Safe4 demo. It keeps the submission
honest and makes the work judges cannot see in a three-minute video auditable.
Each entry records the failure mode, why a naive implementation would be
misleading, and the evidence for the fix.

## 1. A successful receipt was not enough

**Challenge.** The first settlement check could have accepted any successful
transaction containing a USDC-looking log. An unrelated transfer could have
made the demo appear settled.

**Resolution.** The verifier now checks chain ID, transaction hash, status,
sender, recipient, amount, calldata, token event, and block. Six adversarial
tests were added before the first verified settlement was accepted.

**Evidence.** `scripts/verify_arc_settlement.py`,
`tests/test_arc_settlement_verifier.py`, and transaction
`0x24e9595078de0778428eea09af2a10ec53828c10aca6e4c5517ef1dd09144a7a`.

**Why it matters.** Payment authorization is only as trustworthy as its
settlement proof. Safe4 fails closed instead of accepting a hash-shaped string.

## 2. Arc has two USDC interfaces over one balance

**Challenge.** Arc uses USDC as its native gas asset with 18-decimal RPC
precision and also exposes the familiar 6-decimal ERC-20 interface at
`0x3600000000000000000000000000000000000000`. Mixing those units would verify
the wrong amount by a factor of one trillion.

**Resolution.** The demo records both representations explicitly. Direct
ERC-20 evidence is verified in 6-decimal base units; Circle Agent Wallet
evidence is verified against the native transfer event in 18-decimal units,
then normalized back to the requested 6-decimal amount for the Safe4 receipt.

**Evidence.** Arc's
[stablecoin-native model](https://docs.arc.io/arc/concepts/stablecoin-native-model),
the configured decimal values in `scripts/demo_golden_path.env`, and the
Agent Wallet verifier tests.

**Why it matters.** Safe4 proves `0.01 USDC`, not merely “a positive value,”
across Arc's native and ERC-20 surfaces.

## 3. Circle Agent Wallets do not look like EOA transfers

**Challenge.** The authorized Circle transfer was submitted by an ERC-4337
smart account. The top-level transaction targets the EntryPoint and is sent by
a bundler, so the existing EOA verifier correctly rejected it even though the
USDC transfer succeeded.

**Observed failure.**

```text
VERDICT=ALLOWED
reason_code=TASK_PURCHASE_MATCH
SAFE4_GOLDEN_PATH_FAIL: transaction target is not the configured USDC contract
```

The transfer itself settled successfully:

```text
transaction_hash=0x648ef14e4da7c6bfecce0017d19280ed51fb12635bea94712de926d9f967752c
block=54014886
```

**Resolution.** A separate fail-closed ERC-4337 verification path now requires:

- the configured EntryPoint as the top-level target;
- a successful `UserOperationEvent` indexed to the Circle Agent Wallet;
- an exact native-USDC `Transfer` event from that wallet to the configured
  recipient; and
- the exact normalized `0.01 USDC` amount.

The direct EOA verifier remains unchanged. Three focused adversarial tests cover
the Agent Wallet path, and a no-broadcast `circle-rpc-replay` mode proves the
fresh transaction while exercising both Safe4 decisions.

**Evidence.** `verify_circle_agent_wallet_payloads`,
`CircleAgentWalletVerifierTests`,
`docs/hackathon/LIVE_CIRCLE_EXECUTION_TRANSCRIPT.txt`, and
[Arcscan transaction](https://testnet.arcscan.app/tx/0x648ef14e4da7c6bfecce0017d19280ed51fb12635bea94712de926d9f967752c).

**Why it matters.** Safe4 verifies what the smart account actually executed,
not assumptions about who a top-level EVM transaction should resemble.

## 4. Agent Stack support changed during the build

**Challenge.** Older Circle starter kits inspected at the start of the sprint
were Base/Polygon-oriented and would not prove Arc. Current Circle CLI
documentation, however, supports `ARC-TESTNET` directly.

**Resolution.** Safe4 uses the current CLI boundary:

```text
Safe4 ALLOW -> circle wallet transfer -> Arc RPC verification
Safe4 DENY  -> no Circle transfer command
```

Authentication, email OTP, and Terms acceptance stay human-controlled. The
wallet session is local; no credential is committed or printed.

**Evidence.** Circle's
[CLI command reference](https://developers.circle.com/agent-stack/circle-cli/command-reference),
`SettlementExecutor("circle-live")`, and the verified transaction above.

**Why it matters.** The demo integrates the current Agent Stack surface instead
of adapting a stale example onto the wrong chain.

## 5. Runtime policy overrode deployment configuration

**Challenge.** Railway environment variables enabled Arc x402, but a persisted
older policy document still disabled the capability. A health check alone
would have missed that silent configuration drift.

**Resolution.** The stored policy was migrated atomically, preserving its
existing controls while enabling the Arc network and real recipient. A legacy
empty provider-name list also exposed a schema compatibility issue; the
validator now permits “no provider-name restriction” without weakening other
explicit trust-list checks.

**Evidence.** Live `/capabilities` reports `arc-testnet`, the configured
recipient, and advanced x402 enabled. Focused policy tests and the full
regression gate cover the compatibility fix.

**Why it matters.** Safe4 checks effective runtime policy, not just deployment
flags.

## 6. Deployment had to be reproducible without leaking repository state

**Challenge.** Railway's direct local upload could not safely traverse the
managed `.git` directory. Uploading an arbitrary working tree would also make
the deployed source difficult to prove.

**Resolution.** Deployment is built from an immutable `git archive` of the
exact public commit. The archive is audited for secrets and forbidden files
before upload, then Railway health, demo routes, capabilities, and the x402
challenge are checked against the live service.

**Why it matters.** The deployed artifact is traceable to the public evidence
repository and excludes local credentials and private history.

## 7. A browser demo needed an honest authorization boundary

The most tempting demo shortcut was also the least defensible one: expose the
admin receipt endpoint in browser code, label the x402 stub as a settlement,
and turn ALLOW into a transaction-success screen. That would leak an
over-privileged credential and collapse three different states—payment proof,
Safe4 authorization, and onchain execution—into one claim.

The demo now calls the real `/pay` endpoint twice. The first call receives the
machine-readable `scaffolded` x402 challenge. A guarded adapter then issues a
120-second `signed_receipt_fallback` only when all of these constraints hold:

- the separate demo-receipt feature flag is explicitly enabled;
- the presentation gate and a bearer token with `payment:authorize` are both
  present;
- the bearer is bound to the seeded `agent_alpha` demo identity;
- the currency is exactly USDC;
- the recipient is exactly the configured Arc Testnet recipient; and
- the receipt value is exactly the fixed `0.000025 USDC` demo challenge
  (`0.01 USDC × 0.0025`), inside the `0.001000 USDC` hard ceiling.

The browser retains both bearer and receipt tokens only in memory. The second
`/pay` call returns the real `TASK_PURCHASE_MATCH` or
`PURCHASE_PURPOSE_MISMATCH` decision. The final execution stage always says
`No broadcast`; prior RPC-verified Arc evidence is linked separately. Receipt
issuance is rate-limited and audited without recording the receipt token.

Validation covered the hidden route, least-privilege scope, strict request
schema, cap and recipient failures, security headers, both API decisions, and a
headless-browser click-through.

## Suggestions for the Arc core team

These are documentation and developer-experience suggestions from this
integration, not criticisms of the protocol design.

### Publish a reference browser x402 state machine

Provide one small browser example that keeps these states distinct:

```text
challenge received -> payment proof acquired -> policy authorized -> broadcast -> RPC confirmed
```

Give every state a stable machine-readable status and show which component
owns it. In particular, document that a `402` challenge or accepted fallback
receipt is not itself an onchain settlement, and that application
authorization is not transaction confirmation. A safe reference should use
PKCE, keep tokens in memory, never ship an admin credential, and show explicit
`broadcast` and `rpc_verified` booleans.

### Publish one end-to-end USDC verification recipe

The stablecoin-native model is clear conceptually, but a verifier author needs
one concrete page that puts all of these in the same worked example:

- native USDC sends at 18-decimal RPC precision;
- ERC-20 calls through `0x3600…0000` at 6 decimals;
- the raw receipt event address used for native movements;
- the explorer's normalized token-transfer view; and
- how to prove sender, recipient, amount, and status for both forms.

Sample `eth_getTransactionByHash` and `eth_getTransactionReceipt` payloads
would have prevented the most important false assumption in this build.

### Distinguish display decimals from RPC precision everywhere

Some integration tables use 6 decimals for Arc's native currency metadata,
while the stablecoin-native and infrastructure pages correctly explain that
`eth_getBalance` and native value use 18-decimal precision. Add a standard note
beside every network-metadata table:

```text
Wallet/display convention: 6 decimals
EVM native RPC value and eth_getBalance: 18 decimals
ERC-20 interface: 6 decimals
```

That would reduce the risk of integrations multiplying or dividing settlement
amounts incorrectly.

### Add an ERC-4337 settlement-verification example

For smart accounts, the top-level transaction's `from` and `to` are not the
payment sender and token contract. A short Agent Wallet example should show:

1. the bundler-to-EntryPoint transaction;
2. the `UserOperationEvent` that binds the smart-account sender;
3. the native/USDC transfer event that binds recipient and amount; and
4. the explorer view of the same operation.

This would help payment, accounting, and compliance developers avoid rejecting
valid smart-account payments or—worse—weakening verification to “any Transfer
event exists.”

### Offer machine-readable canonical network metadata

A versioned JSON document would make it easier for SDKs, verifiers, and CI to
consume Arc Testnet's chain ID, canonical RPC endpoints, explorer, USDC ERC-20
interface, native precision, CCTP domain, common EntryPoint addresses, and
finality expectations without copying values between prose pages.

### Document explorer normalization explicitly

Arcscan usefully presents native USDC movements as familiar token transfers.
The explorer/API docs should link that normalized record to the corresponding
raw RPC event and explain any address or decimal conversion. A “raw versus
indexed” toggle or example would be particularly useful for evidence systems.

### Provide a payment-verifier test-vector pack

A small public fixture set would create a strong integration target:

- valid native transfer;
- valid ERC-20 transfer;
- valid ERC-4337 Agent Wallet transfer;
- wrong recipient;
- wrong amount/decimal interpretation;
- reverted UserOperation; and
- unrelated Transfer log in an otherwise successful receipt.

Expected pass/fail results would let teams test security-sensitive verification
without spending faucet funds or depending on a live RPC during every CI run.

### Link Arc and Circle Agent Stack journeys directly

Circle's CLI supports `ARC-TESTNET`, but a developer currently has to join
Circle CLI, Agent Wallet, Arc native-USDC, explorer, and x402 documentation
manually. A single maintained tutorial—

```text
create Agent Wallet -> faucet -> Safe4/policy check -> transfer ->
verify UserOperation and USDC settlement -> inspect on Arcscan
```

—would make Arc's strongest agent-payment story much easier to discover and
reproduce.

### Reconcile product support tables and quickstarts

Several current primary pages disagree in ways that materially change a build
plan:

- Paymaster's address reference publishes Arc Testnet v0.7 and v0.8 contracts,
  while the overview's supported-chain table omits Arc.
- Agent Wallet marketing presents configurable policies generally, while the
  CLI policy commands are documented as mainnet-only.
- Gateway Nanopayments support Arc Testnet, but Agent Stack quickstarts and the
  starter-kit wrappers use Base in their examples.
- The starter-kit repository describes the examples as intended for Arc
  Testnet, while the shared `circle-tools` wrappers currently hard-code `BASE`.

Add a generated capability matrix keyed by product, network, wallet/account
type, testnet/mainnet, and SDK/CLI version. Link every quickstart to that matrix
and test its commands in documentation CI.

### Publish one Agent Wallet to Nanopayment compatibility table

The direct Gateway buyer SDK requires an EOA because it verifies EIP-3009
signatures with `ecrecover`; SCA/EIP-1271 signatures are not supported. Agent
Wallet transfers, meanwhile, may execute through ERC-4337 smart accounts, and
the Agent Stack quickstart presents `circle services pay` as the paved route.

Document exactly which Agent Wallet account types can:

1. deposit into Gateway;
2. sign Nanopayment authorizations;
3. use `circle services pay` on each supported network; and
4. retrieve durable settlement evidence.

An explicit compatibility and fallback table would prevent teams from learning
this boundary only after funding a wallet.

### Define durable Nanopayment evidence

A batched Nanopayment does not necessarily produce an immediate unique onchain
transaction. Provide a canonical evidence recipe for hackathon demos and
production auditors: payment/transfer ID, payer, recipient, amount, network,
authorization hash, Gateway state, batch settlement reference, and the point at
which each field becomes final. Include sanitized JSON examples for CLI and SDK
paths.

### Make safe discovery the first Agent Stack example

Document a no-spend sequence before the payment command:

```text
circle services search
circle services inspect
circle services pay --estimate --max-amount 0.01
```

Then show the live command separately. This makes it easier for autonomous
agents to inspect price, recipient, network, method, and schema before asking a
human for payment authority.

### Make `--chain` strict for estimates and payments

In a read-only Circle CLI 0.0.6 probe, a Marketplace service did not advertise
Arc Testnet's exact `eip155:5042002` network. Even so, this command:

```text
circle services pay <url> --chain ARC-TESTNET --estimate
```

returned an estimate with `"chain": "Ethereum"` instead of an explicit
unsupported-network error. For autonomous payment systems, silent network
fallback is unsafe: it can bypass chain-specific policy, evidence, fee, and
settlement assumptions.

Make `--chain` a hard constraint, or add `--require-chain`, and include both the
requested and negotiated CAIP-2 identifiers in structured output. Exit non-zero
when they differ.

### Align the ERC-8004 tutorial with the deployed v2 contracts

The Arc Testnet tutorial currently describes calls whose Solidity types remain
call-compatible but whose documented semantics differ from the verified v2
implementations:

- deployed `register(string)` returns `uint256 agentId`, while the tutorial ABI
  declares no output;
- the tutorial labels `giveFeedback` fields as `score`, `feedbackType`, `tag`,
  `metadataURI`, `evidenceURI`, and `comment`, while the deployed contract uses
  `value`, `valueDecimals`, `tag1`, `tag2`, `endpoint`, and `feedbackURI`; and
- the abbreviated metadata example is described as application-defined, while
  the current ERC-8004 registration format defines a `registration-v1` shape
  with registrations and service endpoints.

Publish generated ABI fragments from the actual deployed implementation and pin
the tutorial to a contract version or implementation hash. Add a documentation
test that compares every shown signature, output, and field meaning against the
verified Arc Testnet ABI.

### Put reputation trust anchors before reputation scores

A live read-only sample found 1,409 `NewFeedback` events in 1,000 Arc Testnet
blocks. One sampled agent had 200 non-revoked entries from 70 clients, while
sampled reviewer wallets each owned hundreds of agent identities. The activity
was useful for exercising the registry but not for making an authorization
decision: an unfiltered average would be Sybil-sensitive and externally
unattributable.

The deployed `getSummary` contract correctly requires a non-empty
`clientAddresses` list. Make that security property prominent in the quickstart:

1. bind the paid address to `getAgentWallet(agentId)`;
2. configure trusted reviewer addresses outside request-supplied input;
3. scope feedback by meaningful tags and endpoint;
4. check revocation, evidence, freshness, proxy implementation, and version; and
5. fail closed when the trust set is empty or the binding drifts.

Show an insecure “aggregate discovered clients” example only as an explicit
anti-pattern. A reference verifier for registration files, wallet binding, and
trusted-reviewer summaries would make the standard much safer to adopt.

### Expose Marketplace catalog revisions and exact-network filtering

Two complete read-only scans on 28 July observed the Marketplace grow from 150
to 470 services and Gateway-capable entries grow from 94 to 245, while exact Arc
Testnet offers remained at zero. Rapid inventory growth is welcome, but an
autonomous agent needs to distinguish a changed catalog from an inconsistent
page or stale cache.

Return a catalog revision, generated timestamp, and stable snapshot token in
`services search`, and support a server-side exact CAIP-2 filter. This would let
automation paginate one coherent snapshot, report reproducible evidence, and
recheck only when the catalog revision changes.

## What remains deliberately qualified

- The live x402 challenge builder is currently marked `scaffolded` / `stub`.
- The submitted task context is request-supplied and not yet principal-bound.
- The demo is Arc Testnet only; there is no mainnet, certification, partnership,
  or Circle Marketplace listing claim.
- Circle execution happens only after Safe4 ALLOW; Circle's native controls
  remain complementary and are not replaced by Safe4.
