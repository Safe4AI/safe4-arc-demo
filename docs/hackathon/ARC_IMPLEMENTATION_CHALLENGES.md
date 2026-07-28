# Arc implementation challenges overcome

This is the engineering record behind the Safe4 demo. It keeps the submission
honest and makes the work judges cannot see in a three-minute video auditable.

## 1. A successful receipt was not enough

The first settlement check could have accepted any successful transaction
containing a USDC-looking log. The verifier now checks chain ID, transaction
hash, status, sender, recipient, amount, calldata, token event, and block. Six
adversarial tests were added before the first verified settlement was accepted.

**Evidence:** `scripts/verify_arc_settlement.py`,
`tests/test_arc_settlement_verifier.py`, and
`0x24e9595078de0778428eea09af2a10ec53828c10aca6e4c5517ef1dd09144a7a`.

**Why it matters:** Safe4 fails closed instead of accepting a hash-shaped
string.

## 2. Arc has two USDC interfaces over one balance

Arc uses USDC as its native gas asset with 18-decimal RPC precision and also
exposes the 6-decimal ERC-20 interface at
`0x3600000000000000000000000000000000000000`. Mixing those units would verify
the wrong amount by a factor of one trillion.

Direct ERC-20 evidence is verified in 6-decimal base units. Circle Agent Wallet
evidence is verified against the native transfer event in 18-decimal units,
then normalized back to the requested 6-decimal amount.

**Evidence:** Arc's
[stablecoin-native model](https://docs.arc.io/arc/concepts/stablecoin-native-model)
and the configured decimal values in `scripts/demo_golden_path.env`.

## 3. Circle Agent Wallets do not look like EOA transfers

The authorized Circle transfer was submitted by an ERC-4337 smart account. The
top-level transaction targets the EntryPoint and is sent by a bundler, so the
existing EOA verifier correctly rejected it even though the USDC transfer
succeeded:

```text
VERDICT=ALLOWED
reason_code=TASK_PURCHASE_MATCH
SAFE4_GOLDEN_PATH_FAIL: transaction target is not the configured USDC contract
```

The transfer settled successfully:

```text
transaction_hash=0x648ef14e4da7c6bfecce0017d19280ed51fb12635bea94712de926d9f967752c
block=54014886
```

A separate fail-closed ERC-4337 path now requires:

- the configured EntryPoint as the top-level target;
- a successful `UserOperationEvent` indexed to the Circle Agent Wallet;
- an exact native-USDC `Transfer` event from that wallet to the recipient; and
- the exact normalized `0.01 USDC` amount.

The direct EOA verifier remains unchanged. Three focused adversarial tests cover
the Agent Wallet path, and `circle-rpc-replay` proves the fresh transaction
without broadcasting another transfer.

**Evidence:** `verify_circle_agent_wallet_payloads`,
`CircleAgentWalletVerifierTests`, and the
[Arcscan transaction](https://testnet.arcscan.app/tx/0x648ef14e4da7c6bfecce0017d19280ed51fb12635bea94712de926d9f967752c).

## 4. Agent Stack support changed during the build

Older Circle starter kits inspected at the start of the sprint were
Base/Polygon-oriented. Current Circle CLI documentation supports
`ARC-TESTNET` directly, so Safe4 uses the current boundary:

```text
Safe4 ALLOW -> circle wallet transfer -> Arc RPC verification
Safe4 DENY  -> no Circle transfer command
```

Authentication, OTP, and Terms acceptance stay human-controlled. The wallet
session is local; no credential is committed or printed.

**Evidence:** Circle's
[CLI command reference](https://developers.circle.com/agent-stack/circle-cli/command-reference).

## 5. Runtime policy overrode deployment configuration

Railway environment variables enabled Arc x402, but a persisted older policy
document still disabled the capability. A health check alone would have missed
the configuration drift.

The stored policy was migrated atomically while preserving its controls. A
legacy empty provider-name list also exposed a schema compatibility issue; the
validator now permits “no provider-name restriction” without weakening other
explicit trust-list checks.

**Why it matters:** Safe4 checks effective runtime policy, not just deployment
flags.

## 6. Deployment had to be reproducible

Railway's direct local upload could not safely traverse the managed `.git`
directory. Deployment is therefore built from an immutable `git archive` of
the exact public commit. The archive is audited for secrets and forbidden files
before upload, then the live health, demo, capability, and x402 routes are
verified.

## Suggestions for the Arc core team

These are documentation and developer-experience suggestions from this
integration, not criticisms of the protocol design.

### Publish one end-to-end USDC verification recipe

Put native 18-decimal RPC values, the 6-decimal ERC-20 interface, raw native
movement events, explorer normalization, and exact sender/recipient/amount
verification in one worked example. Sample transaction and receipt payloads
would have prevented the most important false assumption in this build.

### Distinguish display decimals from RPC precision everywhere

Add a standard note beside each network-metadata table:

```text
Wallet/display convention: 6 decimals
EVM native RPC value and eth_getBalance: 18 decimals
ERC-20 interface: 6 decimals
```

### Add an ERC-4337 settlement-verification example

Show the bundler-to-EntryPoint transaction, `UserOperationEvent`, smart-account
sender, exact USDC recipient/amount event, and Arcscan view of the same
operation. This would help developers avoid rejecting valid smart-account
payments or weakening verification to “any Transfer event exists.”

### Offer machine-readable canonical network metadata

A versioned JSON document could expose chain ID, RPCs, explorer, USDC
interfaces and precisions, CCTP domain, common EntryPoints, and finality
expectations without copying values between prose pages.

### Document explorer normalization explicitly

Link Arcscan's normalized USDC transfer record to the raw RPC event and explain
address/decimal conversion. A “raw versus indexed” example would be valuable
for audit and evidence systems.

### Provide payment-verifier test vectors

Publish fixtures and expected results for valid native, ERC-20, and ERC-4337
transfers plus wrong-recipient, wrong-amount, reverted-UserOperation, and
unrelated-log cases.

### Link Arc and Circle Agent Stack journeys directly

A maintained tutorial covering Agent Wallet creation, faucet funding, a policy
check, transfer, UserOperation/USDC verification, and Arcscan inspection would
make Arc's agent-payment story easier to reproduce.

## What remains deliberately qualified

- The live x402 challenge builder is marked `scaffolded` / `stub`.
- The task context is request-supplied and not yet principal-bound.
- The demo is Arc Testnet only; there is no mainnet, certification, partnership,
  or Circle Marketplace listing claim.
- Circle's native controls remain complementary and are not replaced by Safe4.
