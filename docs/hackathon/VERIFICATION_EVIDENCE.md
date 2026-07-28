# Verification evidence

Observed in the public submission worktree on 28 July 2026 with Python 3.13.14.

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
