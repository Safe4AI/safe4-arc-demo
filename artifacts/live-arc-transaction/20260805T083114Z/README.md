# Safe4 live Arc Testnet transaction evidence

This sanitized bundle records one fresh Circle Agent Wallet transfer submitted
on 5 August 2026 only after Safe4 returned `ALLOWED` for the task-matching
purchase. Arc RPC verification then confirmed the exact sender, recipient, and
`0.01 USDC` amount at block `55411369`.

The paired gift-card request was denied with
`PURCHASE_PURPOSE_MISMATCH`. The coordinator's settlement-executor count stayed
at one, so the denied branch did not ask the coordinator to broadcast another
transaction.

## Result

- Network: Arc Testnet (`5042002`), not mainnet.
- Transaction: [`0xf9d665cf0eb663e33703826ca599d526718042781860faeec5e7ad089fde775d`](https://testnet.arcscan.app/tx/0xf9d665cf0eb663e33703826ca599d526718042781860faeec5e7ad089fde775d)
- Block: `55411369`, timestamp `2026-08-05T08:30:05Z`.
- Sender: `0x3985a31e4e42a31e437c1099306decbe2f08da4d`.
- Recipient: `0x530271DA8CC4e44375f22ad9632bC61A55382f88`.
- Amount: `0.010000 USDC`.
- Execution path: `ERC_4337_AGENT_WALLET`.
- Circle authenticated history: `COMPLETE`, `TRANSFER`.
- Independent local verdict: `PASS`.

## Evidence classes

- `live-run.txt`: an explicit allowlist of coordinator markers and public
  settlement fields; it is not raw process output.
- `rpc-verification.txt`: exact successful output from the focused Arc
  settlement verifier.
- `circle-history.txt`: an allowlisted projection of the authenticated Circle
  transaction-history result.
- `pytest.txt`: focused test command and result covering the live executor and
  Arc verifier.
- `redaction-manifest.md`: material deliberately excluded from this bundle.

## Read-only reproduction

```powershell
.\.python313\python.exe -m scripts.verify_arc_settlement `
  --mode circle-agent-wallet `
  --rpc-url https://rpc.testnet.arc.network `
  --chain-id 5042002 `
  --usdc-address 0x3600000000000000000000000000000000000000 `
  --tx-hash 0xf9d665cf0eb663e33703826ca599d526718042781860faeec5e7ad089fde775d `
  --sender 0x3985a31e4e42a31e437c1099306decbe2f08da4d `
  --recipient 0x530271DA8CC4e44375f22ad9632bC61A55382f88 `
  --amount-units 10000 `
  --usdc-decimals 6 `
  --entrypoint-address 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789 `
  --native-usdc-address 0xfffffffffffffffffffffffffffffffffffffffe `
  --native-usdc-decimals 18
```

This command is read-only. It does not sign or broadcast a transaction.

## Limitations

The Safe4 authorization in this demo used an isolated local database and
request-supplied task context. It is not proof of principal-bound context,
production readiness, mainnet execution, or general semantic reasoning. The
synthetic vendor label is not a Circle Marketplace integration. The executor
counter establishes only that this coordinator did not invoke settlement for
the denied branch; it cannot prove that no unrelated actor submitted an
independent chain transaction. Source revision is recorded as `unversioned
snapshot` because this workspace is not a Git checkout.
