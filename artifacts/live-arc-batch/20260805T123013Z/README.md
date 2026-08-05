# Safe4 sequential Arc Testnet batch evidence

Run ID: `20260805T123013Z`

Safe4 authorized three fixed local purchase requests before the coordinator
submitted three Circle Agent Wallet transfers on Arc Testnet. Each transfer was
RPC verified before the next request was authorized.

| Item | Safe4 | Circle / Arc | Amount | Transaction |
|---|---|---|---:|---|
| market-data | `AUTHORIZED` / `TASK_PURCHASE_MATCH` | `COMPLETE` / RPC verified | 0.001 USDC | `0x0f15d296afbefcd20c0b074c36f6ccc914020825af125c6f2e8b9af97a066145` |
| compute | `AUTHORIZED` / `TASK_PURCHASE_MATCH` | `COMPLETE` / RPC verified | 0.002 USDC | `0x29df57bf6ca1520034f22b6137c9f027c2f7610aebb0067ff6784593665bce4d` |
| agent-memory | `AUTHORIZED` / `TASK_PURCHASE_MATCH` | `COMPLETE` / RPC verified | 0.003 USDC | `0x80cb6d59bcbdd9f25ab7bdd41816febd041cc6bb353c7216dddf6b3c7cfc4a27` |

Totals: 3 planned, 3 authorized, 3 submitted, 3 RPC verified, 0
denied, 0 failed, 0 unknown, and 0 skipped. The observed sender and recipient
balance deltas were exactly 0.006 native USDC.

Independent evidence verdict: **PASS**, limited to this bounded claim.

## Evidence classes

- `preflight.json`: read-only clean-source, authenticated-wallet, Arc chain,
  and balance gate.
- `live-run.json`: normalized fixed-field output emitted by the guarded live
  runner, with CLI provenance wording narrowed after source inspection.
- `rpc-verification.txt`: three separate exact-hash Arc RPC verifier results.
- `circle-history.txt`: allowlisted projection from authenticated Circle
  transaction history.
- `journal-audit.txt`: phase names and counts only; the private journal and its
  six idempotency keys remain under ignored `.tmp` state.
- `pytest.txt`: pre-run tests and public-package audit.
- `source-provenance.txt`: exact Git revision and executable-source digests.
- `redaction-manifest.md`: data excluded from the public bundle.

## Claim boundary

This is evidence of three sequential, non-atomic Arc Testnet USDC transfers to
one code-reviewed recipient after three local Safe4 `/pay` authorizations. The
Safe4 receipt route is a local fixture, not three external paid x402 vendor
endpoints. The coordinator enforces the recipient allowlist; this run does not
prove a general Safe4 recipient policy, atomic multisend, exactly-once external
settlement, concurrency safety, production readiness, or Circle endorsement.
The verifier did not decode the complete UserOperation calldata, so this bundle
does not prove the absence of unrelated non-USDC effects inside an operation.

At execution revision `a2831a76e37e0e45e1d3e5d142484af5d2d12c63`, Circle
subprocesses inherited the wrapper's ephemeral local fixture environment and
HTTPX used its default environment trust. A post-run name-only audit found no
HTTP proxy, custom CA, or Circle proxy variables in the parent environment; no
secret values or raw provider responses were retained. These are recorded as
hardening limitations, not hidden.
