# Safe4 bounded live Arc Testnet transaction tests

This sanitized bundle records a bounded test set with one fresh Circle Agent
Wallet transfer. Safe4 returned `ALLOWED` for the task-matching request before
the coordinator submitted `0.01 USDC` on Arc Testnet. The paired mismatching
request returned `DENIED`, and this coordinator's settlement-executor count
remained `1 -> 1`.

## Results

- Network: Arc Testnet (`5042002`), not mainnet.
- Transaction: [`0x9dedac01a941059342cb0f907a45f8b64478b3309327202db327afee4f12061d`](https://testnet.arcscan.app/tx/0x9dedac01a941059342cb0f907a45f8b64478b3309327202db327afee4f12061d).
- Block: `55430634` at `2026-08-05T11:13:47Z`.
- Sender: `0x3985a31e4e42a31e437c1099306decbe2f08da4d`.
- Recipient: `0x530271DA8CC4e44375f22ad9632bC61A55382f88`.
- Amount: `0.010000 USDC`.
- Execution path: `ERC_4337_AGENT_WALLET`.
- Circle authenticated history: `COMPLETE`, `TRANSFER`.
- Balance observation: `19.98 -> 19.97 USDC`.
- Required live-run markers missing: `0`.
- Focused tests: `25 passed, 1 warning`.
- Independent review: `PASS` for L01-L05.

## Test matrix

| ID | Test | Result |
|---|---|---|
| L01 | Task-matching Safe4 ALLOW followed by one live settlement | PASS |
| L02 | Gift-card mismatch DENY with no additional executor call | PASS |
| L03 | Independent exact-hash Arc RPC verification | PASS |
| L04 | Authenticated Circle history reconciliation | PASS |
| L05 | Public wallet balance delta observation | PASS |

## Source identity

The command ran from the unversioned source workspace. Before packaging, eight
critical runner, verifier, application, and test files were byte-compared with
public commit `2477e6812ba145e785c8ff76e986828f1d27ae5e`; no mismatch was found.

## Read-only reproduction

See `rpc-verification.txt` for the exact command. It queries public Arc RPC and
does not sign or broadcast.

See `source-provenance.txt` for the eight SHA-256 digests used in the source
comparison and `independent-review.md` for the bounded reviewer verdict.

## Limitations

- The Safe4 task context was request-supplied and untrusted.
- The authorized amount and configured settlement amount are independently
  supplied; this run kept both at `0.01 USDC`, but it does not prove a general
  cryptographic binding.
- The vendor label and configured recipient are not cryptographically bound.
- The DENY observation proves only that this coordinator did not invoke its
  executor again. It is not chain-wide prevention evidence.
- This single fresh transfer does not prove production reliability,
  exactly-once external settlement, concurrency safety, cumulative budgets,
  principal-bound intent, or general semantic reasoning.
- The synthetic vendor label is not evidence of Circle Marketplace
  integration, listing, review, or endorsement.
- Known C01-C03 intent-laundering and counterparty-substitution gaps were not
  exercised live.
