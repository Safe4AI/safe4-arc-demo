# Safe4 hackathon claim ledger

Status: prepared for independent C8 review. Every material deck/video claim is
either backed here, explicitly qualified, or marked as a human-confirmed fact.

| Claim | Used in | Evidence | Qualification |
|---|---|---|---|
| Safe4 is a payment firewall between decision and execution. | Deck 1–2; video 0:30 | `app/main.py`, `/pay`; `app/payment_entry_checks.py`; `app/payment_finalize.py` | Product description, not a certification claim. |
| Safe4 evaluates task/purchase purpose. | Deck 4, 6, 8; video demo | `app/core/intent.py`; `tests/test_intent_semantic.py`; `docs/hackathon/DEMO_TRANSCRIPT.txt` | Deterministic concept matching against request-supplied context, not general AI semantic reasoning. |
| The matching research purchase is allowed. | Deck 6; video demo | `scripts/demo_golden_path.py`; `TASK_PURCHASE_MATCH` in `docs/hackathon/DEMO_TRANSCRIPT.txt` | Authorization is exercised through the real local `/pay` path. |
| The gift-card purchase is denied with equal amount, category, and counterparty. | Deck 6, 8; video demo | `tests/test_intent_semantic.py`; `tests/test_main.py`; `UNCHANGED_INPUTS` and `PURCHASE_PURPOSE_MISMATCH` in `docs/hackathon/DEMO_TRANSCRIPT.txt` | Independent C4 reviewer returned PASS; submitted task context is request-supplied and not yet principal-bound. |
| The denied demo branch does not invoke the settlement executor. | Deck 5–6; video demo | Unchanged executor call count and `DENIED_DEMO_EXECUTOR_NOT_INVOKED=PASS` in `docs/hackathon/DEMO_TRANSCRIPT.txt` | Proves only that this demo orchestrator did not invoke execution; it is not a chain-wide proof of absence. |
| A real 0.01 USDC transfer settled on Arc Testnet. | Deck 6–7; video demo | Transaction `0x24e9595078de0778428eea09af2a10ec53828c10aca6e4c5517ef1dd09144a7a`; `docs/ARC_TESTNET_EVIDENCE.md`; Arcscan link | Historical testnet evidence; the replay demo did not broadcast it. |
| RPC verification checks chain, token, sender, recipient, amount, calldata, status, and Transfer event. | Deck 7; video demo | `scripts/verify_arc_settlement.py`; `tests/test_arc_settlement_verifier.py`; C1 verifier output | The default demo re-verifies existing chain evidence; it does not claim a fresh broadcast. |
| The full Python 3.13 regression gate passes 286 tests. | Deck 10; README | `docs/hackathon/VERIFICATION_EVIDENCE.md` | Point-in-time result; update if the final gate count changes. |
| The public demo repository exists. | Deck 10; README | <https://github.com/Safe4AI/safe4-arc-demo>; exact commit and CI recorded in `docs/hackathon/VERIFICATION_EVIDENCE.md` | Commit/CI must be updated after the final push. |
| Circle Agent Wallets support Arc Testnet. | Deck 5, 7; video 2:20 | <https://developers.circle.com/agent-stack/agent-wallets/supported-blockchains> and CLI reference | Live use requires testnet login, email OTP, and Terms acceptance. |
| The adapter is coded to attempt Circle Agent Wallet execution only after ALLOWED. | Deck 5, 7; video 2:20 | `SettlementExecutor("circle-live")` call site in `scripts/demo_golden_path.py`; `tests/test_demo_golden_path.py` | Authenticated end-to-end Circle validation is pending; no successful Circle execution is claimed. |
| Circle provides documented spending policies and compliance guardrails; those docs do not describe the submitted-task-to-purchase check demonstrated here. | Deck 2, 8; video 2:20 | <https://developers.circle.com/agent-stack/agent-wallets> | Narrow comparison of documented controls; Safe4 is complementary, not a replacement. |
| x402 and AP2 are emerging agent-payment rails. | Deck 3 | x402: <https://www.x402.org/>; AP2 announcement: <https://cloud.google.com/blog/products/ai-machine-learning/announcing-agents-to-payments-ap2-protocol> | No claim that all protocol paths are production integrations. |
| Team has 35 combined years in cybersecurity and finance in regulated environments. | Deck 9; video close | Human-confirmed submission fact supplied by Bryn | Names, employers, certifications, and biographies are intentionally not invented. |
| Marketplace listing is a roadmap goal. | Deck 10; video close | Circle Agent Marketplace: <https://agents.circle.com/services> | Safe4 is not currently listed; application is a later human action. |

## Explicit non-claims

- No Arc mainnet use or deployment.
- No certification, regulatory compliance, or partnership claim.
- No claim that the replay command broadcasts a new transaction.
- No claim that Circle has listed, reviewed, endorsed, or audited Safe4.
- No claim of general semantic AI reasoning.
- No ERC-8004 integration claim.
