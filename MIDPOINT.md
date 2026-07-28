# Safe4 midpoint submission — 2 August 2026

## Project

Safe4 is a policy-driven payment firewall for AI agents. It intercepts an
agent-proposed payment before execution, evaluates whether that payment is
allowed, and records the reason and evidence for the decision.

## What works at midpoint

- FastAPI frontend and backend with a judge-facing agent-security demo
- budgets, velocity controls, approval workflows, receipts, audit evidence,
  x402 and AP2 protocol machinery
- Python 3.13 regression gate: 286 passing tests
- real USDC settlement on Arc Testnet
- transaction-specific RPC verification of chain, token, participants, amount,
  calldata, receipt status, and `Transfer` event
- one-command Safe4 golden path with task-matching ALLOWED and purpose-mismatch
  DENIED decisions
- deterministic matching against request-supplied task context, with structured
  reasons and an explicit trust-boundary disclosure
- optional Circle Agent Stack adapter coded to attempt execution after ALLOWED;
  authenticated validation is pending

## Arc evidence

- Chain ID: `5042002`
- USDC: `0x3600000000000000000000000000000000000000`
- Transaction:
  [`0x24e9595078de0778428eea09af2a10ec53828c10aca6e4c5517ef1dd09144a7a`](https://testnet.arcscan.app/tx/0x24e9595078de0778428eea09af2a10ec53828c10aca6e4c5517ef1dd09144a7a)

## Work toward final submission — 22 August 2026

1. Authenticate a Circle Arc Testnet Agent Wallet and capture a fresh,
   post-authorization live transfer.
2. Bind task context to a trusted principal and remove the documented legacy
   justification compatibility path.
3. Rehearse and record the prepared three-minute video.
4. Complete independent claim audit, then update the human-controlled final
   submission.

## Honest limitation

The default golden path uses a real, RPC-verified historical Arc transaction and
labels it as replay evidence. It does not claim the replay command broadcast a
fresh transfer. The Circle live adapter is implemented, but fresh execution
still requires a human-authenticated testnet Circle session.
