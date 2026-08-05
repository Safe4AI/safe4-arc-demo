# Safe4 midpoint submission — 27 July 2026

## Project

Safe4 is a policy-driven payment firewall for AI agents. It intercepts an
agent-proposed payment before execution, evaluates whether that payment is
allowed, and records the reason and evidence for the decision.

## What works at midpoint

- FastAPI frontend and backend with a judge-facing agent-security demo
- budgets, velocity controls, approval workflows, receipts, audit evidence,
  x402 and AP2 protocol machinery
- Python 3.13 regression gate: 270 passing tests
- real USDC settlement on Arc Testnet
- transaction-specific RPC verification of chain, token, participants, amount,
  calldata, receipt status, and `Transfer` event

## Arc evidence

- Chain ID: `5042002`
- USDC: `0x3600000000000000000000000000000000000000`
- Transaction:
  [`0x24e9595078de0778428eea09af2a10ec53828c10aca6e4c5517ef1dd09144a7a`](https://testnet.arcscan.app/tx/0x24e9595078de0778428eea09af2a10ec53828c10aca6e4c5517ef1dd09144a7a)

## Work toward final submission — 9 August 2026

1. Replace the x402 synthetic settlement proof with an RPC-confirmed Arc USDC
   transaction before payment finalization.
2. Replace the current keyword intent heuristic with genuine task-to-payment
   matching.
3. Produce a one-command golden path showing one allowed and one differentiated
   denied payment with legible reasons.
4. Deploy the demo, record the three-minute video, and complete the deck.

## Honest limitation

The verified Arc transaction currently proves the chain and signing path outside
the Safe4 service. It does not yet prove that the service itself initiated that
settlement. The final build will not claim otherwise.
