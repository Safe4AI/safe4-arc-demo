# Safe4 final video package

Target: **2:45–2:55**, maximum **3:00**. Record on Arc Testnet only.

## Spoken script

**0:00–0:30 — problem**

AI agents can now discover services, hold wallets, and pay autonomously. But
there is a security gap between an agent deciding to spend and the money
moving. A wallet can enforce an amount limit or block an address, yet still
approve the wrong purchase for the task. Safe4 is built for that missing
decision point.

**0:30–0:50 — Safe4 in one sentence**

Safe4 is a payment firewall for AI agents: the security layer between the agent
deciding to spend and execution. It evaluates submitted task context, proposed
purchase, amount, counterparty, autonomy scope, policy, and payment proof, then
returns an auditable allow or deny reason.

**0:50–2:20 — live demo**

Here the agent has one task: research competitor pricing using a paid company
data service. The proposed purchase is a competitor-pricing research brief for
zero point zero one USDC. It is within budget, the category is allowed, and the
purchase purpose matches the task.

I run one command: `bash scripts/demo_circle_replay.sh`.

Safe4 returns ALLOWED with the reason `TASK_PURCHASE_MATCH`. The safe replay
mode then asks Arc Testnet RPC to verify the fresh Circle Agent Wallet
transaction. It checks chain ID 5042002, the ERC-4337 EntryPoint target, a
successful UserOperation for the wallet, and the exact native-USDC sender,
recipient, and 18-decimal amount event before normalizing it to 0.01 USDC.
The transaction hash appears in the demo evidence bundle and opens in the
Arc explorer. This command re-verifies the earlier live transfer; it does not
broadcast another one.

Now the agent proposes a gift card for an unrelated entertainment giveaway.
The amount, service category, and counterparty are unchanged. Circle policy is
not invoked in replay. Safe4 returns DENIED with
`PURCHASE_PURPOSE_MISMATCH`: the amount and category are permitted, but the
purchase does not match the submitted task context. The unchanged executor
call count shows this demo orchestrator did not invoke settlement for the
denied branch.

**2:20–2:45 — Arc and Circle**

Arc gives us a payment-native test environment and exact onchain USDC evidence.
Circle Agent Stack gives agents wallet execution and native guardrails. Safe4
does not replace those controls. Circle enforces the floor; Safe4 decides
whether this payment should happen at all. After an ALLOWED decision, the
authenticated Agent Wallet settled 0.01 testnet USDC on Arc. Safe4 then
RPC-verified the ERC-4337 receipt, exact recipient, and amount.

**2:45–2:55 — team and path**

Our team brings 35 combined years across cybersecurity and finance in regulated
environments. Today the task context is request-supplied. The accelerator helps
us bind it to trusted principals, validate with design partners, and prepare
Safe4 for the Circle Agent Marketplace.

## Shot-by-shot run sheet

| Time | Picture | Action / caption |
|---|---|---|
| 0:00–0:30 | Slide 2 | Caption: “A valid wallet action can still be the wrong action.” |
| 0:30–0:50 | Slide 1, then slide 4 | Caption: “Payment firewall for AI agents.” |
| 0:50–1:00 | Terminal at repo root | Show `bash scripts/demo_circle_replay.sh` before pressing Enter. |
| 1:00–1:35 | Terminal allowed block | Hold on task, amount, checks, `VERDICT=ALLOWED`, and reason. |
| 1:35–1:52 | Terminal transaction lines | Hold on `settlement=RPC_VERIFIED` and the full hash. |
| 1:52–2:02 | Arcscan transaction tab | Show Arc Testnet badge and successful USDC transfer; caption “historical replay evidence.” |
| 2:02–2:20 | Terminal denied block | Hold on `VERDICT=DENIED`, mismatch reason, unchanged inputs, and executor call count. |
| 2:20–2:45 | Slides 5, 7, 8 | Caption: “Circle floor + Safe4 task-aware decision.” |
| 2:45–2:55 | Slides 9 and 10 | Team fact and marketplace-readiness roadmap. |

## Exact recording setup

1. Use a clean clone of `https://github.com/Safe4AI/safe4-arc-demo`.
2. Create a Python 3.13 virtual environment and install
   `requirements-dev.txt` and `requirements-arc.txt`.
3. Open these tabs before recording:
   - deck in presentation mode;
   - terminal at repository root;
   - [Fresh Circle Agent Wallet transaction](https://testnet.arcscan.app/tx/0x648ef14e4da7c6bfecce0017d19280ed51fb12635bea94712de926d9f967752c).
4. Increase terminal font until each stable marker remains readable at 1080p.
5. Run `bash scripts/demo_circle_replay.sh` once off-camera as a network preflight.
6. Clear the terminal, start recording, then run the same command once.

## Rehearsal checklist

- [ ] Desktop notifications and unrelated browser tabs are closed.
- [ ] No `.env`, private key, wallet credential, email, or OTP is visible.
- [ ] Terminal shows `MODE=CIRCLE_AGENT_WALLET_RPC_VERIFIED_REPLAY`.
- [ ] Allowed and denied reasons fit on screen without horizontal scrolling.
- [ ] Arcscan visibly says Testnet and the hash matches the terminal.
- [ ] The script says the replay did not broadcast a fresh transfer.
- [ ] Circle Agent Wallet claim is limited to the verified Arc Testnet transfer.
- [ ] Final take is between 2:40 and 2:55.
- [ ] Export at 1080p; verify the final file with `ffprobe`.

## Backup evidence

- Transaction:
  `0x648ef14e4da7c6bfecce0017d19280ed51fb12635bea94712de926d9f967752c`
- Explorer:
  <https://testnet.arcscan.app/tx/0x648ef14e4da7c6bfecce0017d19280ed51fb12635bea94712de926d9f967752c>
- Arc evidence document: `docs/ARC_TESTNET_EVIDENCE.md`
- Committed demo transcript: `docs/hackathon/DEMO_TRANSCRIPT.txt`
- Sanitized live execution evidence: `docs/hackathon/LIVE_CIRCLE_EXECUTION_TRANSCRIPT.txt`
- Raw regression evidence: `docs/hackathon/VERIFICATION_EVIDENCE.md`
