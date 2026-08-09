# Safe4 final video package

Target: **2:45–2:55**, maximum **3:00**. Record on Arc Testnet only.

This is the current run sheet, centered on the ALLOW/DENY verdict flip, the
open challenge lane, a live settlement that stops at step one on a denial
and completes with a real hash on an allow, and a few seconds showing the
SDK reaching Safe4 from outside the browser. It replaces the earlier
Circle-Agent-Wallet-replay script; that older recorded evidence remains
valid historical proof (see `docs/hackathon/VERIFICATION_EVIDENCE.md`) but
is no longer the video's spine.

## Spoken script

**0:00–0:25 — problem**

AI agents can now discover services, hold wallets, and pay autonomously. But
there is a security gap between an agent deciding to spend and the money
moving. A wallet can enforce an amount limit or block an address, yet still
approve the wrong purchase for the task. Safe4 is built for that missing
decision point.

**0:25–0:45 — Safe4 in one sentence**

Safe4 is a payment firewall for AI agents: the security layer between the
agent deciding to spend and execution. It evaluates the submitted task,
proposed purchase, amount, counterparty, autonomy scope, and payment proof,
then returns an auditable allow or deny with a reason.

**0:45–1:15 — the verdict flip**

Here the agent has one task: research competitor pricing using a paid
company data service. The proposed purchase matches that task. I select it
and run it. Safe4 returns ALLOW, reason `TASK_PURCHASE_MATCH`.

Now the agent proposes a gift card for an unrelated giveaway. The amount,
the service category, and the counterparty are unchanged. Only the purpose
changed. Safe4 returns DENY, reason `PURCHASE_PURPOSE_MISMATCH`. Same money,
different answer.

**1:15–1:35 — the open challenge**

This scenario isn't predeclared. I'll type a task and a purchase myself,
right now, live, and Safe4 reports whatever it actually decides — nothing
here is scripted to a known outcome.

**1:35–2:15 — live settlement**

This lane runs the same Safe4 decision, but on ALLOW it broadcasts one real
USDC transfer on Arc Testnet. Watch what happens on a denial first: Safe4's
decision is the first step, and the feed stops right there — nothing is
built, signed, or sent. Now the matching purchase: the feed completes all
five steps, and this hash is real — I can open it on Arc Testnet right now.

**2:15–2:25 — reachable outside the browser**

Safe4 isn't only a page you click. Here's an external agent using our
published SDK, no browser involved: it proposes the same matching purchase
and gets ALLOW, then the same mismatch and gets DENY, straight from the
command line against this deployment.

**2:25–2:45 — Arc and team**

Arc gives us a payment-native test environment and exact on-chain evidence.
Our team brings 35 combined years across cybersecurity and finance in
regulated environments. Today the task context is request-supplied; the
accelerator helps us bind it to trusted principals and validate with design
partners.

## Shot-by-shot run sheet

| Time | Picture | Action / caption |
|---|---|---|
| 0:00–0:25 | Slide 2 | Caption: "A valid wallet action can still be the wrong action." |
| 0:25–0:45 | Slide 1, then slide 4 | Caption: "Payment firewall for AI agents." |
| 0:45–1:00 | Browser: tile 01, run | Hold on green `ALLOW` / `TASK_PURCHASE_MATCH` for a beat. |
| 1:00–1:15 | Browser: tile 03, run | Hold on red `DENY` / `PURCHASE_PURPOSE_MISMATCH` for a beat. |
| 1:15–1:35 | Browser: tile 07, type task + purpose, run | Show the real decision appearing live, no predeclared outcome. |
| 1:35–1:50 | Browser: live-settlement lane, mismatched scenario selected, click "Authorize & settle live" | Feed stops at step 1, "DENIED ... nothing was built, signed, or broadcast." |
| 1:50–2:15 | Browser: live-settlement lane, matching scenario selected, click "Authorize & settle live" | All 5 feed steps complete; hold on the real tx hash and open it on Arcscan. |
| 2:15–2:25 | Terminal: `python examples/third_party_agent_demo.py ...` | Scroll to show ALLOW then DENY output from outside the browser. |
| 2:25–2:45 | Slides 8, 9, 10 | Arc/team/close. |

## Exact recording setup

1. Use a clean clone of `https://github.com/Safe4AI/safe4-arc-demo`.
2. Create a Python 3.13 virtual environment and install
   `requirements-dev.txt` and `requirements-arc.txt`.
3. Open these tabs before recording:
   - deck in presentation mode;
   - terminal at repository root, ready to run
     `python examples/third_party_agent_demo.py --base-url https://demo.safe4.ai --demo-access-token <judge token>`;
   - the live judge page, `?live_admin=<value>` already appended (see
     `docs/hackathon/VIDEO_RECORDING_GUIDE.md` for how to fetch that value
     without ever writing it down).
4. Increase terminal font until each stable marker remains readable at
   1080p.
5. Run through the whole sequence once off-camera so the live-settlement
   lane's two transactions (denial, then allow) are fresh in your memory —
   the allow will broadcast a real transfer, so do this run for real once,
   then do it again on camera. Two live transfers per recording session is
   fine; the caps are `0.01 USDC` per transaction and `0.10 USDC` per day.
6. Clear the terminal, start recording, then run the sequence once.

## Rehearsal checklist

- [ ] Desktop notifications and unrelated browser tabs are closed.
- [ ] No `.env`, private key, admin secret, wallet credential, email, or OTP
      is visible — including in the URL bar (`?live_admin=` must never be
      shown on camera; crop or zoom past it).
- [ ] The green `ALLOW` and red `DENY` from the verdict-flip step are both
      readable.
- [ ] The open-challenge result is visibly typed live, not a predeclared
      tile.
- [ ] The live-settlement feed visibly stops at step 1 on the denial run.
- [ ] The live-settlement feed visibly completes all 5 steps with a real
      hash on the allow run, and the hash opens on Arcscan as Testnet.
- [ ] The SDK terminal segment shows both an ALLOW and a DENY.
- [ ] Final take is between 2:40 and 2:55.
- [ ] Export at 1080p; verify the final file with `ffprobe`.

## Backup evidence

- Live settlement transactions:
  `0xacd1f38ba411e4596c0039bfe438c4b5f41ae0c31227ae6fc770ffcd68be1540`,
  `0xe9cf81485fac6f0b2158040acdab7364328809b0820239fce20e214cbc100db4`
- Current Arc evidence and claim boundaries: `docs/hackathon/VERIFICATION_EVIDENCE.md`,
  `docs/hackathon/CLAIM_LEDGER.md`
- SDK and contract: `docs/x402/CONTRACT.md`, `sdk/python/safe4_client.py`,
  `examples/third_party_agent_demo.py`
- Prior Circle Agent Wallet replay evidence (no longer the video's spine,
  still valid historical proof): `docs/hackathon/DEMO_TRANSCRIPT.txt`,
  `docs/hackathon/LIVE_CIRCLE_EXECUTION_TRANSCRIPT_20260805.txt`
- Reviewed edge-case summary:
  `artifacts/transaction-edge-cases/20260805T011517Z/summary.md`
