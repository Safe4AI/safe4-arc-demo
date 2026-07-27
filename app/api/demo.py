from __future__ import annotations

from fastapi import APIRouter, Header, HTTPException, Query, status
from fastapi.responses import HTMLResponse


router = APIRouter()
_demo_access_token: str | None = None


def setup_demo_api(*, demo_access_token: str | None) -> None:
    global _demo_access_token
    _demo_access_token = (demo_access_token or "").strip() or None


def _require_demo_access(
    *,
    access_token: str | None,
    x_demo_access: str | None,
) -> None:
    if _demo_access_token is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    presented = (access_token or x_demo_access or "").strip()
    if not presented or presented != _demo_access_token:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")


AGENT_SECURITY_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Safe4 | Transaction Security For AI Agents</title>
  <style>
    :root {
      --bg: #f4efe5;
      --panel: rgba(255, 250, 242, 0.9);
      --ink: #15120d;
      --muted: #675c4d;
      --line: rgba(21, 18, 13, 0.11);
      --signal: #d76731;
      --deep: #8a3415;
      --green: #1d6b4f;
      --navy: #214f73;
      --gold: #9a7c32;
      --shadow: 0 28px 80px rgba(53, 34, 21, 0.12);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      color: var(--ink);
      font-family: "Segoe UI", "Avenir Next", "Helvetica Neue", sans-serif;
      background:
        radial-gradient(circle at 15% 15%, rgba(215, 103, 49, 0.16), transparent 28%),
        radial-gradient(circle at 85% 0%, rgba(33, 79, 115, 0.14), transparent 26%),
        linear-gradient(180deg, #faf4eb 0%, var(--bg) 58%, #efe5d6 100%);
    }
    a { color: inherit; text-decoration: none; }
    .wrap { width: min(1200px, calc(100vw - 32px)); margin: 0 auto; padding: 24px 0 64px; }
    .shell, .card, .hero-card, .surface, .quote-card {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 28px;
      backdrop-filter: blur(16px);
      box-shadow: var(--shadow);
    }
    .shell { padding: 22px 24px; }
    .topbar, .footer, .section-head, .hero-actions { display: flex; flex-wrap: wrap; gap: 12px; }
    .topbar, .footer, .section-head { justify-content: space-between; align-items: center; }
    .brand { display: flex; gap: 12px; align-items: center; font-weight: 700; }
    .brand-mark {
      width: 42px; height: 42px; border-radius: 14px; display: grid; place-items: center;
      color: #fff8f2; font-weight: 800; background: linear-gradient(135deg, var(--signal), var(--deep));
    }
    .nav { display: flex; flex-wrap: wrap; gap: 10px; color: var(--muted); font-size: 0.94rem; }
    .nav a { padding: 10px 14px; border-radius: 999px; background: rgba(21, 18, 13, 0.04); }
    .hero { display: grid; grid-template-columns: 1.15fr 0.85fr; gap: 22px; }
    .hero-card, .surface, .quote-card, .card { padding: 24px; }
    .eyebrow {
      display: inline-flex; gap: 10px; padding: 8px 14px; border-radius: 999px;
      background: rgba(21, 18, 13, 0.05); color: var(--muted);
      font-size: 0.77rem; letter-spacing: 0.12em; text-transform: uppercase;
    }
    h1 {
      margin: 18px 0 16px; max-width: 820px; font-family: Georgia, serif;
      font-size: clamp(2.8rem, 5vw, 5.1rem); line-height: 0.93; letter-spacing: -0.045em;
    }
    h2 { margin: 0 0 10px; font-size: 1.05rem; }
    h3 { margin: 14px 0 10px; font-size: 1.15rem; }
    p, li { margin: 0; color: var(--muted); line-height: 1.68; }
    ul { margin: 12px 0 0; padding-left: 18px; display: grid; gap: 8px; }
    .button {
      display: inline-flex; align-items: center; justify-content: center; min-width: 180px;
      padding: 14px 18px; border-radius: 16px; font-weight: 700; border: 1px solid transparent;
    }
    .button.primary { color: #fff7f0; background: linear-gradient(135deg, var(--signal), var(--deep)); }
    .button.secondary { background: rgba(255,255,255,0.72); border-color: rgba(21,18,13,0.08); }
    .metric-grid, .grid, .timeline { display: grid; gap: 18px; }
    .metric-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); margin-top: 24px; }
    .metric {
      padding: 16px 18px; border-radius: 20px; background: rgba(255,255,255,0.62);
      border: 1px solid rgba(21,18,13,0.08);
    }
    .metric .label { font-size: 0.74rem; text-transform: uppercase; letter-spacing: 0.1em; color: var(--muted); }
    .metric .value { margin-top: 8px; font-size: 1.4rem; font-weight: 700; color: var(--ink); }
    .surface { background: linear-gradient(180deg, rgba(19,17,14,0.98), rgba(30,24,20,0.98)); color: #f7ede1; }
    .surface p { color: #d7c6b6; }
    .pill {
      display: inline-flex; gap: 10px; padding: 7px 12px; border-radius: 999px;
      font-size: 0.75rem; letter-spacing: 0.1em; text-transform: uppercase;
      color: #d7c6b6; background: rgba(255,255,255,0.07);
    }
    .code {
      margin-top: 16px; padding: 16px; border-radius: 20px; background: rgba(255,255,255,0.04);
      border: 1px solid rgba(255,255,255,0.08); font-family: "Cascadia Code", Consolas, monospace;
      font-size: 0.85rem; line-height: 1.65; white-space: pre-wrap; color: #f3d9c2;
    }
    .section { margin-top: 28px; }
    .grid { grid-template-columns: repeat(3, minmax(0, 1fr)); }
    .timeline { grid-template-columns: repeat(4, minmax(0, 1fr)); }
    .tag {
      display: inline-block; padding: 7px 11px; border-radius: 999px; color: #fff;
      font-size: 0.74rem; letter-spacing: 0.08em; text-transform: uppercase; background: var(--signal);
    }
    .tag.green { background: var(--green); }
    .tag.navy { background: var(--navy); }
    .tag.gold { background: var(--gold); }
    .timeline .card::before {
      content: attr(data-step); display: inline-grid; place-items: center; width: 34px; height: 34px;
      border-radius: 999px; background: rgba(21,18,13,0.06); color: var(--ink); font-weight: 800;
    }
    .quote { max-width: 920px; font-family: Georgia, serif; font-size: clamp(1.5rem, 2.7vw, 2.2rem); line-height: 1.2; }
    @media (max-width: 980px) {
      .hero, .grid, .timeline, .metric-grid { grid-template-columns: 1fr; }
      .topbar, .footer, .section-head { align-items: flex-start; }
    }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="shell">
      <header class="topbar">
        <div class="brand">
          <div class="brand-mark">S4</div>
          <div>
            <div>Safe4</div>
            <div style="color: var(--muted); font-size: 0.9rem; font-weight: 500;">AI transaction security for programmable payments</div>
          </div>
        </div>
        <nav class="nav">
          <a href="/demo/agent-security">Landing Page</a>
          <a href="/demo/console">Console Mockup</a>
          <a href="/health">Live Health</a>
        </nav>
      </header>
      <section class="hero">
        <article class="hero-card">
          <div class="eyebrow">Safe4 Demo Surface · Agent Transaction Security</div>
          <h1>Put a real security and approval layer between AI agents and money movement.</h1>
          <p>
            Safe4 is the control plane that sits between an agent action and execution. Agents can request
            a transaction, but Safe4 decides whether it should be approved, challenged, escalated, screened,
            or denied, with audit evidence and operator visibility built in from the start.
          </p>
          <div class="hero-actions" style="margin-top: 24px;">
            <a class="button primary" href="/demo/console">Open Console Mockup</a>
            <a class="button secondary" href="/health">Check Live Demo Health</a>
          </div>
          <div class="metric-grid">
            <div class="metric"><div class="label">Decision Surface</div><div class="value">Policy + Proof + Risk</div></div>
            <div class="metric"><div class="label">Agent Outcome</div><div class="value">Authorize, escalate, or deny</div></div>
            <div class="metric"><div class="label">Operator View</div><div class="value">Traceable and replay-safe</div></div>
            <div class="metric"><div class="label">Integration Path</div><div class="value">Range Risk live seam</div></div>
          </div>
        </article>
        <aside class="surface">
          <div class="pill">Core API Flow</div>
          <h2 style="margin-top: 14px;">What an AI agent actually sends</h2>
          <p>Safe4 gives agents one secure entrypoint instead of direct access to wallets, cards, vendors, or settlement rails.</p>
          <div class="code">POST /pay
{
  "agent_id": "agent_alpha",
  "user_id": "user_123",
  "vendor": "acme_travel",
  "amount": 9.99,
  "currency": "USD",
  "description": "Book the approved train ticket for tomorrow's client meeting in Madrid.",
  "context": {
    "trip_id": "trip_789"
  }
}</div>
          <p style="margin-top: 14px;">The same request can come back as <strong>AUTHORIZED</strong>, <strong>PAYMENT_REQUIRED</strong>, a HITL approval request, or a policy denial with a machine-readable reason.</p>
        </aside>
      </section>
      <section class="section">
        <div class="section-head">
          <div>
            <h2>Why teams use Safe4 instead of letting agents spend directly</h2>
            <p>We are not trying to make agents transact faster at any cost. We are making agent-led financial actions governable enough for real operations, finance, and security teams.</p>
          </div>
        </div>
        <div class="grid">
          <article class="card"><span class="tag">Authorization</span><h3>Policy-Gated Payment Entry</h3><p>Agents call Safe4 first. Budgets, velocity, autonomy limits, receipt proof, and policy checks happen before execution can continue.</p></article>
          <article class="card"><span class="tag navy">Approvals</span><h3>Human-in-the-Loop When It Matters</h3><p>Higher-risk actions can pause for review, then resume with approval records and spend-token continuity instead of ad hoc operator workarounds.</p></article>
          <article class="card"><span class="tag green">Integrations</span><h3>Provider-Backed Screening</h3><p>Safe4 can enrich decisions with integrations like Range Risk so agent actions inherit real external risk intelligence before money moves.</p></article>
        </div>
      </section>
      <section class="section">
        <div class="section-head">
          <div>
            <h2>How the Safe4 flow works</h2>
            <p>It is a compact loop for the agent, but a high-signal control plane for operators, finance, and security.</p>
          </div>
        </div>
        <div class="timeline">
          <article class="card" data-step="1"><h3>Agent requests action</h3><p>An agent submits a transaction request with identity, amount, purpose, and optional tool or vendor context.</p></article>
          <article class="card" data-step="2"><h3>Safe4 evaluates posture</h3><p>Policy, infrastructure identity, payment proof, anomaly posture, and provider-backed signals are checked in one path.</p></article>
          <article class="card" data-step="3"><h3>Decision is returned</h3><p>Safe4 returns an authorization, a payment challenge, a HITL approval state, or an explicit denial code.</p></article>
          <article class="card" data-step="4"><h3>Execution proceeds safely</h3><p>Only approved and properly funded requests continue, while audit, trace, and evidence records remain available for review.</p></article>
        </div>
      </section>
      <section class="section">
        <div class="grid">
          <article class="card"><span class="tag gold">Forensics</span><h3>Everything leaves a trail</h3><p>Transaction traces, anomaly evidence, approval timelines, and exportable audit packaging mean operators can reconstruct what happened later.</p></article>
          <article class="card"><span class="tag green">Integrations</span><h3>Composable external signals</h3><p>Provider seams let us plug in KYC, wallet risk, banking, market data, or execution providers without rewriting the core policy path.</p></article>
          <article class="card"><span class="tag navy">Demo Ready</span><h3>Two ways to explore it</h3><p>Use this landing page to frame the system and the console mockup to simulate the operator experience of reviewing agent-led transactions.</p></article>
        </div>
      </section>
      <section class="quote-card section">
        <h3>Safe4 Agent Security Gateway</h3>
        <p class="quote">AI agents will increasingly initiate transactions. The winning infrastructure is not the one that lets them act with the fewest constraints. It is the one that makes their actions safe, legible, and commercially deployable.</p>
      </section>
      <footer class="footer section">
        <div>Demo pages: <strong>/demo/agent-security</strong> and <strong>/demo/console</strong></div>
        <div>Live system checks: <strong>/health</strong>, <strong>/integrations/providers</strong>, <strong>/pay</strong></div>
      </footer>
    </div>
  </div>
</body>
</html>
"""


CONSOLE_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Safe4 | Operator Console Mockup</title>
  <style>
    :root {
      --bg: #0f1418;
      --panel: rgba(18, 24, 31, 0.92);
      --panel-soft: rgba(24, 31, 40, 0.92);
      --ink: #edf3f7;
      --muted: #93a6b5;
      --line: rgba(237, 243, 247, 0.08);
      --green: #39c784;
      --amber: #f0b24d;
      --red: #ea6a6a;
      --blue: #62a7ff;
      --signal: #ff8d54;
      --shadow: 0 28px 80px rgba(0, 0, 0, 0.34);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0; color: var(--ink); font-family: "Segoe UI", "Avenir Next", "Helvetica Neue", sans-serif;
      background:
        radial-gradient(circle at top left, rgba(98, 167, 255, 0.12), transparent 28%),
        radial-gradient(circle at bottom right, rgba(255, 141, 84, 0.12), transparent 24%),
        linear-gradient(180deg, #11181d 0%, #0b0f13 100%);
    }
    .wrap { width: min(1380px, calc(100vw - 24px)); margin: 0 auto; padding: 18px 0 28px; }
    .frame { background: rgba(12, 17, 22, 0.88); border: 1px solid var(--line); border-radius: 26px; box-shadow: var(--shadow); overflow: hidden; }
    .topbar {
      display: flex; align-items: center; justify-content: space-between; gap: 18px;
      padding: 18px 20px; border-bottom: 1px solid var(--line); background: rgba(255, 255, 255, 0.02);
    }
    .brand { display: flex; gap: 12px; align-items: center; }
    .brand-mark {
      width: 38px; height: 38px; border-radius: 12px; display: grid; place-items: center;
      font-weight: 800; color: #101417; background: linear-gradient(135deg, #ffb27b, #ff8d54);
    }
    .brand-copy strong { display: block; font-size: 0.98rem; }
    .brand-copy span, .badge, .nav-item span, .event span, .detail p, .detail li, .kv-row span { color: var(--muted); }
    .status-strip, .hero-actions { display: flex; flex-wrap: wrap; gap: 10px; }
    .badge {
      padding: 8px 12px; border-radius: 999px; border: 1px solid var(--line);
      background: rgba(255,255,255,0.04); font-size: 0.78rem; letter-spacing: 0.06em; text-transform: uppercase;
    }
    .layout { display: grid; grid-template-columns: 290px 1fr 340px; min-height: 820px; }
    .sidebar, .main, .detail { padding: 20px; }
    .sidebar, .detail { background: rgba(255,255,255,0.02); }
    .sidebar { border-right: 1px solid var(--line); }
    .detail { border-left: 1px solid var(--line); }
    .nav-title, .section-title {
      margin: 0 0 12px; font-size: 0.82rem; letter-spacing: 0.12em; text-transform: uppercase; color: var(--muted);
    }
    .nav-list, .event-list { display: grid; gap: 10px; }
    .nav-item, .event {
      width: 100%; text-align: left; color: inherit; background: var(--panel); border: 1px solid var(--line);
      border-radius: 18px; padding: 14px; cursor: pointer;
    }
    .nav-item.active, .event.active {
      border-color: rgba(98, 167, 255, 0.55);
      box-shadow: 0 0 0 1px rgba(98, 167, 255, 0.18) inset;
      background: rgba(24, 34, 46, 0.98);
    }
    .nav-item strong, .event strong { display: block; margin-bottom: 4px; font-size: 0.96rem; }
    .hero { display: grid; grid-template-columns: 1.25fr 0.75fr; gap: 18px; margin-bottom: 18px; }
    .hero-card, .stack-card, .terminal, .scoreboard, .detail-card {
      background: var(--panel-soft); border: 1px solid var(--line); border-radius: 22px; padding: 18px;
    }
    h1 { margin: 8px 0 12px; font-size: clamp(1.7rem, 2.5vw, 2.5rem); line-height: 1.05; letter-spacing: -0.03em; }
    .hero-card p { margin: 0; color: var(--muted); line-height: 1.65; }
    .button {
      display: inline-flex; align-items: center; justify-content: center; padding: 12px 14px; border-radius: 14px;
      text-decoration: none; font-weight: 700; border: 1px solid var(--line); color: var(--ink); background: rgba(255,255,255,0.06);
    }
    .button.primary { color: #13181d; background: linear-gradient(135deg, #ffb27b, #ff8d54); border-color: transparent; }
    .mini { display: grid; gap: 10px; }
    .mini-row, .kv-row {
      display: flex; justify-content: space-between; gap: 12px; padding: 12px 13px;
      border-radius: 16px; background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.05);
    }
    .mini-row strong, .kv-row strong, .score .value { color: var(--ink); }
    .scoreboard { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; margin-bottom: 18px; }
    .score { padding: 14px; border-radius: 18px; background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.05); }
    .score .label { color: var(--muted); font-size: 0.74rem; text-transform: uppercase; letter-spacing: 0.08em; }
    .score .value { margin-top: 8px; font-size: 1.35rem; font-weight: 700; }
    .terminal {
      font-family: "Cascadia Code", Consolas, monospace; font-size: 0.84rem; line-height: 1.6;
      color: #d4e1ec; white-space: pre-wrap; min-height: 240px; overflow: auto;
    }
    .comment { color: #8ea4b8; } .good { color: var(--green); } .warn { color: var(--amber); } .bad { color: var(--red); } .accent { color: #8fc5ff; }
    .detail-card { margin-bottom: 14px; }
    .detail-card h3 { margin: 0 0 10px; font-size: 1rem; }
    .pill {
      display: inline-flex; align-items: center; padding: 6px 10px; border-radius: 999px;
      font-size: 0.73rem; text-transform: uppercase; letter-spacing: 0.08em; border: 1px solid transparent;
    }
    .green { color: #d8ffee; background: rgba(57, 199, 132, 0.12); border-color: rgba(57, 199, 132, 0.28); }
    .amber { color: #ffe9c0; background: rgba(240, 178, 77, 0.14); border-color: rgba(240, 178, 77, 0.28); }
    .red { color: #ffd8d8; background: rgba(234, 106, 106, 0.14); border-color: rgba(234, 106, 106, 0.28); }
    .blue { color: #dcedff; background: rgba(98, 167, 255, 0.14); border-color: rgba(98, 167, 255, 0.28); }
    ul { margin: 12px 0 0; padding-left: 18px; display: grid; gap: 8px; }
    @media (max-width: 1180px) {
      .layout { grid-template-columns: 1fr; }
      .sidebar, .detail { border: 0; border-top: 1px solid var(--line); }
    }
    @media (max-width: 860px) {
      .hero, .scoreboard { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="frame">
      <header class="topbar">
        <div class="brand">
          <div class="brand-mark">S4</div>
          <div class="brand-copy">
            <strong>Safe4 Console Mockup</strong>
            <span>Interactive demo of how operators review AI agent transaction security decisions</span>
          </div>
        </div>
        <div class="status-strip">
          <div class="badge">Live demo surface</div>
          <div class="badge">Policy + approvals + risk</div>
          <div class="badge">Range Risk ready</div>
          <div class="badge" id="live-health-badge">Checking health...</div>
        </div>
      </header>
      <div class="layout">
        <aside class="sidebar">
          <h2 class="nav-title">Demo Scenarios</h2>
          <div class="nav-list">
            <button class="nav-item active" data-scenario="authorized" type="button"><strong>Authorized Travel Purchase</strong><span>Low-risk spend, receipt supplied, policy passes.</span></button>
            <button class="nav-item" data-scenario="payment_required" type="button"><strong>Receipt Missing</strong><span>Agent request is challenged with a payment-required response.</span></button>
            <button class="nav-item" data-scenario="hitl" type="button"><strong>Human Approval Required</strong><span>Trusted agent, but amount and posture trigger HITL review.</span></button>
            <button class="nav-item" data-scenario="denied" type="button"><strong>Blocked High-Risk Transfer</strong><span>External screening and policy deny the request.</span></button>
          </div>
        </aside>
        <main class="main">
          <section class="hero">
            <article class="hero-card">
              <div class="pill blue">Interactive Safe4 Console</div>
              <h1 id="scenario-title">Authorized Travel Purchase</h1>
              <p id="scenario-summary">A trusted travel-booking agent submits a small approved transaction. Safe4 validates policy, verifies the receipt path, records the audit trail, and returns an authorization.</p>
              <div class="hero-actions" style="margin-top: 18px;">
                <a class="button primary" href="/demo/agent-security">Open Landing Page</a>
                <a class="button" href="/health">Check Live Health</a>
              </div>
            </article>
            <article class="stack-card">
              <h2 class="section-title">Current Decision Stack</h2>
              <div class="mini" id="decision-stack"></div>
            </article>
          </section>
          <section class="scoreboard" id="scoreboard"></section>
          <h2 class="section-title">Event Timeline</h2>
          <div class="event-list" id="event-list"></div>
          <h2 class="section-title" style="margin-top: 18px;">Console Output</h2>
          <div class="terminal" id="terminal"></div>
        </main>
        <aside class="detail">
          <div class="detail-card">
            <h3>Live Safe4 Signals</h3>
            <div id="live-signal-status" class="pill blue">Fetching live data</div>
            <div id="live-signals" style="display:grid; gap:10px; margin-top:12px;"></div>
          </div>
          <div class="detail-card">
            <h3>Selected Event</h3>
            <div id="event-status" class="pill blue">Awaiting selection</div>
            <div id="event-meta" style="display:grid; gap:10px; margin-top:12px;"></div>
          </div>
          <div class="detail-card">
            <h3>Operator Notes</h3>
            <p id="operator-note">Select a timeline event to inspect the reason, evidence, and next step for the transaction.</p>
          </div>
          <div class="detail-card">
            <h3>What this demonstrates</h3>
            <ul id="demo-points"></ul>
          </div>
        </aside>
      </div>
    </div>
  </div>
  <script>
    const scenarios = {
      authorized: {
        title: "Authorized Travel Purchase",
        summary: "A trusted travel-booking agent submits a small approved transaction. Safe4 validates policy, verifies the receipt path, records the audit trail, and returns an authorization.",
        stack: [["Identity posture", "Trusted workload · green zone"], ["Receipt state", "Valid X-Payment-Receipt attached"], ["Risk provider", "Range Risk screening clean"], ["Outcome", "AUTHORIZED"]],
        scores: [["Amount", "$9.99"], ["Risk score", "Low"], ["Decision", "Authorized"], ["Trace", "Stored"]],
        events: [
          { title: "Request accepted", status: "blue", meta: { Route: "POST /pay", Agent: "agent_alpha", Vendor: "acme_travel" }, note: "Safe4 received a standard payment authorization request from a known agent identity.", terminal: ["[accent]POST /pay[/accent] agent_alpha -> acme_travel", "[comment]normalized amount: 9.99 USD[/comment]", "[good]request_hash recorded[/good]"] },
          { title: "Receipt verified", status: "green", meta: { Receipt: "Short-lived token", Source: "Safe4 receipts", Replay: "Not reused" }, note: "The firewall fee path is satisfied, so the request can move into policy evaluation.", terminal: ["[good]X-Payment-Receipt verified[/good]", "[comment]fee requirement satisfied[/comment]"] },
          { title: "Risk screening passed", status: "green", meta: { Provider: "Range Risk", Wallet: "Clean", Network: "ethereum" }, note: "External risk posture is acceptable, so there is no sanctions or wallet-risk escalation here.", terminal: ["[accent]Range Risk[/accent] screening requested", "[good]screening result: clear[/good]"] },
          { title: "Authorization returned", status: "green", meta: { Decision: "AUTHORIZED", Audit: "Hash-chained", Transaction: "Recorded" }, note: "Safe4 authorizes the request and preserves the full transaction trace for later review.", terminal: ["[good]decision=AUTHORIZED[/good]", "[comment]audit trace persisted[/comment]"] }
        ],
        points: ["A normal low-risk agent transaction stays fast.", "Receipt proof, policy, and risk checks all happen before authorization.", "Operators still get traces without having to manually intervene."]
      },
      payment_required: {
        title: "Receipt Missing",
        summary: "An agent submits a legitimate request without fee proof. Safe4 responds with a machine-readable payment challenge instead of silently failing or allowing unpaid execution.",
        stack: [["Identity posture", "Known agent"], ["Receipt state", "Missing"], ["Risk provider", "Not reached yet"], ["Outcome", "PAYMENT_REQUIRED"]],
        scores: [["Amount", "$9.99"], ["Risk score", "Pending"], ["Decision", "402 challenge"], ["Trace", "Stored"]],
        events: [
          { title: "Request accepted", status: "blue", meta: { Route: "POST /pay", Agent: "agent_alpha", Vendor: "acme_travel" }, note: "The request structure is valid, so Safe4 processes it rather than rejecting malformed input.", terminal: ["[accent]POST /pay[/accent] request accepted", "[comment]idempotency and body checks passed[/comment]"] },
          { title: "Payment proof missing", status: "amber", meta: { Code: "PAYMENT_REQUIRED", Header: "X-Amount-Due", Retry: "Expected" }, note: "Safe4 returns a 402-style response so the agent or operator can obtain a receipt token and retry cleanly.", terminal: ["[warn]missing X-Payment-Receipt[/warn]", "[accent]returning PAYMENT_REQUIRED challenge[/accent]"] },
          { title: "Retry path preserved", status: "blue", meta: { Next: "POST /receipts/issue", State: "No side effects", Audit: "Logged" }, note: "No downstream execution occurs, but the event is still visible to operators for later review.", terminal: ["[comment]execution halted before vendor rail[/comment]", "[good]retry path prepared[/good]"] }
        ],
        points: ["Safe4 can challenge instead of denying a legitimate request.", "The payment proof step is explicit and machine-readable.", "Operators keep visibility even when the flow stops early."]
      },
      hitl: {
        title: "Human Approval Required",
        summary: "The agent is trusted, but the combination of amount, policy, and posture moves the request into a human approval queue instead of direct execution.",
        stack: [["Identity posture", "Trusted workload"], ["Receipt state", "Valid"], ["Risk provider", "Acceptable but monitored"], ["Outcome", "PENDING_APPROVAL"]],
        scores: [["Amount", "$742.00"], ["Risk score", "Medium"], ["Decision", "HITL"], ["Trace", "Approval linked"]],
        events: [
          { title: "Request accepted", status: "blue", meta: { Route: "POST /pay", Agent: "agent_ops", Vendor: "cloud_vendor" }, note: "The transaction is structurally valid and linked to a known workload identity.", terminal: ["[accent]POST /pay[/accent] agent_ops -> cloud_vendor", "[comment]trusted workload identity detected[/comment]"] },
          { title: "Policy threshold hit", status: "amber", meta: { Trigger: "Amount threshold", Scope: "Direct payment", Rule: "hitl_rule_ops_01" }, note: "The request is not denied, but it exceeds the automation threshold for unattended authorization.", terminal: ["[warn]policy escalation threshold exceeded[/warn]", "[comment]routing into HITL workflow[/comment]"] },
          { title: "Approval request created", status: "amber", meta: { Approval: "Created", SpendToken: "Deferred", Alert: "Webhook/outbox ready" }, note: "Operators can approve or deny the action, and the approval lifecycle remains traceable.", terminal: ["[accent]approval request created[/accent]", "[warn]decision=PENDING_APPROVAL[/warn]"] }
        ],
        points: ["Automation can continue without bypassing operator oversight.", "Approvals fit inside the same transaction path instead of becoming manual side processes.", "HITL events still preserve machine-readable audit evidence."]
      },
      denied: {
        title: "Blocked High-Risk Transfer",
        summary: "An agent proposes a transfer that fails combined policy and external risk review. Safe4 stops the action and returns an explicit denial reason instead of exposing the rail directly.",
        stack: [["Identity posture", "Known but untrusted context"], ["Receipt state", "Valid"], ["Risk provider", "Range Risk flagged wallet"], ["Outcome", "DENIED"]],
        scores: [["Amount", "$8,400.00"], ["Risk score", "High"], ["Decision", "Denied"], ["Trace", "Alert-worthy"]],
        events: [
          { title: "Request accepted", status: "blue", meta: { Route: "POST /pay", Agent: "agent_treasury", Vendor: "external_wallet" }, note: "The request reaches the control plane, but it is not allowed to jump straight to execution.", terminal: ["[accent]POST /pay[/accent] external_wallet transfer", "[comment]evaluating policy + risk[/comment]"] },
          { title: "Range Risk flagged", status: "red", meta: { Provider: "Range Risk", Flag: "Sanctions / wallet risk", Severity: "High" }, note: "External screening surfaced a high-risk condition that materially changes the decision path.", terminal: ["[accent]Range Risk[/accent] screening requested", "[bad]wallet risk flagged[/bad]"] },
          { title: "Policy denial returned", status: "red", meta: { Code: "PAYMENT_DENIED", Reason: "Risk policy", Audit: "Trace + anomaly preserved" }, note: "The transaction is denied with a concrete reason, and the investigation trail remains available for operators.", terminal: ["[bad]decision=DENIED[/bad]", "[comment]audit + anomaly evidence persisted[/comment]"] }
        ],
        points: ["External risk data can directly influence final authorization.", "Unsafe requests stop before touching settlement rails.", "The denial still produces evidence operators can investigate later."]
      }
    };
    const titleEl = document.getElementById("scenario-title");
    const summaryEl = document.getElementById("scenario-summary");
    const stackEl = document.getElementById("decision-stack");
    const scoreboardEl = document.getElementById("scoreboard");
    const eventListEl = document.getElementById("event-list");
    const terminalEl = document.getElementById("terminal");
    const eventStatusEl = document.getElementById("event-status");
    const eventMetaEl = document.getElementById("event-meta");
    const operatorNoteEl = document.getElementById("operator-note");
    const demoPointsEl = document.getElementById("demo-points");
    const liveHealthBadgeEl = document.getElementById("live-health-badge");
    const liveSignalStatusEl = document.getElementById("live-signal-status");
    const liveSignalsEl = document.getElementById("live-signals");
    const navItems = Array.from(document.querySelectorAll(".nav-item"));
    function renderKvRows(target, rows) {
      target.innerHTML = rows.map(([k, v]) => `<div class="kv-row"><span>${k}</span><strong>${v}</strong></div>`).join("");
    }
    async function loadLiveSignals() {
      try {
        const [healthResponse, discoveryResponse] = await Promise.all([
          fetch("/health", { headers: { "Accept": "application/json" } }),
          fetch("/.well-known/openid-configuration", { headers: { "Accept": "application/json" } }),
        ]);
        if (!healthResponse.ok || !discoveryResponse.ok) {
          throw new Error("live endpoint request failed");
        }
        const health = await healthResponse.json();
        const discovery = await discoveryResponse.json();
        const scopes = Array.isArray(discovery.scopes_supported) ? discovery.scopes_supported.length : 0;
        liveHealthBadgeEl.textContent = "Health: " + String(health.status || "unknown").toUpperCase();
        liveSignalStatusEl.className = "pill green";
        liveSignalStatusEl.textContent = "Live data connected";
        renderKvRows(liveSignalsEl, [
          ["Health status", String(health.status || "unknown")],
          ["Database", String(health.database || "unknown")],
          ["OAuth issuer", String(discovery.issuer || "n/a")],
          ["Auth endpoint", String(discovery.authorization_endpoint || "n/a")],
          ["Supported scopes", String(scopes)],
        ]);
      } catch (error) {
        liveHealthBadgeEl.textContent = "Health check unavailable";
        liveSignalStatusEl.className = "pill amber";
        liveSignalStatusEl.textContent = "Using page-local fallback";
        renderKvRows(liveSignalsEl, [
          ["Health status", "Unavailable"],
          ["Database", "Unavailable"],
          ["OAuth issuer", "Unavailable"],
          ["Reason", error instanceof Error ? error.message : "Unknown error"],
        ]);
      }
    }
    function terminalMarkup(lines) {
      return lines.map((line) => line
        .replace(/\\[good\\](.*?)\\[\\/good\\]/g, '<span class="good">$1</span>')
        .replace(/\\[warn\\](.*?)\\[\\/warn\\]/g, '<span class="warn">$1</span>')
        .replace(/\\[bad\\](.*?)\\[\\/bad\\]/g, '<span class="bad">$1</span>')
        .replace(/\\[accent\\](.*?)\\[\\/accent\\]/g, '<span class="accent">$1</span>')
        .replace(/\\[comment\\](.*?)\\[\\/comment\\]/g, '<span class="comment">$1</span>')).join("\\n");
    }
    function selectEvent(scenario, index) {
      const event = scenario.events[index];
      eventStatusEl.className = "pill " + event.status;
      eventStatusEl.textContent = event.title;
      operatorNoteEl.textContent = event.note;
      renderKvRows(eventMetaEl, Object.entries(event.meta));
      terminalEl.innerHTML = terminalMarkup(event.terminal);
      Array.from(eventListEl.children).forEach((child, childIndex) => child.classList.toggle("active", childIndex === index));
    }
    function renderScenario(name) {
      const scenario = scenarios[name];
      titleEl.textContent = scenario.title;
      summaryEl.textContent = scenario.summary;
      stackEl.innerHTML = scenario.stack.map(([label, value]) => `<div class="mini-row"><span>${label}</span><strong>${value}</strong></div>`).join("");
      scoreboardEl.innerHTML = scenario.scores.map(([label, value]) => `<div class="score"><div class="label">${label}</div><div class="value">${value}</div></div>`).join("");
      eventListEl.innerHTML = scenario.events.map((event, index) => `<button class="event${index === 0 ? " active" : ""}" type="button" data-index="${index}"><strong>${event.title}</strong><span>${event.note}</span></button>`).join("");
      demoPointsEl.innerHTML = scenario.points.map((point) => `<li>${point}</li>`).join("");
      Array.from(eventListEl.querySelectorAll(".event")).forEach((button) => button.addEventListener("click", () => selectEvent(scenario, Number(button.dataset.index))));
      navItems.forEach((item) => item.classList.toggle("active", item.dataset.scenario === name));
      selectEvent(scenario, 0);
    }
    navItems.forEach((item) => item.addEventListener("click", () => renderScenario(item.dataset.scenario)));
    renderScenario("authorized");
    loadLiveSignals();
  </script>
</body>
</html>
"""


@router.get("/demo/agent-security", response_class=HTMLResponse)
def agent_security_demo_page(
    access_token: str | None = Query(default=None),
    x_demo_access: str | None = Header(default=None, alias="X-Demo-Access"),
) -> HTMLResponse:
    _require_demo_access(access_token=access_token, x_demo_access=x_demo_access)
    return HTMLResponse(content=AGENT_SECURITY_HTML)


@router.get("/demo/console", response_class=HTMLResponse)
def console_demo_page(
    access_token: str | None = Query(default=None),
    x_demo_access: str | None = Header(default=None, alias="X-Demo-Access"),
) -> HTMLResponse:
    _require_demo_access(access_token=access_token, x_demo_access=x_demo_access)
    return HTMLResponse(content=CONSOLE_HTML)
