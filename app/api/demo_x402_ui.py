"""Judge-facing x402 authorization lab.

The browser flow is deliberately authorization-only. It exercises Safe4's
local ``/pay`` path and guarded signed-receipt fixture, but it never connects a
wallet, signs, broadcasts, or presents historical Arc evidence as a fresh
transaction.
"""

from __future__ import annotations


X402_DEMO_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="theme-color" content="#f5d90a" />
  <title>Safe4 | x402 Judge Lab</title>
  <style>
    :root {
      color-scheme: dark;
      --signal: #f5d90a;
      --signal-soft: rgba(245, 217, 10, 0.12);
      --bg: #070804;
      --panel: #10110b;
      --panel-2: #15170f;
      --ink: #fffdf0;
      --muted: #aaa78e;
      --line: rgba(245, 217, 10, 0.25);
      --line-soft: rgba(255, 255, 255, 0.09);
      --allow: #9df23c;
      --deny: #ff6554;
      --info: #77b7ff;
      --font: "Cascadia Mono", "SFMono-Regular", Consolas, monospace;
      --sans: Inter, "Segoe UI", Arial, sans-serif;
    }

    * { box-sizing: border-box; }
    html { background: var(--bg); }
    body {
      min-width: 320px;
      min-height: 100vh;
      margin: 0;
      color: var(--ink);
      background:
        linear-gradient(rgba(245, 217, 10, 0.026) 1px, transparent 1px),
        linear-gradient(90deg, rgba(245, 217, 10, 0.026) 1px, transparent 1px),
        radial-gradient(circle at 80% -20%, rgba(245, 217, 10, 0.09), transparent 34%),
        var(--bg);
      background-size: 40px 40px, 40px 40px, auto, auto;
      font-family: var(--font);
      font-size: 13px;
      line-height: 1.45;
    }

    button, textarea { font: inherit; }
    button { border-radius: 0; }
    a { color: inherit; }
    :focus-visible { outline: 2px solid var(--ink); outline-offset: 3px; }

    .topbar {
      position: sticky;
      top: 0;
      z-index: 20;
      display: grid;
      grid-template-columns: 1fr auto 1fr;
      align-items: center;
      min-height: 58px;
      padding: 8px clamp(16px, 3vw, 42px);
      color: #080900;
      background: var(--signal);
      border-bottom: 1px solid #080900;
    }
    .brand { display: flex; align-items: center; gap: 10px; font-size: 17px; font-weight: 900; }
    .brand-mark { width: 13px; height: 13px; background: currentColor; transform: rotate(45deg); }
    .top-status { display: flex; gap: 8px; align-items: center; font-size: 10px; font-weight: 800; letter-spacing: .08em; text-transform: uppercase; }
    .top-status span { padding: 6px 9px; border: 1px solid rgba(8, 9, 0, .35); }
    .connect-button {
      justify-self: end;
      min-width: 170px;
      padding: 10px 14px;
      color: var(--signal);
      background: #080900;
      border: 1px solid #080900;
      cursor: pointer;
      font-size: 10px;
      font-weight: 900;
      letter-spacing: .08em;
      text-transform: uppercase;
    }
    .connect-button.connected::before { content: "● "; }
    .connect-button:disabled { cursor: wait; opacity: .72; }

    main { width: min(1420px, calc(100% - 28px)); margin: 0 auto; padding: 22px 0 42px; }
    .intro {
      display: grid;
      grid-template-columns: 1.15fr .85fr;
      gap: 28px;
      align-items: end;
      margin-bottom: 20px;
    }
    .eyebrow, .label, .micro {
      color: var(--signal);
      font-size: 10px;
      font-weight: 800;
      letter-spacing: .12em;
      text-transform: uppercase;
    }
    .eyebrow::before { content: "[ "; }
    .eyebrow::after { content: " ]"; }
    h1 {
      margin: 6px 0 0;
      font-family: var(--sans);
      font-size: clamp(34px, 5vw, 68px);
      font-weight: 950;
      letter-spacing: -.065em;
      line-height: .92;
      text-transform: uppercase;
    }
    .intro-copy { margin: 0; padding-left: 16px; color: var(--muted); border-left: 1px solid var(--line); line-height: 1.65; }

    .scenario-grid { display: grid; grid-template-columns: repeat(6, minmax(0, 1fr)); gap: 8px; margin-bottom: 12px; }
    .scenario-card {
      min-height: 88px;
      padding: 12px;
      color: var(--muted);
      text-align: left;
      background: var(--panel);
      border: 1px solid var(--line-soft);
      cursor: pointer;
    }
    .scenario-card:hover { border-color: var(--line); color: var(--ink); }
    .scenario-card.active { color: var(--ink); background: var(--signal-soft); border-color: var(--signal); box-shadow: inset 0 -3px 0 var(--signal); }
    .scenario-card:disabled { cursor: wait; opacity: .68; }
    .scenario-index { display: block; margin-bottom: 8px; color: var(--signal); font-size: 10px; }
    .scenario-name { display: block; color: inherit; font-family: var(--sans); font-size: 13px; font-weight: 800; line-height: 1.15; }
    .scenario-outcome { display: block; margin-top: 7px; font-size: 10px; letter-spacing: .08em; text-transform: uppercase; }

    .workspace {
      display: grid;
      grid-template-columns: minmax(0, 1.06fr) minmax(420px, .94fr);
      border: 1px solid var(--signal);
      background: var(--panel);
      box-shadow: 10px 10px 0 rgba(245, 217, 10, .07);
    }
    .pane { min-width: 0; padding: 22px; }
    .pane + .pane { border-left: 1px solid var(--signal); }
    .pane-head { display: flex; justify-content: space-between; gap: 16px; align-items: start; margin-bottom: 14px; }
    .pane-head h2 { margin: 5px 0 0; font-family: var(--sans); font-size: 22px; letter-spacing: -.03em; }
    .connection-note { color: var(--muted); font-size: 10px; text-align: right; text-transform: uppercase; }
    .scenario-summary { max-width: 760px; margin: 0 0 14px; color: var(--muted); }

    .request-layout { display: grid; grid-template-columns: minmax(0, 1fr) minmax(260px, .66fr); gap: 14px; }
    .field { display: block; margin-bottom: 10px; }
    .field span { display: block; margin-bottom: 6px; }
    textarea {
      width: 100%;
      min-height: 64px;
      padding: 11px 12px;
      resize: vertical;
      color: var(--ink);
      background: #090a06;
      border: 1px solid var(--line-soft);
      outline: none;
      font-size: 11px;
      line-height: 1.5;
    }
    textarea:focus { border-color: var(--signal); }
    textarea:read-only { color: #c8c5ad; background: #0c0d08; }
    textarea:disabled { opacity: .7; }

    .facts, .money-grid, .evidence-grid { display: grid; gap: 8px; }
    .facts { grid-template-columns: repeat(2, minmax(0, 1fr)); margin-bottom: 10px; }
    .fact, .money, .evidence-item { padding: 10px; background: #0a0b07; border: 1px solid var(--line-soft); }
    .fact strong, .money strong, .evidence-item strong { display: block; margin-top: 4px; color: var(--ink); font-size: 11px; overflow-wrap: anywhere; }

    .legs { display: grid; gap: 6px; }
    .leg {
      display: grid;
      grid-template-columns: 26px 1fr auto;
      gap: 9px;
      align-items: center;
      padding: 9px 10px;
      background: #0a0b07;
      border: 1px solid var(--line-soft);
    }
    .leg-number { color: var(--signal); font-size: 10px; }
    .leg-title { font-family: var(--sans); font-size: 11px; font-weight: 750; }
    .leg-note { display: block; margin-top: 2px; color: var(--muted); font-size: 10px; }
    .leg-state { color: var(--muted); font-size: 10px; font-weight: 800; letter-spacing: .07em; text-transform: uppercase; }
    .leg[data-state="allowed"] .leg-state { color: var(--allow); }
    .leg[data-state="denied"] .leg-state { color: var(--deny); }
    .leg[data-state="running"] .leg-state { color: var(--signal); }

    .run-button {
      width: 100%;
      margin-top: 14px;
      padding: 13px 16px;
      color: #080900;
      background: var(--signal);
      border: 1px solid var(--signal);
      cursor: pointer;
      font-size: 10px;
      font-weight: 900;
      letter-spacing: .1em;
      text-transform: uppercase;
    }
    .run-button:hover:not(:disabled) { color: var(--signal); background: transparent; }
    .run-button:disabled { color: #685e25; background: #29260e; border-color: #51491b; cursor: not-allowed; }
    .error-line { min-height: 16px; margin: 8px 0 0; color: var(--deny); font-size: 10px; }

    .trace { display: grid; gap: 1px; background: var(--line-soft); border: 1px solid var(--line-soft); }
    .trace-step {
      display: grid;
      grid-template-columns: 28px 1fr auto;
      gap: 10px;
      align-items: center;
      min-height: 52px;
      padding: 9px 11px;
      background: #090a06;
    }
    .trace-number { color: var(--signal); font-size: 10px; }
    .trace-title { font-size: 10px; font-weight: 800; letter-spacing: .05em; text-transform: uppercase; }
    .trace-detail { display: block; max-width: 330px; margin-top: 3px; overflow: hidden; color: var(--muted); font-size: 10px; text-overflow: ellipsis; white-space: nowrap; }
    .trace-state { color: var(--muted); font-size: 10px; font-weight: 800; letter-spacing: .07em; text-transform: uppercase; }
    .trace-step[data-state="running"] .trace-state { color: var(--signal); }
    .trace-step[data-state="complete"] .trace-state { color: var(--allow); }
    .trace-step[data-state="denied"] .trace-state { color: var(--deny); }
    .trace-step[data-state="stopped"] .trace-state { color: var(--info); }

    .result { margin-top: 12px; padding: 15px; background: #090a06; border: 1px solid var(--line-soft); }
    .result-word {
      margin-top: 7px;
      font-family: var(--sans);
      font-size: clamp(38px, 4vw, 62px);
      font-weight: 950;
      letter-spacing: -.065em;
      line-height: .9;
      text-transform: uppercase;
    }
    .result[data-kind="allow"] .result-word { color: var(--allow); }
    .result[data-kind="deny"] .result-word { color: var(--deny); }
    .result[data-kind="control"] .result-word { color: var(--info); }
    .result[data-kind="error"] .result-word { color: var(--signal); }
    .reason-code { margin-top: 11px; font-size: 10px; font-weight: 800; letter-spacing: .06em; text-transform: uppercase; }
    .reason { margin: 5px 0 0; color: var(--muted); font-size: 10px; }

    .money-grid { grid-template-columns: repeat(3, minmax(0, 1fr)); margin-top: 10px; }
    .money strong { font-size: 16px; }
    .evidence-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); margin-top: 10px; }
    .evidence-item strong { font-size: 10px; }

    details { margin-top: 12px; padding: 10px 12px; background: #0a0b07; border: 1px solid var(--line-soft); }
    summary { color: var(--signal); cursor: pointer; font-size: 10px; font-weight: 800; letter-spacing: .08em; text-transform: uppercase; }
    .boundary { margin: 9px 0 0; color: var(--muted); font-size: 10px; }

    .evidence-lane {
      display: grid;
      grid-template-columns: 1fr auto auto;
      gap: 12px;
      align-items: center;
      margin-top: 12px;
      padding: 12px 14px;
      background: var(--panel-2);
      border: 1px solid var(--line-soft);
    }
    .evidence-lane p { margin: 3px 0 0; color: var(--muted); font-size: 10px; }
    .evidence-link { color: var(--signal); font-size: 10px; font-weight: 800; letter-spacing: .05em; text-underline-offset: 3px; text-transform: uppercase; }

    @media (max-width: 1080px) {
      .topbar { grid-template-columns: 1fr auto; }
      .top-status { display: none; }
      .scenario-grid { grid-template-columns: repeat(3, minmax(0, 1fr)); }
      .workspace { grid-template-columns: 1fr; }
      .pane + .pane { border-top: 1px solid var(--signal); border-left: 0; }
    }
    @media (max-width: 720px) {
      main { width: min(100% - 18px, 1420px); }
      .intro, .request-layout { grid-template-columns: 1fr; }
      .scenario-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .facts, .money-grid, .evidence-grid { grid-template-columns: 1fr; }
      .evidence-lane { grid-template-columns: 1fr; }
      .pane { padding: 16px; }
    }
  </style>
</head>
<body>
  <header class="topbar">
    <div class="brand"><span class="brand-mark" aria-hidden="true"></span>SAFE4</div>
    <div class="top-status" aria-label="Demo boundaries">
      <span>Local /pay live</span><span>Guarded receipt fixture</span><span>Browser broadcasts 0</span>
    </div>
    <button class="connect-button" id="connectButton" type="button">Connect demo agent</button>
  </header>

  <main>
    <section class="intro" aria-labelledby="pageTitle">
      <div><div class="eyebrow">x402 authorization lab for judges</div><h1 id="pageTitle">See every payment decision.</h1></div>
      <p class="intro-copy">Choose a transaction pattern. Safe4 exposes the HTTP 402 challenge, guarded proof, policy verdict, and the exact point where execution remains stopped.</p>
    </section>

    <nav class="scenario-grid" aria-label="Transaction scenarios">
      <button class="scenario-card active" type="button" data-scenario="single_allow" aria-pressed="true"><span class="scenario-index">01 / API</span><span class="scenario-name">Task-matched purchase</span><span class="scenario-outcome">Expected allow</span></button>
      <button class="scenario-card" type="button" data-scenario="batch_allow" aria-pressed="false"><span class="scenario-index">02 / FAN-OUT</span><span class="scenario-name">3-call agent batch</span><span class="scenario-outcome">Independent requests</span></button>
      <button class="scenario-card" type="button" data-scenario="intent_deny" aria-pressed="false"><span class="scenario-index">03 / INTENT</span><span class="scenario-name">Wrong purchase purpose</span><span class="scenario-outcome">Expected deny</span></button>
      <button class="scenario-card" type="button" data-scenario="scope_deny" aria-pressed="false"><span class="scenario-index">04 / AUTONOMY</span><span class="scenario-name">Scope cap exceeded</span><span class="scenario-outcome">Expected deny</span></button>
      <button class="scenario-card" type="button" data-scenario="receipt_replay" aria-pressed="false"><span class="scenario-index">05 / PROOF</span><span class="scenario-name">Used receipt replay</span><span class="scenario-outcome">Expected block</span></button>
      <button class="scenario-card" type="button" data-scenario="idempotent_retry" aria-pressed="false"><span class="scenario-index">06 / RETRY</span><span class="scenario-name">Idempotent duplicate</span><span class="scenario-outcome">Expected safe replay</span></button>
    </nav>

    <section class="workspace" aria-label="Safe4 x402 judge lab">
      <div class="pane">
        <div class="pane-head">
          <div><span class="label">01 / Proposed payment plan</span><h2 id="scenarioTitle">Task-matched API purchase</h2></div>
          <span class="connection-note" id="connectionNote">Agent disconnected</span>
        </div>
        <p class="scenario-summary" id="scenarioSummary"></p>
        <div class="request-layout">
          <div>
            <label class="field"><span class="micro">Submitted task context · request-supplied</span><textarea id="taskInput" rows="3"></textarea></label>
            <label class="field"><span class="micro">Proposed purchase purpose</span><textarea id="purposeInput" rows="3"></textarea></label>
            <div class="facts" aria-label="Request facts">
              <div class="fact"><span class="micro">Pattern</span><strong id="patternFact">Single fixed-price API call</strong></div>
              <div class="fact"><span class="micro">Proposed total</span><strong id="totalFact">0.010000 USDC</strong></div>
              <div class="fact"><span class="micro">Task trust</span><strong>Request-supplied / untrusted</strong></div>
              <div class="fact"><span class="micro">Settlement</span><strong>Not connected in browser</strong></div>
            </div>
          </div>
          <div>
            <span class="micro">Plan legs</span>
            <div class="legs" id="legList" aria-live="polite"></div>
          </div>
        </div>
        <button class="run-button" id="runButton" type="button" disabled>Connect agent to run scenario</button>
        <p class="error-line" id="errorLine" role="alert" aria-live="polite"></p>
      </div>

      <div class="pane">
        <div class="pane-head">
          <div><span class="label">02 / Observed decision</span><h2>What Safe4 did</h2></div>
          <span class="connection-note">Real local API responses</span>
        </div>
        <div class="trace" aria-label="Decision trace">
          <div class="trace-step" id="stepRequest" data-state="waiting"><span class="trace-number">01</span><span><span class="trace-title">Scoped request</span><span class="trace-detail">Choose a scenario</span></span><span class="trace-state">Waiting</span></div>
          <div class="trace-step" id="stepChallenge" data-state="waiting"><span class="trace-number">02</span><span><span class="trace-title">HTTP 402 + proof</span><span class="trace-detail">No challenge observed</span></span><span class="trace-state">Waiting</span></div>
          <div class="trace-step" id="stepPolicy" data-state="waiting"><span class="trace-number">03</span><span><span class="trace-title">Safe4 policy</span><span class="trace-detail">Intent, budget, scope, replay</span></span><span class="trace-state">Waiting</span></div>
          <div class="trace-step" id="stepExecution" data-state="stopped"><span class="trace-number">04</span><span><span class="trace-title">Execution boundary</span><span class="trace-detail">Browser has no wallet or executor</span></span><span class="trace-state">Stopped</span></div>
        </div>

        <div class="result" id="resultCard" data-kind="idle" aria-live="polite">
          <span class="micro">Policy verdict</span>
          <div class="result-word" id="resultWord">Ready</div>
          <div class="reason-code" id="reasonCode">CONNECT_AGENT</div>
          <p class="reason" id="reasonText">Connect the scoped demo agent, then run any predeclared scenario.</p>
        </div>

        <div class="money-grid" aria-label="Money movement boundary">
          <div class="money"><span class="micro" id="authorizationLabel">Local authorizations</span><strong id="authorizationCount">0</strong></div>
          <div class="money"><span class="micro">Browser broadcasts</span><strong>0</strong></div>
          <div class="money"><span class="micro">External executor</span><strong>Not connected</strong></div>
        </div>

        <div class="evidence-grid" id="evidenceGrid" aria-label="Sanitized observations"></div>
        <details><summary>Evidence boundary</summary><p class="boundary">This page runs Safe4's local <code>/pay</code> authorization path and a guarded signed-receipt fixture. It does not connect a wallet, sign, broadcast, RPC-verify, prove principal-bound intent, or demonstrate Circle Gateway settlement. Batch means independent requests, not atomic settlement.</p></details>
      </div>
    </section>

    <section class="evidence-lane" aria-label="Separate Arc evidence">
      <div><span class="label">Separate live Arc Testnet evidence</span><p>These links are prior Circle Agent Wallet transfers. Running the browser lab never creates another transaction.</p></div>
      <a class="evidence-link" href="https://testnet.arcscan.app/tx/0x9dedac01a941059342cb0f907a45f8b64478b3309327202db327afee4f12061d" target="_blank" rel="noreferrer noopener">Latest 0.01 USDC proof ↗</a>
      <a class="evidence-link" href="https://testnet.arcscan.app/tx/0xf9d665cf0eb663e33703826ca599d526718042781860faeec5e7ad089fde775d" target="_blank" rel="noreferrer noopener">Earlier 0.01 USDC proof ↗</a>
    </section>
  </main>

  <script>
    (() => {
      "use strict";

      const accessGate = new URLSearchParams(window.location.search).get("access_token") || "";
      const connectButton = document.getElementById("connectButton");
      const runButton = document.getElementById("runButton");
      const connectionNote = document.getElementById("connectionNote");
      const taskInput = document.getElementById("taskInput");
      const purposeInput = document.getElementById("purposeInput");
      const scenarioTitle = document.getElementById("scenarioTitle");
      const scenarioSummary = document.getElementById("scenarioSummary");
      const patternFact = document.getElementById("patternFact");
      const totalFact = document.getElementById("totalFact");
      const legList = document.getElementById("legList");
      const errorLine = document.getElementById("errorLine");
      const resultCard = document.getElementById("resultCard");
      const resultWord = document.getElementById("resultWord");
      const reasonCode = document.getElementById("reasonCode");
      const reasonText = document.getElementById("reasonText");
      const authorizationLabel = document.getElementById("authorizationLabel");
      const authorizationCount = document.getElementById("authorizationCount");
      const evidenceGrid = document.getElementById("evidenceGrid");
      const scenarioButtons = Array.from(document.querySelectorAll("[data-scenario]"));
      const steps = ["stepRequest", "stepChallenge", "stepPolicy", "stepExecution"].map((id) => document.getElementById(id));

      const item = (id, label, vendor, category, task, purpose, extra = {}) => ({
        id, label, vendor, category, task, purpose, amount: 0.01, ...extra,
      });
      const companyItem = () => item(
        "company-data", "Company data API", "demo_company_research_api", "company-research",
        "Research competitor pricing using a paid company data service.",
        "Generate a competitor pricing research brief from company data.",
      );

      const SCENARIOS = Object.freeze({
        single_allow: {
          title: "Task-matched API purchase",
          summary: "One fixed-price API request takes the complete 402 → guarded proof → /pay authorization path.",
          pattern: "Single fixed-price API call",
          mode: "single",
          expectedStatus: 200,
          expectedReason: "TASK_PURCHASE_MATCH",
          editable: true,
          items: [companyItem()],
        },
        batch_allow: {
          title: "Three-call agent fan-out",
          summary: "Three services are authorized sequentially. Each leg gets its own challenge, receipt fixture, idempotency key, and decision. This is not atomic multisend.",
          pattern: "3 independent x402-shaped calls",
          mode: "batch",
          expectedStatus: 200,
          expectedReason: "TASK_PURCHASE_MATCH",
          editable: false,
          items: [
            item("market-data", "Market data API", "demo_market_data_api", "market-data", "Monitor crypto market data and prices for the daily risk report.", "Purchase current crypto market data and prices for the daily risk report."),
            item("compute", "Hosted inference", "demo_compute_api", "compute", "Run hosted compute inference for the portfolio risk analysis.", "Purchase hosted compute inference for the portfolio risk analysis."),
            item("agent-memory", "Agent memory store", "demo_agent_memory", "agent-memory", "Store agent memory records for the customer support task.", "Purchase agent memory storage for the customer support task."),
          ],
        },
        intent_deny: {
          title: "Wrong purchase purpose",
          summary: "The amount and service category stay unchanged while the proposed purchase becomes unrelated to the submitted task.",
          pattern: "Intent mismatch control",
          mode: "single",
          expectedStatus: 403,
          expectedReason: "PURCHASE_PURPOSE_MISMATCH",
          editable: true,
          items: [{ ...companyItem(), purpose: "Purchase a gift card for an unrelated entertainment giveaway." }],
        },
        scope_deny: {
          title: "Autonomy scope exceeded",
          summary: "A matching purchase is denied because the presented max-cost scope is lower than the projected spend.",
          pattern: "Scope-of-autonomy control",
          mode: "single",
          expectedStatus: 403,
          expectedReason: "SCOPE_OF_AUTONOMY_MAX_COST_EXCEEDED",
          editable: false,
          items: [{ ...companyItem(), maxCost: 0.005 }],
        },
        receipt_replay: {
          title: "Used receipt replay",
          summary: "One request is authorized, then its already-used proof is presented for a different request and blocked.",
          pattern: "Receipt replay control",
          mode: "receipt_replay",
          expectedStatus: 402,
          expectedReason: "PAYMENT_RECEIPT_ALREADY_USED",
          editable: false,
          items: [companyItem()],
        },
        idempotent_retry: {
          title: "Idempotent duplicate retry",
          summary: "The exact authorized request is retried with the same UUIDv4 key. Safe4 returns the cached response without a second local spend decision.",
          pattern: "Identical request retry",
          mode: "idempotent_retry",
          expectedStatus: 200,
          expectedReason: "TASK_PURCHASE_MATCH",
          editable: false,
          items: [companyItem()],
        },
      });

      let selectedName = "single_allow";
      let bearerToken = "";
      let running = false;

      function setStep(index, state, detail, label) {
        const step = steps[index];
        step.dataset.state = state;
        step.querySelector(".trace-detail").textContent = detail;
        step.querySelector(".trace-state").textContent = label || state;
      }

      function setResult(kind, word, code, reason) {
        resultCard.dataset.kind = kind;
        resultWord.textContent = word;
        reasonCode.textContent = code;
        reasonText.textContent = reason;
      }

      function setEvidence(entries) {
        evidenceGrid.replaceChildren();
        entries.forEach(([label, value]) => {
          const cell = document.createElement("div");
          cell.className = "evidence-item";
          const key = document.createElement("span");
          key.className = "micro";
          key.textContent = label;
          const content = document.createElement("strong");
          content.textContent = String(value);
          cell.append(key, content);
          evidenceGrid.appendChild(cell);
        });
      }

      function renderLegs(scenario) {
        legList.replaceChildren();
        scenario.items.forEach((entry, index) => {
          const row = document.createElement("div");
          row.className = "leg";
          row.dataset.legId = entry.id;
          row.dataset.state = "ready";
          const number = document.createElement("span");
          number.className = "leg-number";
          number.textContent = String(index + 1).padStart(2, "0");
          const copy = document.createElement("span");
          const title = document.createElement("span");
          title.className = "leg-title";
          title.textContent = entry.label;
          const note = document.createElement("span");
          note.className = "leg-note";
          note.textContent = `${entry.category} · ${entry.amount.toFixed(2)} USDC`;
          copy.append(title, note);
          const state = document.createElement("span");
          state.className = "leg-state";
          state.textContent = "Ready";
          row.append(number, copy, state);
          legList.appendChild(row);
        });
      }

      function setLegState(id, state, label) {
        const row = legList.querySelector(`[data-leg-id="${id}"]`);
        if (!row) return;
        row.dataset.state = state;
        row.querySelector(".leg-state").textContent = label;
      }

      function selectScenario(name) {
        if (running || !SCENARIOS[name]) return;
        selectedName = name;
        const scenario = SCENARIOS[name];
        const first = scenario.items[0];
        scenarioTitle.textContent = scenario.title;
        scenarioSummary.textContent = scenario.summary;
        patternFact.textContent = scenario.pattern;
        totalFact.textContent = `${scenario.items.reduce((total, entry) => total + entry.amount, 0).toFixed(6)} USDC`;
        taskInput.value = first.task;
        purposeInput.value = first.purpose;
        taskInput.readOnly = !scenario.editable;
        purposeInput.readOnly = !scenario.editable;
        renderLegs(scenario);
        scenarioButtons.forEach((button) => {
          const selected = button.dataset.scenario === name;
          button.classList.toggle("active", selected);
          button.setAttribute("aria-pressed", selected ? "true" : "false");
        });
        setStep(0, "complete", `${scenario.items.length} predeclared request${scenario.items.length === 1 ? "" : "s"}`, "Ready");
        setStep(1, "waiting", "No challenge observed", "Waiting");
        setStep(2, "waiting", "Policy has not run", "Waiting");
        setStep(3, "stopped", "Browser has no wallet or executor", "Stopped");
        setResult("idle", "Ready", scenario.expectedReason, "Run the selected scenario to observe the actual local API result.");
        authorizationLabel.textContent = "Local authorizations";
        authorizationCount.textContent = "0";
        setEvidence([["Evidence class", "Local authorization"], ["External settlement", "Not invoked"]]);
        errorLine.textContent = "";
      }

      function base64Url(bytes) {
        let binary = "";
        new Uint8Array(bytes).forEach((value) => { binary += String.fromCharCode(value); });
        return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
      }

      function uuid4() {
        if (window.crypto && typeof window.crypto.randomUUID === "function") return window.crypto.randomUUID();
        const values = window.crypto.getRandomValues(new Uint8Array(16));
        values[6] = (values[6] & 0x0f) | 0x40;
        values[8] = (values[8] & 0x3f) | 0x80;
        const hex = Array.from(values, (value) => value.toString(16).padStart(2, "0")).join("");
        return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
      }

      async function parseResponse(response) {
        const text = await response.text();
        let body = {};
        if (text) {
          try { body = JSON.parse(text); } catch (_error) { body = { message: text }; }
        }
        return { response, body };
      }

      function canonicalJson(value) {
        if (Array.isArray(value)) return value.map((entry) => canonicalJson(entry));
        if (value && typeof value === "object") {
          return Object.keys(value).sort().reduce((result, key) => {
            result[key] = canonicalJson(value[key]);
            return result;
          }, {});
        }
        return value;
      }

      function apiError(result, fallback) {
        const detail = result.body && result.body.detail;
        if (typeof detail === "string") return detail;
        if (detail && typeof detail.code === "string") return detail.code;
        if (typeof result.body.message === "string") return result.body.message;
        if (typeof result.body.code === "string") return result.body.code;
        return fallback;
      }

      async function connectAgent() {
        if (bearerToken || running) return;
        connectButton.disabled = true;
        connectButton.textContent = "Connecting...";
        errorLine.textContent = "";
        try {
          if (!window.crypto || !window.crypto.subtle) throw new Error("This demo requires a secure localhost browser context.");
          const random = window.crypto.getRandomValues(new Uint8Array(32));
          const verifier = base64Url(random);
          const digest = await window.crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
          const redirectUri = "https://localhost/callback";
          const authorization = await parseResponse(await fetch("/oauth/authorize", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              client_id: "dev-public-client", redirect_uri: redirectUri,
              scope: "payment:authorize audit:read", code_challenge: base64Url(digest),
              code_challenge_method: "S256", subject: "safe4_demo_operator", agent_id: "agent_alpha",
            }),
          }));
          if (!authorization.response.ok) throw new Error(apiError(authorization, "Could not create the scoped agent session."));
          const tokenResult = await parseResponse(await fetch("/oauth/token", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              grant_type: "authorization_code", client_id: "dev-public-client",
              code: authorization.body.code, redirect_uri: redirectUri, code_verifier: verifier,
            }),
          }));
          if (!tokenResult.response.ok || !tokenResult.body.access_token) throw new Error(apiError(tokenResult, "Could not exchange the PKCE code."));
          const candidateToken = tokenResult.body.access_token;
          const capabilities = await parseResponse(await fetch("/x402/capabilities", { headers: { Authorization: `Bearer ${candidateToken}` } }));
          const networks = Array.isArray(capabilities.body.supported_networks) ? capabilities.body.supported_networks : [];
          if (!capabilities.response.ok || !capabilities.body.enabled || !networks.includes("arc-testnet")) throw new Error("The local Arc-configured x402 scaffold is not enabled.");
          bearerToken = candidateToken;
          connectButton.textContent = "Agent connected";
          connectButton.classList.add("connected");
          connectionNote.textContent = "Scoped session active";
          runButton.disabled = false;
          runButton.textContent = "Run selected scenario →";
          setResult("idle", "Ready", "SCOPED_SESSION_ACTIVE", "The agent can call /pay and read x402 capability metadata.");
        } catch (error) {
          bearerToken = "";
          connectButton.textContent = "Retry connection";
          const message = error instanceof Error ? error.message : "Connection failed.";
          errorLine.textContent = message;
          setResult("error", "Offline", "CONNECTION_FAILED", message);
        } finally {
          connectButton.disabled = false;
        }
      }

      function materializeItem(entry, scenario, index) {
        if (index !== 0 || !scenario.editable) return { ...entry };
        return { ...entry, task: taskInput.value.trim(), purpose: purposeInput.value.trim() };
      }

      function paymentPayload(entry) {
        const payload = {
          agent_id: "agent_alpha",
          user_id: "user_123",
          vendor: entry.vendor,
          amount: entry.amount,
          currency: "USDC",
          description: entry.purpose,
          context: {
            payment_intent: {
              task_id: `judge_demo_${entry.id}`,
              task: entry.task,
              allowed_service_categories: [entry.category],
              service_category: entry.category,
              purchase_purpose: entry.purpose,
            },
          },
        };
        if (typeof entry.maxCost === "number") payload.scope_of_autonomy = { max_cost: entry.maxCost };
        return payload;
      }

      async function postPay(payload, options = {}) {
        const headers = { Authorization: `Bearer ${bearerToken}`, "Content-Type": "application/json" };
        if (options.receiptToken) headers["X-Payment-Receipt"] = options.receiptToken;
        if (options.idempotencyKey) headers["Idempotency-Key"] = options.idempotencyKey;
        return parseResponse(await fetch("/pay", { method: "POST", headers, body: JSON.stringify(payload) }));
      }

      async function preparePayment(payload) {
        const first = await postPay(payload);
        const details = first.body.details || {};
        const challenge = details.x402_challenge;
        if (first.response.status !== 402 || !challenge) throw new Error(apiError(first, "Safe4 did not return the expected x402 challenge."));
        if (challenge.status !== "scaffolded" || challenge.settlement_method !== "signed_receipt_fallback" || challenge.currency !== "USDC") throw new Error("The runtime returned an unsupported demo settlement mode.");
        const receipt = await parseResponse(await fetch("/demo/x402/receipt", {
          method: "POST",
          headers: { Authorization: `Bearer ${bearerToken}`, "Content-Type": "application/json", "X-Demo-Access": accessGate },
          body: JSON.stringify({ amount_due: challenge.amount, currency: challenge.currency, pay_to: details.pay_to }),
        }));
        if (!receipt.response.ok || !receipt.body.receipt_token) throw new Error(apiError(receipt, "The guarded demo receipt could not be created."));
        if (receipt.body.broadcast !== false || receipt.body.rpc_verified !== false || receipt.body.receipt_mode !== "signed_receipt_fallback") throw new Error("The receipt fixture returned an unsafe or ambiguous state.");
        return { payload, challenge, receiptToken: receipt.body.receipt_token };
      }

      async function finalizePayment(prepared, idempotencyKey) {
        return postPay(prepared.payload, { receiptToken: prepared.receiptToken, idempotencyKey });
      }

      function observation(result) {
        if (result.response.status === 200 && result.body.status === "AUTHORIZED") {
          const decision = result.body.intent_decision || {};
          return { status: 200, allowed: true, code: decision.reason_code || "AUTHORIZED", reason: decision.reason || "Authorized", decision };
        }
        const nested = ((result.body.details || {}).intent_decision || {});
        return {
          status: result.response.status,
          allowed: false,
          code: nested.reason_code || result.body.code || "REQUEST_REJECTED",
          reason: nested.reason || result.body.message || apiError(result, "Request rejected"),
          decision: nested,
        };
      }

      function requireObservation(observed, scenario) {
        if (observed.status !== scenario.expectedStatus || observed.code !== scenario.expectedReason) {
          throw new Error(`Expected ${scenario.expectedStatus} ${scenario.expectedReason}; observed ${observed.status} ${observed.code}.`);
        }
      }

      async function runSingle(scenario, entries) {
        const prepared = await preparePayment(paymentPayload(entries[0]));
        setStep(1, "complete", `402 → ${prepared.challenge.amount} USDC guarded receipt`, "Complete");
        setStep(2, "running", "Evaluating intent, budget, scope, and replay controls", "Running");
        const final = await finalizePayment(prepared, uuid4());
        const observed = observation(final);
        requireObservation(observed, scenario);
        setLegState(entries[0].id, observed.allowed ? "allowed" : "denied", observed.allowed ? "Allowed" : "Denied");
        setStep(2, observed.allowed ? "complete" : "denied", observed.code, observed.allowed ? "Allowed" : "Denied");
        setStep(3, "stopped", "Authorization only · browser made no broadcast", "0 broadcasts");
        authorizationCount.textContent = observed.allowed ? "1" : "0";
        const matched = Array.isArray(observed.decision.matched_concepts) ? observed.decision.matched_concepts.join(", ") : "Not exposed for this control";
        setEvidence([["HTTP trace", `402 → ${observed.status}`], ["Reason code", observed.code], ["Matched concepts", matched || "None"], ["Task trust", observed.decision.task_context_trust || "request-supplied-untrusted"]]);
        setResult(observed.allowed ? "allow" : "deny", observed.allowed ? "Allow" : "Deny", observed.code, observed.reason);
      }

      async function runBatch(scenario, entries) {
        const observations = [];
        for (let index = 0; index < entries.length; index += 1) {
          const entry = entries[index];
          setLegState(entry.id, "running", "Running");
          setStep(1, "running", `Challenge ${index + 1}/${entries.length}`, "Running");
          const prepared = await preparePayment(paymentPayload(entry));
          setStep(2, "running", `Policy ${index + 1}/${entries.length}`, "Running");
          const final = await finalizePayment(prepared, uuid4());
          const observed = observation(final);
          if (observed.status !== 200 || observed.code !== "TASK_PURCHASE_MATCH") throw new Error(`Batch leg ${entry.id} failed with ${observed.status} ${observed.code}.`);
          observations.push(observed);
          setLegState(entry.id, "allowed", "Allowed");
        }
        setStep(1, "complete", `${entries.length} independent 402 challenges satisfied`, "Complete");
        setStep(2, "complete", `${entries.length}/${entries.length} independent requests allowed`, "Allowed");
        setStep(3, "stopped", "No atomic batch and no browser settlement", "0 broadcasts");
        authorizationCount.textContent = String(observations.length);
        setEvidence([["HTTP trace", "402→200 × 3"], ["Batch semantics", "Sequential / non-atomic"], ["Service types", "Data, compute, memory"], ["External settlement", "Not invoked"]]);
        setResult("allow", "3 Allowed", "INDEPENDENT_AUTHORIZATIONS", "Safe4 authorized all three predeclared requests independently. This is not an atomic multisend or Gateway batch.");
      }

      async function runReceiptReplay(scenario, entries) {
        const firstEntry = entries[0];
        setLegState(firstEntry.id, "running", "Running");
        const prepared = await preparePayment(paymentPayload(firstEntry));
        setStep(1, "complete", "One guarded receipt issued", "Complete");
        const first = observation(await finalizePayment(prepared, uuid4()));
        if (first.status !== 200) throw new Error(`Initial authorization failed with ${first.status} ${first.code}.`);
        const replayEntry = { ...firstEntry, id: "replay-target", purpose: "Purchase a different company dataset for an unrelated request." };
        const replay = observation(await postPay(paymentPayload(replayEntry), { receiptToken: prepared.receiptToken, idempotencyKey: uuid4() }));
        requireObservation(replay, scenario);
        setLegState(firstEntry.id, "denied", "Replay blocked");
        setStep(2, "denied", replay.code, "Blocked");
        setStep(3, "stopped", "Used proof never reached an external executor", "0 broadcasts");
        authorizationCount.textContent = "1";
        setEvidence([["HTTP trace", "402 → 200 → 402"], ["Replay result", replay.code], ["Receipt token", "Held in memory / never displayed"], ["External settlement", "Not invoked"]]);
        setResult("control", "Blocked", replay.code, "The first request was authorized locally; reuse of its consumed proof for a different request was rejected.");
      }

      async function runIdempotentRetry(scenario, entries) {
        const entry = entries[0];
        setLegState(entry.id, "running", "Running");
        const prepared = await preparePayment(paymentPayload(entry));
        setStep(1, "complete", "Guarded receipt issued once", "Complete");
        const key = uuid4();
        const first = await finalizePayment(prepared, key);
        const second = await finalizePayment(prepared, key);
        const firstObserved = observation(first);
        const secondObserved = observation(second);
        const responsesMatch = JSON.stringify(canonicalJson(first.body)) === JSON.stringify(canonicalJson(second.body));
        if (firstObserved.status !== 200 || secondObserved.status !== 200 || !responsesMatch) throw new Error("The idempotent retry did not return the identical authorized response.");
        setLegState(entry.id, "allowed", "Safe retry");
        setStep(2, "complete", "Same UUIDv4 key returned the cached response", "Replay safe");
        setStep(3, "stopped", "Local response replay only · no external executor", "0 broadcasts");
        authorizationLabel.textContent = "Observed responses";
        authorizationCount.textContent = "200 + cached 200";
        setEvidence([["HTTP trace", "402 → 200 → cached 200"], ["Response bodies", "Semantically identical"], ["Observed server code", firstObserved.code], ["Write-count evidence", "Regression test: one local write"], ["External guarantee", "Not exactly-once settlement"]]);
        setResult("control", "Safe Retry", `OBSERVED: ${firstObserved.code}`, "The identical second body is the visible cache signal. A separate regression test verifies one local budget/log write; this screen does not query that count.");
      }

      async function runScenario() {
        if (!bearerToken || running) return;
        const scenario = SCENARIOS[selectedName];
        if (!taskInput.value.trim() || !purposeInput.value.trim()) { errorLine.textContent = "Task and purchase purpose are required."; return; }
        const entries = scenario.items.map((entry, index) => materializeItem(entry, scenario, index));
        running = true;
        runButton.disabled = true;
        taskInput.disabled = true;
        purposeInput.disabled = true;
        scenarioButtons.forEach((button) => { button.disabled = true; });
        errorLine.textContent = "";
        runButton.textContent = "Running observed API flow...";
        setStep(0, "complete", `${entries.length} scoped request${entries.length === 1 ? "" : "s"}`, "Complete");
        setStep(1, "running", "Calling /pay without payment proof", "Running");
        setStep(2, "waiting", "Waiting for guarded proof", "Waiting");
        setStep(3, "stopped", "Browser has no wallet or executor", "Stopped");
        setResult("idle", "Checking", "REQUEST_IN_FLIGHT", "Safe4 is evaluating the selected scenario.");
        try {
          if (scenario.mode === "batch") await runBatch(scenario, entries);
          else if (scenario.mode === "receipt_replay") await runReceiptReplay(scenario, entries);
          else if (scenario.mode === "idempotent_retry") await runIdempotentRetry(scenario, entries);
          else await runSingle(scenario, entries);
        } catch (error) {
          const message = error instanceof Error ? error.message : "The demo scenario failed.";
          errorLine.textContent = message;
          setResult("error", "Error", "DEMO_SCENARIO_FAILED", message);
          const active = steps.findIndex((step) => step.dataset.state === "running");
          if (active >= 0) setStep(active, "denied", message, "Failed");
          setStep(3, "stopped", "No browser transaction broadcast", "0 broadcasts");
        } finally {
          running = false;
          taskInput.disabled = false;
          purposeInput.disabled = false;
          scenarioButtons.forEach((button) => { button.disabled = false; });
          runButton.disabled = !bearerToken;
          runButton.textContent = "Run selected scenario →";
        }
      }

      scenarioButtons.forEach((button) => button.addEventListener("click", () => selectScenario(button.dataset.scenario)));
      connectButton.addEventListener("click", connectAgent);
      runButton.addEventListener("click", runScenario);
      selectScenario(selectedName);
    })();
  </script>
</body>
</html>
"""
