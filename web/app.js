"use strict";

const elements = {
  systemPill: document.querySelector("#system-pill"),
  systemStatus: document.querySelector("#system-status"),
  runDemo: document.querySelector("#run-demo"),
  resetDemo: document.querySelector("#reset-demo"),
  simulationPanel: document.querySelector("#simulation"),
  demoStatus: document.querySelector("#demo-status"),
  demoSession: document.querySelector("#demo-session"),
  demoStepCount: document.querySelector("#demo-step-count"),
  demoProgress: document.querySelector("#demo-progress"),
  demoTimeline: document.querySelector("#demo-timeline"),
  metricBlocked: document.querySelector("#metric-blocked"),
  metricInspected: document.querySelector("#metric-inspected"),
  metricAllowed: document.querySelector("#metric-allowed"),
  metricIntegrity: document.querySelector("#metric-integrity"),
  metricHead: document.querySelector("#metric-head"),
  criticalCount: document.querySelector("#critical-count"),
  findingCount: document.querySelector("#finding-count"),
  scanMeta: document.querySelector("#scan-meta"),
  findingList: document.querySelector("#finding-list"),
  chainStatus: document.querySelector("#chain-status"),
  auditSequence: document.querySelector("#audit-sequence"),
  auditPolicy: document.querySelector("#audit-policy"),
  auditSession: document.querySelector("#audit-session"),
  auditDecision: document.querySelector("#audit-decision"),
  auditList: document.querySelector("#audit-list"),
  modeChip: document.querySelector("#mode-chip"),
  policyDigest: document.querySelector("#policy-digest"),
  policyCommands: document.querySelector("#policy-commands"),
  taintedSessions: document.querySelector("#tainted-sessions"),
  footerVersion: document.querySelector("#footer-version"),
  toast: document.querySelector("#toast")
};

let toastTimer = null;
let refreshInFlight = false;

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function safeClass(value) {
  return String(value ?? "unknown").toLowerCase().replace(/[^a-z-]/g, "");
}

function setText(element, value) {
  const next = String(value ?? "");
  if (element.textContent !== next) element.textContent = next;
}

function setHtml(element, html) {
  if (element.innerHTML !== html) element.innerHTML = html;
}

function syncList(container, tagName, items, keyOf, renderItem) {
  const entries = items.map((item, index) => ({ item, key: String(keyOf(item, index)) }));
  const existing = new Map();
  for (const child of Array.from(container.children)) {
    const key = child.dataset ? child.dataset.key : undefined;
    if (key === undefined) {
      child.remove();
      continue;
    }
    existing.set(key, child);
  }
  let anchor = null;
  for (const entry of entries) {
    let node = existing.get(entry.key);
    const html = renderItem(entry.item);
    if (!node) {
      node = document.createElement(tagName);
      node.dataset.key = entry.key;
      node.innerHTML = html;
    } else if (node.innerHTML !== html) {
      node.innerHTML = html;
    }
    const expected = anchor ? anchor.nextSibling : container.firstChild;
    if (expected !== node) container.insertBefore(node, expected);
    anchor = node;
  }
  const keys = new Set(entries.map((entry) => entry.key));
  for (const [key, node] of existing) {
    if (!keys.has(key)) node.remove();
  }
}

function shortHash(value, length = 12) {
  const text = String(value ?? "");
  return text.length > length ? `${text.slice(0, length)}…` : text || "—";
}

function formatTime(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return new Intl.DateTimeFormat(undefined, {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false
  }).format(date);
}

function statusLabel(status) {
  const labels = {
    idle: "Ready for simulation",
    running: "Enforcement trace in progress",
    complete: "Attack contained and audit sealed",
    error: "Simulation halted"
  };
  return labels[status] || "Ready for simulation";
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    cache: "no-store",
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({ error: `HTTP ${response.status}` }));
    throw new Error(body.error || `HTTP ${response.status}`);
  }
  return response.json();
}

function showToast(message, error = false) {
  window.clearTimeout(toastTimer);
  elements.toast.textContent = message;
  elements.toast.classList.toggle("error", error);
  elements.toast.classList.add("visible");
  toastTimer = window.setTimeout(() => elements.toast.classList.remove("visible"), 3200);
}

function setConnection(connected) {
  elements.systemPill.classList.toggle("offline", !connected);
  elements.systemStatus.textContent = connected ? "Policy engine online" : "Engine unavailable";
}

function renderState(state) {
  const audit = state.audit || {};
  const policy = state.policy || {};
  const demo = state.demo || {};
  const valid = audit.valid === true;

  setText(elements.systemStatus, `${String(policy.mode || "enforce").toUpperCase()} mode active`);
  setText(elements.metricBlocked, audit.blocked || 0);
  setText(elements.metricInspected, audit.records || 0);
  setText(elements.metricAllowed, audit.allowed || 0);
  setText(elements.metricIntegrity, valid ? "VERIFIED" : audit.records ? "INVALID" : "PENDING");
  setText(elements.metricHead, audit.head?.mac ? `HEAD ${shortHash(audit.head.mac, 14)}` : "No audit head");
  setText(elements.modeChip, String(policy.mode || "enforce").toUpperCase());
  setText(elements.policyDigest, `${policy.version || "—"} · ${shortHash(policy.digest || "unavailable", 12)}`);
  setText(elements.policyCommands, policy.allowed_command_profiles || 0);
  setText(elements.taintedSessions, state.sessions?.tainted || 0);
  setText(elements.footerVersion, `v${state.version || "0.1.0"}`);

  elements.chainStatus.classList.toggle("valid", valid && Boolean(audit.records));
  elements.chainStatus.classList.toggle("invalid", !valid && Boolean(audit.records));
  setHtml(elements.chainStatus, `<span></span> ${valid && audit.records ? "Chain verified" : !valid && audit.records ? "Chain invalid" : "Chain pending"}`);

  const status = demo.status || "idle";
  const running = status === "running";
  const failed = status === "error";
  elements.runDemo.disabled = running;
  elements.resetDemo.disabled = false;
  setText(
    elements.runDemo.querySelector("span"),
    running
      ? "Simulation running"
      : failed
        ? "Retry simulation"
        : status === "complete"
          ? "Run simulation again"
          : "Run live attack simulation"
  );
  setText(elements.demoStatus, failed && demo.error ? `${statusLabel(status)} · ${demo.error}` : statusLabel(status));
  setText(elements.demoSession, demo.session_id ? `Session ${demo.session_id}` : "No active demo session");
  setText(elements.demoStepCount, `${demo.current_step || 0} / ${demo.total_steps || 8}`);
  const progress = Number(demo.current_step || 0);
  if (elements.demoProgress.value !== progress) elements.demoProgress.value = progress;
  setText(elements.demoProgress, `${Math.round((progress / Number(demo.total_steps || 8)) * 100)}%`);
  renderDemo(demo);
}

function renderDemo(demo) {
  const steps = Array.isArray(demo.steps) ? demo.steps : [];
  if (!steps.length) {
    if (demo.status === "error") {
      setHtml(elements.demoTimeline, `
        <li class="timeline-empty">
          <div class="empty-shield">
            <svg viewBox="0 0 32 38" aria-hidden="true"><path d="M16 1 29 6v10c0 9.7-5.2 16.7-13 21C8.2 32.7 3 25.7 3 16V6L16 1Z"></path><path d="M11 12l10 8M21 12l-10 8"></path></svg>
          </div>
          <strong>Trace halted at step ${escapeHtml(demo.failed_step || 1)} of ${escapeHtml(demo.total_steps || 8)}</strong>
          <span>${escapeHtml(demo.error || "The enforcement engine returned an unexpected error.")}</span>
        </li>`);
      return;
    }
    setHtml(elements.demoTimeline, `
      <li class="timeline-empty">
        <div class="empty-shield">
          <svg viewBox="0 0 32 38" aria-hidden="true"><path d="M16 1 29 6v10c0 9.7-5.2 16.7-13 21C8.2 32.7 3 25.7 3 16V6L16 1Z"></path><path d="m12 16 3 3 6-7"></path></svg>
        </div>
        <strong>Run the simulation to inspect the full decision trail</strong>
        <span>Safe repository work continues while high-impact actions are denied.</span>
      </li>`);
    return;
  }
  syncList(elements.demoTimeline, "li", steps, (step) => step.index, (step) => {
    const outcome = safeClass(step.outcome);
    const marker = outcome === "block" ? "X" : outcome === "allow" ? "A" : "O";
    return `
      <span class="timeline-marker">${marker}</span>
      <div class="timeline-copy">
        <strong>${escapeHtml(step.title)}</strong>
        <span>${escapeHtml(step.detail)}</span>
      </div>
      <div class="timeline-result">
        <code>${escapeHtml(String(step.outcome || "observe").toUpperCase())}</code>
        <small>${escapeHtml(step.rule_id || "—")}</small>
      </div>`;
  });
  for (const node of elements.demoTimeline.children) {
    const step = steps.find((entry) => String(entry.index) === node.dataset.key);
    if (!step) continue;
    const outcome = safeClass(step.outcome);
    const className = `timeline-item ${outcome}`;
    if (node.className !== className) node.className = className;
  }
}

function renderFindings(scan) {
  const findings = Array.isArray(scan.findings) ? scan.findings : [];
  const counts = scan.counts || {};
  setText(elements.criticalCount, counts.critical || 0);
  setText(elements.findingCount, `${findings.length} finding${findings.length === 1 ? "" : "s"}`);
  setText(
    elements.scanMeta,
    `${scan.files_scanned || 0} files · ${Math.max(1, Math.round((scan.bytes_scanned || 0) / 1024))} KB scanned${scan.truncated ? " · bounded" : ""}`
  );
  if (!findings.length) {
    setHtml(elements.findingList, `<div class="audit-empty">No instruction or supply-chain findings in the selected repository.</div>`);
    return;
  }
  const visible = findings.slice(0, 14);
  syncList(elements.findingList, "div", visible, (finding, index) => `${index}:${finding.rule_id}:${finding.source}`, (finding) => {
    const severity = safeClass(finding.severity);
    const location = finding.line ? `${finding.source}:${finding.line}` : finding.source;
    return `
      <span class="finding-severity"></span>
      <div class="finding-copy">
        <strong>${escapeHtml(finding.title)}</strong>
        <span>${escapeHtml(location)} · ${escapeHtml(finding.evidence)}</span>
      </div>
      <code>${escapeHtml(finding.rule_id)}</code>`;
  });
  for (const node of elements.findingList.children) {
    const finding = visible[Number(String(node.dataset.key).split(":")[0])];
    if (!finding) continue;
    const className = `finding ${safeClass(finding.severity)}`;
    if (node.className !== className) node.className = className;
  }
}

function renderAudit(payload) {
  const events = Array.isArray(payload.events) ? payload.events : [];
  const verification = payload.verification || {};
  const latest = events[events.length - 1];
  const valid = verification.valid === true;

  elements.chainStatus.classList.toggle("valid", valid && events.length > 0);
  elements.chainStatus.classList.toggle("invalid", !valid && events.length > 0);
  setHtml(elements.chainStatus, `<span></span> ${valid && events.length ? "Chain verified" : !valid && events.length ? "Chain invalid" : "Chain pending"}`);
  setText(elements.auditSequence, latest ? String(latest.sequence).padStart(4, "0") : "0000");
  setText(elements.auditPolicy, latest?.policy_version || "—");
  setText(elements.auditSession, latest?.session ? shortHash(latest.session, 10) : "—");
  setText(elements.auditDecision, latest?.decision?.toUpperCase() || "—");

  if (!events.length) {
    setHtml(elements.auditList, `<div class="audit-empty">No enforcement events yet. Run the simulation or submit a Bob action.</div>`);
    return;
  }
  const visible = events.slice(-14).reverse();
  syncList(elements.auditList, "div", visible, (event) => event.sequence, (event) => `
      <span class="audit-sequence">#${String(event.sequence).padStart(4, "0")}</span>
      <span class="audit-event">${escapeHtml(event.event)}</span>
      <span class="audit-target" title="${escapeHtml(event.target)}">${escapeHtml(event.target || event.reason)}</span>
      <span class="audit-rule">${escapeHtml(event.rule_id)}</span>
      <span class="audit-decision-pill">${escapeHtml(String(event.decision || "").toUpperCase())}</span>`);
  for (const node of elements.auditList.children) {
    const event = visible.find((entry) => String(entry.sequence) === node.dataset.key);
    if (!event) continue;
    const className = `audit-row ${safeClass(event.decision)}`;
    if (node.className !== className) node.className = className;
  }
}

let lastScanAt = 0;

async function refresh(options = {}) {
  if (refreshInFlight) return;
  refreshInFlight = true;
  try {
    const now = Date.now();
    const scanDue = options.forceScan === true || now - lastScanAt >= 10000;
    const [state, audit, scan] = await Promise.all([
      api("/api/state"),
      api("/api/audit?limit=100"),
      scanDue ? api("/api/findings?path=demo%2Fpoisoned_repo") : Promise.resolve(null)
    ]);
    setConnection(true);
    renderState(state);
    renderAudit(audit);
    if (scan) {
      lastScanAt = Date.now();
      renderFindings(scan);
    }
  } catch (error) {
    setConnection(false);
    showToast(`Unable to refresh enforcement state: ${error.message}`, true);
  } finally {
    refreshInFlight = false;
  }
}

async function runDemo() {
  elements.runDemo.disabled = true;
  try {
    const demo = await api("/api/demo", { method: "POST", body: "{}" });
    renderDemo(demo);
    if (elements.simulationPanel && typeof elements.simulationPanel.scrollIntoView === "function") {
      elements.simulationPanel.scrollIntoView({ behavior: "smooth", block: "center" });
    }
    showToast("Live enforcement simulation started");
    await refresh();
  } catch (error) {
    elements.runDemo.disabled = false;
    showToast(`Could not start simulation: ${error.message}`, true);
  }
}

async function resetDemo() {
  if (!window.confirm("Reset the local audit chain and simulation state?")) return;
  try {
    await api("/api/reset", { method: "POST", body: "{}" });
    showToast("Local audit and simulation reset");
    await refresh();
  } catch (error) {
    showToast(`Could not reset state: ${error.message}`, true);
  }
}

elements.runDemo.addEventListener("click", runDemo);
elements.resetDemo.addEventListener("click", resetDemo);
document.addEventListener("visibilitychange", () => {
  if (!document.hidden) refresh({ forceScan: true });
});

window.setInterval(refresh, 1000);
refresh();
