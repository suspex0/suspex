"use strict";
const $ = (id) => document.getElementById(id);
const el = (tag, cls, txt) => {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (txt != null) e.textContent = txt;
  return e;
};

// ---- small fetch helpers -------------------------------------------------
async function getJSON(url) { const r = await fetch(url); return r.json(); }
async function sendJSON(method, url, body) {
  const r = await fetch(url, {
    method,
    headers: { "content-type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  let data = {};
  try { data = await r.json(); } catch (_) { /* no body */ }
  return { ok: r.ok, data };
}

// ---- tri-state normalizer for posture bits -------------------------------
// Unwraps {value, confidence, source} pairs and coerces to on/off/unknown.
function triState(v) {
  let soft = false;
  if (v && typeof v === "object" && "value" in v) {
    soft = v.confidence === "driver-absent-default";
    v = v.value;
  }
  if (v === true) return { state: "on", soft, label: "enabled" };
  if (v === false) return { state: "off", soft, label: "disabled" };
  if (v == null || v === "") return { state: "unknown", soft, label: "unknown" };
  const s = String(v).toLowerCase();
  if (["on", "true", "1", "yes", "enabled", "active", "running"].includes(s))
    return { state: "on", soft, label: String(v) };
  if (["off", "false", "0", "no", "disabled", "inactive", "absent"].includes(s))
    return { state: "off", soft, label: String(v) };
  return { state: "unknown", soft, label: String(v) };
}

// ========================================================================
// Header + status + posture + host
// ========================================================================
function setBadge(connected) {
  const e = $("conn");
  e.textContent = connected ? "connected" : "disconnected";
  e.className = "badge " + (connected ? "on" : "off");
}

const POSTURE = [
  ["memory_integrity", "HVCI"],
  ["vbs_enabled", "VBS"],
  ["secureboot", "Secure Boot"],
  ["credential_guard", "Cred Guard"],
  ["lsa_protected", "LSA Protect"],
  ["kva_shadow", "KVA Shadow"],
  ["driver_blocklist_on", "Drv Blocklist"],
  ["kernel_debugger", "Kernel Dbg"],
  ["testsigning", "Test Signing"],
];

function renderPosture(agent) {
  const grid = $("posture-grid");
  grid.innerHTML = "";
  if (!agent) {
    grid.appendChild(el("div", "empty", "no target connected"));
    $("posture-note").textContent = "";
    return;
  }
  let anySoft = false;
  for (const [key, label] of POSTURE) {
    const t = triState(agent[key]);
    if (t.soft) anySoft = true;
    const chip = el("div", "chip " + t.state);
    chip.appendChild(el("span", "chip-k", label));
    chip.appendChild(el("span", "chip-v", t.label));
    if (t.soft) chip.appendChild(el("span", "chip-soft", "driver-absent default"));
    grid.appendChild(chip);
  }
  // PatchGuard — often a descriptive string.
  const pg = agent.patchguard_state ?? agent.patchguard_expected;
  if (pg != null) {
    const t = triState(pg);
    const chip = el("div", "chip " + (t.state === "unknown" ? "unknown" : "on"));
    chip.appendChild(el("span", "chip-k", "PatchGuard"));
    chip.appendChild(el("span", "chip-v", t.label));
    grid.appendChild(chip);
  }
  $("posture-note").textContent = agent.driver_present
    ? "driver-verified" : "driver absent — some values unverified";
}

function fmtUptime(ms) {
  if (!ms && ms !== 0) return "–";
  let s = Math.floor(ms / 1000);
  const d = Math.floor(s / 86400); s -= d * 86400;
  const h = Math.floor(s / 3600); s -= h * 3600;
  const m = Math.floor(s / 60); s -= m * 60;
  return [d && d + "d", h && h + "h", m && m + "m", s + "s"].filter(Boolean).join(" ");
}

function renderHost(agent) {
  const dl = $("host-dl");
  dl.innerHTML = "";
  if (!agent) { dl.appendChild(el("div", "empty", "no target connected")); return; }
  const health = agent.suspex_driver_health || {};
  const os = agent.os || {};
  const rows = [
    ["Driver state", agent.driver_state || "–"],
    ["Suspex driver", health.ok === false ? (health.error || "unhealthy")
      : (health.state || health.status || (health.ok ? "ok" : "–"))],
    ["OS", (os.name || os.version || agent.os_version || "–") +
      (agent.os_build ? ` (${agent.os_build})` : "")],
    ["PC uptime", fmtUptime(agent.pc_uptime_ms)],
    ["Service uptime", fmtUptime(agent.service_uptime_ms)],
    ["Boot time", agent.boot_time || "–"],
  ];
  for (const [k, v] of rows) {
    dl.appendChild(el("dt", null, k));
    dl.appendChild(el("dd", null, String(v)));
  }
}

async function refreshStatus() {
  try {
    const s = await getJSON("/api/status");
    setBadge(s.connected);
    $("tools-pill").textContent = `${s.tool_calls ?? 0} calls`;
    renderPosture(s.agent);
    renderHost(s.agent);
  } catch (_) { setBadge(false); }
}

async function refreshHealth() {
  try {
    const h = await getJSON("/health");
    if (h.server_version) $("ver-pill").textContent = "v" + h.server_version;
    if (h.tool_count != null) $("tools-pill").title = `${h.tool_count} tools registered`;
  } catch (_) { /* ignore */ }
}

// ========================================================================
// Findings
// ========================================================================
const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
function sevClass(sev) {
  const s = String(sev || "").toLowerCase();
  return ["critical", "high", "medium", "low"].includes(s) ? s : "low";
}
async function refreshFindings() {
  try {
    const rows = await getJSON("/api/findings");
    const list = $("findings-list");
    list.innerHTML = "";
    const counts = {};
    for (const f of rows) {
      const s = sevClass(f.severity);
      counts[s] = (counts[s] || 0) + 1;
    }
    const cc = $("sev-counts"); cc.innerHTML = "";
    for (const s of ["critical", "high", "medium", "low"]) {
      if (!counts[s]) continue;
      cc.appendChild(el("span", "sev-pill " + s, `${counts[s]} ${s}`));
    }
    if (!rows.length) { list.appendChild(el("div", "empty", "no findings yet")); return; }
    rows.sort((a, b) =>
      (SEV_ORDER[sevClass(a.severity)] ?? 9) - (SEV_ORDER[sevClass(b.severity)] ?? 9));
    for (const f of rows.slice(0, 80)) {
      const row = el("div", "finding");
      row.appendChild(el("span", "sev-dot " + sevClass(f.severity)));
      const body = el("div");
      body.appendChild(el("div", "f-title", f.title || f.summary || "(untitled)"));
      if (f.reason || f.detail)
        body.appendChild(el("div", "f-reason", f.reason || f.detail));
      row.appendChild(body);
      list.appendChild(row);
    }
  } catch (_) { /* ignore */ }
}

// ========================================================================
// Tool-call log
// ========================================================================
let _toollog = [];
function renderToollog() {
  const body = $("toollog-body");
  const only = $("only-destr").checked;
  body.innerHTML = "";
  for (const c of _toollog.slice().reverse()) {
    if (only && !c.destructive) continue;
    const tr = el("tr");
    tr.appendChild(el("td", "mono", new Date(c.ts * 1000).toLocaleTimeString()));
    tr.appendChild(el("td", "mono", c.tool));
    tr.appendChild(el("td", null, c.action));
    const flag = el("td", c.destructive ? "destructive" : null,
      c.destructive ? "DESTRUCTIVE" : "");
    tr.appendChild(flag);
    const res = el("td");
    res.appendChild(c.ok ? el("span", "ok", "ok") : el("span", "err", c.error || "err"));
    tr.appendChild(res);
    body.appendChild(tr);
  }
}
async function refreshToollog() {
  try { _toollog = await getJSON("/api/toollog"); renderToollog(); } catch (_) {}
}
$("only-destr").addEventListener("change", renderToollog);

// ========================================================================
// Machines
// ========================================================================
function endpointBlock(endpoints) {
  const wrap = el("div", "endpoints");
  const ents = Object.entries(endpoints || {});
  if (!ents.length) { wrap.appendChild(el("span", "empty", "no endpoint")); return wrap; }
  for (const [kind, addr] of ents) {
    const line = el("span", "ep");
    line.appendChild(el("span", "ep-kind", kind + ": "));
    line.appendChild(document.createTextNode(addr));
    wrap.appendChild(line);
  }
  return wrap;
}

function machineCard(m) {
  const trust = String(m.trust || "untrusted").toLowerCase();
  const card = el("div", "mcard trust-" + trust + (m.connected ? " live" : ""));

  const top = el("div", "mcard-top");
  top.appendChild(el("span", "mcard-name", m.machine));
  top.appendChild(el("span", "trust-tag " + trust, trust));
  card.appendChild(top);

  if (m.purpose) card.appendChild(el("div", "mcard-purpose", m.purpose));
  if (m.note) card.appendChild(el("div", "mcard-note", m.note));
  card.appendChild(endpointBlock(m.endpoints));

  if (m.tags && m.tags.length) {
    const tags = el("div", "tags");
    for (const t of m.tags) tags.appendChild(el("span", "tag", t));
    card.appendChild(tags);
  }

  const vrow = el("div", "views-row");
  const connected = new Set(m.connected_views || []);
  for (const kind of ["kernel", "user"]) {
    const dot = el("span", "vdot" + (connected.has(kind) ? " on" : ""));
    dot.title = kind + (connected.has(kind) ? " connected" : " offline");
    vrow.appendChild(dot);
    vrow.appendChild(document.createTextNode(kind));
  }
  const src = el("span", "src-tag", " · " + (m.source || ""));
  vrow.appendChild(src);
  card.appendChild(vrow);

  const act = el("div", "mcard-actions");
  const mkBtn = (label, cls, fn) => {
    const b = el("button", "btn btn-sm " + (cls || ""), label);
    b.onclick = fn;
    return b;
  };
  act.appendChild(mkBtn("Connect K", "btn-accent", () => connectMachine(m.machine, "kernel")));
  act.appendChild(mkBtn("Both", "", () => connectMachine(m.machine, "both")));
  if (m.connected)
    act.appendChild(mkBtn("Disconnect", "btn-danger", () => disconnectMachine(m.machine)));
  act.appendChild(mkBtn("Use", "", () => useMachine(m.machine)));
  if (m.source === "registry") {
    act.appendChild(mkBtn("Edit", "", () => openEditForm(m)));
    act.appendChild(mkBtn("Delete", "btn-danger", () => deleteMachine(m.machine)));
  }
  card.appendChild(act);
  return card;
}

async function refreshMachines() {
  try {
    const r = await getJSON("/api/machines");
    const box = $("machine-cards");
    box.innerHTML = "";
    const focus = r.focus && (r.focus.machine || r.focus.view);
    if (focus) { $("focus-pill").hidden = false; $("focus-pill").textContent = "focus: " + focus; }
    else $("focus-pill").hidden = true;
    if (!r.machines || !r.machines.length) {
      box.appendChild(el("div", "empty", "no machines — add one above"));
      return;
    }
    for (const m of r.machines) box.appendChild(machineCard(m));
  } catch (_) { /* ignore */ }
}

async function connectMachine(alias, views) {
  const r = await sendJSON("POST", `/api/machines/${encodeURIComponent(alias)}/connect`, { views });
  if (!r.ok || r.data.ok === false) flash(JSON.stringify(r.data.views || r.data.error || r.data));
  refreshMachines(); refreshStatus();
}
async function disconnectMachine(alias) {
  await sendJSON("POST", `/api/machines/${encodeURIComponent(alias)}/disconnect`);
  refreshMachines(); refreshStatus();
}
async function useMachine(alias) {
  await sendJSON("POST", `/api/machines/${encodeURIComponent(alias)}/use`);
  refreshMachines();
}
async function deleteMachine(alias) {
  if (!confirm(`Remove machine "${alias}" from the registry?`)) return;
  const r = await sendJSON("DELETE", `/api/machines/${encodeURIComponent(alias)}`);
  if (r.data.ok === false) flash(r.data.error || "delete failed");
  refreshMachines();
}

function flash(msg) { $("add-err").textContent = msg; setTimeout(() => { $("add-err").textContent = ""; }, 6000); }

// ---- add / edit form -----------------------------------------------------
const form = $("add-form");
let editMode = null; // null = register, else alias string

function showForm(show) {
  form.hidden = !show;
  if (show) form.querySelector('[name="alias"]').focus();
}
$("add-btn").onclick = () => { editMode = null; form.reset();
  form.querySelector('[name="alias"]').disabled = false;
  $("add-err").textContent = ""; showForm(form.hidden); };
$("add-cancel").onclick = () => showForm(false);

function openEditForm(m) {
  editMode = m.machine;
  form.querySelector('[name="alias"]').value = m.machine;
  form.querySelector('[name="alias"]').disabled = true;
  const eps = m.endpoints || {};
  const [kh, kp] = (eps.kernel || "").split(":");
  const [, up] = (eps.user || "").split(":");
  form.querySelector('[name="host"]').value = kh || "";
  form.querySelector('[name="kernel_port"]').value = kp || "";
  form.querySelector('[name="user_port"]').value = up || "";
  form.querySelector('[name="token"]').value = "";
  form.querySelector('[name="trust"]').value = m.trust || "untrusted";
  form.querySelector('[name="purpose"]').value = m.purpose || "";
  form.querySelector('[name="note"]').value = m.note || "";
  form.querySelector('[name="tags"]').value = (m.tags || []).join(", ");
  $("add-err").textContent = "";
  showForm(true);
  form.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

form.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const fd = new FormData(form);
  const body = {
    alias: fd.get("alias").trim(),
    host: fd.get("host").trim(),
    kernel_port: Number(fd.get("kernel_port")) || 0,
    user_port: Number(fd.get("user_port")) || 0,
    token: fd.get("token").trim(),
    trust: fd.get("trust"),
    purpose: fd.get("purpose").trim(),
    note: fd.get("note").trim(),
    tags: fd.get("tags").trim(),
  };
  const url = editMode
    ? `/api/machines/${encodeURIComponent(editMode)}`
    : "/api/machines";
  const r = await sendJSON("POST", url, body);
  if (r.data.ok === false) { flash(r.data.error || "save failed"); return; }
  showForm(false);
  form.querySelector('[name="alias"]').disabled = false;
  refreshMachines();
});

// ========================================================================
// WebSocket live events
// ========================================================================
function connectWs() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(proto + "://" + location.host + "/ws");
  ws.onmessage = (msg) => {
    let data; try { data = JSON.parse(msg.data); } catch (_) { return; }
    if (data.type !== "snapshot") return;
    const list = $("event-list");
    list.innerHTML = "";
    const evs = (data.events || []).slice(-30).reverse();
    if (!evs.length) { list.appendChild(el("div", "empty", "no events")); }
    for (const ev of evs) {
      const div = el("div", "ev");
      div.appendChild(el("span", "ev-kind", `[${ev.kind || "?"}] `));
      div.appendChild(document.createTextNode(
        `tid=${ev.tid || "-"} addr=${ev.address || "-"} ${ev.description || ""}`));
      list.appendChild(div);
    }
  };
  ws.onclose = () => setTimeout(connectWs, 2000);
}

// ========================================================================
// boot
// ========================================================================
refreshHealth();
refreshStatus();
refreshFindings();
refreshToollog();
refreshMachines();
connectWs();
setInterval(refreshStatus, 3000);
setInterval(refreshToollog, 2500);
setInterval(refreshFindings, 5000);
setInterval(refreshMachines, 4000);
