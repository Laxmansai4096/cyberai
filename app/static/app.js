// CyberSentinel AI SOC console. Vanilla JS, CSP-safe (no inline handlers), all data escaped.
"use strict";
const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const dt = (iso) => (iso ? new Date(iso).toLocaleString("en-IN", { dateStyle: "medium", timeStyle: "medium" }) : "");
const view = $("#view");
let S = { token: sessionStorage.getItem("cs_token"), user: JSON.parse(sessionStorage.getItem("cs_user") || "null"), tab: "dashboard" };

function toast(m, ms = 3800) { const t = $("#toast"); t.textContent = m; t.classList.remove("hidden"); clearTimeout(t._h); t._h = setTimeout(() => t.classList.add("hidden"), ms); }
async function api(path, opts = {}) {
  const isForm = opts.body instanceof FormData;
  const res = await fetch(path, { ...opts, headers: { ...(opts.body && !isForm ? { "Content-Type": "application/json" } : {}), ...(S.token ? { Authorization: "Bearer " + S.token } : {}) }, body: opts.body && !isForm ? JSON.stringify(opts.body) : opts.body });
  if (res.status === 401 && S.token) { logout(); throw new Error("Session expired"); }
  const data = res.headers.get("content-type")?.includes("json") ? await res.json() : await res.text();
  if (!res.ok) throw new Error(typeof data?.detail === "string" ? data.detail : JSON.stringify(data?.detail || data));
  return data;
}
const has = (...r) => S.user && S.user.roles.some((x) => r.includes(x));
const sev = (s) => `<span class="sev ${esc(s)}">${esc(s)}</span>`;
const chip = (t) => `<span class="chip">${esc(t)}</span>`;
const st = (s) => `<span class="st ${["resolved", "closed", "executed", "contained", "approved"].includes(s) ? "ok" : ""}">${esc(s.replace("_", " "))}</span>`;
const TABS = [["dashboard", "Dashboard"], ["incidents", "Incidents"], ["alerts", "Alerts"], ["logs", "Logs & ingest"], ["vulns", "Vulnerabilities"], ["intel", "Threat intel"], ["admin", "Admin", () => has("Admin", "SecurityLead", "Viewer")]];

function logout() { sessionStorage.clear(); S = { token: null, user: null, tab: "dashboard" }; render(); }
function go(t, arg) { S.tab = t; S.arg = arg; render(); }
function nav() {
  $("#nav").innerHTML = S.user ? TABS.filter((t) => !t[2] || t[2]()).map(([k, l]) => `<button data-tab="${k}" class="${S.tab === k ? "active" : ""}">${l}</button>`).join("") : "";
  $("#who").innerHTML = S.user ? `${esc(S.user.display_name)} ${S.user.roles.map(chip).join("")} <button class="ghost" id="lo">Sign out</button>` : "";
  $$("#nav button").forEach((b) => b.addEventListener("click", () => go(b.dataset.tab)));
  $("#lo")?.addEventListener("click", logout);
}
async function render() {
  nav();
  if (!S.user) return loginView();
  view.innerHTML = '<p class="muted">Loading…</p>';
  try { await V[S.tab](S.arg); } catch (e) { view.innerHTML = `<div class="card"><b>Error:</b> ${esc(e.message)}</div>`; }
}

function loginView() {
  view.innerHTML = `<div class="card login"><h2>Sign in to the SOC console</h2><form id="lf"><label>Username</label><input id="u" required autocomplete="username"><label>Password</label><input id="p" type="password" required autocomplete="current-password"><p><button class="btn">Sign in</button></p></form>
  <p class="small muted">Demo accounts (password set at deployment):</p><table class="demo">${[["admin", "Admin"], ["lead.sara", "SecurityLead"], ["lead.omar", "SecurityLead (second approver)"], ["analyst.ravi", "Analyst"], ["viewer.neha", "Viewer / auditor"]].map(([u, r]) => `<tr><td><a href="#" data-u="${u}">${u}</a></td><td class="muted small">${r}</td></tr>`).join("")}</table></div>`;
  $$("[data-u]").forEach((a) => a.addEventListener("click", (e) => { e.preventDefault(); $("#u").value = a.dataset.u; $("#p").focus(); }));
  $("#lf").addEventListener("submit", async (e) => {
    e.preventDefault();
    try { const r = await api("/api/auth/login", { method: "POST", body: { username: $("#u").value.trim(), password: $("#p").value } }); S.token = r.access_token; S.user = r.user; sessionStorage.setItem("cs_token", S.token); sessionStorage.setItem("cs_user", JSON.stringify(S.user)); go("dashboard"); }
    catch (err) { toast(err.message); }
  });
}

function chart(tl) {
  const W = 760, H = 170, pad = 24, max = Math.max(1, ...tl.map((t) => t.total)), bw = (W - pad * 2) / tl.length;
  const bars = tl.map((t, i) => { const x = pad + i * bw, h = (t.total / max) * (H - 40), hf = (t.failures / max) * (H - 40);
    return `<rect x="${x + 2}" y="${H - 20 - h}" width="${bw - 4}" height="${h}" fill="var(--bar)" rx="2"><title>${t.hour} – ${t.total} events, ${t.failures} failures</title></rect><rect x="${x + 2}" y="${H - 20 - hf}" width="${bw - 4}" height="${hf}" fill="var(--bar2)" rx="2"/>${i % 3 === 0 ? `<text x="${x + bw / 2}" y="${H - 6}" text-anchor="middle">${t.hour}</text>` : ""}`; }).join("");
  return `<svg viewBox="0 0 ${W} ${H}" width="100%" role="img" aria-label="Events per hour">${bars}<text x="${pad}" y="12">max ${max}/h (UTC)</text></svg><div class="legend"><i style="background:var(--bar)"></i>all events<i style="background:var(--bar2)"></i>failures</div>`;
}
const hbars = (rows, key, val) => { const m = Math.max(1, ...rows.map((r) => r[val])); return rows.map((r) => `<div class="hbar"><span title="${esc(r[key])}">${esc(r[key])}</span><div class="b" style="width:${(r[val] / m) * 60}%"></div><span class="small">${r[val]}</span></div>`).join("") || '<p class="muted small">None</p>'; };

const V = {
  async dashboard() {
    const d = await api("/api/dashboard");
    const sc = has("Admin", "SecurityLead") ? await api("/api/demo/scenarios") : [];
    const stats = [["Events (24h)", d.logs_24h], ["Failures (24h)", d.failures_24h], ["Open alerts", d.open_alerts], ["Open incidents", d.open_incidents], ["Pending actions", d.pending_actions], ["High-risk assets", `${d.assets_high_risk}/${d.assets}`]];
    view.innerHTML = `<div class="grid">${stats.map(([l, v]) => `<div class="card"><div class="stat">${esc(v)}</div><div class="label">${l}</div></div>`).join("")}</div>
    <div class="two"><div class="card"><h2>Activity – last 24 hours</h2>${chart(d.timeline)}</div>
    <div class="card"><h2>Open alerts by severity</h2>${Object.entries(d.alerts_by_severity).map(([k, v]) => `<div class="hbar"><span>${sev(k)}</span><div class="b" style="width:${(v / Math.max(1, d.open_alerts)) * 60}%;background:var(--${k === "critical" ? "crit" : k === "medium" ? "med" : k})"></div><span class="small">${v}</span></div>`).join("")}</div></div>
    <div class="two"><div class="card"><h2>Top detections</h2>${hbars(d.top_rules, "rule", "count")}</div><div class="card"><h2>Top attacking IPs</h2>${hbars(d.top_ips, "ip", "events")}</div></div>
    ${sc.length ? `<div class="card"><h2>Attack simulator</h2><p class="small muted">Generates synthetic attacks (documentation IP ranges only) and runs them through the real pipeline.</p>${["all", ...sc].map((s) => `<button class="ghost" data-sim="${s}">${s.replace(/_/g, " ")}</button>`).join("")}</div>` : ""}`;
    $$("[data-sim]").forEach((b) => b.addEventListener("click", async () => { b.disabled = true; try { const r = await api("/api/demo/simulate", { method: "POST", body: { scenario: b.dataset.sim } }); toast(`Ingested ${r.ingested} events → ${r.alerts_created} new alerts, ${r.incidents.length} incidents`); go("dashboard"); } catch (e) { toast(e.message); b.disabled = false; } }));
  },
  async incidents(id) {
    if (id) return incidentDetail(id);
    const rows = await api("/api/incidents");
    view.innerHTML = `<div class="card"><h2>Incidents</h2><table><thead><tr><th>Severity</th><th>Title</th><th>MITRE</th><th>Alerts</th><th>Last seen</th><th>Status</th><th>Owner</th></tr></thead><tbody>
    ${rows.map((i) => `<tr class="click" data-inc="${i.id}"><td>${sev(i.severity)}</td><td>${esc(i.title)}</td><td>${(i.mitre || []).map(chip).join("")}</td><td>${i.alert_ids.length}</td><td>${dt(i.last_seen)}</td><td>${st(i.status)}</td><td>${esc(i.assigned_to || "–")}</td></tr>`).join("") || '<tr><td colspan="7" class="muted">No incidents. Ingest logs or run the simulator on the dashboard.</td></tr>'}</tbody></table></div>`;
    $$("[data-inc]").forEach((r) => r.addEventListener("click", () => go("incidents", r.dataset.inc)));
  },
  async alerts() {
    const rows = await api("/api/alerts");
    view.innerHTML = `<div class="card"><h2>Alerts</h2><div class="row"><div><label>Status</label><select id="fs"><option value="">all</option><option>new</option><option>acknowledged</option><option>resolved</option><option>false_positive</option></select></div><div><label>Severity</label><select id="fv"><option value="">all</option><option>critical</option><option>high</option><option>medium</option><option>low</option></select></div></div>
    <table><thead><tr><th>Severity</th><th>Rule</th><th>Entity</th><th>Events</th><th>Last seen</th><th>Status</th><th></th></tr></thead><tbody id="ab"></tbody></table></div><div id="ad"></div>`;
    const draw = () => {
      const f = rows.filter((a) => (!$("#fs").value || a.status === $("#fs").value) && (!$("#fv").value || a.severity === $("#fv").value));
      $("#ab").innerHTML = f.map((a) => `<tr><td>${sev(a.severity)}</td><td>${esc(a.rule_name)} <span class="small muted">${esc(a.rule_id)}</span></td><td class="mono">${esc(a.entity_type)}: ${esc(a.entity)}</td><td>${a.count}</td><td>${dt(a.last_seen)}</td><td>${st(a.status)}</td>
      <td><button class="ghost" data-ev="${a.id}">Evidence</button>${a.incident_id ? `<button class="ghost" data-inc="${a.incident_id}">Incident</button>` : ""}${has("Admin", "SecurityLead", "Analyst") && ["new", "acknowledged"].includes(a.status) ? `<button class="ghost" data-as="${a.id}" data-s="acknowledged">Ack</button><button class="ghost" data-as="${a.id}" data-s="false_positive">False +</button>` : ""}</td></tr>`).join("") || '<tr><td colspan="7" class="muted">No alerts</td></tr>';
      $$("[data-inc]").forEach((b) => b.addEventListener("click", () => go("incidents", b.dataset.inc)));
      $$("[data-as]").forEach((b) => b.addEventListener("click", async () => { await api(`/api/alerts/${b.dataset.as}/status`, { method: "POST", body: { status: b.dataset.s } }); go("alerts"); }));
      $$("[data-ev]").forEach((b) => b.addEventListener("click", async () => { const a = await api(`/api/alerts/${b.dataset.ev}`); $("#ad").innerHTML = `<div class="card"><h2>Evidence – ${esc(a.rule_name)}</h2><p>${esc(a.description)}</p><pre class="mono small">${esc(JSON.stringify(a.extra, null, 2))}</pre>${logTable(a.evidence_logs)}</div>`; $("#ad").scrollIntoView({ behavior: "smooth" }); }));
    };
    $("#fs").addEventListener("change", draw); $("#fv").addEventListener("change", draw); draw();
  },
  async logs() {
    const rows = await api("/api/logs?hours=168&limit=300");
    const canWrite = has("Admin", "SecurityLead", "Analyst");
    view.innerHTML = `${canWrite ? `<div class="two"><div class="card"><h2>Ingest JSON events</h2><textarea id="ij">[
  {"source":"firewall","src_ip":"203.0.113.10","dst_ip":"10.0.0.4","dst_port":3389,"action":"deny"},
  {"source":"generic","event_type":"auth.login_failure","user":"alice","ip":"203.0.113.10","outcome":"failure"}
]</textarea><p><button class="btn" id="ib">Ingest</button></p></div>
    <div class="card"><h2>Upload a log file</h2><p class="small muted">JSONL / JSON array, or Linux auth.log (sshd) lines. Max 2 MB.</p><label>Source hint for plain lines</label><select id="us"><option value="linux_auth">linux_auth</option><option value="">auto</option></select><label>File</label><input type="file" id="uf" accept=".log,.txt,.json,.jsonl"><p><button class="btn" id="ub">Upload & analyse</button></p></div></div>` : ""}
    <div class="card"><h2>Recent events (7 days)</h2><div class="row"><div><input id="lq" placeholder="filter by user, IP, type, source…"></div></div><div id="lt"></div></div>`;
    const draw = () => { const q = ($("#lq").value || "").toLowerCase(); $("#lt").innerHTML = logTable(rows.filter((l) => !q || JSON.stringify(l).toLowerCase().includes(q)).slice(0, 200)); };
    $("#lq").addEventListener("input", draw); draw();
    const done = (r) => { toast(`Ingested ${r.ingested} (skipped ${r.skipped}) → ${r.alerts_created} new / ${r.alerts_updated} updated alerts`); go("logs"); };
    $("#ib")?.addEventListener("click", async () => { try { const ev = JSON.parse($("#ij").value); done(await api("/api/logs", { method: "POST", body: { events: Array.isArray(ev) ? ev : [ev] } })); } catch (e) { toast(e.message); } });
    $("#ub")?.addEventListener("click", async () => { const f = $("#uf").files[0]; if (!f) return toast("Choose a file"); const fd = new FormData(); fd.append("file", f); fd.append("source", $("#us").value); try { done(await api("/api/logs/upload", { method: "POST", body: fd })); } catch (e) { toast(e.message); } });
  },
  async vulns() {
    const assets = await api("/api/assets");
    const canWrite = has("Admin", "SecurityLead", "Analyst");
    view.innerHTML = `<div class="card"><h2>Assets & vulnerability assessment</h2><table><thead><tr><th>Asset</th><th>Criticality</th><th>Packages</th><th>Risk</th><th>Findings</th><th>Last scan</th><th></th></tr></thead><tbody>
    ${assets.map((a) => { const s = a.last_scan; return `<tr><td><b>${esc(a.name)}</b><div class="small muted">${esc(a.kind)} · ${esc(a.owner)} · ${esc(a.environment)}</div></td><td>${sev(a.criticality)}</td><td class="small">${a.packages.map((p) => esc(`${p.name}@${p.version}`)).join("<br>")}</td>
      <td>${s ? `<b>${s.risk_score}</b>/100 ${sev(s.rating)}` : "–"}</td><td class="small">${s ? Object.entries(s.counts).filter(([, v]) => v).map(([k, v]) => `${v} ${k}`).join(", ") || "none" : "–"}</td><td class="small">${dt(s?.scanned_at)}</td>
      <td>${canWrite ? `<button class="ghost" data-scan="${a.id}">Scan</button>` : ""}${s ? `<button class="ghost" data-fd="${a.id}">Findings</button>` : ""}</td></tr>`; }).join("")}</tbody></table></div><div id="fd"></div>
    ${canWrite ? `<div class="card"><h2>Add asset</h2><div class="row"><div><label>Name</label><input id="an" value="web-02"></div><div><label>Kind</label><select id="ak"><option>server</option><option>application</option><option>database</option><option>network</option><option>endpoint</option></select></div><div><label>Criticality</label><select id="ac"><option>medium</option><option>low</option><option>high</option><option>critical</option></select></div><div><label>Owner</label><input id="ao" value="IT"></div></div>
    <label>Packages – one per line: ecosystem | name | version (PyPI, npm, Maven, Debian…)</label><textarea id="ap">npm | express | 4.18.2
PyPI | pillow | 10.0.0</textarea><label>Configuration (JSON)</label><textarea id="acf">{"mfa_enabled": false, "tls_min_version": "1.2", "open_ports": [22, 443], "internet_exposed": true, "days_since_patch": 120}</textarea><p><button class="btn" id="aa">Add asset</button></p></div>` : ""}`;
    $$("[data-scan]").forEach((b) => b.addEventListener("click", async () => { b.disabled = true; try { const a = await api(`/api/assets/${b.dataset.scan}/scan`, { method: "POST" }); toast(`${a.name}: risk ${a.last_scan.risk_score}/100 (${a.last_scan.package_source})`); go("vulns"); } catch (e) { toast(e.message); } }));
    $$("[data-fd]").forEach((b) => b.addEventListener("click", () => { const a = assets.find((x) => x.id === b.dataset.fd); $("#fd").innerHTML = `<div class="card"><h2>Findings – ${esc(a.name)}</h2><table><thead><tr><th>Severity</th><th>ID</th><th>Finding</th><th>Fix</th><th>Source</th></tr></thead><tbody>${a.last_scan.findings.map((f) => `<tr><td>${sev(f.severity)}</td><td class="mono">${esc(f.id)}</td><td>${esc(f.summary)}${f.package ? `<div class="small muted">${esc(f.package)}@${esc(f.version)}</div>` : ""}</td><td class="small">${esc(f.fixed_in ? "Upgrade to " + f.fixed_in : f.remediation || "")}</td><td class="small">${esc(f.source)}</td></tr>`).join("")}</tbody></table></div>`; $("#fd").scrollIntoView({ behavior: "smooth" }); }));
    $("#aa")?.addEventListener("click", async () => {
      try {
        const packages = $("#ap").value.split("\n").map((l) => l.split("|").map((s) => s.trim())).filter((x) => x[1]).map(([ecosystem, name, version]) => ({ ecosystem, name, version }));
        await api("/api/assets", { method: "POST", body: { name: $("#an").value, kind: $("#ak").value, criticality: $("#ac").value, owner: $("#ao").value, packages, config: JSON.parse($("#acf").value || "{}") } }); toast("Asset added"); go("vulns");
      } catch (e) { toast(e.message); }
    });
  },
  async intel() {
    const [iocs, bl] = await Promise.all([api("/api/iocs"), api("/api/blocklist")]);
    view.innerHTML = `<div class="two"><div class="card"><h2>Threat-intel indicators</h2><table>${iocs.map((i) => `<tr><td class="mono">${esc(i.value)}</td><td>${esc(i.description)}</td><td>${i.builtin ? chip("built-in") : chip("custom")}</td></tr>`).join("")}</table>
    ${has("Admin", "SecurityLead") ? `<h3>Add IP indicator</h3><div class="row"><div><input id="iv" placeholder="IP address"></div><div><input id="id" placeholder="description"></div><div style="flex:0"><button class="btn" id="ia">Add</button></div></div>` : ""}</div>
    <div class="card"><h2>Blocklist (executed actions)</h2>${bl.length ? `<table>${bl.map((b) => `<tr><td class="mono">${esc(b.ip)}</td><td class="small">${dt(b.at)}</td><td class="small muted">${esc(b.action_id)}</td></tr>`).join("")}</table>` : '<p class="muted">Empty</p>'}</div></div>`;
    $("#ia")?.addEventListener("click", async () => { try { await api("/api/iocs", { method: "POST", body: { value: $("#iv").value.trim(), description: $("#id").value } }); go("intel"); } catch (e) { toast(e.message); } });
  },
  async admin() {
    const audit = await api("/api/admin/audit?limit=150");
    const users = has("Admin") ? await api("/api/admin/users") : [];
    view.innerHTML = `${users.length ? `<div class="card"><h2>Users</h2><table>${users.map((u) => `<tr><td>${esc(u.display_name)} <span class="small muted">${esc(u.username)}</span></td><td>${u.roles.map(chip).join("")}</td><td class="small">${dt(u.last_login)}</td><td>${u.disabled ? st("disabled") : st("active")}</td><td>${u.id !== S.user.id ? `<button class="ghost" data-u="${u.id}" data-a="${u.disabled ? "enable" : "disable"}">${u.disabled ? "Enable" : "Disable"}</button>` : ""}</td></tr>`).join("")}</table></div>` : ""}
    <div class="card"><h2>Audit log</h2><table><thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Resource</th><th>IP</th></tr></thead><tbody>${audit.map((a) => `<tr><td class="small">${dt(a.ts)}</td><td>${esc(a.actor)}</td><td class="mono">${esc(a.action)}</td><td class="small">${esc(a.resource_type)}/${esc(a.resource_id)}</td><td class="small mono">${esc(a.ip)}</td></tr>`).join("")}</tbody></table></div>`;
    $$("[data-u]").forEach((b) => b.addEventListener("click", async () => { await api(`/api/admin/users/${b.dataset.u}/${b.dataset.a}`, { method: "POST" }); go("admin"); }));
  },
};

function logTable(rows) {
  return `<table><thead><tr><th>Time (UTC)</th><th>Source</th><th>Event</th><th>User</th><th>IP</th><th>Outcome</th><th>Detail</th></tr></thead><tbody>${rows.map((l) => `<tr><td class="small mono">${esc(l.timestamp)}</td><td>${chip(l.source)}</td><td class="mono">${esc(l.event_type)}</td><td>${esc(l.user || "")}</td><td class="mono">${esc(l.ip || "")}</td><td>${esc(l.outcome || "")}</td><td class="small">${esc(l.resource || (l.dst_port ? "port " + l.dst_port : "") || l.host || "")}</td></tr>`).join("") || '<tr><td colspan="7" class="muted">No events</td></tr>'}</tbody></table>`;
}

async function incidentDetail(id) {
  const i = await api(`/api/incidents/${id}`);
  const x = i.explanation || {};
  const w = has("Admin", "SecurityLead", "Analyst"), lead = has("Admin", "SecurityLead");
  view.innerHTML = `<p><button class="ghost" id="back">← All incidents</button></p>
  <div class="card"><h2>${sev(i.severity)} ${esc(i.title)} ${st(i.status)}</h2><p class="small muted">${esc(i.id)} · first ${dt(i.first_seen)} · last ${dt(i.last_seen)} · owner ${esc(i.assigned_to || "unassigned")}</p>
  <div class="explain"><b>AI explanation</b> <span class="small muted">(${esc(x.generator)} · confidence ${Math.round((x.confidence || 0) * 100)}%)</span><p>${esc(x.summary)}</p>
  <h3>Why it matters</h3><ul>${(x.why_it_matters || []).map((s) => `<li>${esc(s)}</li>`).join("")}</ul>
  ${x.risk_factors?.length ? `<h3>Risk factors</h3><ul>${x.risk_factors.map((s) => `<li>${esc(s)}</li>`).join("")}</ul>` : ""}
  <h3>MITRE ATT&CK</h3>${(x.mitre || []).map((m) => chip(`${m.id} ${m.name} · ${m.tactic}`)).join("")}
  <h3>Timeline</h3><ul>${(x.timeline || []).map((t) => `<li><span class="mono small">${esc(t.at)}</span> ${esc(t.text)}</li>`).join("")}</ul>
  <h3>Next steps</h3><ol>${(x.next_steps || []).map((s) => `<li>${esc(s)}</li>`).join("")}</ol></div>
  ${w ? `<div class="row" style="margin-top:12px"><div><label>Status</label><select id="is">${["open", "investigating", "contained", "closed"].map((s) => `<option ${s === i.status ? "selected" : ""}>${s}</option>`).join("")}</select></div><div><label>Assign to</label><input id="ia" value="${esc(i.assigned_to || S.user.username)}"></div><div style="flex:2"><label>Note</label><input id="in"></div><div style="flex:0"><button class="btn" id="iu">Update</button></div></div>` : ""}
  ${(i.notes || []).length ? `<h3>Notes</h3><ul>${i.notes.map((n) => `<li><span class="small muted">${dt(n.at)} ${esc(n.by)}:</span> ${esc(n.text)}</li>`).join("")}</ul>` : ""}</div>
  <div class="card"><h2>Response actions</h2><p class="small muted">Propose → a different SecurityLead approves → execute (dry-run by default) → revert if needed. Every step is audited.</p>
  ${(x.recommended_actions || []).length && w ? `<h3>Recommended</h3>${x.recommended_actions.map((r) => `<button class="ghost" data-rk="${esc(r.kind)}" data-rt="${esc(r.target)}" title="${esc(r.why)}">${esc(r.kind.replace(/_/g, " "))}: ${esc(r.target)}</button>`).join("")}` : ""}
  ${w ? `<div class="row"><div><label>Action</label><select id="ak"><option>block_ip</option><option>disable_user</option><option>force_password_reset</option><option>isolate_host</option></select></div><div><label>Target</label><input id="at"></div>
  <div><label>Target system</label><select id="as"><option value="local">local (CyberSentinel blocklist)</option><option value="mediflow">mediflow (via queue)</option><option value="simulated">simulated</option></select></div><div><label>Mode</label><select id="ad"><option value="true">dry-run</option><option value="false">live</option></select></div></div><label>Reason</label><input id="ar" value="Containment for ${esc(i.title)}"><p><button class="btn" id="ap">Propose action</button></p>` : ""}
  <table><thead><tr><th>Action</th><th>Target</th><th>Mode</th><th>Status</th><th>Requested / approved</th><th>Result</th><th></th></tr></thead><tbody>${i.actions.map((a) => `<tr><td>${esc(a.kind)}</td><td class="mono">${esc(a.target)} <span class="small muted">${esc(a.target_system)}</span></td><td>${a.dry_run ? chip("dry-run") : "<b>live</b>"}</td><td>${st(a.status)}</td><td class="small">${esc(a.requested_by)} / ${esc(a.approved_by || "–")}</td><td class="small">${esc(a.result?.detail || "")}</td>
  <td>${lead && a.status === "proposed" ? `<button class="ghost" data-act="approve" data-id="${a.id}">Approve</button><button class="ghost" data-act="reject" data-id="${a.id}">Reject</button>` : ""}${lead && a.status === "approved" ? `<button class="ghost" data-act="execute" data-id="${a.id}">Execute</button>` : ""}${lead && a.status === "executed" && a.kind !== "force_password_reset" ? `<button class="ghost" data-act="revert" data-id="${a.id}">Revert</button>` : ""}</td></tr>`).join("") || '<tr><td colspan="7" class="muted">No actions yet</td></tr>'}</tbody></table></div>
  <div class="card"><h2>Alerts (${i.alerts.length})</h2><table><thead><tr><th>Severity</th><th>Rule</th><th>Entity</th><th>Events</th><th>Window</th><th>Details</th></tr></thead><tbody>${i.alerts.map((a) => `<tr><td>${sev(a.severity)}</td><td>${esc(a.rule_name)}<div class="small muted">${a.mitre.join(", ")}</div></td><td class="mono">${esc(a.entity)}</td><td>${a.count}</td><td class="small">${esc(a.first_seen)}<br>${esc(a.last_seen)}</td><td class="small mono">${esc(JSON.stringify(a.extra))}</td></tr>`).join("")}</tbody></table></div>`;
  $("#back").addEventListener("click", () => go("incidents"));
  $("#iu")?.addEventListener("click", async () => { await api(`/api/incidents/${id}`, { method: "PATCH", body: { status: $("#is").value, assigned_to: $("#ia").value, note: $("#in").value || null } }); toast("Incident updated"); incidentDetail(id); });
  $$("[data-rk]").forEach((b) => b.addEventListener("click", () => { $("#ak").value = b.dataset.rk; $("#at").value = b.dataset.rt; $("#at").focus(); }));
  $("#ap")?.addEventListener("click", async () => { try { await api(`/api/incidents/${id}/actions`, { method: "POST", body: { kind: $("#ak").value, target: $("#at").value, target_system: $("#as").value, dry_run: $("#ad").value === "true", reason: $("#ar").value } }); toast("Action proposed – waiting for SecurityLead approval"); incidentDetail(id); } catch (e) { toast(e.message); } });
  $$("[data-act]").forEach((b) => b.addEventListener("click", async () => { try { await api(`/api/actions/${b.dataset.id}/${b.dataset.act}`, { method: "POST", body: b.dataset.act === "reject" ? { note: "rejected in console" } : undefined }); toast(`Action ${b.dataset.act}d`); incidentDetail(id); } catch (e) { toast(e.message); } }));
}

render();
