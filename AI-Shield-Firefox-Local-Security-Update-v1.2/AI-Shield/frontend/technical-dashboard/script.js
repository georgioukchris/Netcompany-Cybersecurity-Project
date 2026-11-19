const $ = id => document.getElementById(id);
const BASE_KEY = "aiShieldApiBase", TOKEN_KEY = "aiShieldAdminToken", ANALYST_KEY = "aiShieldAnalyst";
let incidents = [], shadowTools = [], shadowEvents = [], resolutionCategories = {}, intel = null, intelHours = 24;
const SERVED_BY_BACKEND = location.protocol === "http:" || location.protocol === "https:";
const DEFAULT_API = location.protocol === "file:" ? "http://localhost:8000" : "";
// When served from FastAPI, always call the API on this exact origin.
const base = () => SERVED_BY_BACKEND ? "" : (localStorage.getItem(BASE_KEY) ?? DEFAULT_API).trim().replace(/\/+$/, "");
const url = path => `${base()}${path}`;
// Signed in at /login as an admin: the session cookie authenticates every call and the
// analyst is the signed-in person. The admin token (Settings) is only a fallback for API use.
let SESSION = null;
const adminHeaders = () => SESSION ? {} : ({ "X-Admin-Token": localStorage.getItem(TOKEN_KEY) || "" });
const analyst = () => SESSION ? SESSION.name : (localStorage.getItem(ANALYST_KEY) || "").trim();
const hasAuth = () => !!SESSION || !!localStorage.getItem(TOKEN_KEY);

// Five data categories. Colours: validated categorical palette for this dark surface
// (#111c2d): lightness band, chroma, CVD and normal-vision separation, 3:1 contrast.
const CATS = {
  PERSONAL:    { label: "Personal Data",    el: "Προσωπικά",   color: "#3987e5" },
  FINANCIAL:   { label: "Financial Data",   el: "Οικονομικά",  color: "#d95926" },
  CREDENTIALS: { label: "Credentials",      el: "Διαπιστευτήρια", color: "#199e70" },
  BUSINESS:    { label: "Business Data",    el: "Εταιρικά",    color: "#c98500" },
  MEDICAL:     { label: "Medical Data",     el: "Ιατρικά",     color: "#d55181" },
  THREAT:      { label: "Threat signal",    el: "Prompt injection", color: "#7d8ea6" },
};
const WINDOW_LABEL = { 1: "τελευταία ώρα", 24: "24 ώρες", 168: "7 ημέρες" };
const BUCKET_LABEL = { 300: "ανά 5 λεπτά", 3600: "ανά ώρα", 86400: "ανά ημέρα" };
const CAT_ORDER = ["PERSONAL", "FINANCIAL", "CREDENTIALS", "BUSINESS", "MEDICAL"];
const STATUS_EL = { OPEN: "Open", ACKNOWLEDGED: "Acknowledged", INVESTIGATING: "Investigating", RESOLVED: "Resolved", AUTO_CLOSED: "Auto-closed" };
const POLICY_ICON = { BLOCK: "🛑 BLOCK", WARN: "⚠️ WARN", REDACT: "✂️ REDACT", ALLOW: "✅ ALLOW" };
function policyTags(action) {
  if (action === "WARN_REDACT") return `<span class="tag WARN">${POLICY_ICON.WARN}</span> <span class="tag REDACT">${POLICY_ICON.REDACT}</span>`;
  return `<span class="tag ${esc(action)}">${esc(POLICY_ICON[action] || action)}</span>`;
}
const ACTION_EL = { ACKNOWLEDGE: "Ανάληψη", INVESTIGATE: "Διερεύνηση", RESOLVE: "Επίλυση" };

function setConnection(text, ok = false) {
  $("connectionText").textContent = text;
  $("connDot").className = ok ? "ok" : "bad";
}
function showAnalyst() {
  const name = analyst();
  $("analystName2").textContent = name || "Analyst";
  $("analystText").textContent = SESSION ? `${SESSION.email} · admin` : name ? "Security analyst · ενεργός" : "Όρισε όνομα στις ρυθμίσεις";
  $("analystAvatar").textContent = name ? name.split(/[\s._-]+/).filter(Boolean).slice(0, 2).map(w => w[0].toUpperCase()).join("") : "?";
}
function updateHeroStats() {
  if (intel) {
    $("statWindow").textContent = WINDOW_LABEL[intel.hours] || `${intel.hours} ώρες`;
    $("statFindings").textContent = intel.total_findings.toLocaleString("el-GR");
    $("statFindingsSub").textContent = intel.total_incidents ? `${Math.round(100 * intel.incidents_with_findings / intel.total_incidents)}% ελέγχων` : "";
  }
  const active = incidents.filter(x => ["OPEN", "ACKNOWLEDGED", "INVESTIGATING"].includes(x.status));
  $("statActive").textContent = active.length;
  const crit = active.filter(x => x.risk === "CRITICAL").length;
  $("statCritical").textContent = crit ? `${crit} critical` : "";
  $("statCritical").classList.toggle("hot", crit > 0);
  if (shadowTools.length) {
    const un = shadowTools.filter(t => t.status === "UNAPPROVED").length;
    $("statUnapproved").textContent = un;
    $("statTools").textContent = `από ${shadowTools.length}`;
  }
}
$("refreshAllBtn").onclick = async () => {
  $("refreshAllBtn").disabled = true;
  await loadDashboard();
  $("refreshAllBtn").disabled = false;
};
$("profileEdit").onclick = () => openSettings();
// Highlight the tab of the section in view.
const tabLinks = [...document.querySelectorAll(".tab")];
const spy = new IntersectionObserver(entries => entries.forEach(e => {
  if (e.isIntersecting) tabLinks.forEach(t => t.classList.toggle("active", t.getAttribute("href") === `#${e.target.id}`));
}), { rootMargin: "-40% 0px -55% 0px" });
["intelligence", "investigations", "dlp-policy", "shadow-radar", "users"].forEach(id => $(id) && spy.observe($(id)));

async function loadPolicy() {
  if (!hasAuth()) return;
  try {
    const data = await api("/api/admin/policy");
    $("policyRows").innerHTML = data.rows.map(r => `<tr class="static">
      <td>${esc(r.category)}</td>
      <td><div class="chips">${r.type_labels.map(l => `<span>${esc(l)}</span>`).join("")}</div></td>
      <td class="act">${policyTags(r.action)}</td>
      <td>${esc(r.why)}</td></tr>`).join("");
  } catch (err) { $("policyRows").innerHTML = `<tr class="static"><td colspan="4" class="empty">${esc(err.message)}</td></tr>`; }
}
function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
function formatDate(value) {
  if (!value) return "—";
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? String(value) : d.toLocaleString("el-GR");
}
function shortDate(value) {
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? "—" : d.toLocaleString("el-GR", { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" });
}
function duration(ms) {
  if (!(ms >= 0)) return "—";
  const m = Math.round(ms / 60000);
  if (m < 60) return `${m} λεπ.`;
  const h = m / 60;
  return h < 48 ? `${h.toFixed(1)} ώρ.` : `${(h / 24).toFixed(1)} ημ.`;
}
async function api(path, options = {}) {
  const response = await fetch(url(path), { credentials: "same-origin", ...options, headers: { ...adminHeaders(), ...(options.headers || {}) } });
  if (response.status === 401 && SESSION) { location.assign("/login/?next=/admin/"); throw new Error("Η σύνδεση έληξε."); }
  const data = await response.json().catch(() => ({ detail: "Μη έγκυρη απάντηση API" }));
  if (!response.ok) {
    const detail = Array.isArray(data.detail) ? data.detail.map(d => d.msg).join("; ") : data.detail;
    throw new Error(detail || `HTTP ${response.status}`);
  }
  return data;
}
const catChip = key => key && CATS[key]
  ? `<span class="cat-chip"><i style="background:${CATS[key].color}"></i>${esc(CATS[key].label)}</span>` : '<span class="muted">—</span>';

// ------------------------------ Settings ------------------------------
$("settingsBtn").onclick = () => openSettings();
function openSettings() {
  $("apiBase").value = SERVED_BY_BACKEND ? "" : (localStorage.getItem(BASE_KEY) ?? DEFAULT_API);
  $("adminToken").value = localStorage.getItem(TOKEN_KEY) || "";
  $("analystName").value = analyst();
  $("settingsDialog").showModal();
}
$("saveSettings").onclick = async e => {
  e.preventDefault();
  const b = $("apiBase").value.trim(), t = $("adminToken").value.trim(), a = $("analystName").value.trim();
  if (SERVED_BY_BACKEND) localStorage.removeItem(BASE_KEY);
  else if (b) localStorage.setItem(BASE_KEY, b); else localStorage.removeItem(BASE_KEY);
  if (t) localStorage.setItem(TOKEN_KEY, t); else localStorage.removeItem(TOKEN_KEY);
  if (a) localStorage.setItem(ANALYST_KEY, a); else localStorage.removeItem(ANALYST_KEY);
  showAnalyst();
  $("settingsDialog").close();
  await loadDashboard();
};

async function loadDashboard() {
  showAnalyst();
  await Promise.allSettled([loadIncidents(), loadIntelligence(), loadShadowRadar(), loadPolicy(), loadUsers()]);
  updateHeroStats();
}

// =================== 5. Sensitive Data Intelligence ===================
document.querySelectorAll("#intelWindow button").forEach(b => b.onclick = () => {
  document.querySelectorAll("#intelWindow button").forEach(x => x.classList.toggle("on", x === b));
  intelHours = Number(b.dataset.hours);
  loadIntelligence();
});
$("intelTableBtn").onclick = () => {
  const show = $("intelTable").hidden;
  $("intelTable").hidden = !show; $("intelCharts").hidden = show;
  $("intelTableBtn").setAttribute("aria-pressed", String(show));
  $("intelTableBtn").textContent = show ? "◔ Γραφήματα" : "▤ Πίνακας";
};
async function loadIntelligence() {
  if (!hasAuth()) return;
  try {
    intel = await api(`/api/admin/intelligence?hours=${intelHours}`);
    renderIntelligence();
  } catch (err) {
    $("catCards").innerHTML = `<p class="empty">${esc(err.message)}</p>`;
  }
}
function renderIntelligence() {
  const d = intel;
  $("intelThreatNote").textContent = d.threat_signals ? ` · Επιπλέον ${d.threat_signals} σήματα prompt injection.` : "";
  $("catCards").innerHTML = d.categories.map(c => `
    <article class="cat-card" style="--c:${CATS[c.key].color}">
      <div class="cat-top"><span class="cat-name"><i></i>${esc(c.label)}</span><span class="cat-share">${c.share.toLocaleString("el-GR")}%</span></div>
      <strong>${c.findings.toLocaleString("el-GR")}</strong><small>ευρήματα · ${c.incidents} συμβάντα</small>
      <div class="share-bar" role="img" aria-label="${esc(c.label)}: ${c.share}% των ευρημάτων"><span style="width:${c.share}%"></span></div>
      <p class="cat-ex">${esc(c.examples)}</p>
      <div class="type-list">${c.types.length ? c.types.slice(0, 4).map(t => `<span>${esc(t.type)} <b>${t.findings}</b></span>`).join("") : '<span class="muted">Κανένα εύρημα</span>'}</div>
    </article>`).join("");
  $("trendLegend").innerHTML = CAT_ORDER.map(k => `<span><i style="background:${CATS[k].color}"></i>${CATS[k].label}</span>`).join("");
  drawTrend(); drawProviders(); renderIntelTable(); updateHeroStats();
}
// Time buckets aligned to the Unix epoch, exactly like the backend query.
function bucketRange(hours, size) {
  const now = Math.floor(Date.now() / 1000);
  const last = Math.floor(now / size) * size;
  const first = Math.floor((now - hours * 3600) / size) * size;
  const out = [];
  for (let t = first; t <= last; t += size) out.push(t);
  return out;
}
const pad2 = n => String(n).padStart(2, "0");
function bucketLabel(t, size) {
  const d = new Date(t * 1000);
  return size >= 86400 ? `${pad2(d.getDate())}/${pad2(d.getMonth() + 1)}` : `${pad2(d.getHours())}:${pad2(d.getMinutes())}`;
}
function bucketTitle(t, size) {
  const a = new Date(t * 1000), b = new Date((t + size) * 1000);
  const day = `${pad2(a.getDate())}/${pad2(a.getMonth() + 1)}/${a.getFullYear()}`;
  return size >= 86400 ? day : `${day} · ${pad2(a.getHours())}:${pad2(a.getMinutes())}–${pad2(b.getHours())}:${pad2(b.getMinutes())}`;
}
// Axis top = 4 × a whole-number step, so every gridline label is an integer.
// Small ranges use any integer step (23 -> 6,12,18,24); larger ones 1/2/2.5/5 × 10^n.
function niceMax(v) {
  const raw = Math.max(1, v) / 4;
  if (raw <= 10) return Math.ceil(raw) * 4;
  const p = 10 ** Math.floor(Math.log10(raw));
  return [1, 2, 2.5, 5, 10].map(m => m * p).find(st => st >= raw) * 4;
}
const tip = $("vizTip");
function showTip(evt, html) {
  tip.innerHTML = html; tip.hidden = false;
  const r = tip.getBoundingClientRect();
  let x = evt.clientX + 14, y = evt.clientY + 14;
  if (x + r.width > innerWidth - 8) x = evt.clientX - r.width - 14;
  if (y + r.height > innerHeight - 8) y = evt.clientY - r.height - 14;
  tip.style.left = `${x}px`; tip.style.top = `${y}px`;
}
function hideTip() { tip.hidden = true; }
function roundedTop(x, y, w, h, r) {
  r = Math.min(r, w / 2, h);
  return `M${x},${y + h}V${y + r}Q${x},${y} ${x + r},${y}H${x + w - r}Q${x + w},${y} ${x + w},${y + r}V${y + h}Z`;
}
function roundedRight(x, y, w, h, r) {
  r = Math.min(r, h / 2, w);
  return `M${x},${y}H${x + w - r}Q${x + w},${y} ${x + w},${y + r}V${y + h - r}Q${x + w},${y + h} ${x + w - r},${y + h}H${x}Z`;
}
// Monotone cubic interpolation (no overshoot below 0 or between points).
function monotonePath(pts, move = true) {
  const n = pts.length;
  if (n < 2) return pts.length ? `${move ? "M" : "L"}${pts[0][0]},${pts[0][1]}` : "";
  const dx = [], m = [], t = [];
  for (let i = 0; i < n - 1; i++) { dx[i] = pts[i + 1][0] - pts[i][0]; m[i] = (pts[i + 1][1] - pts[i][1]) / dx[i]; }
  t[0] = m[0]; t[n - 1] = m[n - 2];
  for (let i = 1; i < n - 1; i++) t[i] = m[i - 1] * m[i] <= 0 ? 0 : 3 * (dx[i - 1] + dx[i]) / ((2 * dx[i] + dx[i - 1]) / m[i - 1] + (dx[i] + 2 * dx[i - 1]) / m[i]);
  let d = `${move ? "M" : "L"}${pts[0][0]},${pts[0][1]}`;
  for (let i = 0; i < n - 1; i++) {
    const h = dx[i] / 3;
    d += `C${pts[i][0] + h},${pts[i][1] + h * t[i]} ${pts[i + 1][0] - h},${pts[i + 1][1] - h * t[i + 1]} ${pts[i + 1][0]},${pts[i + 1][1]}`;
  }
  return d;
}
function drawTrend() {
  const el = $("trendChart");
  const size = intel.bucket_seconds;
  $("trendTitle").textContent = `Ευρήματα ${BUCKET_LABEL[size] || ""}`;
  const byDay = Object.fromEntries((intel.trend || []).map(t => [t.bucket, t]));
  const days = bucketRange(intel.hours, size);
  const val = (d, k) => byDay[d]?.[k] || 0;
  const totals = days.map(d => CAT_ORDER.reduce((n, k) => n + val(d, k), 0));
  const W = Math.max(320, el.clientWidth || 600), H = 230, L = 32, R = 12, T = 12, B = 26;
  const max = niceMax(Math.max(1, ...totals));
  const x = i => L + (days.length === 1 ? (W - L - R) / 2 : i * (W - L - R) / (days.length - 1));
  const y = v => T + (H - T - B) * (1 - v / max);
  // cumulative tops per category, bottom -> top in fixed category order
  const cum = []; let lower = days.map(() => 0);
  CAT_ORDER.forEach(k => { const upper = lower.map((v, i) => v + val(days[i], k)); cum.push({ k, lower, upper }); lower = upper; });
  let svg = `<svg viewBox="0 0 ${W} ${H}" width="100%" height="${H}" role="img" aria-label="Ευρήματα ανά χρονικό διάστημα και κατηγορία"><defs>` +
    CAT_ORDER.map(k => `<linearGradient id="g-${k}" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="${CATS[k].color}" stop-opacity=".55"/><stop offset="1" stop-color="${CATS[k].color}" stop-opacity=".12"/></linearGradient>`).join("") + `</defs>`;
  for (let i = 0; i <= 4; i++) {
    const v = max * i / 4, yy = y(v);
    svg += `<line x1="${L}" x2="${W - R}" y1="${yy}" y2="${yy}" class="grid"/><text x="${L - 8}" y="${yy + 3}" class="axis" text-anchor="end">${Math.round(v)}</text>`;
  }
  cum.forEach(({ k, lower, upper }) => {
    if (upper.every((v, i) => v === lower[i])) return;
    const up = upper.map((v, i) => [x(i), y(v)]), lo = lower.map((v, i) => [x(i), y(v)]).reverse();
    svg += `<path d="${monotonePath(up)}${monotonePath(lo, false)}Z" fill="url(#g-${k})"/>`;
    svg += `<path d="${monotonePath(up)}" fill="none" stroke="${CATS[k].color}" stroke-width="2" stroke-linejoin="round"/>`;
  });
  const labelEvery = Math.ceil(days.length / 7);
  days.forEach((d, i) => {
    const edge = i === 0 ? "start" : i === days.length - 1 ? "end" : "middle";
    if (i % labelEvery === 0 && days.length - 1 - i >= labelEvery / 2 || i === days.length - 1)
      svg += `<text x="${x(i)}" y="${H - 7}" class="axis" text-anchor="${edge}">${bucketLabel(d, size)}</text>`;
  });
  svg += `<g class="cross" visibility="hidden"><line class="cross-line" y1="${T}" y2="${H - B}"/>` +
    CAT_ORDER.map(k => `<circle r="4.5" fill="${CATS[k].color}" stroke="#1e2453" stroke-width="2" data-k="${k}"/>`).join("") + `</g>`;
  svg += `<rect class="hit" x="${L}" y="${T}" width="${W - L - R}" height="${H - T - B}"/>`;
  el.innerHTML = svg + "</svg>";
  const cross = el.querySelector(".cross"), line = el.querySelector(".cross-line"), hit = el.querySelector(".hit");
  hit.onmousemove = e => {
    const r = hit.getBoundingClientRect(), px = (e.clientX - r.left) * (W - L - R) / r.width;
    const i = Math.max(0, Math.min(days.length - 1, Math.round(px / ((W - L - R) / Math.max(1, days.length - 1)))));
    const d = days[i];
    cross.setAttribute("visibility", "visible");
    line.setAttribute("x1", x(i)); line.setAttribute("x2", x(i));
    cum.forEach(({ k, upper, lower }) => {
      const c = cross.querySelector(`circle[data-k="${k}"]`);
      c.setAttribute("cx", x(i)); c.setAttribute("cy", y(upper[i]));
      c.setAttribute("visibility", upper[i] > lower[i] ? "visible" : "hidden");
    });
    showTip(e, `<b>${bucketTitle(d, size)}</b>` +
      CAT_ORDER.map(k => `<span class="tip-row"><i style="background:${CATS[k].color}"></i>${CATS[k].label}<b>${val(d, k)}</b></span>`).join("") +
      `<span class="tip-row total">Σύνολο<b>${totals[i]}</b></span>`);
  };
  hit.onmouseleave = () => { cross.setAttribute("visibility", "hidden"); hideTip(); };
}
function drawProviders() {
  const el = $("providerChart");
  const rows = (intel.providers || []).slice(0, 8);
  if (!rows.length) { el.innerHTML = '<p class="empty">Δεν υπάρχουν ευρήματα σε αυτό το διάστημα.</p>'; return; }
  const W = Math.max(300, el.clientWidth || 400), rowH = 30, L = 92, R = 40, H = rows.length * rowH + 6;
  const max = Math.max(...rows.map(r => r.findings));
  const sx = v => (W - L - R) * v / max;
  let svg = `<svg viewBox="0 0 ${W} ${H}" width="100%" height="${H}" role="img" aria-label="Ευρήματα ανά AI provider">`;
  rows.forEach((p, i) => {
    const yy = i * rowH + 7, bh = 12;
    let x = L;
    const present = CAT_ORDER.filter(k => p[k] > 0);
    svg += `<text x="${L - 8}" y="${yy + 11}" class="axis strong" text-anchor="end">${esc(p.provider)}</text>`;
    present.forEach((k, j) => {
      const w = Math.max(1, sx(p[k]) - (j < present.length - 1 ? 2 : 0));
      svg += j === present.length - 1 ? `<path d="${roundedRight(x, yy, w, bh, 6)}" fill="${CATS[k].color}" class="seg-mark" data-p="${i}" data-k="${k}"/>`
        : `<rect x="${x}" y="${yy}" width="${w}" height="${bh}" fill="${CATS[k].color}" class="seg-mark" data-p="${i}" data-k="${k}"/>`;
      x += sx(p[k]);
    });
    svg += `<text x="${L + sx(p.findings) + 6}" y="${yy + 11}" class="axis">${p.findings}</text>`;
  });
  el.innerHTML = svg + "</svg>";
  el.querySelectorAll(".seg-mark").forEach(m => {
    const p = rows[Number(m.dataset.p)], k = m.dataset.k;
    m.onmousemove = e => showTip(e, `<b>${esc(p.provider)}</b><br><span class="tip-row"><i style="background:${CATS[k].color}"></i>${CATS[k].label}<b>${p[k]}</b></span><span class="tip-row total">Σύνολο provider<b>${p.findings}</b></span>`);
    m.onmouseleave = hideTip;
  });
}
function renderIntelTable() {
  const d = intel;
  $("intelTable").innerHTML = `<table><thead><tr><th>ΚΑΤΗΓΟΡΙΑ</th><th>ΕΥΡΗΜΑΤΑ</th><th>ΠΟΣΟΣΤΟ</th><th>ΣΥΜΒΑΝΤΑ</th><th>ΤΥΠΟΙ</th></tr></thead><tbody>` +
    d.categories.map(c => `<tr class="static"><td>${catChip(c.key)}</td><td>${c.findings}</td><td>${c.share}%</td><td>${c.incidents}</td><td>${esc(c.types.map(t => `${t.type} (${t.findings})`).join(", ") || "—")}</td></tr>`).join("") +
    `</tbody></table><table><thead><tr><th>AI PROVIDER</th>${CAT_ORDER.map(k => `<th>${CATS[k].label.toUpperCase()}</th>`).join("")}<th>ΣΥΝΟΛΟ</th></tr></thead><tbody>` +
    (d.providers.length ? d.providers.map(p => `<tr class="static"><td>${esc(p.provider)}</td>${CAT_ORDER.map(k => `<td>${p[k]}</td>`).join("")}<td><b>${p.findings}</b></td></tr>`).join("") : '<tr class="static"><td colspan="7" class="empty">—</td></tr>') +
    `</tbody></table>`;
}
let resizeTimer;
addEventListener("resize", () => { clearTimeout(resizeTimer); resizeTimer = setTimeout(() => { if (intel) { drawTrend(); drawProviders(); } }, 150); });

// =================== 6. Incident Investigation Center ===================
$("refreshBtn").onclick = loadIncidents;
const PAGE = 15;
let shown = PAGE;
const SEV = { CRITICAL: 3, HIGH: 2, MEDIUM: 1, LOW: 0 };
$("moreBtn").onclick = () => { shown += PAGE; renderIncidentRows(); };
const resetAndRender = () => { shown = PAGE; renderIncidentRows(); };
$("searchInput").addEventListener("input", resetAndRender);
["statusFilter", "riskFilter", "categoryFilter", "providerFilter"].forEach(id => $(id).onchange = resetAndRender);
document.querySelectorAll(".kpi").forEach(k => k.onclick = () => { $("statusFilter").value = k.dataset.status; resetAndRender(); });
$("categoryFilter").innerHTML = '<option value="">Όλες οι κατηγορίες</option>' +
  [...CAT_ORDER, "THREAT"].map(k => `<option value="${k}">${CATS[k].label}</option>`).join("");

async function loadIncidents() {
  if (!hasAuth()) { setConnection("Απαιτείται σύνδεση"); location.assign("/login/?next=/admin/"); return; }
  $("refreshBtn").disabled = true; $("refreshBtn").textContent = "Φόρτωση…";
  let failed = false;
  try {
    const data = await api("/api/admin/incidents?limit=500");
    incidents = Array.isArray(data.incidents) ? data.incidents : [];
    resolutionCategories = data.resolution_categories || {};
    $("resolveCategory").innerHTML = '<option value="">— Επίλεξε —</option>' +
      Object.entries(resolutionCategories).map(([k, v]) => `<option value="${esc(k)}">${esc(v)}</option>`).join("");
    const providers = [...new Set(incidents.map(x => x.tool_name))].sort();
    const current = $("providerFilter").value;
    $("providerFilter").innerHTML = '<option value="">Όλοι οι providers</option>' + providers.map(p => `<option ${p === current ? "selected" : ""}>${esc(p)}</option>`).join("");
    setConnection("Συνδεδεμένο", true);
  } catch (err) {
    setConnection(err.message); incidents = []; failed = true;
    $("incidentRows").innerHTML = `<tr><td colspan="8" class="empty">${esc(err.message)} — έλεγξε URL, token και backend.</td></tr>`;
  } finally {
    $("refreshBtn").disabled = false; $("refreshBtn").textContent = "↻ Ανανέωση";
    renderKpis(); if (!failed) renderIncidentRows(); updateHeroStats();
  }
}
function renderKpis() {
  const count = s => incidents.filter(x => x.status === s).length;
  $("kpiOpen").textContent = count("OPEN");
  $("kpiAck").textContent = count("ACKNOWLEDGED");
  $("kpiInv").textContent = count("INVESTIGATING");
  $("kpiRes").textContent = count("RESOLVED");
  const times = incidents.filter(x => x.status === "RESOLVED" && x.status_updated_at)
    .map(x => new Date(x.status_updated_at) - new Date(x.created_at)).filter(n => n >= 0);
  $("kpiMttr").textContent = `Μέσος χρόνος επίλυσης ${times.length ? duration(times.reduce((a, b) => a + b, 0) / times.length) : "—"}`;
  document.querySelectorAll(".kpi").forEach(k => k.classList.toggle("on", k.dataset.status === $("statusFilter").value));
}
function rowActions(x) {
  const b = (a, label, cls = "btn-outline") => `<button class="btn btn-sm ${cls}" data-act="${a}" data-id="${esc(x.id)}">${label}</button>`;
  switch (x.status) {
    case "OPEN": return b("ACKNOWLEDGE", "Acknowledge") + b("INVESTIGATE", "Investigate") + b("RESOLVE", "Resolve");
    case "ACKNOWLEDGED": return b("INVESTIGATE", "Investigate", "btn-primary") + b("RESOLVE", "Resolve");
    case "INVESTIGATING": return b("VIEW", "Ανάλυση", "btn-primary") + b("RESOLVE", "Resolve");
    default: return b("VIEW", "Προβολή");
  }
}
function renderIncidentRows() {
  const q = $("searchInput").value.toLowerCase().trim(), st = $("statusFilter").value, risk = $("riskFilter").value,
        cat = $("categoryFilter").value, prov = $("providerFilter").value;
  const rows = incidents.filter(x =>
    (st === "ACTIVE" ? ["OPEN", "ACKNOWLEDGED", "INVESTIGATING"].includes(x.status) : !st || x.status === st) &&
    (!risk || String(x.risk).toUpperCase() === risk) &&
    (!cat || (x.categories || []).includes(cat)) &&
    (!prov || x.tool_name === prov) &&
    (!q || [x.id, x.tool_name, x.user_id, x.assigned_to].some(v => String(v ?? "").toLowerCase().includes(q))));
  // Triage order for active work: highest severity first, then oldest waiting first.
  // Resolved / all: newest first.
  const activeView = st === "ACTIVE" || ["OPEN", "ACKNOWLEDGED", "INVESTIGATING"].includes(st);
  rows.sort((a, b) => activeView
    ? (SEV[b.risk] ?? 0) - (SEV[a.risk] ?? 0) || new Date(a.created_at) - new Date(b.created_at)
    : new Date(b.created_at) - new Date(a.created_at));
  const total = rows.length;
  rows.splice(shown);
  $("rowCount").textContent = `${total} ${total === 1 ? "περιστατικό" : "περιστατικά"}${total > rows.length ? ` · εμφανίζονται ${rows.length}` : ""}`;
  $("moreRow").hidden = total <= rows.length;
  document.querySelectorAll(".kpi").forEach(k => k.classList.toggle("on", k.dataset.status === st));
  $("incidentRows").innerHTML = rows.length ? rows.map(x => {
    const more = (x.categories || []).filter(c => c !== x.primary_category).length;
    const src = String(x.user_id || "").startsWith("team:") ? `Extension · ${esc(String(x.user_id).slice(5))}` : `Gateway · ${esc(x.user_id)}`;
    return `<tr data-id="${esc(x.id)}">
      <td><b>#${esc(x.id)}</b><small class="sub">${src}</small></td>
      <td><span class="tag ${esc(String(x.risk).toUpperCase())}">${esc(x.risk)}</span></td>
      <td>${esc(x.tool_name)}${x.content_type === "pdf" ? ' <span class="tag file" title="Ο έλεγχος αφορά συνημμένο PDF">PDF</span>' : ""}</td>
      <td>${catChip(x.primary_category)}${more ? `<small class="sub">+${more} ακόμη</small>` : ""}</td>
      <td><span class="tag ${esc(String(x.action).toUpperCase())}">${esc(x.action)}</span>${x.action === "WARN" ? `<small class="sub">${x.user_confirmed_at ? "✓ στάλθηκε μετά από επιβεβαίωση" : "δεν επιβεβαιώθηκε"}</small>` : ""}</td>
      <td title="${esc(formatDate(x.created_at))}">${esc(shortDate(x.created_at))}</td>
      <td><span class="tag st-${esc(x.status)}">${esc(STATUS_EL[x.status] || x.status)}</span>${x.assigned_to ? `<small class="sub">${esc(x.assigned_to)}</small>` : ""}</td>
      <td class="right actions">${rowActions(x)}</td></tr>`;
  }).join("") : `<tr><td colspan="8" class="empty">${incidents.length ? "Κανένα περιστατικό με αυτά τα φίλτρα." : "Δεν υπάρχουν ακόμη περιστατικά."}</td></tr>`;
  document.querySelectorAll("#incidentRows tr[data-id]").forEach(tr => tr.onclick = e => {
    const btn = e.target.closest("button[data-act]");
    if (btn) { e.stopPropagation(); handleAction(btn.dataset.act, Number(btn.dataset.id), btn); }
    else openCase(Number(tr.dataset.id));
  });
}
function requireAnalyst() {
  if (analyst()) return true;
  alert("Συμπλήρωσε πρώτα το «Όνομα analyst» στις Ρυθμίσεις. Καταγράφεται σε κάθε ενέργεια.");
  openSettings();
  return false;
}
async function postAction(id, action, extra = {}) {
  return api(`/api/admin/incidents/${encodeURIComponent(id)}/actions`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ action, analyst: analyst(), ...extra })
  });
}
async function handleAction(act, id, btn) {
  if (act === "VIEW") return openCase(id);
  if (act === "RESOLVE") { if (requireAnalyst()) openCase(id, true); return; }
  if (!requireAnalyst()) return;
  if (btn) btn.disabled = true;
  try {
    await postAction(id, act);
    await loadIncidents();
    if (act === "INVESTIGATE") await openCase(id);
  } catch (err) { alert(`${ACTION_EL[act]}: ${err.message}`); if (btn) btn.disabled = false; }
}

// ------------------------------ Case view ------------------------------
let currentCase = null;
$("closeCase").onclick = () => $("caseDialog").close();
$("cancelResolve").onclick = () => { $("resolveForm").hidden = true; renderCaseActions(); };
$("resolveForm").onsubmit = async e => {
  e.preventDefault();
  if (!requireAnalyst()) return;
  const note = $("resolveNote").value.trim(), category = $("resolveCategory").value;
  if (!category || note.length < 10) { alert("Επίλεξε κατηγορία και γράψε αιτιολογία τουλάχιστον 10 χαρακτήρων."); return; }
  try {
    await postAction(currentCase, "RESOLVE", { note, resolution_category: category });
    $("resolveNote").value = ""; $("resolveForm").hidden = true;
    await loadIncidents(); await Promise.allSettled([openCase(currentCase), loadIntelligence()]);
  } catch (err) { alert(`Επίλυση: ${err.message}`); }
};
async function openCase(id, resolve = false) {
  currentCase = id;
  $("caseTitle").textContent = `Incident #${id}`; $("caseTags").innerHTML = "";
  $("caseBody").innerHTML = '<p class="muted">Φόρτωση ανάλυσης…</p>'; $("caseActions").innerHTML = "";
  $("resolveForm").hidden = true;
  if (!$("caseDialog").open) $("caseDialog").showModal();
  try {
    const data = await api(`/api/admin/incidents/${encodeURIComponent(id)}`);
    renderCase(data);
    if (resolve && data.incident.status !== "RESOLVED") { $("resolveForm").hidden = false; $("caseActions").innerHTML = ""; $("resolveCategory").focus(); }
  } catch (err) { $("caseBody").innerHTML = `<p class="empty">${esc(err.message)}</p>`; }
}
let caseData = null;
function renderCaseActions() {
  const x = caseData?.incident; if (!x) return;
  $("caseActions").innerHTML = rowActions(x);
  $("caseActions").querySelectorAll("button[data-act]").forEach(b => {
    if (b.dataset.act === "VIEW") { b.remove(); return; }
    b.onclick = async () => {
      if (b.dataset.act === "RESOLVE") { if (requireAnalyst()) { $("resolveForm").hidden = false; $("caseActions").innerHTML = ""; } return; }
      await handleAction(b.dataset.act, x.id, b);
      if (b.dataset.act === "ACKNOWLEDGE") await openCase(x.id);
    };
  });
}
function renderCase(data) {
  caseData = data;
  const x = data.incident, a = data.analysis;
  $("caseEyebrow").textContent = `INCIDENT · ${a.source.toUpperCase()}`;
  $("caseTags").innerHTML = `<span class="tag ${esc(x.risk)}">${esc(x.risk)}</span> <span class="tag ${esc(x.action)}">${esc(x.action)}</span> <span class="tag st-${esc(x.status)}">${esc(STATUS_EL[x.status] || x.status)}</span>`;
  const policyTag = a.provider_policy_status ? `<span class="tag pol-${esc(a.provider_policy_status)}">${esc(a.provider_policy_status)}</span>` : '<span class="muted">εκτός inventory</span>';
  const fx = a.findings.length ? a.findings.map(f => `<tr class="static"><td><code>${esc(f.type)}</code></td><td>${catChip(f.category)}</td><td><span class="tag ${esc(String(f.severity).toUpperCase())}">${esc(f.severity)}</span></td><td>${f.policy_action ? policyTags(f.policy_action) : "—"}</td><td>${esc(f.count)}</td><td>${esc(f.detected_by)}</td></tr>`).join("")
    : '<tr class="static"><td colspan="6" class="empty">Χωρίς ευρήματα</td></tr>';
  const tl = [{ action: "DETECTED", analyst: "AI Shield", to_status: "OPEN", note: `${x.action} · ${x.risk}`, created_at: x.created_at }, ...data.activity];
  $("caseBody").innerHTML = `
    <div class="kv">
      <div><span>AI provider</span><b>${esc(x.tool_name)}</b></div>
      <div><span>Provider policy (Shadow AI)</span>${policyTag}</div>
      <div><span>Πηγή</span><b>${esc(a.source)}</b>${x.content_type === "pdf" ? '<small class="sub">Ελέγχθηκε το κείμενο του αρχείου· όνομα και περιεχόμενο δεν αποθηκεύονται.</small>' : ""}</div>
      <div><span>Ομάδα / χρήστης</span><b>${esc(a.team_or_user)}</b></div>
      <div><span>Detection category</span>${catChip(a.primary_category)}</div>
      <div><span>Timestamp</span><b>${esc(formatDate(x.created_at))}</b></div>
      <div><span>Analyst</span><b>${esc(x.assigned_to || "—")}</b></div>
      <div><span>${x.action === "WARN" ? "Επιβεβαίωση χρήστη" : "Τελευταία αλλαγή"}</span><b>${x.action === "WARN" ? (x.user_confirmed_at ? "Ναι · " + esc(formatDate(x.user_confirmed_at)) : "Όχι") : esc(formatDate(x.status_updated_at))}</b></div>
    </div>
    <div class="callout ${["PSEUDONYMIZE", "REDACT", "BLOCK", "ALLOW"].includes(x.action) || (x.action === "WARN" && !x.user_confirmed_at) ? "ok" : "warn"}"><b>Έκθεση δεδομένων</b>${esc(a.data_exposure)}</div>
    <h4>Ευρήματα</h4>
    <div class="table-wrap"><table class="mini"><thead><tr><th>ΤΥΠΟΣ</th><th>ΚΑΤΗΓΟΡΙΑ</th><th>SEVERITY</th><th>ΕΝΕΡΓΕΙΑ DLP</th><th>ΠΛΗΘΟΣ</th><th>ΕΝΤΟΠΙΣΤΗΚΕ ΑΠΟ</th></tr></thead><tbody>${fx}</tbody></table></div>
    <h4>Συσχέτιση (±24 ώρες)</h4>
    <div class="kv three">
      <div><span>Ίδιος provider</span><b>${a.related.same_provider_24h}</b></div>
      <div><span>Ίδια ομάδα / χρήστης</span><b>${a.related.same_source_24h}</b></div>
      <div><span>Ανοιχτά της ίδιας πηγής</span><b>${a.related.same_source_open}</b></div>
    </div>
    <h4>Προτεινόμενες ενέργειες</h4>
    <ul class="recs">${a.recommendations.map(r => `<li>${esc(r)}</li>`).join("") || "<li>—</li>"}</ul>
    ${x.status === "RESOLVED" ? `<div class="callout ok"><b>Επίλυση · ${esc(resolutionCategories[x.resolution_category] || x.resolution_category || "")}</b>${esc(x.resolution_note || "")}</div>` : ""}
    <h4>Χρονολόγιο</h4>
    <ol class="timeline">${tl.map(t => `<li><b>${esc(t.action === "DETECTED" ? "Εντοπισμός" : ACTION_EL[t.action] || t.action)}</b> → ${esc(STATUS_EL[t.to_status] || t.to_status)} <span class="muted">· ${esc(t.analyst)} · ${esc(formatDate(t.created_at))}</span>${t.note && t.action !== "DETECTED" ? `<p>${esc(t.note)}</p>` : ""}</li>`).join("")}</ol>
    <p class="privacy-line">${esc(a.privacy_note)}</p>`;
  renderCaseActions();
}

// --------------------------- AI Shadow Radar ---------------------------
async function loadShadowRadar() {
  if (!hasAuth()) return;
  $("refreshShadowBtn").disabled = true; $("refreshShadowBtn").textContent = "Φόρτωση…";
  try {
    const [inventory, events] = await Promise.all([
      api("/api/admin/shadow/inventory"),
      api("/api/admin/shadow/events?limit=100")
    ]);
    shadowTools = Array.isArray(inventory.tools) ? inventory.tools : [];
    shadowEvents = Array.isArray(events.events) ? events.events : [];
    renderShadowRadar(); updateHeroStats();
  } catch (err) {
    $("shadowToolRows").innerHTML = `<tr><td colspan="6" class="empty">${esc(err.message)}</td></tr>`;
    $("shadowEventRows").innerHTML = `<tr><td colspan="6" class="empty">${esc(err.message)}</td></tr>`;
  } finally {
    $("refreshShadowBtn").disabled = false; $("refreshShadowBtn").textContent = "↻ Ανανέωση";
  }
}
function renderShadowRadar() {
  const unapproved = shadowTools.filter(t => t.status === "UNAPPROVED").length;
  const visits = shadowTools.reduce((n, t) => n + Number(t.events_7d || 0), 0);
  const teams = new Set(shadowTools.flatMap(t => t.teams || [])).size;
  $("shadowToolsMetric").textContent = shadowTools.length;
  $("shadowUnapprovedMetric").textContent = unapproved;
  $("shadowEventsMetric").textContent = visits;
  $("shadowTeamsMetric").textContent = teams;
  $("shadowRowCount").textContent = `${shadowTools.length} AI domains`;
  $("shadowToolRows").innerHTML = shadowTools.length ? shadowTools.map(t => `<tr>
    <td><b>${esc(t.provider_name)}</b><br><small>${esc(t.category)}</small></td>
    <td>${esc(t.domain)}</td>
    <td><select class="status-select ${esc(t.status)}" data-tool-id="${esc(t.id)}" aria-label="Policy status for ${esc(t.provider_name)}">
      <option value="APPROVED" ${t.status === "APPROVED" ? "selected" : ""}>APPROVED</option>
      <option value="REVIEW" ${t.status === "REVIEW" ? "selected" : ""}>REVIEW</option>
      <option value="UNAPPROVED" ${t.status === "UNAPPROVED" ? "selected" : ""}>UNAPPROVED</option>
    </select></td>
    <td>${Number(t.events_7d || 0)}</td>
    <td>${esc((t.teams || []).join(", ") || "—")}</td>
    <td>${esc(formatDate(t.last_seen))}</td>
  </tr>`).join("") : '<tr><td colspan="6" class="empty">Δεν υπάρχουν AI tools στο inventory.</td></tr>';
  document.querySelectorAll(".status-select").forEach(select => select.onchange = () => updateShadowStatus(select));
  $("shadowEventRows").innerHTML = shadowEvents.length ? shadowEvents.map(e => `<tr>
    <td>${esc(e.provider_name)}</td><td>${esc(e.domain)}</td><td>${esc(e.team_label)}</td>
    <td><span class="tag ${e.status_at_time === "APPROVED" ? "ALLOW" : e.status_at_time === "UNAPPROVED" ? "BLOCK" : "WARN"}">${esc(e.status_at_time)}</span></td>
    <td>${esc(e.source)}</td><td>${esc(formatDate(e.observed_at))}</td>
  </tr>`).join("") : '<tr><td colspan="6" class="empty">Δεν υπάρχουν ακόμη events. Εγκατέστησε το extension ή φόρτωσε synthetic demo data.</td></tr>';
}
async function updateShadowStatus(select) {
  const toolId = select.dataset.toolId, status = select.value;
  select.disabled = true;
  try {
    await api(`/api/admin/shadow/tools/${encodeURIComponent(toolId)}`, {
      method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ status })
    });
    await loadShadowRadar();
  } catch (err) {
    alert(`Δεν αποθηκεύτηκε η πολιτική: ${err.message}`);
    await loadShadowRadar();
  } finally { select.disabled = false; }
}
$("seedShadowBtn").onclick = async () => {
  if (!confirm("Να προστεθούν 48 synthetic demo events; Θα εμφανίζονται με source synthetic-demo.")) return;
  try {
    const result = await api("/api/admin/shadow/demo-seed", { method: "POST" });
    alert(`Προστέθηκαν ${result.inserted} synthetic events.`); await loadShadowRadar();
  } catch (err) { alert(`Αποτυχία δημιουργίας demo data: ${err.message}`); }
};

async function initSession() {
  try {
    const res = await fetch("/api/auth/me", { credentials: "same-origin" });
    if (res.ok) SESSION = (await res.json()).user;
  } catch { /* opened without the backend (file://): token mode */ }
  if (!SESSION) return;
  $("userName").textContent = SESSION.name;
  $("userRole").textContent = "Διαχειριστής";
  $("userChip").hidden = false;
  $("logoutBtn").hidden = false;
  $("settingsBtn").hidden = true;      // nothing to configure: the session is the credential
  $("profileEdit").hidden = true;
  $("logoutBtn").onclick = async () => {
    try { await fetch("/api/auth/logout", { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" }, body: "{}" }); } catch {}
    location.assign("/login/");
  };
}
initSession().then(loadDashboard);


// ===================== Users: registration by email & access =====================
let users = [], meId = null;
const USER_STATUS = { active: "Ενεργός", invited: "Εκκρεμεί πρόσκληση", disabled: "Απενεργοποιημένος" };
const ACCOUNT_ACT = { CREATE: "ΕΓΓΡΑΦΗ", INVITE: "ΠΡΟΣΚΛΗΣΗ", ACTIVATE: "ΕΝΕΡΓΟΠΟΙΗΣΗ", ROLE: "ΡΟΛΟΣ",
  DISABLE: "ΑΠΕΝΕΡΓΟΠΟΙΗΣΗ", ENABLE: "ΕΠΑΝΕΝΕΡΓΟΠΟΙΗΣΗ", DELETE: "ΔΙΑΓΡΑΦΗ", RENAME: "ΟΝΟΜΑ" };

async function loadUsers() {
  if (!hasAuth()) return;
  try {
    const data = await api("/api/admin/users");
    users = data.users; meId = data.me;
    $("inviteHint").textContent = data.mail_configured
      ? `Θα σταλεί email πρόσκλησης που ισχύει ${data.invite_hours} ώρες.`
      : `Δεν έχει ρυθμιστεί αποστολή email (SMTP): θα πάρεις σύνδεσμο πρόσκλησης (${data.invite_hours} ώρες) να τον στείλεις εσύ.`;
    renderUsers();
    $("acctLog").innerHTML = data.activity.length ? data.activity.map(a => `<li><span class="act">${esc(ACCOUNT_ACT[a.action] || a.action)}</span>
      <span><b>${esc(a.target_email)}</b>${a.detail ? ` · ${esc(a.detail)}` : ""} <span class="muted">από ${esc(a.actor)}</span></span>
      <time>${esc(formatDate(a.created_at))}</time></li>`).join("") : '<li class="muted">Δεν υπάρχουν ακόμα ενέργειες.</li>';
  } catch (err) {
    $("userRows").innerHTML = `<tr class="static"><td colspan="6" class="empty">${esc(err.message)}</td></tr>`;
  }
}
function renderUsers() {
  const q = $("userSearch").value.trim().toLowerCase(), st = $("userStatusFilter").value, role = $("userRoleFilter").value;
  const rows = users.filter(u => (!st || u.status === st) && (!role || u.role === role) &&
    (!q || `${u.name} ${u.email}`.toLowerCase().includes(q)));
  $("usersTotal").textContent = users.length;
  $("usersAdmins").textContent = users.filter(u => u.role === "admin" && u.status !== "disabled").length;
  $("usersInvited").textContent = users.filter(u => u.status === "invited").length;
  $("usersDisabled").textContent = users.filter(u => u.status === "disabled").length;
  $("userCount").textContent = `${rows.length} από ${users.length} χρήστες`;
  $("userRows").innerHTML = rows.length ? rows.map(u => {
    const me = u.id === meId;
    const methods = [u.password ? "Κωδικός" : "", u.google ? "Google" : ""].filter(Boolean);
    const invite = u.status === "invited" && u.invite_expires_at
      ? `<small class="sub">${new Date(u.invite_expires_at) < new Date() ? "η πρόσκληση έληξε" : `λήγει ${esc(shortDate(u.invite_expires_at))}`}</small>` : "";
    const actions = me ? '<span class="muted">—</span>' : [
      u.status === "invited" ? `<button class="btn btn-sm btn-outline" data-uact="invite" data-id="${u.id}">✉ Νέα πρόσκληση</button>` : "",
      u.status === "disabled" ? `<button class="btn btn-sm btn-outline" data-uact="enable" data-id="${u.id}">Ενεργοποίηση</button>`
                              : `<button class="btn btn-sm btn-outline" data-uact="disable" data-id="${u.id}">Απενεργοποίηση</button>`,
      `<button class="btn btn-sm btn-danger" data-uact="delete" data-id="${u.id}" aria-label="Διαγραφή ${esc(u.email)}">Διαγραφή</button>`
    ].join("");
    return `<tr class="static" data-user="${u.id}">
      <td class="u-who"><b>${esc(u.name)}${me ? '<span class="me">ΕΣΥ</span>' : ""}</b><small>${esc(u.email)}</small></td>
      <td><select data-role="${u.id}" ${me ? "disabled title=\"Δεν αλλάζεις τον δικό σου ρόλο\"" : ""} aria-label="Ρόλος ${esc(u.email)}">
        <option value="user" ${u.role === "user" ? "selected" : ""}>Χρήστης</option>
        <option value="admin" ${u.role === "admin" ? "selected" : ""}>Διαχειριστής</option></select></td>
      <td><span class="tag u-${esc(u.status)}">${esc(USER_STATUS[u.status] || u.status)}</span>${invite}</td>
      <td class="methods">${methods.length ? methods.map(m => `<span>${m}</span>`).join("") : '<span class="muted">—</span>'}</td>
      <td>${u.last_login_at ? esc(shortDate(u.last_login_at)) : '<span class="muted">ποτέ</span>'}</td>
      <td class="right actions">${actions}</td></tr>`;
  }).join("") : '<tr class="static"><td colspan="6" class="empty">Κανένας χρήστης με αυτά τα φίλτρα.</td></tr>';
  document.querySelectorAll("#userRows select[data-role]").forEach(sel => sel.onchange = () => changeRole(sel));
  document.querySelectorAll("#userRows button[data-uact]").forEach(b => b.onclick = () => userAction(b.dataset.uact, Number(b.dataset.id), b));
}
["userSearch", "userStatusFilter", "userRoleFilter"].forEach(id => $(id).addEventListener("input", renderUsers));
$("refreshUsersBtn").onclick = loadUsers;

function inviteResult(html, kind) {
  const el = $("inviteResult");
  el.className = `invite-result ${kind}`; el.innerHTML = html; el.hidden = false;
  const copy = el.querySelector("[data-copylink]");
  if (copy) copy.onclick = async () => {
    const input = el.querySelector("input"); input.select();
    try { await navigator.clipboard.writeText(input.value); copy.textContent = "✓ Αντιγράφηκε"; } catch { document.execCommand("copy"); }
  };
}
function inviteOutcome(email, data) {
  if (data.invite_sent) return inviteResult(`✉ Στάλθηκε email πρόσκλησης στο <b>${esc(email)}</b>. Ισχύει ${data.invite_hours} ώρες.`, "ok");
  inviteResult(`Ο λογαριασμός <b>${esc(email)}</b> είναι έτοιμος, αλλά δεν έχει ρυθμιστεί αποστολή email (SMTP).
    Στείλε του αυτόν τον σύνδεσμο (ισχύει ${data.invite_hours} ώρες, μία χρήση). Δίνει πρόσβαση στον λογαριασμό, οπότε στείλ' τον μόνο στον ίδιο:
    <div class="link-row"><input readonly value="${esc(data.invite_link)}" aria-label="Σύνδεσμος πρόσκλησης"><button type="button" class="btn btn-sm btn-primary" data-copylink>Αντιγραφή</button></div>`, "warn");
}

$("inviteForm").addEventListener("submit", async e => {
  e.preventDefault();
  const email = $("inviteEmail").value.trim(), name = $("inviteName").value.trim(), role = $("inviteRole").value;
  const bad = !/^[^@\s]+@[^@\s]+\.[^@\s]{2,}$/.test(email);
  $("inviteEmail").setAttribute("aria-invalid", String(bad));
  if (bad) { inviteResult("Γράψε ένα έγκυρο email.", "err"); $("inviteEmail").focus(); return; }
  if (role === "admin" && !confirm(`Ο/Η ${email} θα έχει πλήρη πρόσβαση στο Admin Console. Συνέχεια;`)) return;
  const btn = $("inviteBtn"); btn.disabled = true;
  try {
    const data = await api("/api/admin/users", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email, name, role }) });
    inviteOutcome(data.user.email, data);
    $("inviteForm").reset();
    await loadUsers();
  } catch (err) {
    inviteResult(esc(err.message), "err");
  } finally { btn.disabled = false; }
});

async function changeRole(sel) {
  const u = users.find(x => x.id === Number(sel.dataset.role));
  const to = sel.value;
  if (to === "admin" && !confirm(`Ο/Η ${u.email} θα γίνει διαχειριστής με πλήρη πρόσβαση. Συνέχεια;`)) { sel.value = u.role; return; }
  sel.disabled = true;
  try {
    await api(`/api/admin/users/${u.id}`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ role: to }) });
  } catch (err) { alert(err.message); }
  await loadUsers();
}
async function userAction(act, id, btn) {
  const u = users.find(x => x.id === id);
  const ask = { disable: `Απενεργοποίηση του ${u.email}; Θα αποσυνδεθεί αμέσως από κάθε συσκευή.`,
                delete: `Οριστική διαγραφή του λογαριασμού ${u.email}; Τα περιστατικά του παραμένουν στο ιστορικό.` }[act];
  if (ask && !confirm(ask)) return;
  btn.disabled = true;
  try {
    if (act === "invite") {
      const data = await api(`/api/admin/users/${id}/invite`, { method: "POST" });
      inviteOutcome(u.email, data);
      $("inviteResult").scrollIntoView({ behavior: "smooth", block: "center" });
    } else if (act === "delete") {
      await api(`/api/admin/users/${id}`, { method: "DELETE" });
    } else {
      await api(`/api/admin/users/${id}`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ disabled: act === "disable" }) });
    }
  } catch (err) { alert(err.message); }
  await loadUsers();
}
