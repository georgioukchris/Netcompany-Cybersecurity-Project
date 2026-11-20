/* AI Shield — extension settings page. */
const api = globalThis.browser || globalThis.chrome;
const $ = id => document.getElementById(id);
const FIELDS = ["apiBase", "discoveryToken", "teamLabel", "promptGuardEnabled", "restoreResponses"];
const TEAM_RE = /^[\p{L}\p{N} _-]{1,40}$/u;
const ACTION_LABEL = { BLOCK: "🛑 BLOCK", WARN: "⚠️ WARN", REDACT: "✂️ REDACT", ALLOW: "✅ ALLOW" };
let saved = {};

const esc = v => String(v ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const base = () => ($("apiBase").value.trim() || "http://localhost:8000").replace(/\/+$/, "");
const tags = action => action === "WARN_REDACT"
  ? `<span class="tag WARN">${ACTION_LABEL.WARN}</span><span class="tag REDACT">${ACTION_LABEL.REDACT}</span>`
  : `<span class="tag ${esc(action)}">${esc(ACTION_LABEL[action] || action)}</span>`;

function toast(text, kind = "ok") {
  const t = $("toast"); t.textContent = text; t.className = `toast ${kind}`; t.hidden = false;
  clearTimeout(toast.timer); toast.timer = setTimeout(() => { t.hidden = true; }, 4000);
}
async function fetchJson(path, { token, method = "GET", body, timeout = 5000 } = {}) {
  const ctrl = new AbortController(); const timer = setTimeout(() => ctrl.abort(), timeout);
  const started = performance.now();
  try {
    const res = await fetch(`${base()}${path}`, {
      method, signal: ctrl.signal, cache: "no-store",
      headers: { ...(token ? { "X-Discovery-Token": token } : {}), ...(body ? { "Content-Type": "application/json" } : {}) },
      body: body ? JSON.stringify(body) : undefined,
    });
    const data = await res.json().catch(() => ({}));
    return { ok: res.ok, status: res.status, data, ms: Math.round(performance.now() - started) };
  } catch (e) {
    return { ok: false, status: 0, data: { detail: e.name === "AbortError" ? "Λήξη χρόνου" : e.message }, ms: null };
  } finally { clearTimeout(timer); }
}

// ------------------------------ settings ------------------------------
function current() {
  return {
    apiBase: $("apiBase").value.trim().replace(/\/+$/, ""),
    discoveryToken: $("discoveryToken").value.trim(),
    teamLabel: $("teamLabel").value.trim() || "Unassigned",
    promptGuardEnabled: $("promptGuardEnabled").checked,
    restoreResponses: $("restoreResponses").checked,
  };
}
function fill(s) {
  $("apiBase").value = s.apiBase || "http://localhost:8000";
  $("discoveryToken").value = s.discoveryToken || "";
  $("teamLabel").value = s.teamLabel || "Unassigned";
  $("promptGuardEnabled").checked = s.promptGuardEnabled === true;
  $("restoreResponses").checked = s.restoreResponses !== false;
  markTeamChip();
}
function dirty() {
  const c = current();
  return FIELDS.some(k => String(c[k]) !== String(saved[k] ?? (k === "restoreResponses" ? true : k === "promptGuardEnabled" ? false : "")));
}
function updateSavebar() { $("savebar").hidden = !dirty(); }
function markTeamChip() {
  document.querySelectorAll("#teamChips button").forEach(b => b.classList.toggle("on", b.textContent === $("teamLabel").value.trim()));
}

async function load() {
  try { $("version").textContent = `v${api.runtime.getManifest().version}`; } catch { /* ignore */ }
  const data = await api.storage.local.get(["settings"]);
  saved = { apiBase: "http://localhost:8000", teamLabel: "Unassigned", promptGuardEnabled: false, restoreResponses: true, discoveryToken: "", ...(data.settings || {}) };
  fill(saved);
  updateSavebar();
  refreshVault();
  await refreshStatus();
}

$("settingsForm").addEventListener("input", () => { markTeamChip(); updateSavebar(); });
$("settingsForm").addEventListener("change", updateSavebar);
$("teamChips").addEventListener("click", e => {
  const b = e.target.closest("button"); if (!b) return;
  $("teamLabel").value = b.textContent; markTeamChip(); updateSavebar();
});
$("toggleToken").onclick = () => {
  const i = $("discoveryToken"); i.type = i.type === "password" ? "text" : "password";
  $("toggleToken").setAttribute("aria-label", i.type === "password" ? "Εμφάνιση token" : "Απόκρυψη token");
};
$("revertBtn").onclick = () => { fill(saved); updateSavebar(); };
$("settingsForm").addEventListener("submit", async e => {
  e.preventDefault();
  const s = current();
  if (!/^https?:\/\/[^\s/]+/.test(s.apiBase)) return toast("Το API Base URL δεν είναι έγκυρο (π.χ. http://localhost:8000).", "bad");
  if (!s.discoveryToken) return toast("Συμπλήρωσε το token επέκτασης (SHADOW_INGEST_TOKEN).", "bad");
  if (!TEAM_RE.test(s.teamLabel)) return toast("Ομάδα: μόνο γράμματα, αριθμοί, κενό, - και _ (έως 40).", "bad");
  $("saveBtn").disabled = true;
  try {
    await api.storage.local.set({ settings: s });
    try { await api.runtime.sendMessage({ type: "AI_SHIELD_SETTINGS_UPDATED" }); } catch { /* worker wakes later */ }
    saved = s; updateSavebar();
    document.querySelectorAll(".unsaved-hint").forEach(n => n.remove());
    toast("Οι ρυθμίσεις αποθηκεύτηκαν. Ανανέωσε (F5) τις ανοιχτές σελίδες ChatGPT / Gemini / Claude.");
    await refreshStatus();
  } finally { $("saveBtn").disabled = false; }
});

// ------------------------------ status ------------------------------
function tile(id, state, value, sub) {
  const t = $(id); t.classList.remove("ok", "bad", "warn"); if (state) t.classList.add(state);
  t.querySelector("b").textContent = value; t.querySelector("em").textContent = sub || "";
}
async function refreshStatus() {
  const s = current();
  const health = await fetchJson("/health");
  tile("stBackend", health.ok ? "ok" : "bad", health.ok ? "Online" : "Offline",
       health.ok ? `${health.ms} ms · ${base().replace(/^https?:\/\//, "")}` : (health.data.detail || `HTTP ${health.status}`));
  let tokenOk = false;
  if (!s.discoveryToken) tile("stToken", "warn", "Λείπει", "Συμπλήρωσε το SHADOW_INGEST_TOKEN");
  else if (!health.ok) tile("stToken", "", "—", "Το backend δεν απαντά");
  else {
    const pol = await fetchJson("/api/shadow/policy", { token: s.discoveryToken });
    tokenOk = pol.ok;
    tile("stToken", pol.ok ? "ok" : "bad", pol.ok ? "Έγκυρο" : (pol.status === 401 ? "Λάθος token" : "Σφάλμα"),
         pol.ok ? "Ταιριάζει με το .env" : (pol.status === 401 ? "Δεν ταιριάζει με το SHADOW_INGEST_TOKEN" : (pol.data.detail || `HTTP ${pol.status}`)));
    if (pol.ok) renderPolicy(pol.data.rows || []);
  }
  const guard = saved.promptGuardEnabled === true;
  tile("stGuard", guard ? "ok" : "warn", guard ? "Ενεργό" : "Ανενεργό", guard ? "Έλεγχος σε κάθε Send" : "Τα μηνύματα δεν ελέγχονται");
  const o = $("overall"); o.className = "overall";
  let msg;
  if (!health.ok) { o.classList.add("bad"); msg = "Το backend δεν είναι διαθέσιμο"; }
  else if (!tokenOk) { o.classList.add("bad"); msg = s.discoveryToken ? "Λάθος token επέκτασης" : "Λείπει το token"; }
  else if (!guard) { o.classList.add("warn"); msg = "Συνδεδεμένο · Prompt Guard ανενεργό"; }
  else { o.classList.add("ok"); msg = `Προστατεύεται · ομάδα ${saved.teamLabel || "Unassigned"}`; }
  o.querySelector("span").textContent = msg;
}

$("testBtn").onclick = async () => {
  const btn = $("testBtn"), out = $("testOut"); btn.disabled = true; out.hidden = false;
  out.innerHTML = "<ul><li>Έλεγχος…</li></ul>";
  const s = current();
  const health = await fetchJson("/health");
  const rows = [[`Backend ${base()}`, health.ok ? `Online · ${health.ms} ms${health.data.version ? ` · v${health.data.version}` : ""}` : (health.data.detail || `HTTP ${health.status}`), health.ok ? "ok" : "bad"]];
  let hint = "";
  if (health.ok) {
    const [cat, pol] = await Promise.all([fetchJson("/api/shadow/catalog"), s.discoveryToken ? fetchJson("/api/shadow/policy", { token: s.discoveryToken }) : Promise.resolve(null)]);
    const tools = Array.isArray(cat.data.tools) ? cat.data.tools : [];
    rows.push(["Κατάλογος AI", cat.ok ? `${new Set(tools.map(t => t.provider_key)).size} υπηρεσίες · ${tools.length} domains` : `HTTP ${cat.status}`, cat.ok ? "ok" : "bad"]);
    if (!pol) { rows.push(["Token επέκτασης", "Λείπει", "warn"]); hint = "Βάλε το SHADOW_INGEST_TOKEN από το .env."; }
    else {
      rows.push(["Token επέκτασης", pol.ok ? "Έγκυρο" : pol.status === 401 ? "Λάθος" : `HTTP ${pol.status}`, pol.ok ? "ok" : "bad"]);
      rows.push(["Πολιτική DLP", pol.ok ? `${(pol.data.rows || []).length} κανόνες` : "—", pol.ok ? "ok" : "warn"]);
      if (pol.status === 401) hint = "Το token δεν ταιριάζει με το SHADOW_INGEST_TOKEN του .env. Αντέγραψέ το ακριβώς, χωρίς κενά.";
      if (pol.ok) renderPolicy(pol.data.rows || []);
    }
  } else {
    hint = "Τρέξε «docker compose up -d» και έλεγξε ότι το http://localhost:8000/health επιστρέφει \"status\":\"ok\".";
  }
  out.innerHTML = `<ul>${rows.map(([k, v, c]) => `<li><span>${esc(k)}</span><b class="${c}">${esc(v)}</b></li>`).join("")}</ul>` +
    (hint ? `<div class="hint">${esc(hint)}</div>` : "") + (dirty() ? `<div class="hint unsaved-hint">Ο έλεγχος έγινε με τις τιμές της φόρμας· πάτα «Αποθήκευση» για να ισχύσουν.</div>` : "");
  btn.disabled = false;
  if (!dirty()) refreshStatus();
};

// ------------------------------ policy ------------------------------
function renderPolicy(rows) {
  $("policyRows").innerHTML = rows.map(r => `<div class="prow">
    <div class="prow-head"><b>${esc(r.category)}</b><span>${tags(r.action)}</span></div>
    <div class="prow-types">${(r.type_labels || r.types).map(t => `<span>${esc(t)}</span>`).join("")}</div>
    <p>${esc(r.why)}</p></div>`).join("") || '<p class="muted">Καμία πολιτική.</p>';
}

// ------------------------------ preview ------------------------------
$("previewText").addEventListener("input", () => {
  $("previewCount").textContent = `${$("previewText").value.length.toLocaleString("el-GR")} / 5.000`;
});
$("samples").addEventListener("click", e => {
  const b = e.target.closest("button[data-s]"); if (!b) return;
  $("previewText").value = b.dataset.s; $("previewText").dispatchEvent(new Event("input")); $("previewBtn").click();
});
$("previewBtn").onclick = async () => {
  const text = $("previewText").value.trim();
  if (!text) return toast("Γράψε πρώτα ένα κείμενο.", "bad");
  const token = current().discoveryToken;
  if (!token) return toast("Χρειάζεται το token επέκτασης.", "bad");
  $("previewBtn").disabled = true;
  try {
    const r = await fetchJson("/api/shadow/policy-preview", { token, method: "POST", body: { prompt: text }, timeout: 8000 });
    if (!r.ok) throw new Error(r.status === 401 ? "Λάθος token επέκτασης" : (r.data.detail || `HTTP ${r.status}`));
    const d = r.data, out = $("previewOut"); out.hidden = false;
    const v = $("pvVerdict"); v.className = `verdict ${d.action}`; v.textContent = ACTION_LABEL[d.action] || d.action;
    $("pvReason").textContent = d.reason;
    $("pvRules").innerHTML = (d.rules || []).map(x => `<span class="tag ${x.action === "WARN_REDACT" ? "WARN" : esc(x.action)}" title="${esc(x.type)}">${esc(x.label)} · ${x.action === "WARN_REDACT" ? "WARN + REDACT" : esc(x.action)}</span>`).join("");
    const pre = $("pvSent"); pre.classList.toggle("blocked", d.action === "BLOCK");
    if (d.action === "BLOCK") {
      $("pvSentLabel").textContent = "Το AI θα λάμβανε";
      pre.textContent = "Τίποτα — η αποστολή μπλοκάρεται.";
    } else {
      // Same engine as the real send, on a throwaway vault (nothing is stored).
      const p = globalThis.AIShieldPseudo.pseudonymize(globalThis.AIShieldPseudo.newVault(), text, d.entities || []);
      $("pvSentLabel").textContent = d.action === "WARN" ? "Το AI θα λάμβανε μετά την επιβεβαίωσή σου" : "Το AI θα λάμβανε";
      pre.innerHTML = esc(p.text).replace(/\[[A-Z_]+_\d{3}\]/g, m => `<mark>${m}</mark>`);
    }
  } catch (err) { toast(`Η δοκιμή απέτυχε: ${err.message}`, "bad"); }
  finally { $("previewBtn").disabled = false; }
};

// ------------------------------ vault ------------------------------
async function refreshVault() {
  try {
    const res = await api.runtime.sendMessage({ type: "AI_SHIELD_VAULT_SNAPSHOT" });
    const tokens = Object.keys((res && res.tokens) || {});
    tile("stVault", tokens.length ? "ok" : "", String(tokens.length), tokens.length ? "ψευδώνυμα σε αυτή τη συνεδρία" : "κενό");
    // Only the pseudonyms are listed here, never the real values.
    $("vaultTokens").innerHTML = tokens.length ? tokens.slice(0, 40).map(t => `<code>${esc(t)}</code>`).join("") + (tokens.length > 40 ? `<span class="muted">+${tokens.length - 40}</span>` : "")
      : '<span class="muted">Κενό</span>';
  } catch { tile("stVault", "warn", "—", "μη διαθέσιμο"); }
}
$("clearVaultBtn").onclick = async () => {
  if (!confirm("Να διαγραφεί το vault; Οι παλιές απαντήσεις θα δείχνουν πλέον μόνο ψευδώνυμα.")) return;
  try { await api.runtime.sendMessage({ type: "AI_SHIELD_VAULT_CLEAR" }); toast("Το vault διαγράφηκε."); }
  catch (e) { toast(`Αποτυχία: ${e.message}`, "bad"); }
  refreshVault();
};

window.addEventListener("beforeunload", e => { if (dirty()) { e.preventDefault(); e.returnValue = ""; } });
load();
