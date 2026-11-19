const $ = id => document.getElementById(id);
const API_KEY = "aiShieldApiBase";
const DEFAULT_API = location.protocol === "file:" ? "http://localhost:8000" : "";
const apiBase = () => (localStorage.getItem(API_KEY) ?? DEFAULT_API).trim().replace(/\/+$/,"");
const apiUrl = path => `${apiBase()}${path}`;
let history = [];
let busy = false;
let pendingWarning = false;
const stats = { messages: 0, hidden: 0, blocked: 0 };
function bump(key, n = 1) { stats[key] += n; const el = $({ messages: "statMessages", hidden: "statHidden", blocked: "statBlocked" }[key]); if (el) el.textContent = stats[key]; }
const ACTION_LABEL = { BLOCK: "🛑 BLOCK", WARN: "⚠️ WARN", REDACT: "✂️ REDACT", ALLOW: "✅ ALLOW", PSEUDONYMIZE: "✂️ PSEUDONYMIZE" };

$("settingsBtn").addEventListener("click", () => {
  $("apiBase").value = localStorage.getItem(API_KEY) ?? DEFAULT_API;
  $("settingsDialog").showModal();
});
$("saveSettings").addEventListener("click", e => {
  e.preventDefault();
  const value = $("apiBase").value.trim();
  if (value) localStorage.setItem(API_KEY,value); else localStorage.removeItem(API_KEY);
  $("settingsDialog").close();
});
$("messageInput").addEventListener("input", () => {
  $("charCount").textContent = `${$("messageInput").value.length.toLocaleString("el-GR")} / 12.000`;
});
$("messageInput").addEventListener("keydown", e => {
  if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendMessage(false); }
});
$("sendBtn").addEventListener("click", () => sendMessage(false));
$("newChatBtn").addEventListener("click", () => {
  history = []; pendingWarning = false;
  for (const k of Object.keys(stats)) { stats[k] = 0; bump(k, 0); }
  $("chatMessages").replaceChildren();
  $("chatMessages").innerHTML = '<div class="chat-empty"><div class="empty-orb"></div><h4>Νέα συνομιλία</h4><p>Το AI Shield είναι έτοιμο να ελέγξει το πρώτο σου μήνυμα.</p></div>';
  $("decisionPanel").hidden = true; $("decisionEmpty").hidden = false;
  setStatus("🔒 Νέα συνομιλία. Η προστασία είναι ενεργή.");
});
function setStatus(text, kind="") {
  const el=$("securityStatus"); el.textContent=text; el.className=`security-status ${kind}`;
}
function addMessage(role, content) {
  const empty=$("chatMessages").querySelector(".chat-empty"); if(empty) empty.remove();
  const wrap=document.createElement("div");
  wrap.className=`message ${role}`;
  const label=document.createElement("div"); label.className="message-label";
  label.textContent=role==="user"?"ΕΣΥ":"AI ASSISTANT";
  const body=document.createElement("div"); body.className="message-body"; body.textContent=content;
  wrap.append(label,body); $("chatMessages").append(wrap);
  $("chatMessages").scrollTop=$("chatMessages").scrollHeight;
}
function tag(cls, text) { const t=document.createElement("span"); t.className=`tag ${cls}`; t.textContent=text; return t; }
function showDecision(data) {
  const panel=$("decisionPanel"); panel.hidden=false; panel.replaceChildren(); $("decisionEmpty").hidden=true;
  const action=String(data.action || "UNKNOWN").toUpperCase(), risk=String(data.risk || "").toUpperCase();
  const head=document.createElement("div"); head.className="verdict";
  head.append(tag(action, ACTION_LABEL[action] || action));
  if (risk) head.append(tag(risk, `Κίνδυνος ${risk}`));
  const desc=document.createElement("p"); desc.textContent=data.reason || "";
  const chips=document.createElement("div"); chips.className="finding-chips";
  const findings=data.findings||[];
  if (findings.length) findings.forEach(f=>{ const c=document.createElement("span"); c.textContent=`${f.type} × ${f.count}`; chips.append(c); });
  else { const c=document.createElement("span"); c.textContent="Κανένα εύρημα"; chips.append(c); }
  panel.append(head,desc,chips);
}
function markLastUser(cls, text) {
  const all=$("chatMessages").querySelectorAll(".message.user"); const last=all[all.length-1]; if(!last) return;
  last.classList.add(cls); const l=last.querySelector(".message-label"); if(l) l.textContent=`ΕΣΥ · ${text}`;
}
function showError(message) { setStatus(`⚠ ${message}`,"error"); }
let warnIncidentId=null;
async function sendMessage(confirmWarning=false) {
  if (busy) return;
  const typed=$("messageInput").value.trim();
  if (!confirmWarning && !typed) { $("messageInput").focus(); return; }
  if (!confirmWarning) {
    history.push({role:"user",content:typed});
    addMessage("user",typed); bump("messages");
    $("messageInput").value=""; $("charCount").textContent="0 / 12.000";
  }
  busy=true; $("sendBtn").disabled=true; $("sendBtn").textContent="Έλεγχος…";
  setStatus("⏳ Έλεγχος περιεχομένου και επικοινωνία με AI…");
  try {
    const response=await fetch(apiUrl("/api/chat"),{
      method:"POST", headers:{"Content-Type":"application/json"},
      body:JSON.stringify({
        provider:$("provider").value, model:$("model").value,
        messages:history.slice(-20), user_id:"demo-user",
        confirm_warning:confirmWarning,
        warn_incident_id:confirmWarning ? warnIncidentId : null
      })
    });
    if(response.status===401){ location.assign("/login/?next=/app/"); return; }
    const data=await response.json().catch(()=>({detail:"Μη έγκυρη απάντηση από το backend."}));
    if(!response.ok) throw new Error(data.detail || `HTTP ${response.status}`);
    showDecision(data);
    if(data.status==="blocked") {
      setStatus(`🛑 BLOCK · ${data.reason || "Το μήνυμα μπλοκαρίστηκε."} Δεν στάλθηκε στο AI.`,"error"); bump("blocked");
      markLastUser("blocked", "🛑 ΔΕΝ ΣΤΑΛΘΗΚΕ");
      history.pop(); return;
    }
    if(data.status==="confirmation_required") {
      pendingWarning=true; warnIncidentId=data.incident_id ?? null;
      setStatus(`⚠️ WARN · ${data.reason || "Χρειάζεται επιβεβαίωση."} Συνέχισε μόνο αν έχεις δικαίωμα να το μοιραστείς.`,"warn");
      const btn=document.createElement("button"); btn.className="btn btn-primary";
      btn.textContent="⚠️ Κατανοώ — αποστολή";
      btn.addEventListener("click",()=>{ if(pendingWarning){pendingWarning=false;sendMessage(true);} });
      $("decisionPanel").append(btn);
      return;
    }
    pendingWarning=false;
    if(data.reply) {
      history.push({role:"assistant",content:data.reply});
      addMessage("assistant",data.reply);
    }
    const redacted=(data.pseudonymized_count||0)>0;
    // pseudonymized_count = unique values hidden across the whole conversation context.
    if (redacted && data.pseudonymized_count > stats.hidden) bump("hidden", data.pseudonymized_count - stats.hidden);
    setStatus(redacted
      ? `✂️ ${data.action}: ${data.pseudonymized_count} ευαίσθητα στοιχεία στάλθηκαν ως ψευδώνυμα ([AFM_001] κ.λπ.) και επανήλθαν τοπικά στην απάντηση.`
      : "✓ Έλεγχος επιτυχής. Η απάντηση ελέγχθηκε πριν εμφανιστεί.",
      "success");
  } catch(error) {
    showError(`${error.message}. Έλεγξε backend, API key και σύνδεση.`);
    if(!confirmWarning && history.at(-1)?.role==="user") history.pop();
  } finally {
    busy=false; $("sendBtn").disabled=false; $("sendBtn").textContent="Αποστολή ↗";
  }
}

// ------------------------- Browser extension download -------------------------
async function loadExtensionInfo() {
  const shown = apiBase() || location.origin;
  $("extApiUrl").textContent = shown.startsWith("http") ? shown : "http://localhost:8000";
  try {
    const res = await fetch(apiUrl("/api/extension/info"), { cache: "no-store" });
    const info = await res.json();
    const byBrowser = Object.fromEntries((info.builds || []).map(b => [b.browser, b]));
    document.querySelectorAll(".dl[data-browser]").forEach(a => {
      const b = byBrowser[a.dataset.browser];
      const meta = a.querySelector("[data-meta]");
      if (!b) { a.classList.add("off"); meta.textContent = "Δεν είναι διαθέσιμο"; return; }
      a.href = apiUrl(b.url); a.setAttribute("download", "");
      meta.textContent = `v${b.version} · ${b.size_kb} KB · zip`;
    });
  } catch {
    document.querySelectorAll(".dl[data-browser] [data-meta]").forEach(m => { m.textContent = "Το backend δεν απαντά"; });
  }
}
document.querySelectorAll(".seg [data-tab]").forEach(btn => btn.addEventListener("click", () => {
  document.querySelectorAll(".seg [data-tab]").forEach(b => { const on = b === btn; b.classList.toggle("on", on); b.setAttribute("aria-selected", String(on)); });
  document.querySelectorAll(".steps[data-steps]").forEach(ol => { ol.hidden = ol.dataset.steps !== btn.dataset.tab; });
}));
document.querySelectorAll(".copy[data-copy]").forEach(btn => btn.addEventListener("click", async () => {
  try { await navigator.clipboard.writeText($(btn.dataset.copy).textContent); btn.textContent = "✓"; setTimeout(() => { btn.textContent = "⧉"; }, 1200); } catch { /* clipboard blocked */ }
}));
// Highlight the tab of the section in view.
const tabLinks = [...document.querySelectorAll(".tab")];
addEventListener("scroll", () => {
  const ext = $("extension").getBoundingClientRect().top < innerHeight * 0.5;
  tabLinks.forEach(t => t.classList.toggle("active", (t.getAttribute("href") === "#extension") === ext));
}, { passive: true });
// Pre-select the visitor's browser.
if (/Firefox\//.test(navigator.userAgent) === false) document.querySelector('.seg [data-tab="chrome"]').click();
loadExtensionInfo();

// ------------------------- Signed-in account -------------------------
(async () => {
  try {
    const res = await fetch("/api/auth/me", { credentials: "same-origin" });
    const user = res.ok ? (await res.json()).user : null;
    if (!user) return;
    $("userName").textContent = user.name;
    $("userRole").textContent = user.role === "admin" ? "Διαχειριστής" : "Χρήστης";
    $("userChip").hidden = false;
    $("logoutBtn").hidden = false;
    $("logoutBtn").onclick = async () => {
      try { await fetch("/api/auth/logout", { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" }, body: "{}" }); } catch {}
      location.assign("/login/");
    };
    if (new URLSearchParams(location.search).get("denied") === "admin")
      setStatus("🔒 Το Admin Console είναι διαθέσιμο μόνο σε διαχειριστές.", "warn");
  } catch { /* opened without the backend */ }
})();
