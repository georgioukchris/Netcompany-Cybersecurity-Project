const $ = (id) => document.getElementById(id);
const API_KEY = "aiShieldApiBase";
function apiBase(){ return (localStorage.getItem(API_KEY) || "").trim().replace(/\/+$/,""); }
function apiUrl(path){ return `${apiBase()}${path}`; }
$("prompt").addEventListener("input", () => $("charCount").textContent = `${$("prompt").value.length.toLocaleString("el-GR")} / 20.000`);
$("clearBtn").addEventListener("click", () => { $("prompt").value=""; $("charCount").textContent="0 / 20.000"; $("emptyState").hidden=false; $("resultState").hidden=true; });
$("settingsBtn").addEventListener("click", () => { $("apiBase").value=apiBase(); $("settingsDialog").showModal(); });
$("saveSettings").addEventListener("click", (e) => { e.preventDefault(); const value=$("apiBase").value.trim(); if(value) localStorage.setItem(API_KEY,value); else localStorage.removeItem(API_KEY); $("settingsDialog").close(); });
$("copyBtn").addEventListener("click", async () => { try { await navigator.clipboard.writeText($("safePrompt").textContent); $("copyBtn").textContent="Αντιγράφηκε ✓"; setTimeout(()=>$("copyBtn").textContent="Αντιγραφή",1500); } catch { $("copyBtn").textContent="Αποτυχία αντιγραφής"; } });
$("scanBtn").addEventListener("click", scan);
function showError(message){ $("emptyState").hidden=true; $("resultState").hidden=false; $("decisionBox").className="decision block"; $("decisionIcon").textContent="!"; $("decisionTitle").textContent="API ERROR"; $("decisionReason").textContent=message; $("riskValue").textContent="UNKNOWN"; $("findingCount").textContent="—"; $("findingsList").innerHTML=""; $("safePromptWrap").hidden=true; $("blockedNote").hidden=true; }
async function scan(){
  const prompt=$("prompt").value;
  if(!prompt.trim()){ $("prompt").focus(); return; }
  const button=$("scanBtn"); button.disabled=true; button.textContent="Έλεγχος σε εξέλιξη…";
  try{
    const response=await fetch(apiUrl("/api/scan"),{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({prompt,user_id:"demo-user",tool_name:$("toolName").value.trim()||"unknown",confirm_warning:false})});
    const data=await response.json().catch(()=>({detail:"Μη έγκυρη απάντηση από το API."}));
    if(!response.ok) throw new Error(data.detail||`HTTP ${response.status}`);
    renderResult(data);
  }catch(error){ showError(`${error.message}. Έλεγξε ότι το backend λειτουργεί και ότι το API URL είναι σωστό.`); }
  finally{button.disabled=false;button.innerHTML="<span>⌕</span> Έλεγχος ασφαλείας";}
}
function renderResult(data){
  $("emptyState").hidden=true; $("resultState").hidden=false;
  const action=(data.action||"UNKNOWN").toUpperCase(), risk=(data.risk||"UNKNOWN").toUpperCase();
  $("decisionBox").className=`decision ${action.toLowerCase()}`;
  $("decisionIcon").textContent=action==="ALLOW"?"✓":action==="REDACT"?"✎":action==="WARN"?"!":"×";
  $("decisionTitle").textContent=action; $("decisionReason").textContent=data.reason||"Δεν δόθηκε αιτιολόγηση.";
  $("riskValue").textContent=risk; $("riskValue").style.color=risk==="CRITICAL"||risk==="HIGH"?"#ff8793":risk==="MEDIUM"?"#f4bd63":"#54d6cf";
  const findings=Array.isArray(data.findings)?data.findings:[];
  $("findingCount").textContent=findings.length;
  $("findingsList").innerHTML=findings.length?findings.map(f=>`<div class="finding"><span><b>${escapeHtml(f.type||"UNKNOWN")}</b><br><small>${escapeHtml(f.severity||"")}</small></span><small>${Number(f.count)||0} εντοπισμός/οί</small></div>`).join(""):'<div class="finding"><span>Δεν εντοπίστηκαν ευρήματα</span><small>✓</small></div>';
  const allowed=Boolean(data.forward_allowed)&&typeof data.safe_prompt==="string";
  $("safePromptWrap").hidden=!allowed; $("blockedNote").hidden=allowed;
  if(allowed) $("safePrompt").textContent=data.safe_prompt;
}
function escapeHtml(value){return String(value).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));}
