const $=id=>document.getElementById(id), BASE_KEY="aiShieldApiBase", TOKEN_KEY="aiShieldAdminToken";
let incidents=[];
const base=()=> (localStorage.getItem(BASE_KEY)||"").trim().replace(/\/+$/,"");
const url=path=>`${base()}${path}`;
function setConnection(text,ok=false){$("connectionText").textContent=text;$("connectionText").style.color=ok?"#54d6cf":"#ff9ba5";}
$("settingsBtn").onclick=()=>{$("apiBase").value=base();$("adminToken").value=localStorage.getItem(TOKEN_KEY)||"";$("settingsDialog").showModal();};
$("saveSettings").onclick=async e=>{e.preventDefault();const b=$("apiBase").value.trim(),t=$("adminToken").value.trim();if(b)localStorage.setItem(BASE_KEY,b);else localStorage.removeItem(BASE_KEY);if(t)localStorage.setItem(TOKEN_KEY,t);else localStorage.removeItem(TOKEN_KEY);$("settingsDialog").close();await loadIncidents();};
$("refreshBtn").onclick=loadIncidents;
$("searchInput").addEventListener("input",renderRows);$("riskFilter").onchange=renderRows;$("actionFilter").onchange=renderRows;
$("closeDetail").onclick=()=>$("detailDialog").close();
async function loadIncidents(){
 const token=localStorage.getItem(TOKEN_KEY)||""; if(!token){setConnection("Απαιτείται admin token");$("settingsDialog").showModal();return;}
 $("refreshBtn").disabled=true;$("refreshBtn").textContent="Φόρτωση…";
 try{
  const response=await fetch(url("/api/admin/incidents?limit=500"),{headers:{"X-Admin-Token":token}});
  const data=await response.json().catch(()=>({detail:"Μη έγκυρη απάντηση API"}));
  if(!response.ok)throw new Error(data.detail||`HTTP ${response.status}`);
  incidents=Array.isArray(data.incidents)?data.incidents:[];
  setConnection("Συνδεδεμένο",true);renderMetrics();renderRows();
 }catch(err){setConnection(err.message);$("incidentRows").innerHTML=`<tr><td colspan="6" class="empty">${esc(err.message)} — έλεγξε URL, token και backend.</td></tr>`;incidents=[];renderMetrics();$("rowCount").textContent="0 συμβάντα";}
 finally{$("refreshBtn").disabled=false;$("refreshBtn").textContent="↻ Ανανέωση";}
}
function renderMetrics(){
 $("totalMetric").textContent=incidents.length;
 $("blockedMetric").textContent=incidents.filter(x=>x.action==="BLOCK").length;
 $("highMetric").textContent=incidents.filter(x=>["HIGH","CRITICAL"].includes(String(x.risk).toUpperCase())).length;
 $("redactMetric").textContent=incidents.filter(x=>x.action==="REDACT").length;
}
function renderRows(){
 const q=$("searchInput").value.toLowerCase(),risk=$("riskFilter").value,action=$("actionFilter").value;
 const rows=incidents.filter(x=>(!risk||String(x.risk).toUpperCase()===risk)&&(!action||String(x.action).toUpperCase()===action)&&[x.id,x.user_id,x.tool_name].some(v=>String(v??"").toLowerCase().includes(q)));
 $("rowCount").textContent=`${rows.length} συμβάντα`;
 $("incidentRows").innerHTML=rows.length?rows.map((x,i)=>`<tr data-index="${incidents.indexOf(x)}"><td>#${esc(x.id??"—")}</td><td>${esc(x.user_id??"—")}</td><td>${esc(x.tool_name??"—")}</td><td><span class="tag ${esc(String(x.action||"").toUpperCase())}">${esc(x.action??"—")}</span></td><td><span class="tag ${esc(String(x.risk||"").toUpperCase())}">${esc(x.risk??"—")}</span></td><td>${esc(formatDate(x.created_at))}</td></tr>`).join(""):'<tr><td colspan="6" class="empty">Δεν βρέθηκαν συμβάντα με αυτά τα φίλτρα.</td></tr>';
 document.querySelectorAll("#incidentRows tr[data-index]").forEach(tr=>tr.onclick=()=>showDetail(incidents[Number(tr.dataset.index)]));
}
function showDetail(item){$("detailContent").textContent=JSON.stringify(item,null,2);$("detailDialog").showModal();}
function formatDate(value){if(!value)return"—";const d=new Date(value);return Number.isNaN(d.getTime())?String(value):d.toLocaleString("el-GR");}
function esc(value){return String(value).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));}
loadIncidents();
