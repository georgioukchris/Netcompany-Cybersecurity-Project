/* AI Shield Shadow Radar — metadata-only browser discovery
 * + Reversible Privacy Engine vault (pseudonym <-> real value, memory only). */
const api = globalThis.browser || globalThis.chrome;
// Chrome MV3 service worker loads the shared engine here; Firefox lists it in manifest.background.scripts.
if (!globalThis.AIShieldPseudo && typeof importScripts === "function") importScripts("pseudonym-core.js");
const Pseudo = globalThis.AIShieldPseudo;
const DEFAULT_API = "http://localhost:8000";
let catalogCache = [];
let catalogFetchedAt = 0;
let installIdCache = null;

async function getSettings() {
  const data = await api.storage.local.get(["settings"]);
  return data.settings || { apiBase: DEFAULT_API, discoveryToken: "", teamLabel: "Unassigned" };
}
async function getInstallId() {
  if (installIdCache) return installIdCache;
  const data = await api.storage.local.get(["installId"]);
  installIdCache = data.installId || crypto.randomUUID();
  if (!data.installId) await api.storage.local.set({ installId: installIdCache });
  return installIdCache;
}
function normalizedBase(value) {
  return String(value || DEFAULT_API).trim().replace(/\/+$/, "");
}
async function loadCatalog(force = false) {
  if (!force && catalogCache.length && Date.now() - catalogFetchedAt < 10 * 60 * 1000) return catalogCache;
  const settings = await getSettings();
  const response = await fetch(`${normalizedBase(settings.apiBase)}/api/shadow/catalog`, { cache: "no-store" });
  if (!response.ok) throw new Error(`Catalog request failed: HTTP ${response.status}`);
  const data = await response.json();
  catalogCache = Array.isArray(data.tools) ? data.tools : [];
  catalogFetchedAt = Date.now();
  return catalogCache;
}
function matchDomain(hostname, catalog) {
  const host = String(hostname || "").toLowerCase().replace(/\.$/, "");
  return catalog.find(item => host === item.domain || host.endsWith(`.${item.domain}`));
}
async function sendDomainEvent(domain) {
  const settings = await getSettings();
  if (!settings.discoveryToken) throw new Error("Discovery token is not configured");
  const response = await fetch(`${normalizedBase(settings.apiBase)}/api/shadow/events`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Discovery-Token": settings.discoveryToken
    },
    body: JSON.stringify({
      domain,
      install_id: await getInstallId(),
      team_label: settings.teamLabel || "Unassigned"
    })
  });
  if (!response.ok) throw new Error(`Event ingestion failed: HTTP ${response.status}`);
}
async function inspectTab(tabId, rawUrl) {
  if (!rawUrl || !/^https?:\/\//i.test(rawUrl)) {
    const stored = await api.storage.local.get(["lastDomainByTab"]);
    const lastByTab = stored.lastDomainByTab || {};
    lastByTab[String(tabId)] = "";
    await api.storage.local.set({ lastDomainByTab: lastByTab });
    return;
  }
  let hostname;
  try { hostname = new URL(rawUrl).hostname.toLowerCase(); } catch { return; }
  // Only hostname is used. URL path, query, fragment, title and page contents are discarded.
  let catalog;
  try { catalog = await loadCatalog(); } catch { return; }
  const match = matchDomain(hostname, catalog);
  const stored = await api.storage.local.get(["lastDomainByTab"]);
  const lastByTab = stored.lastDomainByTab || {};
  const previous = lastByTab[String(tabId)] || "";
  if (!match) {
    lastByTab[String(tabId)] = "";
    await api.storage.local.set({ lastDomainByTab: lastByTab });
    return;
  }
  if (previous === match.domain) return;
  try {
    // Mark the domain as seen only after the backend confirms the event.
    // This permits retries after an offline backend or invalid token.
    await sendDomainEvent(match.domain);
    lastByTab[String(tabId)] = match.domain;
    await api.storage.local.set({ lastDomainByTab: lastByTab });
  } catch (error) {
    // Do not log URLs, titles or page content. Only a generic error is exposed in extension console.
    console.warn("AI Shield discovery event could not be sent.", error.message);
  }
}

api.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab && tab.url) inspectTab(tabId, tab.url);
});
api.tabs.onActivated.addListener(async activeInfo => {
  try {
    const tab = await api.tabs.get(activeInfo.tabId);
    if (tab && tab.url) await inspectTab(activeInfo.tabId, tab.url);
  } catch { /* The tab may have closed before it could be inspected. */ }
});
api.tabs.onRemoved.addListener(async tabId => {
  const stored = await api.storage.local.get(["lastDomainByTab"]);
  const lastByTab = stored.lastDomainByTab || {};
  delete lastByTab[String(tabId)];
  await api.storage.local.set({ lastDomainByTab: lastByTab });
});

// --------------------- Reversible Privacy Engine vault ---------------------
// The mapping [PERSON_001] -> "John Smith" never leaves this browser. It is kept in
// storage.session (RAM only, wiped when the browser closes) so it survives the
// background/service worker being suspended. It is never sent to the backend.
const VAULT_KEY = "aiShieldVault";
const sessionArea = api.storage && api.storage.session ? api.storage.session : null;
let vaultMem = null;
let vaultLock = Promise.resolve();

async function loadVault() {
  if (vaultMem) return vaultMem;
  let stored = null;
  if (sessionArea) {
    try { stored = (await sessionArea.get(VAULT_KEY))[VAULT_KEY] || null; } catch { stored = null; }
  }
  vaultMem = stored && stored.byToken ? stored : Pseudo.newVault();
  return vaultMem;
}
async function saveVault() {
  if (sessionArea) {
    try { await sessionArea.set({ [VAULT_KEY]: vaultMem }); } catch { /* memory copy still works */ }
  }
}
function withVault(fn) {
  const run = vaultLock.then(async () => fn(await loadVault()));
  vaultLock = run.catch(() => {});
  return run;
}
async function broadcastVault() {
  const tokens = { ...(await loadVault()).byToken };
  let tabs = [];
  try { tabs = await api.tabs.query({}); } catch { return; }
  for (const tab of tabs) {
    if (tab.id === undefined) continue;
    // Only tabs running prompt-guard.js (the supported AI sites) have a listener.
    Promise.resolve(api.tabs.sendMessage(tab.id, { type: "AI_SHIELD_VAULT_UPDATED", tokens })).catch(() => {});
  }
}

api.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message && message.type === "AI_SHIELD_PSEUDONYMIZE") {
    withVault(async vault => {
      const result = Pseudo.pseudonymize(vault, String(message.prompt || ""), message.entities || [],
        Array.isArray(message.allowedPrefixes) ? message.allowedPrefixes : undefined);
      if (result.replaced.length) await saveVault();
      return result;
    }).then(async result => {
      sendResponse(result);
      if (result.replaced.length) await broadcastVault();
    }).catch(error => sendResponse({ error: error.message }));
    return true;
  }
  if (message && message.type === "AI_SHIELD_VAULT_SNAPSHOT") {
    loadVault().then(v => sendResponse({ tokens: { ...v.byToken } }))
      .catch(error => sendResponse({ error: error.message, tokens: {} }));
    return true;
  }
  if (message && message.type === "AI_SHIELD_VAULT_CLEAR") {
    withVault(async () => { vaultMem = Pseudo.newVault(); await saveVault(); })
      .then(async () => { sendResponse({ ok: true }); await broadcastVault(); })
      .catch(error => sendResponse({ error: error.message }));
    return true;
  }
  if (message && message.type === "AI_SHIELD_SCAN_PROMPT") {
    (async () => {
      const settings = await getSettings();
      if (!settings.promptGuardEnabled) throw new Error("Το Prompt Guard δεν είναι ενεργοποιημένο στις ρυθμίσεις επέκτασης.");
      if (!settings.discoveryToken) throw new Error("Δεν έχει ρυθμιστεί το Discovery token.");
      // Values already in the local vault (e.g. a client named in an earlier message)
      // will be pseudonymized too. Tell the backend only their TYPES and counts so the
      // audit log is accurate; the values and tokens never leave the browser.
      const vaultMatches = [];
      try {
        const probe = Pseudo.pseudonymize(JSON.parse(JSON.stringify(await loadVault())), String(message.prompt || ""), []);
        const counts = {};
        for (const r of probe.replaced) {
          const m = /^\[([A-Z_]+)_\d+\]$/.exec(r.token);
          if (m) counts[m[1]] = (counts[m[1]] || 0) + 1;
        }
        for (const [token_type, count] of Object.entries(counts)) vaultMatches.push({ token_type, count });
      } catch { /* vault unavailable: the scan still runs */ }
      const response = await fetch(`${normalizedBase(settings.apiBase)}/api/shadow/scan-prompt`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Discovery-Token": settings.discoveryToken
        },
        body: JSON.stringify({
          prompt: String(message.prompt || ""),
          provider_key: String(message.providerKey || "unknown-ai"),
          team_label: settings.teamLabel || "Unassigned",
          confirm_warning: message.confirmWarning === true,
          warn_incident_id: Number.isInteger(message.warnIncidentId) ? message.warnIncidentId : null,
          vault_matches: vaultMatches
        })
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.detail || `Prompt scanner HTTP ${response.status}`);
      return data;
    })().then(sendResponse).catch(error => sendResponse({ error: error.message }));
    return true;
  }
  if (message && message.type === "AI_SHIELD_SETTINGS_UPDATED") {
    catalogFetchedAt = 0;
    return (async () => {
      try {
        await api.storage.local.set({ lastDomainByTab: {} });
        await loadCatalog(true);
        const tabs = await api.tabs.query({});
        for (const tab of tabs) if (tab.id !== undefined && tab.url) await inspectTab(tab.id, tab.url);
      } catch { /* The API may be offline; later tab navigation will retry. */ }
    })();
  }
});

if (api.runtime && api.runtime.onStartup) {
  api.runtime.onStartup.addListener(async () => {
    try {
      await api.storage.local.set({ lastDomainByTab: {} });
      await loadCatalog(true);
      const tabs = await api.tabs.query({});
      for (const tab of tabs) if (tab.id !== undefined && tab.url) await inspectTab(tab.id, tab.url);
    } catch { /* Extension remains idle until a matching AI domain is visited. */ }
  });
}
if (api.runtime && api.runtime.onInstalled) {
  api.runtime.onInstalled.addListener(async () => {
    try {
      await api.storage.local.set({ lastDomainByTab: {} });
      await loadCatalog(true);
      const tabs = await api.tabs.query({});
      for (const tab of tabs) if (tab.id !== undefined && tab.url) await inspectTab(tab.id, tab.url);
    } catch { /* Backend may not be running at installation time; later navigation retries. */ }
  });
}
