/* AI Shield Prompt Guard — Reversible Privacy Engine.
 * The prompt is inspected only on an explicit Send/Enter action by the user's local
 * AI Shield backend (no model API is called). Sensitive values are replaced with
 * consistent pseudonyms ([PERSON_001], [AFM_001], [ACCOUNT_001]) before sending.
 * When the AI answers, the pseudonyms are swapped back to the real values ONLY in
 * this page's display; the provider never receives the real values.
 */
(() => {
  const ext = globalThis.browser || globalThis.chrome;
  if (!ext?.runtime || !ext?.storage) return;

  const host = location.hostname.toLowerCase();
  const provider = host.includes("chatgpt.com") || host === "chat.openai.com" ? "chatgpt"
    : host === "claude.ai" || host.endsWith(".claude.ai") ? "claude"
    : host === "gemini.google.com" ? "gemini"
    : "unknown-ai";

  const selectors = [
    '[data-testid="prompt-textarea"]',
    '[data-testid*="chat-input"] [contenteditable="true"]',
    '[data-testid*="chat-input"] textarea',
    'rich-textarea [contenteditable="true"]',
    'rich-textarea textarea',
    '[data-testid*="chat-input"][contenteditable="true"]',   // claude.ai
    '[contenteditable="true"][aria-label*="prompt" i]',      // claude.ai "Write your prompt to Claude"
    'div.ProseMirror[contenteditable="true"]',
    '[contenteditable="true"][role="textbox"]',
    'textarea[placeholder]',
    'textarea'
  ];
  const sendSelectors = [
    'button[data-testid="send-button"]',
    'button[data-testid*="send"]',
    'button.send-button',                                   // Gemini
    'button:has(mat-icon[fonticon="send"])',                // Gemini (Material icon)
    'button:has(mat-icon[data-mat-icon-name="send"])',
    'button[aria-label*="Send" i]',
    'button[aria-label*="Αποστολή" i]',                     // Greek UI
    'button[title*="Send" i]',
    'button[title*="Αποστολή" i]',
    '[role="button"][aria-label*="Send" i]',
    '[role="button"][aria-label*="Αποστολή" i]',
    'button[type="submit"]'
  ];
  function safeQueryAll(root, selector) {
    try { return [...root.querySelectorAll(selector)]; } catch { return []; } // :has() on old engines
  }

  const Pseudo = globalThis.AIShieldPseudo;
  let settings = { promptGuardEnabled: false, teamLabel: "Unassigned", restoreResponses: true };
  let settingsReady = false;
  let settingsLoadFailed = false;
  let busy = false;
  let bypassButton = null;
  let bypassEnterTarget = null;
  let lastToast = null;

  function visible(el) {
    if (!el || !el.isConnected) return false;
    const r = el.getBoundingClientRect();
    return r.width > 0 && r.height > 0 && getComputedStyle(el).visibility !== "hidden";
  }
  function isComposer(el) {
    return !!el && el.matches('textarea, input[type="text"], [contenteditable="true"], [role="textbox"]');
  }
  function readText(el) {
    return (el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement)
      ? el.value : (el.innerText || el.textContent || "");
  }
  function findComposer(button) {
    const form = button && button.closest("form");
    if (form) {
      for (const selector of selectors) {
        const candidate = [...form.querySelectorAll(selector)].find(visible);
        if (candidate && isComposer(candidate)) return candidate;
      }
    }
    const active = document.activeElement;
    if (isComposer(active) && visible(active)) return active;
    for (const selector of selectors) {
      const matches = [...document.querySelectorAll(selector)].filter(el => visible(el) && isComposer(el));
      if (matches.length) return matches[matches.length - 1];
    }
    return null;
  }
  function findSendButton(composer, clicked) {
    if (clicked && clicked.isConnected && visible(clicked)) return clicked;
    if (!composer) return null;
    // Sites such as Gemini have no <form>: search the composer's nearest
    // containers, innermost first, so the button of THIS composer is chosen.
    const scopes = [];
    const form = composer.closest("form");
    if (form) scopes.push(form);
    let el = composer.parentElement;
    for (let depth = 0; el && depth < 10; depth++, el = el.parentElement) scopes.push(el);
    for (const scope of scopes) {
      for (const selector of sendSelectors) {
        const btn = safeQueryAll(scope, selector).find(b => visible(b) && looksLikeSendButton(b));
        if (btn) return btn;
      }
    }
    return null;
  }
  function looksLikeSendButton(button) {
    if (!button || !button.matches('button,[role="button"]')) return false;
    const label = [button.getAttribute("aria-label"), button.getAttribute("title"),
      button.getAttribute("data-testid"), button.getAttribute("type"),
      button.getAttribute("class")].join(" ").toLowerCase();
    if (/(^|[\s_-])send|submit|αποστολ/.test(label)) return true;
    if (safeQueryAll(button, 'mat-icon[fonticon="send"], mat-icon[data-mat-icon-name="send"]').length) return true;
    const form = button.closest("form");
    return button.getAttribute("type") === "submit" && !!form;
  }
  function toast(message, kind = "info") {
    if (lastToast) lastToast.remove();
    const el = document.createElement("div");
    el.textContent = `AI Shield · ${message}`;
    el.setAttribute("role", "status");
    el.setAttribute("data-ai-shield", "toast");
    Object.assign(el.style, {
      position: "fixed", zIndex: "2147483647", right: "18px", bottom: "18px",
      maxWidth: "min(460px, calc(100vw - 36px))", padding: "12px 16px",
      borderRadius: "10px", color: "#f7fbff", font: "13px/1.45 system-ui,sans-serif",
      boxShadow: "0 8px 32px rgba(0,0,0,.35)",
      background: kind === "danger" ? "#9f3038" : kind === "success" ? "#126b59" : "#243750"
    });
    document.documentElement.appendChild(el);
    lastToast = el;
    setTimeout(() => { if (lastToast === el) lastToast = null; el.remove(); }, 6500);
  }
  function setComposerText(el, value) {
    el.focus();
    if (el instanceof HTMLTextAreaElement || el instanceof HTMLInputElement) {
      const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
      const setter = Object.getOwnPropertyDescriptor(proto, "value")?.set;
      if (setter) setter.call(el, value); else el.value = value;
    } else {
      // execCommand goes through the editor's own input pipeline (ProseMirror, Lexical,
      // Quill), so its internal state matches what is shown. Fallback: plain text.
      let ok = false;
      try {
        const sel = window.getSelection();
        const range = document.createRange();
        range.selectNodeContents(el);
        sel.removeAllRanges();
        sel.addRange(range);
        ok = document.execCommand("insertText", false, value);
      } catch { ok = false; }
      const norm = t => String(t).replace(/\s+/g, " ").trim();
      if (!ok || norm(readText(el)) !== norm(value)) el.textContent = value;
    }
    el.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: "insertText", data: value }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  }
  async function sendAgain(button, composer) {
    // After the text is replaced, frameworks (Angular in Gemini, React in ChatGPT)
    // may re-render or briefly disable the button: wait for a usable one.
    for (let i = 0; i < 20; i++) {
      const btn = button && button.isConnected && visible(button) ? button : findSendButton(composer, null);
      const disabled = btn && (btn.disabled || btn.getAttribute("aria-disabled") === "true");
      if (btn && !disabled) {
        bypassButton = btn;
        btn.click();
        return true;
      }
      await new Promise(r => setTimeout(r, 50));
    }
    const form = composer && composer.closest("form");
    if (form && typeof form.requestSubmit === "function") {
      form.requestSubmit();
      return true;
    }
    // No button and no form: replay Enter on the (already pseudonymized) composer.
    if (composer && composer.isConnected) {
      bypassEnterTarget = composer;
      composer.focus();
      composer.dispatchEvent(new KeyboardEvent("keydown", {
        key: "Enter", code: "Enter", keyCode: 13, which: 13, bubbles: true, cancelable: true
      }));
      bypassEnterTarget = null;
      return true;
    }
    return false;
  }
  async function scan(prompt, confirmWarning = false, warnIncidentId = null) {
    return ext.runtime.sendMessage({
      type: "AI_SHIELD_SCAN_PROMPT",
      prompt,
      providerKey: provider,
      confirmWarning,
      warnIncidentId
    });
  }
  async function pseudonymizeLocally(prompt, entities, allowedPrefixes) {
    const res = await ext.runtime.sendMessage({ type: "AI_SHIELD_PSEUDONYMIZE", prompt, entities: entities || [], allowedPrefixes });
    if (!res || res.error || typeof res.text !== "string") throw new Error(res?.error || "Το vault ψευδωνύμων δεν απάντησε");
    return res;
  }
  function pauseEvent(event) {
    event.preventDefault();
    event.stopPropagation();
    if (typeof event.stopImmediatePropagation === "function") event.stopImmediatePropagation();
  }

  async function runGuard(event, composer, button) {
    if (busy) { pauseEvent(event); return; }
    pauseEvent(event);
    busy = true;
    try {
      // Wait for settings to load; never let an early page interaction race initialization.
      if (!settingsReady) {
        try {
          const data = await ext.storage.local.get(["settings"]);
          settings = { ...settings, ...(data.settings || {}) };
          settingsReady = true;
        } catch {
          settingsLoadFailed = true;
        }
      }
      if (settingsLoadFailed) {
        // Fail closed: an unchecked prompt is never sent.
        toast("Δεν ήταν δυνατή η ανάγνωση ρυθμίσεων. Το μήνυμα ΔΕΝ στάλθηκε.", "danger");
        return;
      }
      if (!settings.promptGuardEnabled) {
        await sendAgain(button, composer);
        return;
      }

      const prompt = readText(composer).trim();
      if (!prompt) return;
      toast("Έλεγχος prompt τοπικά πριν από την αποστολή…");
      let result;
      try {
        result = await scan(prompt, false);
        if (!result || result.error) throw new Error(result?.error || "No response from local scanner");
      } catch (error) {
        // Fail closed: if the local scanner is unreachable, the prompt is NOT sent.
        toast(`Δεν ήταν δυνατός ο έλεγχος. Το μήνυμα ΔΕΝ στάλθηκε. ${error.message}`, "danger");
        return;
      }

      // DLP matrix decided by the backend: BLOCK > WARN > REDACT > ALLOW.
      const action = String(result.action || "BLOCK").toUpperCase();

      if (action === "BLOCK") {
        toast(`🛑 BLOCK · ${result.reason || "Η πολιτική DLP μπλόκαρε την αποστολή."} Το μήνυμα ΔΕΝ στάλθηκε.`, "danger");
        return;
      }
      if (action === "WARN") {
        const approved = window.confirm(
          `⚠️ AI Shield · Προειδοποίηση DLP\n\n${result.reason || "Το μήνυμα περιέχει ευαίσθητο περιεχόμενο."}` +
          `\n\nΘέλεις να το στείλεις στο AI;`
        );
        if (!approved) {
          toast("Η αποστολή ακυρώθηκε από τον χρήστη.", "danger");
          return;
        }
        // Confirm with the backend as well: the same incident is marked "confirmed by the user".
        result = await scan(prompt, true, Number.isInteger(result.incident_id) ? result.incident_id : null);
        if (!result || result.error || result.forward_allowed !== true || !Array.isArray(result.entities)) {
          toast("Η πολιτική του backend δεν επέτρεψε την αποστολή.", "danger");
          return;
        }
      } else if (action === "REDACT") {
        if (result.forward_allowed !== true || !Array.isArray(result.entities)) {
          toast("Δεν επιστράφηκαν θέσεις ευαίσθητων στοιχείων. Η αποστολή σταμάτησε.", "danger");
          return;
        }
      } else if (action === "ALLOW") {
        if (result.forward_allowed !== true) {
          toast("Η πολιτική του backend δεν επέτρεψε την αποστολή.", "danger");
          return;
        }
      } else {
        toast("Άγνωστη απόφαση πολιτικής. Η αποστολή σταμάτησε.", "danger");
        return;
      }

      // Reversible Privacy Engine: replace scanner hits AND values already in the vault
      // (e.g. "John Smith" mentioned again without a label) with consistent pseudonyms.
      let pseudo;
      try {
        pseudo = await pseudonymizeLocally(prompt, result.entities || [],
          Array.isArray(result.redact_token_types) ? result.redact_token_types : undefined);
      } catch (error) {
        toast(`Η ψευδωνυμοποίηση απέτυχε. Το μήνυμα ΔΕΝ στάλθηκε. ${error.message}`, "danger");
        return;
      }
      if ((result.entities || []).length && !pseudo.changed) {
        toast("Η ψευδωνυμοποίηση δεν άλλαξε το κείμενο. Το μήνυμα ΔΕΝ στάλθηκε.", "danger");
        return;
      }
      if (pseudo.changed) {
        setComposerText(composer, pseudo.text);
        await settleEditor();
        const sent = readText(composer).replace(/\s+/g, " ").trim();
        if (sent !== pseudo.text.replace(/\s+/g, " ").trim()) {
          toast("Ο editor της σελίδας δεν δέχτηκε το ψευδωνυμοποιημένο κείμενο. Το μήνυμα ΔΕΝ στάλθηκε.", "danger");
          return;
        }
        const list = pseudo.replaced.map(r => r.token).slice(0, 6).join(", ");
        const more = pseudo.replaced.length > 6 ? ` +${pseudo.replaced.length - 6}` : "";
        const n = pseudo.replaced.length;
        const head = action === "WARN" ? "⚠️ WARN (επιβεβαιώθηκε) + ✂️ REDACT" : "✂️ REDACT";
        toast(`${head} · ${n} ${n === 1 ? "στοιχείο στάλθηκε ως ψευδώνυμο" : "στοιχεία στάλθηκαν ως ψευδώνυμα"}: ${list}${more}. Στην απάντηση θα εμφανιστούν οι πραγματικές τιμές μόνο σε σένα.`, "success");
      } else {
        // Text unchanged (ALLOW, or WARN confirmed without pseudonyms): still let the page's
        // own state catch up, and make sure exactly the text that was scanned is what goes out.
        await settleEditor();
        if (normalize(readText(composer)) !== normalize(prompt)) {
          toast("Το κείμενο άλλαξε μετά τον έλεγχο. Το μήνυμα ΔΕΝ στάλθηκε. Πάτησε ξανά Send για νέο έλεγχο.", "danger");
          return;
        }
        if (action === "WARN") toast("⚠️ WARN · Στάλθηκε μετά από επιβεβαίωσή σου.", "success");
        else toast(`✅ ALLOW · ${result.reason || "Δεν εντοπίστηκαν ευαίσθητα δεδομένα."}`, "success");
      }

      if (!(await sendAgain(button, composer))) {
        toast("Ο έλεγχος ολοκληρώθηκε, αλλά δεν βρέθηκε κουμπί αποστολής. Πάτησε ξανά Send.", "danger");
      }
    } catch (error) {
      toast(`Σφάλμα ελέγχου. Η αποστολή σταμάτησε. ${error.message}`, "danger");
    } finally {
      busy = false;
    }
  }

  // React apps (claude.ai, ChatGPT) send from their own state, not from the DOM:
  // give the editor -> app state update time to commit before pressing Send again.
  async function settleEditor() {
    await new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r)));
    await new Promise(r => setTimeout(r, 150));
  }
  const normalize = text => String(text || "").replace(/\s+/g, " ").trim();

  document.addEventListener("click", event => {
    const button = event.target?.closest?.('button,[role="button"]');
    if (!button) return;
    if (bypassButton === button) { bypassButton = null; return; }
    if (!settings.promptGuardEnabled && settingsReady && !settingsLoadFailed) return;
    if (!looksLikeSendButton(button)) return;
    const composer = findComposer(button);
    if (composer) runGuard(event, composer, button);
  }, true);

  document.addEventListener("keydown", event => {
    if (event.key !== "Enter" || event.shiftKey || event.isComposing || event.altKey || event.ctrlKey || event.metaKey) return;
    if (bypassEnterTarget && event.target === bypassEnterTarget) return; // our own replay
    const target = event.target;
    const composer = isComposer(target) ? target : findComposer(null);
    if (!composer || !visible(composer) || !readText(composer).trim()) return;
    if (settingsReady && !settingsLoadFailed && !settings.promptGuardEnabled) return;
    const button = findSendButton(composer, null);
    // Fail closed: a chat composer (textarea / contenteditable) is guarded even when
    // its send button cannot be found. Plain <input> fields (search, rename) are not.
    if (!button && composer.matches("input")) return;
    runGuard(event, composer, button);
  }, true);

  // ------------------- PDF attachments: same DLP rules as typed prompts -------------------
  // A PDF attached via the file picker, drag & drop or paste is held back until the local
  // AI Shield backend has read its text and applied the policy:
  //   BLOCK  -> the file is not attached.
  //   WARN   -> the user must confirm; then the original file is attached.
  //   REDACT -> the PDF itself is NOT attached (it contains the real values); its text goes
  //             into the message with consistent pseudonyms ([AFM_001]) instead, and the AI's
  //             answer is de-anonymized on screen like any other message.
  //   ALLOW  -> the original file is attached.
  // Files that cannot be inspected (encrypted, too large, scanner unreachable) are not attached.
  const MAX_FILE_BYTES = 10 * 1024 * 1024;
  const ourEvents = new WeakSet();   // events we re-dispatch after the check
  let fileBusy = false;
  const isPdf = f => !!f && (f.type === "application/pdf" || /\.pdf$/i.test(f.name || ""));
  const guardOff = () => settingsReady && !settingsLoadFailed && !settings.promptGuardEnabled;

  async function loadSettingsNow() {
    if (settingsReady) return;
    try {
      const data = await ext.storage.local.get(["settings"]);
      settings = { ...settings, ...(data.settings || {}) };
      settingsReady = true;
    } catch {
      settingsLoadFailed = true;
      settingsReady = true;
    }
  }
  // FileReader (callback API) instead of file.arrayBuffer(): in Firefox the File belongs to
  // the page, and awaiting a promise/ArrayBuffer from the page's side throws
  // "Permission denied to access property constructor". A data: URL is a plain string.
  function fileToBase64(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => {
        const url = String(reader.result || "");
        const comma = url.indexOf(",");
        if (comma < 0) reject(new Error("Το αρχείο δεν διαβάστηκε."));
        else resolve(url.slice(comma + 1));
      };
      reader.onerror = () => reject(new Error("Το αρχείο δεν διαβάστηκε."));
      reader.readAsDataURL(file);
    });
  }
  function scanFile(contentBase64, confirmWarning = false, warnIncidentId = null) {
    return ext.runtime.sendMessage({ type: "AI_SHIELD_SCAN_FILE", contentBase64, providerKey: provider, confirmWarning, warnIncidentId });
  }
  async function inspectPdf(file) {
    const name = file.name || "έγγραφο.pdf";
    const stop = msg => ({ keep: false, danger: true, msg: `🛑 ${name}: ${msg} Δεν επισυνάφθηκε.` });
    if (file.size > MAX_FILE_BYTES) return stop("ξεπερνά τα 10 MB και δεν μπορεί να ελεγχθεί.");
    let b64, result;
    try {
      b64 = await fileToBase64(file);
      result = await scanFile(b64);
      if (!result || result.error) throw new Error(result?.error || "Καμία απάντηση από τον scanner.");
    } catch (error) {
      return stop(`δεν ήταν δυνατός ο έλεγχος (${error.message}).`);
    }
    const action = String(result.action || "BLOCK").toUpperCase();
    if (action === "BLOCK") return stop(`BLOCK · ${result.reason || "Η πολιτική DLP δεν επιτρέπει αυτό το αρχείο."}`);
    if (action === "WARN") {
      const approved = window.confirm(
        `⚠️ AI Shield · Προειδοποίηση DLP για συνημμένο\n\n📄 ${name}\n${result.reason || "Το αρχείο περιέχει ευαίσθητο περιεχόμενο."}` +
        `\n\nΘέλεις να το στείλεις στο AI;`);
      if (!approved) return { keep: false, danger: true, msg: `${name}: η επισύναψη ακυρώθηκε από εσένα.` };
      try {
        result = await scanFile(b64, true, Number.isInteger(result.incident_id) ? result.incident_id : null);
        if (!result || result.error) throw new Error(result?.error || "Καμία απάντηση.");
      } catch (error) {
        return stop(`η επιβεβαίωση απέτυχε (${error.message}).`);
      }
    } else if (action !== "REDACT" && action !== "ALLOW") {
      return stop("άγνωστη απόφαση πολιτικής.");
    }
    if (result.forward_allowed !== true) return stop("η πολιτική δεν επέτρεψε την αποστολή.");
    if (result.upload_original === true) {
      return { keep: true, msg: action === "WARN" ? `⚠️ ${name}: επισυνάπτεται μετά από επιβεβαίωσή σου.`
        : `✅ ${name}: δεν βρέθηκαν ευαίσθητα δεδομένα, επισυνάπτεται.` };
    }
    // Sensitive values inside: the original PDF never leaves; its text goes in pseudonymized.
    if (typeof result.text !== "string" || !Array.isArray(result.entities) || !result.entities.length) {
      return stop("δεν επιστράφηκαν θέσεις ευαίσθητων στοιχείων.");
    }
    let pseudo;
    try {
      pseudo = await pseudonymizeLocally(result.text, result.entities,
        Array.isArray(result.redact_token_types) ? result.redact_token_types : undefined);
    } catch (error) {
      return stop(`η ψευδωνυμοποίηση απέτυχε (${error.message}).`);
    }
    if (!pseudo.changed) return stop("η ψευδωνυμοποίηση δεν άλλαξε το κείμενο.");
    const list = pseudo.replaced.map(r => r.token).slice(0, 5).join(", ");
    const more = pseudo.replaced.length > 5 ? ` +${pseudo.replaced.length - 5}` : "";
    return {
      keep: false,
      // The file name is NOT included: it may itself contain personal data.
      text: `📄 Συνημμένο PDF (κείμενο· τα ευαίσθητα στοιχεία αντικαταστάθηκαν από το AI Shield):\n\n${pseudo.text}`,
      msg: `✂️ ${action === "WARN" ? "WARN + " : ""}REDACT · ${name}: το PDF δεν επισυνάφθηκε. Το κείμενό του μπήκε στο μήνυμα με ψευδώνυμα (${list}${more}). Έλεγξέ το και πάτησε Αποστολή.`
    };
  }
  function toFileList(files) {
    const dt = new DataTransfer();
    for (const f of files) dt.items.add(f);
    return dt;
  }
  function insertIntoComposer(texts) {
    if (!texts.length) return true;
    const composer = findComposer(null);
    if (!composer) return false;
    const current = readText(composer).trim();
    setComposerText(composer, (current ? `${current}\n\n` : "") + texts.join("\n\n"));
    return true;
  }
  async function handleAttach(files, replay, reject) {
    fileBusy = true;
    try {
      await loadSettingsNow();
      if (settingsLoadFailed) { reject(); toast("Δεν ήταν δυνατή η ανάγνωση ρυθμίσεων. Το αρχείο ΔΕΝ επισυνάφθηκε.", "danger"); return; }
      if (!settings.promptGuardEnabled) { replay(files); return; }
      const pdfCount = files.filter(isPdf).length;
      toast(`Έλεγχος ${pdfCount === 1 ? "του PDF" : `${pdfCount} PDF`} τοπικά πριν επισυναφθεί…`);
      const keep = [], texts = [], msgs = [];
      let danger = false;
      for (const file of files) {
        if (!isPdf(file)) { keep.push(file); continue; }
        const r = await inspectPdf(file);
        if (r.keep) keep.push(file);
        if (r.text) texts.push(r.text);
        msgs.push(r.msg);
        danger = danger || !!r.danger;
      }
      if (keep.length) {
        try { replay(keep); }
        catch (error) { reject(); msgs.push(`Η επισύναψη δεν ολοκληρώθηκε (${error.message}). Επισύναψέ το ξανά.`); danger = true; }
      } else reject();
      if (texts.length) {
        await settleEditor();
        if (!insertIntoComposer(texts)) { msgs.push("Δεν βρέθηκε πεδίο μηνύματος για το κείμενο του PDF."); danger = true; }
      }
      toast(msgs.join("  •  "), danger ? "danger" : "success");
    } catch (error) {
      reject();
      toast(`Σφάλμα ελέγχου αρχείου. Δεν επισυνάφθηκε. ${error.message}`, "danger");
    } finally {
      fileBusy = false;
    }
  }
  function holdIfPdf(event, files) {
    if (ourEvents.has(event) || !files.some(isPdf) || guardOff()) return false;
    pauseEvent(event);
    if (fileBusy) { toast("Ολοκληρώνεται ο έλεγχος προηγούμενου αρχείου. Δοκίμασε ξανά σε λίγο.", "danger"); return false; }
    return true;
  }

  // 1) File picker: <input type="file">. Browsers fire "input" then "change"; both are held.
  function onFileInput(event) {
    const input = event.target;
    if (!(input instanceof HTMLInputElement) || input.type !== "file") return;
    const files = [...(input.files || [])];
    if (event.type === "input") {
      if (!ourEvents.has(event) && files.some(isPdf) && !guardOff()) pauseEvent(event);
      return;
    }
    if (!holdIfPdf(event, files)) { if (!ourEvents.has(event) && files.some(isPdf) && !guardOff()) input.value = ""; return; }
    handleAttach(files, keep => {
      if (keep.length !== files.length) {
        try { input.files = toFileList(keep).files; }
        catch { input.value = ""; toast("Ο browser δεν επέτρεψε να κρατηθούν μόνο τα επιτρεπτά αρχεία: επισύναψέ τα ξανά χωρίς το PDF.", "danger"); return; }
      }
      for (const type of ["input", "change"]) {
        const ev = new Event(type, { bubbles: true });
        ourEvents.add(ev);
        input.dispatchEvent(ev);
      }
    }, () => { input.value = ""; });
  }
  document.addEventListener("input", onFileInput, true);
  document.addEventListener("change", onFileInput, true);

  // 2) Drag & drop onto the chat.
  window.addEventListener("drop", event => {
    const files = [...(event.dataTransfer?.files || [])];
    if (!holdIfPdf(event, files)) return;
    const target = event.target, { clientX, clientY } = event;
    const where = () => (target && target.isConnected ? target : (findComposer(null) || document.body));
    handleAttach(files, keep => {
      const ev = new DragEvent("drop", { bubbles: true, cancelable: true, composed: true, dataTransfer: toFileList(keep), clientX, clientY });
      ourEvents.add(ev);
      where().dispatchEvent(ev);
    }, () => {
      // Let the page close its "drop here" overlay.
      const ev = new DragEvent("dragleave", { bubbles: true, cancelable: true, clientX, clientY });
      ourEvents.add(ev);
      where().dispatchEvent(ev);
    });
  }, true);

  // 3) Pasting a file (copied in the file manager) into the chat.
  window.addEventListener("paste", event => {
    const files = [...(event.clipboardData?.files || [])];
    if (!holdIfPdf(event, files)) return;
    const target = event.target;
    handleAttach(files, keep => {
      let ev;
      try { ev = new ClipboardEvent("paste", { bubbles: true, cancelable: true, clipboardData: toFileList(keep) }); }
      catch { toast("Ο browser δεν επιτρέπει επανεπικόλληση: επισύναψε τα υπόλοιπα αρχεία με το κουμπί.", "danger"); return; }
      ourEvents.add(ev);
      (target && target.isConnected ? target : document.activeElement || document.body).dispatchEvent(ev);
    }, () => {});
  }, true);

  // ------------------- De-anonymize AI responses (display only) -------------------
  // Text nodes are changed in place (nodeValue), never re-parented, so the chat
  // app's own renderer keeps working while it streams. If the app rewrites a node
  // back to the token, the observer simply restores it again.
  let vaultTokens = {};
  let tokenRegex = null;
  const restoredNodes = new Map(); // Text node -> [[start,end],...] of restored values
  const writtenText = new WeakMap(); // Text node -> value we wrote (ignore our own mutation)
  const HIGHLIGHT = "ai-shield-restored";
  const canHighlight = typeof CSS !== "undefined" && CSS.highlights && typeof Highlight === "function";
  let pending = new Set();
  let flushTimer = null;

  function skipNode(node) {
    const parent = node.parentElement;
    if (!parent) return true;
    // Never write real values into the composer or any editable field: they would be re-sent.
    return !!parent.closest('textarea, input, [contenteditable=""], [contenteditable="true"], [contenteditable="plaintext-only"], script, style, noscript, [data-ai-shield]');
  }
  function restoreNode(node) {
    if (!tokenRegex || node.nodeType !== Node.TEXT_NODE || skipNode(node)) return;
    const res = Pseudo.restoreText(vaultTokens, tokenRegex, node.nodeValue);
    if (!res) return;
    writtenText.set(node, res.text);
    node.nodeValue = res.text;
    restoredNodes.set(node, res.ranges);
  }
  function restoreTree(root) {
    if (!root || !tokenRegex) return;
    if (root.nodeType === Node.TEXT_NODE) { restoreNode(root); return; }
    if (root.nodeType !== Node.ELEMENT_NODE && root.nodeType !== Node.DOCUMENT_NODE) return;
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    let n;
    while ((n = walker.nextNode())) restoreNode(n);
  }
  function refreshHighlight() {
    if (!canHighlight) return;
    const hl = new Highlight();
    for (const [node, ranges] of restoredNodes) {
      if (!node.isConnected) { restoredNodes.delete(node); continue; }
      for (const [s, e] of ranges) {
        if (e > node.nodeValue.length) continue;
        const r = document.createRange();
        r.setStart(node, s); r.setEnd(node, e);
        hl.add(r);
      }
    }
    CSS.highlights.set(HIGHLIGHT, hl);
  }
  function flush() {
    flushTimer = null;
    const batch = pending; pending = new Set();
    for (const n of batch) if (n.isConnected) restoreTree(n);
    refreshHighlight();
  }
  function schedule(node) {
    pending.add(node);
    if (!flushTimer) flushTimer = setTimeout(flush, 40);
  }
  const observer = new MutationObserver(mutations => {
    if (!tokenRegex) return;
    for (const m of mutations) {
      if (m.type === "characterData") {
        if (writtenText.get(m.target) === m.target.nodeValue) continue; // our own restore
        // Text changed again (streaming / re-render): forget old ranges, re-check.
        restoredNodes.delete(m.target);
        schedule(m.target);
      } else {
        for (const n of m.addedNodes) schedule(n);
      }
    }
  });
  function applyVault(tokens) {
    vaultTokens = tokens && typeof tokens === "object" ? tokens : {};
    const active = settings.restoreResponses !== false && Object.keys(vaultTokens).length > 0;
    tokenRegex = active ? Pseudo.buildTokenRegex(vaultTokens) : null;
    if (!tokenRegex) { observer.disconnect(); return; }
    observer.observe(document.documentElement, { childList: true, subtree: true, characterData: true });
    schedule(document.body || document.documentElement);
  }
  if (canHighlight) {
    const style = document.createElement("style");
    style.textContent = `::highlight(${HIGHLIGHT}){background-color:rgba(84,214,207,.28);text-decoration:underline dotted rgba(84,214,207,.9);}`;
    (document.head || document.documentElement).appendChild(style);
  }
  ext.runtime.onMessage.addListener(message => {
    if (message && message.type === "AI_SHIELD_VAULT_UPDATED") applyVault(message.tokens);
  });
  function loadVaultSnapshot() {
    Promise.resolve(ext.runtime.sendMessage({ type: "AI_SHIELD_VAULT_SNAPSHOT" }))
      .then(res => applyVault(res && res.tokens)).catch(() => {});
  }

  ext.storage.local.get(["settings"]).then(data => {
    settings = { ...settings, ...(data.settings || {}) };
    settingsReady = true;
    loadVaultSnapshot();
  }).catch(() => {
    settingsLoadFailed = true;
    settingsReady = true;
  });

  if (ext.storage.onChanged) {
    ext.storage.onChanged.addListener((changes, area) => {
      if (area === "local" && changes.settings) {
        settings = { ...settings, ...(changes.settings.newValue || {}) };
        loadVaultSnapshot();
      }
    });
  }
})();
