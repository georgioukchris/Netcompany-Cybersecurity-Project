/* AI Shield — Reversible Privacy Engine (shared by background and content script).
 *
 *   "client John Smith, AFM 123456789"  ->  "client [PERSON_001], AFM [AFM_001]"
 *   AI reply "Dear [PERSON_001]"        ->  shown to the user as "Dear John Smith"
 *
 * Pure functions only: no DOM, no network, no storage. The vault object is
 * plain JSON so the background can keep it in storage.session (memory only,
 * cleared when the browser closes, never written to disk or sent anywhere).
 */
(() => {
  const MIN_KNOWN_VALUE_LENGTH = 4;

  function newVault() {
    return { byKey: {}, byToken: {}, counters: {} };
  }

  function normKey(prefix, value) {
    return `${prefix}\u0000${String(value).replace(/\s+/g, " ").trim()}`;
  }

  function tokenFor(vault, prefix, value) {
    const key = normKey(prefix, value);
    let token = vault.byKey[key];
    if (!token) {
      const n = (vault.counters[prefix] || 0) + 1;
      vault.counters[prefix] = n;
      token = `[${prefix}_${String(n).padStart(3, "0")}]`;
      vault.byKey[key] = token;
      vault.byToken[token] = value;
    }
    return token;
  }

  // Backend offsets are Unicode code points (Python); JS strings are UTF-16.
  function codePointToUtf16Offsets(text) {
    const map = [0];
    let u16 = 0;
    for (const ch of text) { u16 += ch.length; map.push(u16); }
    return map;
  }

  const WORD = /[\p{L}\p{N}_]/u;

  /**
   * @param vault    mutable vault (tokens are added as needed)
   * @param text     the prompt exactly as it was sent to the scanner
   * @param entities [{type, token_type, start, end}] code-point offsets from the backend
   * @param allowedPrefixes optional list of pseudonym prefixes (e.g. ["AFM","IBAN"]) that the
   *        DLP policy hides; known vault values of other types (e.g. names, now ALLOW) are left as is.
   * @returns {text, replaced:[{token,type}], changed:boolean}
   */
  function pseudonymize(vault, text, entities, allowedPrefixes) {
    const allowed = Array.isArray(allowedPrefixes) ? new Set(allowedPrefixes) : null;
    const cp = codePointToUtf16Offsets(text);
    const cpLen = cp.length - 1;
    const spans = [];

    for (const e of Array.isArray(entities) ? entities : []) {
      const s = Number(e.start), en = Number(e.end);
      if (!Number.isInteger(s) || !Number.isInteger(en) || s < 0 || en <= s || en > cpLen) continue;
      const start = cp[s], end = cp[en];
      const value = text.slice(start, end);
      if (!value.trim()) continue;
      const prefix = String(e.token_type || e.type || "DATA").toUpperCase().replace(/[^A-Z_]/g, "") || "DATA";
      spans.push({ start, end, token: tokenFor(vault, prefix, value), type: e.type || prefix });
    }

    // Consistency across the conversation: values already in the vault are hidden
    // even when this message mentions them without a label.
    const prefixOf = t => (/^\[([A-Z_]+)_\d+\]$/.exec(t) || [])[1];
    const known = Object.entries(vault.byToken)
      .filter(([t, v]) => typeof v === "string" && v.length >= MIN_KNOWN_VALUE_LENGTH && (!allowed || allowed.has(prefixOf(t))))
      .sort((a, b) => b[1].length - a[1].length);
    for (const [token, value] of known) {
      let pos = text.indexOf(value);
      while (pos !== -1) {
        const end = pos + value.length;
        const leftOk = pos === 0 || !WORD.test(text[pos - 1]);
        const rightOk = end === text.length || !WORD.test(text[end]);
        if (leftOk && rightOk) spans.push({ start: pos, end, token, type: "KNOWN" });
        pos = text.indexOf(value, pos + 1);
      }
    }

    const chosen = [];
    for (const sp of spans) {
      if (!chosen.some(c => sp.start < c.end && c.start < sp.end)) chosen.push(sp);
    }
    chosen.sort((a, b) => b.start - a.start);
    let out = text;
    for (const c of chosen) out = out.slice(0, c.start) + c.token + out.slice(c.end);

    const seen = new Set();
    const replaced = [];
    for (const c of chosen.slice().reverse()) {
      if (!seen.has(c.token)) { seen.add(c.token); replaced.push({ token: c.token, type: c.type }); }
    }
    return { text: out, replaced, changed: out !== text };
  }

  function escapeRe(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }

  /** Regex that finds tokens of the prefixes present in `tokens` ({token: value}). */
  function buildTokenRegex(tokens) {
    const prefixes = new Set();
    for (const t of Object.keys(tokens || {})) {
      const m = /^\[([A-Z_]+)_\d+\]$/.exec(t);
      if (m) prefixes.add(m[1]);
    }
    if (!prefixes.size) return null;
    const alt = [...prefixes].sort((a, b) => b.length - a.length).map(escapeRe).join("|");
    // Brackets optional: models sometimes write PERSON_001 or **[PERSON_001]**.
    return new RegExp(`\\[?(?<![A-Za-z0-9_])(${alt})_(\\d{1,6})(?![A-Za-z0-9_])\\]?`, "g");
  }

  /** Replace known tokens with real values. Returns {text, ranges:[[start,end],...]} or null. */
  function restoreText(tokens, regex, text) {
    if (!regex || !text) return null;
    regex.lastIndex = 0;
    let out = "", last = 0, m;
    const ranges = [];
    while ((m = regex.exec(text)) !== null) {
      const key = `[${m[1]}_${String(parseInt(m[2], 10)).padStart(3, "0")}]`;
      const value = tokens[key];
      if (value === undefined) continue;
      out += text.slice(last, m.index);
      const s = out.length;
      out += value;
      ranges.push([s, out.length]);
      last = m.index + m[0].length;
    }
    if (!ranges.length) return null;
    out += text.slice(last);
    return { text: out, ranges };
  }

  globalThis.AIShieldPseudo = { newVault, pseudonymize, buildTokenRegex, restoreText };
})();
