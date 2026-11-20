/* NexGuard · login page: sign in and account invitation activation. */
(() => {
  const $ = id => document.getElementById(id);
  const views = { signed: $("vSigned"), signin: $("vSignin"), reset: $("vReset") };
  const params = new URLSearchParams(location.search);
  const next = params.get("next") || "";
  let minLen = 10;
  let resetToken = "";

  const ERRORS = {
    account_disabled: "Ο λογαριασμός είναι απενεργοποιημένος. Επικοινώνησε με τον διαχειριστή."
  };

  function show(name) {
    for (const [k, el] of Object.entries(views)) el.hidden = k !== name;
    const first = views[name].querySelector("input:not([type=checkbox])");
    if (first) setTimeout(() => first.focus(), 30);
  }
  function alertBox(text, kind = "error") {
    const el = $("alert");
    if (!text) { el.hidden = true; return; }
    el.className = `alert ${kind}`;
    el.textContent = text;
    el.hidden = false;
  }
  async function post(url, body) {
    const res = await fetch(url, {
      method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json" }, body: JSON.stringify(body)
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const detail = Array.isArray(data.detail) ? "Έλεγξε τα στοιχεία που έγραψες." : data.detail;
      throw new Error(detail || `Σφάλμα ${res.status}`);
    }
    return data;
  }
  function busy(btn, on, label) {
    btn.disabled = on;
    if (on) { btn.dataset.label = btn.textContent; btn.textContent = label; }
    else if (btn.dataset.label) btn.textContent = btn.dataset.label;
  }
  const validEmail = v => /^[^@\s]+@[^@\s]+\.[^@\s]{2,}$/.test(v);
  const rules = pw => ({ len: pw.length >= minLen, case: pw.toLowerCase() !== pw && pw.toUpperCase() !== pw, num: /\d/.test(pw) });

  // ------------------------------------------------------------ show / hide password
  document.querySelectorAll(".eye").forEach(btn => btn.addEventListener("click", () => {
    const input = $(btn.dataset.toggle);
    const hidden = input.type === "password";
    input.type = hidden ? "text" : "password";
    btn.setAttribute("aria-label", hidden ? "Απόκρυψη κωδικού" : "Εμφάνιση κωδικού");
  }));

  // ------------------------------------------------------------ sign in
  $("signinForm").addEventListener("submit", async e => {
    e.preventDefault();
    const email = $("email").value.trim(), password = $("password").value;
    $("email").setAttribute("aria-invalid", String(!validEmail(email)));
    $("password").setAttribute("aria-invalid", String(!password));
    if (!validEmail(email) || !password) { alertBox("Συμπλήρωσε έγκυρο email και κωδικό."); return; }
    const btn = $("signinBtn");
    busy(btn, true, "Σύνδεση…");
    try {
      const data = await post("/api/auth/login", { email, password, remember: $("remember").checked, next });
      location.assign(data.redirect || "/app/");
    } catch (err) {
      alertBox(err.message);
      $("password").value = "";
      $("password").focus();
      busy(btn, false);
    }
  });

  // ------------------------------------------------------------ reset password
  function paintRules() {
    const r = rules($("newPassword").value);
    document.querySelectorAll("#rules li").forEach(li => li.classList.toggle("ok", !!r[li.dataset.rule]));
  }
  $("newPassword").addEventListener("input", paintRules);
  $("resetForm").addEventListener("submit", async e => {
    e.preventDefault();
    const pw = $("newPassword").value, pw2 = $("newPassword2").value, r = rules(pw);
    if (!r.len || !r.case || !r.num) { alertBox("Ο νέος κωδικός δεν πληροί τους κανόνες."); return; }
    if (pw !== pw2) { $("newPassword2").setAttribute("aria-invalid", "true"); alertBox("Οι δύο κωδικοί δεν ταιριάζουν."); return; }
    const btn = $("resetBtn");
    busy(btn, true, "Αποθήκευση…");
    try {
      const data = await post("/api/auth/reset", { token: resetToken, password: pw });
      resetToken = "";
      history.replaceState(null, "", location.pathname);
      $("resetForm").reset(); paintRules();
      show("signin");
      alertBox(data.message, "success");
    } catch (err) {
      alertBox(err.message);
    } finally {
      busy(btn, false);
    }
  });

  // ------------------------------------------------------------ logout (when already signed in)
  $("logoutBtn").addEventListener("click", async () => {
    try { await post("/api/auth/logout", {}); } catch { /* ignore */ }
    show("signin");
    alertBox("Αποσυνδέθηκες.", "info");
  });

  // ------------------------------------------------------------ start
  (async () => {
    const hash = new URLSearchParams(location.hash.slice(1));
    let invite = false;
    if (hash.get("reset") || hash.get("invite")) {
      invite = !!hash.get("invite");
      resetToken = hash.get("invite") || hash.get("reset");
      history.replaceState(null, "", location.pathname);   // remove the token from the address bar
    }
    if (invite) {                                           // invitation from the Admin Console
      $("resetEyebrow").textContent = "Πρόσκληση";
      $("resetTitle").textContent = "Ενεργοποίηση λογαριασμού";
      $("resetIntro").hidden = false;
      $("resetBtn").textContent = "Ενεργοποίηση";
      document.title = "Ενεργοποίηση λογαριασμού — NexGuard";
    }
    try {
      const cfg = await (await fetch("/api/auth/config", { credentials: "same-origin" })).json();
      minLen = cfg.password_min || minLen;
      $("minLen").textContent = minLen;
    } catch { /* keep defaults */ }

    if (resetToken) { show("reset"); return; }
    const err = params.get("error");
    if (err) alertBox(ERRORS[err] || "Η σύνδεση απέτυχε. Δοκίμασε ξανά.");
    try {
      const res = await fetch("/api/auth/me", { credentials: "same-origin" });
      const user = res.ok ? (await res.json()).user : null;
      if (user) {
        $("signedName").textContent = user.name;
        $("signedEmail").textContent = `${user.email} · ${user.role === "admin" ? "Διαχειριστής" : "Χρήστης"}`;
        $("continueBtn").href = user.role === "admin" ? (next.startsWith("/app") ? next : "/admin/") : "/app/";
        show("signed");
        return;
      }
    } catch { /* not signed in */ }
    show("signin");
  })();
})();
