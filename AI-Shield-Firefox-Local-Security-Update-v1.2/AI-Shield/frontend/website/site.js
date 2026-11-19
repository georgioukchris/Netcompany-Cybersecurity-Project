/* NexGuard · public website: mobile menu, footer year, "Σύνδεση" → "Άνοιγμα πλατφόρμας" when signed in. */
(() => {
  const burger = document.getElementById("burger"), menu = document.getElementById("menu");
  burger.addEventListener("click", () => {
    const open = menu.classList.toggle("open");
    burger.setAttribute("aria-expanded", String(open));
  });
  menu.querySelectorAll("a").forEach(a => a.addEventListener("click", () => {
    menu.classList.remove("open"); burger.setAttribute("aria-expanded", "false");
  }));
  document.getElementById("year").textContent = new Date().getFullYear();

  fetch("/api/auth/me", { credentials: "same-origin" }).then(r => r.ok ? r.json() : null).then(data => {
    if (!data || !data.user) return;
    const target = data.user.role === "admin" ? "/admin/" : "/app/";
    document.querySelectorAll('a[href="/login/"]').forEach(a => { a.href = target; a.textContent = "Άνοιγμα πλατφόρμας →"; });
  }).catch(() => {});
})();
