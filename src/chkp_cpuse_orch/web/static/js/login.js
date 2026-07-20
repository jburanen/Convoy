/*
  chkp-cpuse-orch — login page logic. Plain JS, no build step.
  Posts credentials to /api/auth/login; the server sets an HttpOnly session
  cookie on success, then we hand off to the main UI.
*/

"use strict";

const form = document.getElementById("login-form");
const errorBox = document.getElementById("login-error");
const submitBtn = document.getElementById("login-submit");

function showError(message) {
  errorBox.textContent = message;
  errorBox.classList.remove("hidden");
}

// If auth isn't actually enabled (auth-optional and unconfigured), there's no
// login to do — send the operator straight to the app.
(async function checkEnabled() {
  try {
    const resp = await fetch("/api/auth/config");
    if (resp.ok) {
      const cfg = await resp.json();
      if (!cfg.auth_enabled) window.location.replace("/");
    }
  } catch { /* offline — let the form attempt and surface the error */ }
})();

form.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  errorBox.classList.add("hidden");
  const username = document.getElementById("login-username").value.trim();
  const passwordInput = document.getElementById("login-password");
  const password = passwordInput.value;
  submitBtn.disabled = true;
  try {
    const resp = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    passwordInput.value = ""; // plaintext leaves the page as soon as possible
    if (resp.ok) {
      window.location.replace("/");
      return;
    }
    let detail = "Sign in failed.";
    try { detail = (await resp.json()).detail ?? detail; } catch { /* not json */ }
    showError(detail);
  } catch (e) {
    showError("Could not reach the server: " + e.message);
  } finally {
    submitBtn.disabled = false;
  }
});
