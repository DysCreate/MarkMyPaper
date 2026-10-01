(function () {
  "use strict";

  function getToken() {
    const params = new URLSearchParams(window.location.search);
    return params.get("token") || "";
  }

  document.addEventListener("DOMContentLoaded", function () {
    const token = getToken();
    const form = document.getElementById("reset-form");
    const errEl = document.getElementById("reset-err");
    const okEl = document.getElementById("reset-ok");
    const missingEl = document.getElementById("reset-missing");

    if (!token) {
      form.hidden = true;
      missingEl.hidden = false;
      return;
    }

    form.addEventListener("submit", async function (event) {
      event.preventDefault();
      errEl.hidden = true;
      okEl.hidden = true;

      const pwd = document.getElementById("reset-password").value;
      const confirm = document.getElementById("reset-confirm").value;
      if (pwd !== confirm) {
        errEl.textContent = "The two passwords do not match.";
        errEl.hidden = false;
        return;
      }

      try {
        const res = await fetch("/api/reset-password", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ token: token, new_password: pwd })
        });
        const data = await res.json();
        if (!res.ok) {
          errEl.textContent = data.message || "Password reset failed.";
          errEl.hidden = false;
          return;
        }
        form.hidden = true;
        okEl.hidden = false;
      } catch (e) {
        errEl.textContent = "Could not reach the app. Is it running?";
        errEl.hidden = false;
      }
    });
  });
})();
