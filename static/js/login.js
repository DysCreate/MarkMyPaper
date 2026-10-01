(function () {
  "use strict";

  function show(mode) {
    document.getElementById("login-form").hidden = mode === "register";
    document.getElementById("register-form").hidden = mode === "login";
  }

  async function auth(mode, event) {
    event.preventDefault();
    const errEl = document.getElementById(mode === "login" ? "login-err" : "reg-err");
    errEl.hidden = true;
    errEl.textContent = "";

    let body;
    if (mode === "login") {
      body = {
        email: document.getElementById("login-email").value,
        password: document.getElementById("login-password").value
      };
    } else {
      body = {
        name: document.getElementById("reg-name").value,
        email: document.getElementById("reg-email").value,
        password: document.getElementById("reg-password").value
      };
    }

    try {
      const res = await fetch("/api/" + mode, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
      });
      const data = await res.json();
      if (!res.ok) {
        errEl.textContent = data.message || "Request failed";
        errEl.hidden = false;
        return;
      }
      localStorage.setItem("mkp_token", data.token);
      window.location.href = "/upload.html";
    } catch (e) {
      errEl.textContent = "Could not reach the app. Is it running?";
      errEl.hidden = false;
    }
  }

  document.addEventListener("DOMContentLoaded", function () {
    document.getElementById("login-form").querySelector("form")
      .addEventListener("submit", function (e) { auth("login", e); });
    document.getElementById("register-form").querySelector("form")
      .addEventListener("submit", function (e) { auth("register", e); });
    document.getElementById("show-register")
      .addEventListener("click", function () { show("register"); });
    document.getElementById("show-login")
      .addEventListener("click", function () { show("login"); });
    if (window.location.hash === "#register") {
      show("register");
    }
  });
})();
