/* TravelBrain AI Frontend — BFF Session & Security Event Management */
(function () {
  "use strict";
  var $ = function (id) {
    return document.getElementById(id);
  };
  var conversation = $("conversation");
  var messages = $("messages");
  var hero = $("hero");
  var input = $("input");
  var composer = $("composer");
  var sendBtn = $("sendBtn");
  var statusBtn = $("apiStatus");
  var statusText = statusBtn ? statusBtn.querySelector(".status-text") : null;
  var securityBtn = $("securityBtn");
  var securityModal = $("securityModal");
  var securityModalScrim = $("securityModalScrim");
  var closeSecurityModal = $("closeSecurityModal");
  var doneSecurityModal = $("doneSecurityModal");
  var securityEventsList = $("securityEventsList");
  var logoutAllBtn = $("logoutAllBtn");
  var mfaCodeInput = $("mfaCodeInput");
  var submitMfaBtn = $("submitMfaBtn");

  var csrfToken = "";
  var userSession = null;
  var busy = false;
  var currentEventSource = null;
  var mfaChallengeToken = null;

  function showToast(msg) {
    var toast = $("toast");
    if (!toast) return;
    toast.textContent = msg;
    toast.hidden = false;
    toast.classList.add("show");
    setTimeout(function () {
      toast.classList.remove("show");
      toast.hidden = true;
    }, 3000);
  }

  function initSession() {
    if (statusBtn && statusText) {
      statusBtn.setAttribute("data-state", "checking");
      statusText.textContent = "Connecting…";
    }
    return fetch("/api/v1/auth/me", { credentials: "same-origin" })
      .then(function (res) {
        if (!res.ok) throw new Error("HTTP " + res.status);
        return res.json();
      })
      .then(function (data) {
        userSession = data;
        csrfToken = data.csrf_token || "";
        if (statusBtn && statusText) {
          statusBtn.setAttribute("data-state", "ok");
          statusText.textContent = data.email || "API Connected";
          statusBtn.title = "Connected to BFF Gateway";
        }
      })
      .catch(function (err) {
        console.warn("Session handshake fallback:", err);
        if (statusBtn && statusText) {
          statusBtn.setAttribute("data-state", "ok");
          statusText.textContent = "Guest Mode";
        }
      });
  }

  function loadSecurityEvents() {
    if (!securityEventsList) return;
    fetch("/api/v1/users/me/security-events", { credentials: "same-origin" })
      .then(function (res) {
        return res.json();
      })
      .then(function (data) {
        var events = data.security_events || [];
        if (events.length === 0) {
          securityEventsList.textContent = "No security events recorded.";
          return;
        }
        var html = "<ul style='padding-left:16px; margin:0;'>";
        events.slice(0, 10).forEach(function (e) {
          var tag = e.suspicious ? " <strong style='color:var(--rose)'>[SUSPICIOUS]</strong>" : "";
          html += "<li>" + (e.timestamp || "").split("T")[0] + " - " + e.provider + " (" + e.ip_address + ")" + tag + "</li>";
        });
        html += "</ul>";
        securityEventsList.innerHTML = html;
      })
      .catch(function () {
        securityEventsList.textContent = "Sign in to view security log.";
      });
  }

  if (securityBtn && securityModal && securityModalScrim) {
    securityBtn.addEventListener("click", function () {
      securityModal.hidden = false;
      securityModalScrim.hidden = false;
      loadSecurityEvents();
    });
    var closeModal = function () {
      securityModal.hidden = true;
      securityModalScrim.hidden = true;
    };
    if (closeSecurityModal) closeSecurityModal.addEventListener("click", closeModal);
    if (doneSecurityModal) doneSecurityModal.addEventListener("click", closeModal);
    securityModalScrim.addEventListener("click", closeModal);
  }

  if (submitMfaBtn && mfaCodeInput) {
    submitMfaBtn.addEventListener("click", function () {
      var code = mfaCodeInput.value.trim();
      if (!code) return;
      var payload = {
        mfa_challenge_token: mfaChallengeToken || "mfa_challenge_demo",
        totp_code: code,
      };
      fetch("/api/v1/auth/mfa/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken },
        body: JSON.stringify(payload),
      })
        .then(function (res) {
          return res.json();
        })
        .then(function (resData) {
          if (resData.authenticated) {
            showToast("MFA verification successful!");
            initSession();
          } else {
            showToast(resData.detail || "MFA verification failed");
          }
        })
        .catch(function (err) {
          showToast("MFA error: " + err.message);
        });
    });
  }

  if (logoutAllBtn) {
    logoutAllBtn.addEventListener("click", function () {
      fetch("/api/v1/users/me/logout-all", {
        method: "POST",
        headers: { "X-CSRF-Token": csrfToken },
      })
        .then(function () {
          showToast("All active sessions revoked.");
          initSession();
        });
    });
  }

  initSession();
})();
