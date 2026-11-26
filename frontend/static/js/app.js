/* TravelBrain AI Frontend — Multi-Agent Planning, Session & Security Management */
(function () {
  "use strict";
  var $ = function (id) {
    return document.getElementById(id);
  };
  var conversation = $("conversation");
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
  var activeSessionsList = $("activeSessionsList");
  var logoutAllBtn = $("logoutAllBtn");
  var mfaCodeInput = $("mfaCodeInput");
  var submitMfaBtn = $("submitMfaBtn");
  var loginEmailInput = $("loginEmailInput");
  var loginPasswordInput = $("loginPasswordInput");
  var loginSubmitBtn = $("loginSubmitBtn");
  var saveIdpBtn = $("saveIdpBtn");
  var idpOrgIdInput = $("idpOrgIdInput");
  var idpNameInput = $("idpNameInput");
  var idpTypeSelect = $("idpTypeSelect");
  var idpIssuerInput = $("idpIssuerInput");
  var idpClientIdInput = $("idpClientIdInput");

  var csrfToken = "";
  var userSession = null;
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
          statusBtn.title = "Connected as " + (data.email || "User");
        }
      })
      .catch(function () {
        if (statusBtn && statusText) {
          statusBtn.setAttribute("data-state", "ok");
          statusText.textContent = "Guest Mode";
        }
      });
  }

  /* Safe rendering of security events without innerHTML concatenation */
  function loadSecurityEvents() {
    if (!securityEventsList) return;
    fetch("/api/v1/users/me/security-events", { credentials: "same-origin" })
      .then(function (res) {
        return res.json();
      })
      .then(function (data) {
        var events = data.security_events || [];
        securityEventsList.textContent = "";
        if (events.length === 0) {
          securityEventsList.textContent = "No security events recorded.";
          return;
        }
        var ul = document.createElement("ul");
        ul.style.paddingLeft = "16px";
        ul.style.margin = "0";
        events.slice(0, 10).forEach(function (e) {
          var li = document.createElement("li");
          var dateStr = (e.timestamp || "").split("T")[0];
          li.textContent =
            dateStr +
            " - " +
            (e.provider || "Direct") +
            " (" +
            (e.ip_address || "unknown") +
            ")";
          if (e.suspicious) {
            var tag = document.createElement("strong");
            tag.style.color = "var(--rose, #ff4d4d)";
            tag.style.marginLeft = "6px";
            tag.textContent = "[SUSPICIOUS]";
            li.appendChild(tag);
          }
          ul.appendChild(li);
        });
        securityEventsList.appendChild(ul);
      })
      .catch(function () {
        securityEventsList.textContent = "Sign in to view security log.";
      });
  }

  /* Render Active Sessions with per-session Revoke UI */
  function loadActiveSessions() {
    if (!activeSessionsList) return;
    fetch("/api/v1/users/me/sessions", { credentials: "same-origin" })
      .then(function (res) {
        if (!res.ok) throw new Error("HTTP " + res.status);
        return res.json();
      })
      .then(function (data) {
        var sessions = data.sessions || [];
        activeSessionsList.textContent = "";
        if (sessions.length === 0) {
          activeSessionsList.textContent = "No active sessions found.";
          return;
        }
        var ul = document.createElement("ul");
        ul.style.paddingLeft = "0";
        ul.style.listStyle = "none";
        ul.style.margin = "0";
        sessions.forEach(function (sess) {
          var li = document.createElement("li");
          li.style.display = "flex";
          li.style.justifyContent = "space-between";
          li.style.alignItems = "center";
          li.style.padding = "4px 0";

          var info = document.createElement("span");
          info.textContent = (sess.ip_address || "IP: unknown") + " - " + (sess.user_agent || "Browser") + (sess.is_current ? " (Current)" : "");

          var btn = document.createElement("button");
          btn.className = "btn btn-ghost btn-xs";
          btn.textContent = "Revoke";
          btn.addEventListener("click", function () {
            revokeSession(sess.session_id);
          });

          li.appendChild(info);
          li.appendChild(btn);
          ul.appendChild(li);
        });
        activeSessionsList.appendChild(ul);
      })
      .catch(function () {
        activeSessionsList.textContent = "Sign in to view active sessions.";
      });
  }

  function revokeSession(sessionId) {
    fetch("/api/v1/users/me/sessions/revoke", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": csrfToken
      },
      body: JSON.stringify({ session_id: sessionId })
    })
      .then(function (res) {
        if (res.ok) {
          showToast("Session revoked.");
          loadActiveSessions();
        } else {
          showToast("Failed to revoke session.");
        }
      })
      .catch(function (err) {
        showToast("Error revoking session: " + err.message);
      });
  }

  /* Direct Login Submission Handler */
  if (loginSubmitBtn && loginEmailInput && loginPasswordInput) {
    loginSubmitBtn.addEventListener("click", function () {
      var email = loginEmailInput.value.trim();
      var password = loginPasswordInput.value;
      if (!email || !password) {
        showToast("Email and password required.");
        return;
      }
      fetch("/api/v1/auth/login", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": csrfToken
        },
        body: JSON.stringify({ email: email, password: password })
      })
        .then(function (res) {
          return res.json();
        })
        .then(function (data) {
          if (data.mfa_required || data.mfa_challenge_token) {
            mfaChallengeToken = data.mfa_challenge_token;
            showToast("MFA Required! Enter 6-digit TOTP code below.");
            if (mfaCodeInput) mfaCodeInput.focus();
          } else if (data.access_token || data.authenticated) {
            showToast("Login successful!");
            loginEmailInput.value = "";
            loginPasswordInput.value = "";
            initSession();
          } else {
            showToast(data.detail || "Authentication failed.");
          }
        })
        .catch(function (err) {
          showToast("Login error: " + err.message);
        });
    });
  }

  /* Enterprise IdP Configuration Handler */
  if (saveIdpBtn && idpOrgIdInput && idpNameInput) {
    saveIdpBtn.addEventListener("click", function () {
      var orgId = idpOrgIdInput.value.trim();
      var idpName = idpNameInput.value.trim();
      var idpType = idpTypeSelect ? idpTypeSelect.value : "oidc";
      var issuer = idpIssuerInput ? idpIssuerInput.value.trim() : "";
      var clientId = idpClientIdInput ? idpClientIdInput.value.trim() : "";

      if (!orgId || !idpName) {
        showToast("Org ID and IdP Name required.");
        return;
      }

      var payload = {
        idp_name: idpName,
        idp_type: idpType,
        issuer_url: issuer,
        client_id: clientId,
        allowed_domains: []
      };

      fetch("/api/v1/orgs/" + encodeURIComponent(orgId) + "/idp-config", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": csrfToken
        },
        body: JSON.stringify(payload)
      })
        .then(function (res) {
          return res.json();
        })
        .then(function (data) {
          if (data.org_id || data.status === "configured") {
            showToast("Enterprise IdP saved successfully!");
          } else {
            showToast(data.detail || "Failed to configure IdP.");
          }
        })
        .catch(function (err) {
          showToast("IdP save error: " + err.message);
        });
    });
  }

  /* Planning Stream and Render Logic */
  function startPlanning(queryText) {
    if (!queryText || !queryText.trim()) return;
    if (hero) hero.hidden = true;
    if (sendBtn) sendBtn.disabled = true;
    var userBubble = document.createElement("div");
    userBubble.className = "msg msg-user";
    userBubble.textContent = queryText;
    conversation.appendChild(userBubble);
    var agentBubble = document.createElement("div");
    agentBubble.className = "msg msg-agent";
    agentBubble.textContent =
      "Gathering requirements and starting multi-agent planning…";
    conversation.appendChild(agentBubble);
    fetch("/api/v1/plan", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": csrfToken
      },
      body: JSON.stringify({ message: queryText })
    })
      .then(function (res) {
        if (!res.ok) throw new Error("HTTP " + res.status);
        return res.json();
      })
      .then(function (data) {
        var cid = data.correlation_id;
        var sseUrl = data.sse_url || "/api/v1/events/stream/" + cid;
        connectSSE(sseUrl, agentBubble);
      })
      .catch(function (err) {
        agentBubble.textContent = "Error initiating trip plan: " + err.message;
        if (sendBtn) sendBtn.disabled = false;
      });
  }

  function connectSSE(url, targetElem) {
    if (currentEventSource) {
      currentEventSource.close();
    }
    currentEventSource = new EventSource(url);
    currentEventSource.onmessage = function (event) {
      try {
        var data = JSON.parse(event.data);
        if (data.message) {
          targetElem.textContent = data.message;
        }
        if (
          data.stage === "completed" ||
          data.stage === "synthesis_completed"
        ) {
          currentEventSource.close();
          if (sendBtn) sendBtn.disabled = false;
          showToast("Trip itinerary successfully generated!");
        }
      } catch (e) {
        targetElem.textContent = event.data;
      }
    };
    currentEventSource.onerror = function () {
      currentEventSource.close();
      if (sendBtn) sendBtn.disabled = false;
    };
  }

  if (composer && input) {
    composer.addEventListener("submit", function (e) {
      e.preventDefault();
      var val = input.value;
      input.value = "";
      startPlanning(val);
    });
  }

  if (securityBtn && securityModal && securityModalScrim) {
    securityBtn.addEventListener("click", function () {
      securityModal.hidden = false;
      securityModalScrim.hidden = false;
      loadSecurityEvents();
      loadActiveSessions();
    });
    var closeModal = function () {
      securityModal.hidden = true;
      securityModalScrim.hidden = true;
    };
    if (closeSecurityModal)
      closeSecurityModal.addEventListener("click", closeModal);
    if (doneSecurityModal)
      doneSecurityModal.addEventListener("click", closeModal);
    securityModalScrim.addEventListener("click", closeModal);
  }

  if (submitMfaBtn && mfaCodeInput) {
    submitMfaBtn.addEventListener("click", function () {
      var code = mfaCodeInput.value.trim();
      if (!code) return;
      var payload = {
        mfa_challenge_token: mfaChallengeToken,
        totp_code: code
      };
      fetch("/api/v1/auth/mfa/verify", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": csrfToken
        },
        body: JSON.stringify(payload)
      })
        .then(function (res) {
          return res.json();
        })
        .then(function (resData) {
          if (resData.authenticated) {
            showToast("MFA verification successful!");
            mfaChallengeToken = null;
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
        headers: { "X-CSRF-Token": csrfToken }
      }).then(function () {
        showToast("All active sessions revoked.");
        initSession();
        loadActiveSessions();
      });
    });
  }

  initSession();
})();
