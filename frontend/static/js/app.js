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
  var logoutAllBtn = $("logoutAllBtn");
  var mfaCodeInput = $("mfaCodeInput");
  var submitMfaBtn = $("submitMfaBtn");

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
          li.textContent = dateStr + " - " + (e.provider || "Direct") + " (" + (e.ip_address || "unknown") + ")";
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
    agentBubble.textContent = "Gathering requirements and starting multi-agent planning…";
    conversation.appendChild(agentBubble);

    fetch("/api/v1/plan", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": csrfToken,
      },
      body: JSON.stringify({ message: queryText }),
    })
      .then(function (res) {
        if (!res.ok) throw new Error("HTTP " + res.status);
        return res.json();
      })
      .then(function (data) {
        var cid = data.correlation_id;
        var sseUrl = data.sse_url || ("/api/v1/events/stream/" + cid);
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
        if (data.stage === "completed" || data.stage === "synthesis_completed") {
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
        mfa_challenge_token: mfaChallengeToken,
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
        headers: { "X-CSRF-Token": csrfToken },
      })
        .then(function () {
          showToast("All active sessions revoked.");
          initSession();
        });
    });
  }

  initSession();
