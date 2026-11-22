/* Step 8 (M-8): Frontend Alignment with BFF Contract & Session Management */
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

  var csrfToken = "";
  var userSession = null;
  var busy = false;
  var currentEventSource = null;

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

  function send(text, structuredDest, structuredDep) {
    if (busy) return;
    var message = String(
      text == null ? (input ? input.value : "") : text,
    ).trim();
    if (!message) return;

    if (input) input.value = "";
    busy = True;

    var headers = { "Content-Type": "application/json" };
    if (csrfToken) {
      headers["X-CSRF-Token"] = csrfToken;
    }
    var payload = {
      message: message,
      destination: structuredDest || null,
      departure_city: structuredDep || null,
    };

    fetch("/api/v1/trips/plan", {
      method: "POST",
      headers: headers,
      body: JSON.stringify(payload),
    })
      .then(function (res) {
        return res.json();
      })
      .then(function (planData) {
        var streamUrl = planData.stream_url || planData.sse_url;
        if (!streamUrl) return;
        if (currentEventSource) currentEventSource.close();
        currentEventSource = new EventSource(streamUrl);
      })
      .catch(function (err) {
        console.error("Trip plan error:", err);
      });
  }

  initSession();
})();
