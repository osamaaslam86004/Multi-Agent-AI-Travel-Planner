/* ============================================================
   TravelBrain AI — Frontend Client (BFF Contract Enabled)
   Talks to:
     GET  /api/v1/auth/me                Session & CSRF Token Init
     POST /api/v1/trips/plan             Initiate Travel Planning
     GET  /api/v1/trips/{id}/stream      SSE Real-Time Progress Stream
   ============================================================ */
(function () {
  "use strict";

  /* ---------------- DOM Helpers ---------------- */
  var $ = function (id) {
    return document.getElementById(id);
  };
  var conversation = $("conversation");
  var messages = $("messages");
  var hero = $("hero");
  var input = $("input");
  var composer = $("composer");
  var sendBtn = $("sendBtn");
  var builder = $("builder");
  var toastEl = $("toast");
  var composerWrap = document.querySelector(".composer-wrap");
  var statusBtn = $("apiStatus");
  var statusText = statusBtn ? statusBtn.querySelector(".status-text") : null;

  /* ---------------- State ---------------- */
  var THEME_KEY = "travelbrain.theme";
  var csrfToken = "";
  var userSession = null;
  var busy = false;
  var currentEventSource = null;

  /* ---------------- Utilities ---------------- */
  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined && text !== null) node.textContent = text;
    return node;
  }

  function icon(paths, cls) {
    var svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("fill", "none");
    svg.setAttribute("stroke", "currentColor");
    svg.setAttribute("stroke-width", "2");
    svg.setAttribute("stroke-linecap", "round");
    svg.setAttribute("stroke-linejoin", "round");
    if (cls) svg.setAttribute("class", cls);
    var p = document.createElementNS("http://www.w3.org/2000/svg", "path");
    p.setAttribute("d", paths);
    svg.appendChild(p);
    return svg;
  }

  var toastTimer;
  function toast(msg) {
    if (!toastEl) return;
    toastEl.textContent = msg;
    toastEl.hidden = false;
    requestAnimationFrame(function () {
      toastEl.classList.add("show");
    });
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () {
      toastEl.classList.remove("show");
      setTimeout(function () {
        toastEl.hidden = true;
      }, 250);
    }, 2800);
  }

  function scrollToEnd(smooth) {
    requestAnimationFrame(function () {
      if (conversation) {
        conversation.scrollTo({
          top: conversation.scrollHeight,
          behavior: smooth ? "smooth" : "auto",
        });
      }
    });
  }

  /* ---------------- Theme ---------------- */
  function initTheme() {
    var stored = null;
    try {
      stored = localStorage.getItem(THEME_KEY);
    } catch (e) {}
    var prefersLight =
      window.matchMedia &&
      window.matchMedia("(prefers-color-scheme: light)").matches;
    document.documentElement.setAttribute(
      "data-theme",
      stored || (prefersLight ? "light" : "dark"),
    );
  }

  var themeToggle = $("themeToggle");
  if (themeToggle) {
    themeToggle.addEventListener("click", function () {
      var next =
        document.documentElement.getAttribute("data-theme") === "dark"
          ? "light"
          : "dark";
      document.documentElement.setAttribute("data-theme", next);
      try {
        localStorage.setItem(THEME_KEY, next);
      } catch (e) {}
    });
  }

  /* ---------------- Session & BFF Auth ---------------- */
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
        updateEmptyState();
      })
      .catch(function (err) {
        console.warn("Session handshake fallback:", err);
        if (statusBtn && statusText) {
          statusBtn.setAttribute("data-state", "ok");
          statusText.textContent = "Guest Mode";
        }
        updateEmptyState();
      });
  }

  function updateEmptyState() {
    var hasMessages = messages && messages.children.length > 0;
    if (hero) hero.classList.toggle("is-hidden", hasMessages);
    if (composerWrap) composerWrap.classList.toggle("is-locked", busy);
    if (input) input.disabled = busy;
    if (sendBtn) sendBtn.disabled = busy;
  }

  /* ---------------- Rendering ---------------- */
  function renderUser(text) {
    var wrap = el("div", "msg msg-user");
    wrap.appendChild(el("div", "bubble-user", text));
    messages.appendChild(wrap);
    return wrap;
  }

  function toText(value) {
    if (value === null || value === undefined) return "";
    if (typeof value === "string") return value;
    if (typeof value === "number" || typeof value === "boolean")
      return String(value);
    if (Array.isArray(value)) {
      return value.map(toText).filter(Boolean).join("\n\n");
    }
    if (typeof value === "object") {
      if (typeof value.text === "string") return value.text;
      if (typeof value.content === "string") return value.content;
      try {
        return "```json\n" + JSON.stringify(value, null, 2) + "\n```";
      } catch (e) {
        return String(value);
      }
    }
    return String(value);
  }

  function mdBlock(source, emptyText) {
    var box = el("div", "md");
    var text = toText(source).trim();
    if (!text) {
      var empty = el("div", "md-empty");
      empty.appendChild(
        icon(
          "M12 9v4M12 17h.01M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z",
        ),
      );
      empty.appendChild(
        el("span", null, emptyText || "No data returned for this section."),
      );
      box.appendChild(empty);
      return box;
    }
    if (window.MD && window.MD.render) {
      box.innerHTML = window.MD.render(text);
    } else {
      box.textContent = text;
    }
    return box;
  }

  function toolButton(label, pathD, handler) {
    var b = el("button", "icon-btn sm");
    b.type = "button";
    b.title = label;
    b.setAttribute("aria-label", label);
    b.appendChild(icon(pathD));
    b.addEventListener("click", handler);
    return b;
  }

  function plainTextOf(content, query) {
    return ["# " + (query || "Trip Plan"), "", toText(content)].join("\n");
  }

  function renderResult(finalContent, userQuery) {
    var card = el("article", "card");
    var head = el("div", "card-head");
    var avatar = el("div", "card-avatar");
    avatar.appendChild(
      icon(
        "M17.8 19.2 16 11l3.5-3.5a2.1 2.1 0 0 0-3-3L13 8 4.8 6.2a.8.8 0 0 0-.8 1.3L8 11l-2 2-2.2-.5a.6.6 0 0 0-.6 1L5 16l2.5 1.8a.6.6 0 0 0 1-.6L8 15l2-2 3.5 4a.8.8 0 0 0 1.3-.8Z",
      ),
    );
    head.appendChild(avatar);

    var titleBox = el("div", "card-title");
    titleBox.appendChild(el("strong", null, "TravelBrain AI"));
    titleBox.appendChild(el("small", null, "Plan Ready"));
    head.appendChild(titleBox);

    var tools = el("div", "card-tools");
    tools.appendChild(
      toolButton(
        "Copy plan",
        "M8 4h10a2 2 0 0 1 2 2v10M16 8H6a2 2 0 0 0-2 2v10a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V10a2 2 0 0 0-2-2Z",
        function () {
          var text = plainTextOf(finalContent, userQuery);
          if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text).then(
              function () {
                toast("Plan copied to clipboard");
              },
              function () {
                toast("Could not copy");
              },
            );
          } else {
            toast("Clipboard not available");
          }
        },
      ),
    );
    tools.appendChild(
      toolButton(
        "Download as Markdown",
        "M12 3v12m0 0 4-4m-4 4-4-4M4 17v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2",
        function () {
          var blob = new Blob([plainTextOf(finalContent, userQuery)], {
            type: "text/markdown;charset=utf-8",
          });
          var url = URL.createObjectURL(blob);
          var a = document.createElement("a");
          a.href = url;
          a.download = "travelbrain-plan.md";
          document.body.appendChild(a);
          a.click();
          document.body.removeChild(a);
          setTimeout(function () {
            URL.revokeObjectURL(url);
          }, 1000);
        },
      ),
    );
    tools.appendChild(
      toolButton(
        "Print",
        "M6 9V3h12v6M6 18H4a2 2 0 0 1-2-2v-4a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v4a2 2 0 0 1-2 2h-2M6 14h12v7H6z",
        function () {
          window.print();
        },
      ),
    );
    head.appendChild(tools);
    card.appendChild(head);

    var body = el("div", "card-body");
    body.appendChild(mdBlock(finalContent, "Empty response returned."));
    card.appendChild(body);

    var wrap = el("div", "msg");
    wrap.appendChild(card);
    messages.appendChild(wrap);
    return wrap;
  }

  function renderError(message, detailText) {
    var card = el("article", "card error-card");
    var body = el("div", "error-body");
    body.appendChild(
      icon(
        "M12 9v4M12 17h.01M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z",
        "error-ico",
      ),
    );
    var textBox = el("div");
    textBox.appendChild(el("strong", null, message || "Trip Synthesis Error"));
    textBox.appendChild(
      el(
        "p",
        null,
        detailText ||
          "The multi-agent workflow encountered an issue. Please try again.",
      ),
    );
    body.appendChild(textBox);
    card.appendChild(body);

    var wrap = el("div", "msg");
    wrap.appendChild(card);
    messages.appendChild(wrap);
    return wrap;
  }

  /* ---------------- Real-time SSE Progress Card ---------------- */
  function renderProgressCard() {
    var card = el("article", "card progress-card");
    var head = el("div", "progress-head");
    var label = el("span", "progress-label", "Initiating trip request…");
    var meta = el("span", "progress-meta");
    var pct = el("b", null, "0%");
    meta.appendChild(pct);
    head.appendChild(label);
    head.appendChild(meta);
    card.appendChild(head);

    var track = el("div", "progress-track");
    var fill = el("div", "progress-fill");
    fill.style.width = "0%";
    track.appendChild(fill);
    card.appendChild(track);

    var wrap = el("div", "msg");
    wrap.appendChild(card);
    messages.appendChild(wrap);

    return {
      node: wrap,
      update: function (percentage, messageText) {
        var p = Math.min(Math.max(percentage || 0, 0), 100);
        fill.style.width = p + "%";
        pct.textContent = p + "%";
        if (messageText) label.textContent = messageText;
      },
      finish: function () {
        fill.style.width = "100%";
        pct.textContent = "100%";
      },
    };
  }

  /* ---------------- Send Query & Handle SSE Stream ---------------- */
  function setBusy(state) {
    busy = state;
    if (sendBtn) sendBtn.classList.toggle("is-busy", state);
    updateEmptyState();
  }

  function send(text, structuredDest, structuredDep) {
    if (busy) return;
    var message = String(
      text == null ? (input ? input.value : "") : text,
    ).trim();
    if (!message) return;

    if (input) {
      input.value = "";
      autosize();
    }
    setBusy(true);
    renderUser(message);
    updateEmptyState();

    var progressCard = renderProgressCard();
    scrollToEnd(true);

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
        if (!res.ok) {
          return res.json().then(
            function (errData) {
              throw new Error(errData.detail || "HTTP " + res.status);
            },
            function () {
              throw new Error("HTTP request failed with status " + res.status);
            },
          );
        }
        return res.json();
      })
      .then(function (planData) {
        var streamUrl = planData.stream_url;
        if (!streamUrl) {
          throw new Error("Server did not return a stream URL.");
        }

        if (currentEventSource) {
          currentEventSource.close();
        }

        var evtSource = new EventSource(streamUrl);
        currentEventSource = evtSource;

        evtSource.onmessage = function (e) {
          try {
            var data = JSON.parse(e.data);
            if (data.percentage !== undefined) {
              progressCard.update(data.percentage, data.message);
            }

            if (data.stage === "completed" || data.final_response) {
              evtSource.close();
              currentEventSource = null;
              progressCard.finish();
              if (progressCard.node.parentNode) {
                progressCard.node.remove();
              }

              var resultText = data.final_response || data.itinerary || "";
              renderResult(resultText, message);
              scrollToEnd(true);
              setBusy(false);
              if (input) input.focus();
            } else if (data.stage === "error" || data.stage === "timeout") {
              evtSource.close();
              currentEventSource = null;
              if (progressCard.node.parentNode) {
                progressCard.node.remove();
              }
              renderError(
                "Synthesis Failed",
                data.error || "Trip planning service encountered an error.",
              );
              scrollToEnd(true);
              setBusy(false);
              if (input) input.focus();
            }
          } catch (err) {
            console.error("Error parsing SSE event:", err, e.data);
          }
        };

        evtSource.onerror = function (err) {
          console.warn("SSE connection error:", err);
          evtSource.close();
          currentEventSource = null;
          if (busy) {
            if (progressCard.node.parentNode) {
              progressCard.node.remove();
            }
            renderError(
              "Connection Lost",
              "Lost real-time progress connection to the Gateway.",
            );
            scrollToEnd(true);
            setBusy(false);
            if (input) input.focus();
          }
        };
      })
      .catch(function (err) {
        if (progressCard.node.parentNode) {
          progressCard.node.remove();
        }
        renderError("Could not submit trip request", err.message);
        scrollToEnd(true);
        setBusy(false);
        if (input) input.focus();
      });
  }

  /* ---------------- New Trip ---------------- */
  function startNewTrip() {
    if (busy) {
      toast("Wait for the current plan to finish.");
      return;
    }
    if (currentEventSource) {
      currentEventSource.close();
      currentEventSource = null;
    }
    if (messages) messages.innerHTML = "";
    updateEmptyState();
    if (input) input.focus();
  }

  var newTripBtn = $("newTripBtn");
  if (newTripBtn) {
    newTripBtn.addEventListener("click", startNewTrip);
  }

  /* ---------------- Composer & Trip Builder ---------------- */
  function autosize() {
    if (!input) return;
    input.style.height = "auto";
    input.style.height = Math.min(input.scrollHeight, 200) + "px";
  }

  if (input) {
    input.addEventListener("input", autosize);
    input.addEventListener("keydown", function (e) {
      if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        send();
      }
    });
  }

  if (composer) {
    composer.addEventListener("submit", function (e) {
      e.preventDefault();
      send();
    });
  }

  document.querySelectorAll(".suggestion").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var prompt = btn.getAttribute("data-prompt");
      var dest = btn.getAttribute("data-dest");
      var dep = btn.getAttribute("data-dep");
      send(prompt, dest, dep);
    });
  });

  var builderToggle = $("builderToggle");
  if (builderToggle && builder) {
    builderToggle.addEventListener("click", function () {
      var show = builder.hidden;
      builder.hidden = !show;
      builderToggle.classList.toggle("is-on", show);
      if (show && $("fFrom")) $("fFrom").focus();
    });
  }

  document.querySelectorAll("#interestChips .chip").forEach(function (chip) {
    chip.addEventListener("click", function () {
      chip.classList.toggle("on");
    });
  });

  var builderClear = $("builderClear");
  if (builderClear) {
    builderClear.addEventListener("click", function () {
      ["fFrom", "fTo", "fDate", "fDays", "fPeople", "fBudget"].forEach(
        function (id) {
          if ($(id)) $(id).value = "";
        },
      );
      document.querySelectorAll("#interestChips .chip").forEach(function (c) {
        c.classList.remove("on");
      });
    });
  }

  var builderApply = $("builderApply");
  if (builderApply) {
    builderApply.addEventListener("click", function () {
      var from = $("fFrom") ? $("fFrom").value.trim() : "";
      var to = $("fTo") ? $("fTo").value.trim() : "";
      var date = $("fDate") ? $("fDate").value : "";
      var days = $("fDays") ? $("fDays").value.trim() : "";
      var people = $("fPeople") ? $("fPeople").value.trim() : "";
      var budget = $("fBudget") ? $("fBudget").value.trim() : "";
      var interests = [];
      document
        .querySelectorAll("#interestChips .chip.on")
        .forEach(function (c) {
          interests.push(c.getAttribute("data-value"));
        });

      if (!to) {
        toast("Add a destination first.");
        if ($("fTo")) $("fTo").focus();
        return;
      }

      var parts = ["Plan a"];
      if (days) parts.push(days + " day");
      parts.push("trip to " + to);
      if (from) parts.push("from " + from);
      if (date) {
        var d = new Date(date + "T00:00:00");
        if (!isNaN(d)) {
          parts.push(
            "departing " +
              d.toLocaleDateString(undefined, {
                day: "numeric",
                month: "long",
                year: "numeric",
              }),
          );
        }
      }
      if (people)
        parts.push(
          "for " + people + (people === "1" ? " traveller" : " travellers"),
        );
      if (budget) parts.push("with a budget of " + budget);
      if (interests.length) parts.push("focused on " + interests.join(", "));

      var sentence =
        parts.join(" ") +
        ". Find flights, hotels, the weather outlook and a day-by-day itinerary.";

      if (builder) builder.hidden = true;
      if (builderToggle) builderToggle.classList.remove("is-on");

      send(sentence, to, from);
    });
  }

  /* ---------------- Boot ---------------- */
  initTheme();
  updateEmptyState();
  initSession();
  autosize();
})();
