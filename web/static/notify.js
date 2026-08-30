// Shadow Console browser attention/notification layer.
//
// Design: the dashboard already reloads every ~10s via a <meta refresh>
// (see index.html), so this script re-runs its full decision logic once
// per page load rather than running its own separate polling loop -- that
// keeps this a *second read* of existing data, not a second poller.
// State that must survive across those reloads (what's already been
// notified, what's still "unseen") lives in localStorage, which is also
// how multiple tabs of the same origin naturally share state without a
// BroadcastChannel (see README note in the PR/commit for the known race).
//
// IMPORTANT: nothing in this file may mark a backend incident resolved.
// It only tracks whether *this browser* has looked at it yet.
(function () {
  "use strict";

  var dataEl = document.getElementById("notify-data");
  if (!dataEl) {
    // Not the dashboard page (e.g. /events, /clients) -- nothing to do.
    return;
  }

  var payload;
  try {
    payload = JSON.parse(dataEl.textContent);
  } catch (e) {
    return;
  }

  var LS_LAST_NOTIFIED_ID = "shadow_last_notified_event_id";
  var LS_BASELINE_DONE = "shadow_notify_baseline_done";
  var LS_UNSEEN_MAP = "shadow_unseen_critical";
  var LS_POLLER_DEAD_NOTIFIED = "shadow_poller_dead_notified";

  var NORMAL_TITLE = "Shadow Console";
  var BLINK_TITLE = "Shadow Console — ATTENTION";
  var BLINK_INTERVAL_MS = 1500;
  var POLLER_DEAD_KEY = "__poller_dead__";

  function getFaviconEl() {
    return document.getElementById("favicon-link");
  }

  function faviconUrl(name) {
    // Reuse url_for-rendered static path's directory rather than hardcode.
    var link = getFaviconEl();
    if (!link) return null;
    return link.href.replace(/favicon(-alert)?\.svg(\?.*)?$/, name);
  }

  function readJSON(key, fallback) {
    try {
      var raw = localStorage.getItem(key);
      return raw ? JSON.parse(raw) : fallback;
    } catch (e) {
      return fallback;
    }
  }

  function writeJSON(key, value) {
    try {
      localStorage.setItem(key, JSON.stringify(value));
    } catch (e) {
      // localStorage unavailable (private browsing, quota, etc) -- degrade
      // to "no cross-reload memory" rather than throwing.
    }
  }

  function readInt(key, fallback) {
    var raw = localStorage.getItem(key);
    var n = raw === null ? NaN : parseInt(raw, 10);
    return isNaN(n) ? fallback : n;
  }

  // ---- Notification permission control ------------------------------

  function notificationSupport() {
    return typeof Notification !== "undefined";
  }

  function renderControls() {
    var el = document.getElementById("notify-controls");
    if (!el) return;

    if (!notificationSupport()) {
      el.textContent = "Desktop Notifications: Unsupported";
      return;
    }

    var state = Notification.permission; // "default" | "granted" | "denied"
    if (state === "granted") {
      el.textContent = "Desktop Notifications: Enabled";
    } else if (state === "denied") {
      el.textContent = "Desktop Notifications: Blocked";
    } else {
      el.innerHTML = "";
      var span = document.createElement("span");
      span.textContent = "Desktop Notifications: Disabled ";
      var btn = document.createElement("button");
      btn.type = "button";
      btn.className = "btn btn-sm btn-outline-secondary";
      btn.textContent = "Enable Desktop Notifications";
      btn.addEventListener("click", function () {
        Notification.requestPermission().then(function () {
          renderControls();
        });
      });
      el.appendChild(span);
      el.appendChild(btn);
    }
  }

  function fireNotification(title, body, options) {
    if (!notificationSupport() || Notification.permission !== "granted") return;
    try {
      new Notification(title, Object.assign({ body: body }, options || {}));
    } catch (e) {
      // Some browsers throw on notification construction in odd contexts
      // (e.g. no service worker on some mobile browsers) -- title/favicon
      // attention still works, so just skip the native notification.
    }
  }

  // ---- Title / favicon attention state -------------------------------

  var blinkTimer = null;

  function deviceTypeWord(deviceType) {
    if (deviceType === "switch") return "SWITCH";
    if (deviceType === "camera") return "CAMERA";
    return "DEVICE";
  }

  function eventTypeWord(eventType) {
    return eventType === "DEVICE_MISSING" ? "MISSING" : "OFFLINE";
  }

  function alertTitleFor(unseen) {
    var keys = Object.keys(unseen);
    if (keys.length === 0) return null;
    if (keys.length === 1) {
      var only = unseen[keys[0]];
      if (keys[0] === POLLER_DEAD_KEY) {
        return "⚠ POLLER DEAD — " + NORMAL_TITLE;
      }
      return "⚠ " + deviceTypeWord(only.device_type) + " " + eventTypeWord(only.event_type) + " — " + NORMAL_TITLE;
    }
    return "⚠ " + keys.length + " CRITICAL — " + NORMAL_TITLE;
  }

  function applyAttentionState() {
    var unseen = readJSON(LS_UNSEEN_MAP, {});
    var alertTitle = alertTitleFor(unseen);

    if (blinkTimer) {
      clearInterval(blinkTimer);
      blinkTimer = null;
    }

    var favLink = getFaviconEl();

    if (alertTitle) {
      document.title = alertTitle;
      var toggle = false;
      blinkTimer = setInterval(function () {
        document.title = toggle ? alertTitle : BLINK_TITLE;
        toggle = !toggle;
      }, BLINK_INTERVAL_MS);
      if (favLink) {
        var alertHref = faviconUrl("favicon-alert.svg");
        if (alertHref) favLink.href = alertHref;
      }
    } else {
      document.title = NORMAL_TITLE;
      if (favLink) {
        var normalHref = faviconUrl("favicon.svg");
        if (normalHref) favLink.href = normalHref;
      }
    }
  }

  function clearUnseen() {
    writeJSON(LS_UNSEEN_MAP, {});
    applyAttentionState();
  }

  document.addEventListener("visibilitychange", function () {
    if (document.visibilityState === "visible") {
      // Returning to the tab clears BROWSER attention only. It must never
      // touch the backend incident -- that's a separate concern entirely,
      // resolved only by the device actually coming back (see
      // shadow_poller.py's device_incidents lifecycle).
      clearUnseen();
    }
  });

  // ---- Main pass: decide what's new since last check ------------------

  function processEvents() {
    var events = (payload.events || []).slice().sort(function (a, b) { return a.id - b.id; });
    var maxId = events.reduce(function (m, e) { return Math.max(m, e.id); }, 0);

    var baselineDone = readJSON(LS_BASELINE_DONE, false);
    var unseen = readJSON(LS_UNSEEN_MAP, {});
    // Gate ALL browser-attention effects (unseen map, blink, native
    // notification) on the tab being hidden right now. If the user is
    // already looking at the dashboard, the incident panel already shows
    // this -- title/favicon flashing on top of that would be the
    // "obnoxious while already looking" behavior the spec explicitly
    // rules out. last_notified_event_id still advances either way so a
    // later reload-while-hidden doesn't retroactively treat this as new.
    var hidden = document.hidden;

    if (!baselineDone) {
      // First load ever: establish a cursor at the current max id so we
      // never treat months-old, already-known incidents as "just
      // happened." Still show currently-active ones in title/favicon
      // (the dashboard itself already shows them prominently per spec),
      // just don't pop a native notification for them.
      if (hidden) {
        events.forEach(function (e) {
          if (e.severity === "critical" && e.active) {
            unseen[e.mac || e.id] = { device_type: e.device_type, event_type: e.event_type, name: e.name };
          }
        });
        writeJSON(LS_UNSEEN_MAP, unseen);
      }
      writeJSON(LS_LAST_NOTIFIED_ID, maxId);
      writeJSON(LS_BASELINE_DONE, true);
      return;
    }

    var lastNotified = readInt(LS_LAST_NOTIFIED_ID, 0);
    var newEvents = events.filter(function (e) { return e.id > lastNotified; });
    if (newEvents.length === 0) return;

    newEvents.forEach(function (e) {
      var label = e.name || e.mac || "device";
      var key = e.mac || e.id;

      if (e.severity === "critical") {
        if (hidden) {
          unseen[key] = { device_type: e.device_type, event_type: e.event_type, name: e.name };
          fireNotification(NORMAL_TITLE, label + " is offline", { tag: "shadow-" + key });
        }
      } else if (e.severity === "recovery") {
        // A recovery always clears the device from "unseen," even if this
        // load happens to be visible -- it's no longer broken, so there's
        // nothing left to draw attention to for it.
        delete unseen[key];
        if (hidden) {
          var body = "Resolved: " + label + " is back online.";
          if (e.downtime) body += "\nDowntime: " + e.downtime;
          fireNotification(NORMAL_TITLE, body, { tag: "shadow-" + key, silent: true });
        }
      }
    });

    writeJSON(LS_UNSEEN_MAP, unseen);
    writeJSON(LS_LAST_NOTIFIED_ID, maxId);
  }

  function processPollerDead() {
    var unseen = readJSON(LS_UNSEEN_MAP, {});
    var wasNotified = readJSON(LS_POLLER_DEAD_NOTIFIED, false);
    var hidden = document.hidden;

    if (payload.poller_dead) {
      // Only mark "notified" at the moment we actually surface it (tab
      // hidden). If the tab is visible while poller_dead starts, we must
      // NOT flip this flag yet -- otherwise if the tab is later hidden
      // while it's still dead, the notification would be silently
      // suppressed forever for an outage the user never actually saw.
      if (hidden) {
        unseen[POLLER_DEAD_KEY] = { device_type: null, event_type: "POLLER_DEAD", name: null };
        if (!wasNotified) {
          fireNotification(NORMAL_TITLE, "Poller appears offline -- no data updates.", { tag: "shadow-poller-dead" });
          writeJSON(LS_POLLER_DEAD_NOTIFIED, true);
        }
      }
    } else if (wasNotified) {
      delete unseen[POLLER_DEAD_KEY];
      writeJSON(LS_POLLER_DEAD_NOTIFIED, false);
    }

    writeJSON(LS_UNSEEN_MAP, unseen);
  }

  renderControls();
  processEvents();
  processPollerDead();
  applyAttentionState();
})();
