/* ai_agenttrap probe. Collects automation/agent signals and sends ONE small JSON beacon. No personal data. */
(function () {
  "use strict";
  var A = window.__AT || null, st = { mouse: 0, touch: 0, clicks: 0, synth: 0, first: null, markers: [] }, t0 = Date.now(), sent = 0, ready = false;

  function inject(j) {
    try {
      if (j.comment) document.body.appendChild(document.createComment(" " + j.comment + " "));
      var d = document.createElement("div"); d.className = "at-x"; d.setAttribute("aria-hidden", "true");
      d.style.cssText = "position:absolute;left:-9999px;top:auto;width:1px;height:1px;overflow:hidden";
      d.innerHTML = (j.hidden || "") + (j.notice || "");
      document.body.appendChild(d);
    } catch (e) {}
  }

  function webgl() {
    try {
      var c = document.createElement("canvas"), g = c.getContext("webgl") || c.getContext("experimental-webgl");
      var x = g && g.getExtension("WEBGL_debug_renderer_info");
      return x ? String(g.getParameter(x.UNMASKED_RENDERER_WEBGL)) : "";
    } catch (e) { return ""; }
  }

  function artifacts() {
    var rx = /^(cdc_|\$cdc_|__playwright|__pw|_phantom|callPhantom|__nightmare|domAutomation|__webdriver|__selenium|_selenium|__driver)/, out = [];
    try { Object.getOwnPropertyNames(window).forEach(function (k) { if (rx.test(k) && out.length < 10) out.push(k); }); } catch (e) {}
    try { if (document.documentElement.getAttribute("webdriver")) out.push("html[webdriver]"); } catch (e) {}
    return out;
  }

  function scanMarkers() {
    var out = st.markers.slice(0, 5);
    try {
      (A.sel || []).forEach(function (s) { var n = document.querySelector(s); if (n && out.length < 5) out.push({ sel: s, tag: n.tagName }); });
    } catch (e) {}
    return out;
  }

  function observe() {
    if (!window.MutationObserver || !A.rx) return;
    var rx; try { rx = new RegExp(A.rx, "i"); } catch (e) { return; }
    new MutationObserver(function (ms) {
      ms.forEach(function (m) {
        m.addedNodes.forEach(function (n) {
          if (n.nodeType !== 1 || (n.classList && n.classList.contains("at-x")) || st.markers.length >= 5) return;
          var s = (n.id || "") + " " + (typeof n.className === "string" ? n.className : "");
          if (rx.test(s)) st.markers.push({ id: String(n.id || "").slice(0, 40), cls: String(n.className || "").slice(0, 40), tag: n.tagName });
        });
      });
    }).observe(document.documentElement, { childList: true, subtree: true });
  }

  function collect() {
    var n = navigator, ua = n.userAgent || "";
    return {
      webdriver: n.webdriver === true, automation_keys: artifacts(), dom_markers: scanMarkers(), webgl: webgl(),
      plugins: n.plugins ? n.plugins.length : -1, mobile: /Mobi|Android/i.test(ua),
      outer_zero: window.outerWidth === 0 && window.outerHeight === 0,
      languages_empty: !(n.languages && n.languages.length), languages: (n.languages || []).join(",").slice(0, 60),
      hw: n.hardwareConcurrency || 0, mem: n.deviceMemory || 0, platform: n.platform || "",
      brands: n.userAgentData ? n.userAgentData.brands.map(function (b) { return b.brand; }).join(",").slice(0, 100) : "",
      tz: (function () { try { return Intl.DateTimeFormat().resolvedOptions().timeZone; } catch (e) { return ""; } })(),
      screen: screen.width + "x" + screen.height, viewport: innerWidth + "x" + innerHeight,
      mouse_moves: st.mouse, touches: st.touch, trusted_clicks: st.clicks, synthetic_events: st.synth,
      first_interaction_ms: st.first, elapsed_ms: Date.now() - t0, page: location.pathname.slice(0, 100)
    };
  }

  function send() {
    if (!ready || sent >= 3) return; sent++;
    var body = JSON.stringify({ t: A.t, d: collect() });
    try { if (navigator.sendBeacon && navigator.sendBeacon("/_at/p", body)) return; } catch (e) {}
    try { fetch("/_at/p", { method: "POST", body: body, keepalive: true, credentials: "same-origin" }); } catch (e) {}
  }

  function note(e, kind) {
    if (st.first === null) st.first = Date.now() - t0;
    if (e.isTrusted === false) st.synth++;
    else if (kind === "click") st.clicks++;
  }

  function start() {
    ready = true; observe();
    addEventListener("mousemove", function (e) { st.mouse++; note(e, "move"); }, { passive: true });
    addEventListener("touchstart", function (e) { st.touch++; note(e, "touch"); }, { passive: true });
    addEventListener("click", function (e) { note(e, "click"); }, true);
    addEventListener("keydown", function (e) { note(e, "key"); }, true);
    setTimeout(send, 4000);
    addEventListener("visibilitychange", function () { if (document.visibilityState === "hidden") send(); });
    addEventListener("pagehide", send);
  }

  function boot() {
    if (A && A.t) return start();                       // trap page: server already issued token
    fetch("/_at/init?p=" + encodeURIComponent(location.pathname), { credentials: "same-origin" })
      .then(function (r) { return r.json(); })
      .then(function (j) { A = j; window.__AT = j; inject(j); start(); })
      .catch(function () {});
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot); else boot();
})();
