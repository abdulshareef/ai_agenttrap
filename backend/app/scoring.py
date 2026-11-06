"""Turns raw events for one actor (IP) into evidence, a verdict and attribution."""
import hashlib, json, statistics
from collections import Counter
from datetime import datetime
from .fingerprint import header_anomalies
from .signatures import parse_ua

DECOY_PATHS = ("/.env", "/.git", "/wp-login.php", "/xmlrpc.php", "/phpmyadmin", "/internal/", "/admin-backup")

VERDICTS = {
    "confirmed_agent": "Confirmed LLM-driven agent",
    "declared_agent": "Declared AI crawler / signed agent",
    "probable_browser_agent": "Probable agentic browser / automation",
    "scanner": "Conventional scanner / script",
    "human": "Likely human",
    "unclassified": "Unclassified / insufficient data",
}

def _ts(e):
    return datetime.fromisoformat(e["ts"])

def probe_flags(d: dict):
    out = []
    if d.get("webdriver"):
        out.append(("webdriver", "navigator.webdriver = true", 30, "Browser is under WebDriver/CDP automation."))
    if d.get("automation_keys"):
        out.append(("automation_artifacts", "Automation globals present", 30, ", ".join(d["automation_keys"][:6])))
    if d.get("dom_markers"):
        out.append(("agent_dom_markers", "Agent UI injected into page DOM", 40, json.dumps(d["dom_markers"][:4])))
    gl = (d.get("webgl") or "").lower()
    if any(x in gl for x in ("swiftshader", "llvmpipe", "software")):
        out.append(("software_gl", "Software WebGL renderer", 10, d.get("webgl", "")))
    ua = d.get("ua", "")
    if "headlesschrome" in ua.lower():
        out.append(("headless_ua", "HeadlessChrome in UA", 25, ua[:120]))
    if "chrome/" in ua.lower() and d.get("plugins") == 0 and not d.get("mobile"):
        out.append(("no_plugins", "Desktop Chrome with zero plugins", 8, ""))
    if d.get("outer_zero"):
        out.append(("outer_zero", "window.outerWidth/Height is 0", 12, "Typical of headless."))
    if d.get("languages_empty"):
        out.append(("no_languages", "navigator.languages empty", 8, ""))
    if d.get("synthetic_events", 0) > 0:
        out.append(("untrusted_events", "Synthetic (isTrusted=false) input events", 25, f"{d['synthetic_events']} event(s)"))
    return out

def analyze(ip: str, evs: list, vid_ips: dict | None = None) -> dict:
    evs = sorted(evs, key=lambda e: e["seq"])
    ev_out = []
    def add(code, title, pts, detail="", seq=None):
        if any(x["code"] == code and x["detail"] == detail for x in ev_out):
            return
        ev_out.append({"code": code, "title": title, "points": pts, "detail": detail, "seq": seq})

    reqs = [e for e in evs if e["type"] != "probe"]
    probes = [e for e in evs if e["type"] == "probe"]
    uas = Counter(e.get("ua", "") for e in evs if e.get("ua"))
    first, last = _ts(evs[0]), _ts(evs[-1])

    # --- UA / header evidence
    crawler = None; frameworks = set(); tools = set(); scanner = None
    for ua, n in uas.items():
        p = parse_ua(ua)
        tools.add(p["tool"])
        if p["crawler"] and not crawler:
            crawler = p["crawler"]; add("declared_crawler", f"Declared AI crawler UA: {crawler['product']}", 40, f"{crawler['vendor']} ({crawler['role']}) - UA-claimed, verify against vendor IP list")
        if p["scanner"]:
            scanner = p["scanner"]; add("scanner_ua", f"Security scanner UA: {p['scanner']}", 25)
        if p["automation"]:
            frameworks.add(p["automation"]); add("automation_ua", f"Automation UA token: {p['automation']}", 25)
        if p["client"]:
            add("scripted_client", f"Scripted HTTP client: {p['client']}", 10)
        if p["hint"]:
            add("ua_ai_hint", f"UA mentions AI/agent term: {p['hint']}", 15, ua[:120])
    for e in reqs[:200]:
        for code, title, pts, detail in header_anomalies(e.get("hdr", {})):
            add(code, title, pts, detail, e["seq"])
    wba = next((e["hdr"].get("signature-agent") for e in reqs if "signature-agent" in e.get("hdr", {})), None)

    # --- canaries, callbacks, bait credentials
    declared = {}; handoff = set()
    for e in reqs:
        issuer = e.get("token_vid")
        if issuer and vid_ips:
            handoff |= {i for i in vid_ips.get(issuer, set()) if i != ip}
        if e["type"] == "canary" and e.get("canary_valid"):
            k = e.get("canary_kind")
            if k == "h":
                add("canary_hidden_link", "Followed hidden link (crawler-followable)", 20, e["path"], e["seq"])
            elif k == "t":
                add("canary_text_url", "Fetched URL that existed only as hidden text/comment", 45, "Requires reading and acting on page text, not just following links.", e["seq"])
        elif e["type"] == "callback" and e.get("canary_valid"):
            add("callback", "Executed injected instruction: disclosure callback", 70, "An AI agent read hidden text and obeyed it.", e["seq"])
            declared.update({k: v for k, v in (e.get("declared") or {}).items() if v})
        elif e["type"] == "login" and e.get("bait_valid"):
            add("bait_creds", "Used bait credentials harvested from page/.env", 50, f"user={e.get('username')}", e["seq"])
    if handoff:
        add("identity_handoff", "Token issued to a different IP (relay/handoff)", 10, "Linked IPs: " + ", ".join(sorted(handoff)[:6]))

    # --- JS probe evidence
    pm = {}
    for e in probes:
        d = e.get("data", {}) or {}
        for code, title, pts, detail in probe_flags(d | {"ua": e.get("ua", "")}):
            add(code, title, pts, detail, e["seq"])
        for k, v in d.items():
            if v not in (None, "", [], 0, False):
                pm[k] = v
        if d.get("automation_keys"):
            for k in d["automation_keys"]:
                kl = k.lower()
                frameworks.add("Playwright" if "playwright" in kl or kl.startswith("__pw") else
                               "Selenium" if "selenium" in kl or "cdc_" in kl or "webdriver" in kl else
                               "PhantomJS" if "phantom" in kl else "Automation framework")

    # --- behaviour
    times = [_ts(e) for e in reqs]
    if len(times) >= 6:
        gaps = [(b - a).total_seconds() for a, b in zip(times, times[1:])]
        mean = statistics.mean(gaps)
        if mean > 0 and statistics.pstdev(gaps) / mean < 0.3:
            add("regular_timing", "Machine-regular request timing", 10, f"mean gap {mean:.2f}s")
    burst = any(sum(1 for t in times if 0 <= (t - s).total_seconds() <= 60) >= 10 for s in times)
    if burst:
        add("burst", "10+ requests within 60s", 10)
    paths = Counter(e["path"] for e in reqs)
    decoys = [p for p in paths if any(p.startswith(d) for d in DECOY_PATHS)]
    if len(paths) >= 4:
        add("breadth", f"Probed {len(paths)} distinct trap paths", 15)
    if decoys:
        add("decoy_paths", "Requested decoy/sensitive paths", min(20, 10 * len(decoys)), ", ".join(sorted(decoys)[:6]))
    if len({t for t in tools if t not in ("unknown",)}) >= 2:
        add("tool_switching", "Multiple client tools from same IP", 20, ", ".join(sorted(tools)))
    if any(e["path"] == "/robots.txt" for e in reqs) and any(e["path"].startswith(("/internal", "/admin-backup", "/.env")) for e in reqs):
        add("robots_ignored", "Fetched robots.txt then entered disallowed paths", 10)

    score = min(100, sum(x["points"] for x in ev_out))
    codes = {x["code"] for x in ev_out}
    interactive = pm.get("mouse_moves", 0) >= 3 or pm.get("touches", 0) >= 1 or pm.get("trusted_clicks", 0) >= 1
    bot_codes = codes & {"webdriver", "automation_artifacts", "agent_dom_markers", "headless_ua", "untrusted_events"}

    if codes & {"callback", "canary_text_url", "bait_creds"}:
        verdict = "confirmed_agent"
    elif crawler or wba:
        verdict = "declared_agent"
    elif bot_codes and (score >= 50 or "agent_dom_markers" in codes):
        verdict = "probable_browser_agent"
    elif scanner or codes & {"scripted_client", "decoy_paths", "empty_ua"} or score >= 30:
        verdict = "scanner"
    elif probes and interactive and not bot_codes and score < 20:
        verdict = "human"
    else:
        verdict = "unclassified"
    conf = "High" if verdict == "confirmed_agent" or score >= 70 else "Medium" if score >= 40 else "Low"
    subtype = None
    if verdict == "confirmed_agent":
        subtype = "agentic browser" if probes else "HTTP-tool agent (no JS executed)"

    # --- attribution (who created / operates it)
    basis = []; creator = "Unknown"
    if wba:
        creator = wba.strip('"'); basis.append("Web Bot Auth Signature-Agent header (claimed)")
    if crawler:
        creator = f"{crawler['vendor']} - {crawler['product']} ({crawler['role']})"; basis.append("User-Agent token (spoofable)")
    if pm.get("dom_markers"):
        basis.append("Agent UI marker in DOM")
    if declared.get("agent") or declared.get("model"):
        if creator == "Unknown":
            creator = f"Self-declared: {declared.get('agent', '?')}"
        basis.append("Self-declared via callback (unverified, LLM output)")
    attribution = {"creator": creator, "basis": basis, "framework": sorted(frameworks), "declared": declared,
                   "signature_agent": wba}

    digest = hashlib.sha256(json.dumps([e["hash"] for e in evs]).encode()).hexdigest()
    return {
        "ip": ip, "first_seen": evs[0]["ts"], "last_seen": evs[-1]["ts"],
        "duration_s": round((last - first).total_seconds(), 1), "events": len(evs), "requests": len(reqs),
        "verdict": verdict, "verdict_label": VERDICTS[verdict], "subtype": subtype, "confidence": conf, "score": score,
        "evidence": sorted(ev_out, key=lambda x: -x["points"]), "attribution": attribution,
        "uas": uas.most_common(8), "tools": sorted(tools), "paths": paths.most_common(30),
        "probe": pm, "linked_ips": sorted(handoff),
        "chain": {"first_seq": evs[0]["seq"], "last_seq": evs[-1]["seq"], "first_hash": evs[0]["hash"],
                  "last_hash": evs[-1]["hash"], "digest": digest},
    }

def vid_ip_map(events):
    m = {}
    for e in events:
        if e["type"] in ("hit", "probe"):
            m.setdefault(e.get("vid"), set()).add(e["ip"])
    return m

def analyze_all(events):
    by = {}
    for e in events:
        by.setdefault(e["ip"], []).append(e)
    vm = vid_ip_map(events)
    return sorted((analyze(ip, evs, vm) for ip, evs in by.items()), key=lambda a: a["last_seen"], reverse=True)
