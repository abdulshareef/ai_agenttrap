"""HTML for dashboard + reports. Brand: navy #06315C, lime #CFE63A. All dynamic text is escaped."""
from html import escape as h
import json

CSS = """
:root{--navy:#06315C;--lime:#CFE63A;--ink:#14212e;--mut:#5b6b7b;--line:#dbe3ea;--bg:#f4f7fa;--card:#fff;--bad:#b3261e;--warn:#9a6700;--ok:#1a7f37}
*{box-sizing:border-box}body{margin:0;font:15px/1.5 Calibri,Carlito,system-ui,sans-serif;background:var(--bg);color:var(--ink)}
header{background:var(--navy);color:#fff;padding:14px 18px;display:flex;gap:16px;align-items:center;flex-wrap:wrap}
header b{font-size:18px}header .tag{background:var(--lime);color:var(--navy);padding:1px 8px;border-radius:3px;font-weight:700;font-size:13px}
header nav{margin-left:auto;display:flex;gap:14px}header a{color:#dce8f5;text-decoration:none}header a:hover{color:var(--lime)}
main{max-width:1100px;margin:0 auto;padding:16px}
h1{font-size:22px;margin:6px 0 12px}h2{font-size:17px;margin:22px 0 8px;color:var(--navy);border-bottom:2px solid var(--lime);padding-bottom:3px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin-bottom:14px}
.card{background:var(--card);border:1px solid var(--line);border-radius:6px;padding:10px 12px}.card b{display:block;font-size:24px;color:var(--navy)}.card span{color:var(--mut);font-size:13px}
.wrap{overflow-x:auto;background:var(--card);border:1px solid var(--line);border-radius:6px}
table{border-collapse:collapse;width:100%;font-size:14px}th,td{padding:7px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}th{background:#eef3f8;color:var(--navy);white-space:nowrap}
tr:last-child td{border-bottom:0}a{color:#0b5cad}code,.mono{font-family:"Courier New",monospace;font-size:12.5px;word-break:break-all}
.chip{display:inline-block;padding:2px 9px;border-radius:12px;font-size:13px;font-weight:700;white-space:nowrap}
.v-confirmed_agent{background:var(--navy);color:var(--lime)}.v-declared_agent{background:#dbe9f7;color:var(--navy)}
.v-probable_browser_agent{background:#fff1cc;color:var(--warn)}.v-scanner{background:#fde3e1;color:var(--bad)}
.v-human{background:#dcf3e1;color:var(--ok)}.v-unclassified{background:#e8ecef;color:var(--mut)}
.kv{display:grid;grid-template-columns:max-content 1fr;gap:3px 14px;background:var(--card);border:1px solid var(--line);border-radius:6px;padding:10px 14px}.kv dt{color:var(--mut)}.kv dd{margin:0;word-break:break-word}
.btns a,.btns button{display:inline-block;background:var(--navy);color:#fff;border:0;padding:7px 12px;border-radius:4px;text-decoration:none;margin:0 6px 6px 0;font:inherit;cursor:pointer}
form.login{max-width:340px;margin:60px auto;background:#fff;padding:20px;border:1px solid var(--line);border-radius:6px}
input{width:100%;padding:9px;margin:6px 0 12px;border:1px solid var(--line);border-radius:4px;font:inherit}
pre{background:#0d1b2a;color:#e5eef7;padding:12px;border-radius:6px;overflow-x:auto;font-size:12.5px}
.note{color:var(--mut);font-size:13px}.pts{font-weight:700;color:var(--navy)}
@media print{header nav,.btns{display:none}body{background:#fff}}
"""

def page(title, body, nav=True):
    n = ('<nav><a href="/_at/admin">Actors</a><a href="/_at/admin/snippets">Snippets</a>'
         '<a href="/_at/admin/verify">Verify chain</a><a href="/_at/admin/whoami">Whoami</a>'
         '<a href="/_at/admin/logout">Logout</a></nav>') if nav else ""
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<meta name="robots" content="noindex,nofollow"><title>{h(title)}</title><style>{CSS}</style></head><body>'
            f'<header><b>ai_agenttrap</b><span class="tag">honeypot</span>{n}</header><main>{body}</main></body></html>')

def login_page(err=""):
    e = f'<p style="color:var(--bad)">{h(err)}</p>' if err else ""
    return page("Sign in", f'<form class="login" method="post" action="/_at/admin/login"><h1>Admin sign-in</h1>{e}'
                '<label>Password<input type="password" name="password" autofocus autocomplete="current-password"></label>'
                '<button class="btns" style="background:var(--navy);color:#fff;border:0;padding:9px 14px;border-radius:4px">Sign in</button></form>', nav=False)

def chip(a):
    return f'<span class="chip v-{h(a["verdict"])}">{h(a["verdict_label"])}</span>'

def dashboard(actors, intel_of, total_events, chain_ok):
    n = lambda v: sum(1 for a in actors if a["verdict"] == v)
    cards = "".join(f'<div class="card"><b>{v}</b><span>{h(l)}</span></div>' for v, l in [
        (total_events, "events (window)"), (len(actors), "distinct IPs"), (n("confirmed_agent"), "confirmed LLM agents"),
        (n("declared_agent"), "declared AI crawlers"), (n("probable_browser_agent"), "probable browser agents"), (n("scanner"), "scanners/scripts")])
    rows = ""
    for a in actors:
        i = intel_of(a["ip"]) or {}
        org = (i.get("rdap") or {}).get("org") or (i.get("rdap") or {}).get("name") or ""
        rows += (f'<tr><td><a href="/_at/admin/actor/{h(a["ip"])}">{h(a["ip"])}</a></td><td>{chip(a)}</td><td class="pts">{a["score"]}</td>'
                 f'<td>{h(a["attribution"]["creator"])}</td><td>{h(org)}</td><td>{a["requests"]}</td><td class="mono">{h(a["first_seen"][:19])}</td><td class="mono">{h(a["last_seen"][:19])}</td></tr>')
    if not rows:
        rows = '<tr><td colspan="8">No visitors recorded yet. Deploy the trap page and wait for traffic.</td></tr>'
    ok = "" if chain_ok else '<p style="color:var(--bad)"><b>Integrity warning:</b> the hash chain failed verification. Open Verify chain.</p>'
    return page("Actors", f'<h1>Visitors, newest first</h1>{ok}<div class="cards">{cards}</div><div class="wrap"><table><tr><th>IP</th><th>Verdict</th><th>Score</th><th>Creator / vendor</th><th>Network</th><th>Reqs</th><th>First seen (UTC)</th><th>Last seen (UTC)</th></tr>{rows}</table></div>'
                f'<p class="note">Verdicts are heuristic. User-Agent and self-declared fields are attacker-controlled; treat them as claims.</p>')

def _kv(pairs):
    return '<dl class="kv">' + "".join(f"<dt>{h(k)}</dt><dd>{v}</dd>" for k, v in pairs) + "</dl>"

def report_body(a, intel, timeline, chain_status, generated):
    i = intel or {}
    r = i.get("rdap") or {}
    at = a["attribution"]
    decl = at["declared"]
    flags = []
    if i.get("tor_exit"): flags.append("Tor exit node")
    if i.get("hosting"): flags.append("Hosting / cloud provider")
    origin = _kv([("IP address", f'<code>{h(a["ip"])}</code>'), ("Reverse DNS", h(i.get("rdns") or "n/a")),
                  ("Network name", h(r.get("name") or "n/a")), ("Organisation", h(r.get("org") or "n/a")),
                  ("Country (registry)", h(r.get("country") or "n/a")), ("CIDR / range", h(r.get("cidr") or r.get("range") or "n/a")),
                  ("Flags", h(", ".join(flags) or "none")), ("Linked IPs (same bait token)", h(", ".join(a["linked_ips"]) or "none")),
                  ("Intel errors", h(", ".join(i.get("errors", [])) or "none"))])
    attr = _kv([("Creator / vendor", h(at["creator"])), ("Basis", h("; ".join(at["basis"]) or "none")),
                ("Automation framework", h(", ".join(at["framework"]) or "none detected")),
                ("Agent type", h(a["subtype"] or a["verdict_label"]))])
    dec = (_kv([(k, h(str(v))) for k, v in decl.items()]) + '<p class="note">Self-declared by the agent (LLM output): unverified.</p>') if decl else '<p class="note">No callback received.</p>'
    ev = "".join(f'<tr><td class="pts">+{e["points"]}</td><td>{h(e["title"])}</td><td>{h(str(e["detail"]))}</td><td>{e["seq"] or ""}</td></tr>' for e in a["evidence"]) or '<tr><td colspan="4">No evidence.</td></tr>'
    uas = "".join(f'<tr><td>{n}</td><td class="mono">{h(u)}</td></tr>' for u, n in a["uas"])
    pr = a["probe"]
    probe = _kv([(k, h(json.dumps(v) if not isinstance(v, str) else v)[:300]) for k, v in sorted(pr.items())]) if pr else '<p class="note">No JavaScript probe received (client did not execute JS).</p>'
    tl = "".join(f'<tr><td>{e["seq"]}</td><td class="mono">{h(e["ts"][11:23])}</td><td>{h(e["type"])}</td><td>{h(e["method"])}</td><td class="mono">{h(e["path"])}{h(("?" + e["query"]) if e.get("query") else "")}</td><td>{h(e.get("note",""))}</td></tr>' for e in timeline)
    c = a["chain"]
    integ = _kv([("Chain status (whole log)", h(chain_status)), ("Events in report", f'seq {c["first_seq"]} - {c["last_seq"]}'),
                 ("First record hash", f'<code>{c["first_hash"]}</code>'), ("Last record hash", f'<code>{c["last_hash"]}</code>'),
                 ("Evidence digest (SHA-256)", f'<code>{c["digest"]}</code>'), ("Report generated (UTC)", h(generated))])
    return (f'<h1>Agent report: {h(a["ip"])}</h1><p>{chip(a)} &nbsp; confidence <b>{h(a["confidence"])}</b> &nbsp; score <b>{a["score"]}/100</b></p>'
            f'<div class="btns"><a href="/_at/admin/actor/{h(a["ip"])}.json">JSON</a><a href="/_at/admin/report/{h(a["ip"])}.html">Download report</a><button onclick="window.print()">Print / save PDF</button></div>'
            f'<h2>Origin</h2>{origin}<h2>Attribution: who built or runs it</h2>{attr}<h2>Self-declaration (reverse prompt injection)</h2>{dec}'
            f'<h2>Evidence</h2><div class="wrap"><table><tr><th>Pts</th><th>Finding</th><th>Detail</th><th>Seq</th></tr>{ev}</table></div>'
            f'<h2>Client fingerprint</h2><div class="wrap"><table><tr><th>Hits</th><th>User-Agent</th></tr>{uas}</table></div><h2>Browser probe</h2>{probe}'
            f'<h2>Timeline</h2><div class="wrap"><table><tr><th>Seq</th><th>Time</th><th>Type</th><th>Method</th><th>Path</th><th>Note</th></tr>{tl}</table></div>'
            f'<h2>Integrity</h2>{integ}<p class="note">Each record embeds the hash of the previous one, so alteration or deletion breaks the chain. Hashes can support an electronic-record certificate; this report is not itself a certificate. '
            f'Limits: no TLS/JA3 view behind Firebase Hosting; IP is as reported by the CDN; UA and declared fields are spoofable; verdicts are heuristic.</p>')

def snippets(base, sn):
    esc = h
    return page("Snippets", f'<h1>Copy-paste snippets</h1>'
                f'<h2>1. Probe + bait on ANY existing page (before &lt;/body&gt;)</h2><pre>{esc(sn["script"])}</pre>'
                f'<h2>2. Static bait for pages where you cannot run JS</h2><pre>{esc(sn["static"])}</pre>'
                f'<h2>3. Append to your robots.txt</h2><pre>{esc(sn["robots"])}</pre>'
                f'<h2>4. Append to your llms.txt (create it if missing)</h2><pre>{esc(sn["llms"])}</pre>')
