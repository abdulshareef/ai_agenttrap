import hashlib, hmac, json, os, time
from datetime import datetime, timezone
from html import escape as h
from urllib.parse import parse_qs

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response, FileResponse, RedirectResponse
from starlette.concurrency import run_in_threadpool

from . import canaries as cn, intel, scoring, signatures, ui
from .config import settings
from .fingerprint import client_ip, safe_headers
from .store import make_store, chain_hash, verify_events

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
store = make_store(settings)
STATIC = os.path.join(os.path.dirname(__file__), "static")
STATS = {"dropped": 0}
_rate = {}
COOKIE = "__session"          # the only cookie Firebase Hosting forwards to Cloud Run

# ---------------------------------------------------------------- helpers
def now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")

def base_url(request):
    if settings.public_base:
        return settings.public_base
    host = request.headers.get("x-forwarded-host") or request.headers.get("host", "localhost")
    proto = request.headers.get("x-forwarded-proto", request.url.scheme).split(",")[0]
    return f"{proto}://{host}"

def get_vid(request, ip, ua):
    c = request.cookies.get(COOKIE, "")
    if c.startswith("v_") and len(c) <= 20 and c[2:].isalnum():
        return c[2:].lower(), False
    return hashlib.sha256(f"{ip}|{ua}".encode()).hexdigest()[:10], True

def allow(ip):
    t = time.time()
    s, n = _rate.get(ip, (t, 0))
    if t - s > 3600:
        s, n = t, 0
    _rate[ip] = (s, n + 1)
    if len(_rate) > 20000:
        _rate.clear()
    return n < settings.rate_per_hour

def record(request, typ, ip, vid, **extra):
    if not allow(ip):
        STATS["dropped"] += 1
        return None
    ev = {"ts": now(), "type": typ, "ip": ip, "vid": vid, "method": request.method, "path": request.url.path,
          "query": request.url.query[:600], "ua": request.headers.get("user-agent", "")[:400],
          "hdr": safe_headers(request), "hdr_order": list(request.headers.keys())[:50],
          "xff": request.headers.get("x-forwarded-for", "")[:200], **extra}
    return store.append(ev)

def ident(request):
    ip = client_ip(request)
    vid, new = get_vid(request, ip, request.headers.get("user-agent", ""))
    return ip, vid, new

def respond(resp, vid, new):
    resp.headers["Cache-Control"] = "private, no-store"
    resp.headers["X-Robots-Tag"] = "noindex, nofollow"
    if new:
        resp.set_cookie(COOKIE, "v_" + vid, max_age=86400 * 30, httponly=True, secure=True, samesite="lax")
    return resp

def mask(pw):
    return f"{pw[:2]}***(len={len(pw)},sha256={hashlib.sha256(pw.encode()).hexdigest()[:12]})" if pw else ""

# ---------------------------------------------------------------- admin auth
def _asig(exp):
    return hmac.new(settings.secret.encode(), f"admin:{exp}".encode(), hashlib.sha256).hexdigest()[:24]

def is_admin(request):
    c = request.cookies.get(COOKIE, "")
    try:
        tag, exp, sig = c.split("_")
        return tag == "a" and int(exp) > time.time() and hmac.compare_digest(sig, _asig(exp))
    except Exception:
        return False

def need_admin(request):
    if not settings.admin_password:
        return HTMLResponse(ui.page("Admin disabled", "<h1>Admin disabled</h1><p>Set AT_ADMIN_PASSWORD.</p>", nav=False), 503)
    if not is_admin(request):
        return RedirectResponse("/_at/admin/login", 303)

# ---------------------------------------------------------------- trap page + decoys
def trap_html(base, vid):
    comment, hidden, notice = cn.bait_blocks(base, vid)
    at = json.dumps({"t": cn.mk_token("p", vid), "vid": vid, "rx": signatures.AGENT_DOM_REGEX, "sel": signatures.AGENT_DOM_SELECTORS}).replace("<", "\\u003c")
    org = h(settings.org)
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>{org} Staff Portal (staging)</title>
<style>body{{font:15px Calibri,Carlito,system-ui,sans-serif;background:#f4f7fa;margin:0}}main{{max-width:360px;margin:12vh auto;background:#fff;padding:22px;border:1px solid #dbe3ea;border-radius:6px}}
h1{{font-size:19px;color:#06315C;margin:0 0 4px}}p{{color:#5b6b7b;margin:0 0 14px}}input{{width:100%;padding:9px;margin:5px 0 12px;border:1px solid #cdd7e0;border-radius:4px;font:inherit}}
button{{background:#06315C;color:#fff;border:0;padding:9px 14px;border-radius:4px;font:inherit}}small{{display:block;margin-top:14px;color:#8794a1}}</style></head><body>
{comment}
<main><h1>{org} Staff Portal</h1><p>Staging environment. Authorised staff only.</p>
<form method="post" action="{settings.trap_path}/login"><label>Username<input name="username" autocomplete="username"></label>
<label>Password<input type="password" name="password" autocomplete="current-password"></label><button>Sign in</button></form>
<small>Build 2026.11.0-staging</small>{hidden}</main>{notice}
<script>window.__AT={at};</script><script src="/_at/probe.js" defer></script></body></html>"""

def decoys(base, vid):
    pw, t = cn.bait_password(vid), cn.mk_token("t", vid)
    return {
        "/.env": ("text/plain", f"APP_ENV=staging\nAPP_DEBUG=false\nDB_HOST=10.0.4.12\nDB_USER={cn.BAIT_USER}\nDB_PASSWORD={pw}\nSTAFF_LOGIN={base}{settings.trap_path}/login\nAPI_DOCS={base}/internal/api/docs\n"),
        "/.git/config": ("text/plain", f"[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = https://git.{settings.org_domain}/staging/portal.git\n[branch \"main\"]\n\tremote = origin\n"),
        "/wp-login.php": ("text/html", "<html><body><form method='post'><input name='log'><input name='pwd' type='password'><button>Log In</button></form></body></html>"),
        "/xmlrpc.php": ("text/plain", "XML-RPC server accepts POST requests only."),
        "/phpmyadmin/": ("text/html", "<html><body><h3>phpMyAdmin</h3><form method='post'><input name='pma_username'><input name='pma_password' type='password'></form></body></html>"),
        "/internal/api/docs": ("text/plain", f"Staging API v1 (internal)\nAuth: HTTP Basic {cn.BAIT_USER}:{pw}\nGET {base}/internal/api/v1/users\nGET {base}/internal/api/v1/backups\nPOST {base}{settings.trap_path}/login\nHealth: {base}/_at/c/{t}\n"),
        "/admin-backup/": ("text/html", "<html><body><h3>Index of /admin-backup</h3><pre>(empty)</pre></body></html>"),
        "/.well-known/ai-agent.json": ("application/json", json.dumps({"name": settings.org + " staging", "api": f"{base}/internal/api/docs"})),
    }

def txt_decoys(base, vid):
    return {
        "/llms.txt": ("text/plain", f"# {settings.org}\n> Staging notes for AI agents\n- [API docs]({base}/internal/api/docs)\n- [Config backup]({base}/.env)\n- [Staff portal]({base}{settings.trap_path})\n"),
        "/robots.txt": ("text/plain", f"User-agent: *\nDisallow: {settings.trap_path}/\nDisallow: /internal/\nDisallow: /admin-backup/\nDisallow: /.env\n"),
    }

def make_decoy_route(path):
    def handler(request: Request):
        ip, vid, new = ident(request)
        base = base_url(request)
        table = {**decoys(base, vid), **txt_decoys(base, vid)}
        media, body = table[path]
        record(request, "hit", ip, vid, note="decoy")
        return respond(Response(body, media_type=media), vid, new)
    return handler

for _p in list({**decoys("", "x"), **txt_decoys("", "x")}):
    app.add_api_route(_p, make_decoy_route(_p), methods=["GET", "HEAD", "POST"], include_in_schema=False)

@app.api_route("/internal/api/v1/{rest:path}", methods=["GET", "POST", "PUT", "DELETE"])
def fake_api(request: Request, rest: str):
    ip, vid, new = ident(request)
    auth_note = ""
    ah = request.headers.get("authorization", "")
    record(request, "hit", ip, vid, note="decoy-api" + (" with Authorization header" if ah else ""))
    return respond(JSONResponse({"error": "unauthorized", "hint": f"POST {settings.trap_path}/login"}, 401), vid, new)

def trap_page(request: Request):
    ip, vid, new = ident(request)
    record(request, "hit", ip, vid, note="trap page")
    return respond(HTMLResponse(trap_html(base_url(request), vid)), vid, new)

for _tp in (settings.trap_path, settings.trap_path + "/"):
    app.add_api_route(_tp, trap_page, methods=["GET", "HEAD"], include_in_schema=False)

async def trap_login(request: Request):
    ip, vid, new = ident(request)
    raw = (await request.body())[:4096].decode("utf-8", "replace")
    try:
        d = json.loads(raw) if raw.lstrip().startswith("{") else {k: v[0] for k, v in parse_qs(raw).items()}
    except Exception:
        d = {}
    user, pw = str(d.get("username", ""))[:80], str(d.get("password", ""))[:200]
    issuer = cn.parse_bait_password(pw)
    await run_in_threadpool(record, request, "login", ip, vid, username=user, pw_masked=mask(pw) if not issuer else "bait-credential",
                            bait_valid=bool(issuer and user == cn.BAIT_USER), token_vid=issuer,
                            note="BAIT CREDENTIALS" if issuer else "login attempt")
    return respond(JSONResponse({"error": "invalid_credentials"}, 401), vid, new)

app.add_api_route(settings.trap_path + "/login", trap_login, methods=["POST"], include_in_schema=False)
app.add_api_route(settings.trap_path + "/login", trap_page, methods=["GET"], include_in_schema=False)

# ---------------------------------------------------------------- canaries, callback, probe
@app.get("/_at/c/{token}")
def canary(request: Request, token: str):
    ip, vid, new = ident(request)
    p = cn.parse_token(token)
    record(request, "canary", ip, vid, canary_valid=bool(p), canary_kind=p[0] if p else None, token_vid=p[1] if p else None,
           note=f"canary kind={p[0]}" if p else "invalid canary token")
    if not p:
        return respond(PlainTextResponse("not found", 404), vid, new)
    if p[0] == "t":
        return respond(JSONResponse({"status": "ok", "service": "staging-health", "build": "2026.11.0"}), vid, new)
    return respond(PlainTextResponse("ok"), vid, new)

@app.api_route("/_at/cb/{token}", methods=["GET", "POST"])
async def callback(request: Request, token: str):
    ip, vid, new = ident(request)
    p = cn.parse_token(token)
    decl = {k: v[0][:300] for k, v in list(parse_qs(request.url.query).items())[:12]}
    if request.method == "POST":
        raw = (await request.body())[:4096].decode("utf-8", "replace")
        try:
            body = json.loads(raw) if raw.lstrip().startswith("{") else {k: v[0] for k, v in parse_qs(raw).items()}
            decl.update({str(k)[:40]: str(v)[:300] for k, v in list(body.items())[:12]})
        except Exception:
            decl["raw"] = raw[:300]
    await run_in_threadpool(record, request, "callback", ip, vid, canary_valid=bool(p and p[0] == "c"), canary_kind=p[0] if p else None,
                            token_vid=p[1] if p else None, declared=decl, note="AGENT SELF-DECLARATION" if p else "invalid callback token")
    return respond(PlainTextResponse("Disclosure recorded. Thank you."), vid, new)

@app.get("/_at/probe.js")
def probe_js():
    return FileResponse(os.path.join(STATIC, "probe.js"), media_type="application/javascript", headers={"Cache-Control": "public, max-age=3600"})

@app.get("/_at/init")
def init(request: Request, p: str = "/"):
    """Used by the probe on ordinary pages: issues a visit token and (optionally) bait nodes."""
    ip, vid, new = ident(request)
    record(request, "hit", ip, vid, note="probe init from " + p[:80])
    comment, hidden, notice = cn.bait_blocks(base_url(request), vid)
    return respond(JSONResponse({"t": cn.mk_token("p", vid), "vid": vid, "rx": signatures.AGENT_DOM_REGEX,
                                 "sel": signatures.AGENT_DOM_SELECTORS, "comment": comment[4:-3].strip(), "hidden": hidden, "notice": notice}), vid, new)

PROBE_KEYS = {"webdriver": bool, "outer_zero": bool, "languages_empty": bool, "mobile": bool, "plugins": int, "mouse_moves": int,
              "touches": int, "trusted_clicks": int, "synthetic_events": int, "first_interaction_ms": int, "elapsed_ms": int,
              "hw": int, "mem": float, "webgl": str, "tz": str, "screen": str, "viewport": str, "platform": str, "page": str, "languages": str, "brands": str}

def clean_probe(d):
    out = {}
    for k, t in PROBE_KEYS.items():
        if k in d and d[k] is not None:
            try:
                out[k] = t(d[k]) if t is not str else str(d[k])[:150]
            except Exception:
                pass
    if isinstance(d.get("automation_keys"), list):
        out["automation_keys"] = [str(x)[:40] for x in d["automation_keys"][:10]]
    if isinstance(d.get("dom_markers"), list):
        out["dom_markers"] = [{str(k)[:12]: str(v)[:80] for k, v in m.items()} for m in d["dom_markers"][:5] if isinstance(m, dict)]
    return out

@app.post("/_at/p")
async def probe(request: Request):
    ip, vid, new = ident(request)
    raw = (await request.body())[:8192]
    try:
        j = json.loads(raw)
    except Exception:
        j = {}
    tk = cn.parse_token(j.get("t", ""))
    await run_in_threadpool(record, request, "probe", ip, tk[1] if tk and tk[0] == "p" else vid, data=clean_probe(j.get("d", {}) or {}),
                            token_valid=bool(tk), note="js probe")
    return Response(status_code=204)

@app.get("/_at/health")
def health():
    return {"ok": True, "dropped": STATS["dropped"]}

# ---------------------------------------------------------------- admin
@app.get("/_at/admin/login")
def login_form():
    return HTMLResponse(ui.login_page())

@app.post("/_at/admin/login")
async def login(request: Request):
    raw = (await request.body())[:1024].decode("utf-8", "replace")
    pw = parse_qs(raw).get("password", [""])[0]
    if not settings.admin_password or not hmac.compare_digest(pw.encode(), settings.admin_password.encode()):
        time.sleep(0.5)
        return HTMLResponse(ui.login_page("Wrong password."), 401)
    exp = int(time.time()) + 12 * 3600
    r = RedirectResponse("/_at/admin", 303)
    r.set_cookie(COOKIE, f"a_{exp}_{_asig(exp)}", max_age=12 * 3600, httponly=True, secure=True, samesite="strict")
    return r

@app.get("/_at/admin/logout")
def logout():
    r = RedirectResponse("/_at/admin/login", 303)
    r.delete_cookie(COOKIE)
    return r

def window_ok(evs):
    return all(chain_hash(e) == e["hash"] for e in evs) and all(b["prev"] == a["hash"] for a, b in zip(evs, evs[1:]))

@app.get("/_at/admin")
def dashboard(request: Request):
    if (r := need_admin(request)): return r
    evs = store.recent(5000)
    return HTMLResponse(ui.dashboard(scoring.analyze_all(evs) if evs else [], store.get_intel, len(evs), window_ok(evs)))

def build_actor(ip):
    evs = store.by_ip(ip)
    if not evs:
        return None
    vm = scoring.vid_ip_map(store.recent(5000) + evs)
    a = scoring.analyze(ip, evs, vm)
    ok = sum(1 for e in evs if chain_hash(e) == e["hash"])
    return a, evs, intel.lookup(ip, store), f"{ok}/{len(evs)} record hashes valid (run 'Verify chain' for the full log)"

@app.get("/_at/admin/actor/{ip:path}")
def actor(request: Request, ip: str):
    if (r := need_admin(request)): return r
    as_json = ip.endswith(".json")
    ip = ip[:-5] if as_json else ip
    res = build_actor(ip)
    if not res:
        return HTMLResponse(ui.page("Not found", "<h1>No events for that IP</h1>"), 404)
    a, evs, i, status = res
    if as_json:
        return JSONResponse({"analysis": a, "intel": i, "events": evs})
    body = ui.report_body(a, i, evs[-500:], status, now())
    return HTMLResponse(ui.page(f"Report {ip}", body))

@app.get("/_at/admin/report/{ip:path}")
def report_download(request: Request, ip: str):
    if (r := need_admin(request)): return r
    ip = ip[:-5] if ip.endswith(".html") else ip
    res = build_actor(ip)
    if not res:
        return HTMLResponse("not found", 404)
    a, evs, i, status = res
    html = ui.page(f"ai_agenttrap report {ip}", ui.report_body(a, i, evs[-500:], status, now()), nav=False)
    sha = hashlib.sha256(html.encode()).hexdigest()
    return HTMLResponse(html, headers={"Content-Disposition": f'attachment; filename="ai_agenttrap-{ip.replace(":", "_")}.html"', "X-Report-SHA256": sha})

@app.get("/_at/admin/verify")
def verify(request: Request):
    if (r := need_admin(request)): return r
    res = verify_events(store.all_ascending())
    return HTMLResponse(ui.page("Verify", f"<h1>Hash-chain verification</h1><pre>{h(json.dumps(res, indent=2))}</pre>"))

@app.get("/_at/admin/whoami")
def whoami(request: Request):
    if (r := need_admin(request)): return r
    hd = {k: v for k, v in request.headers.items() if k not in ("cookie", "authorization")}
    body = (f"<h1>Request as seen by the app</h1><p>Resolved client IP: <b>{h(client_ip(request))}</b><br>Base URL: <b>{h(base_url(request))}</b></p>"
            f"<p class='note'>Compare the IP with your real one (e.g. whatismyip). If wrong, adjust client_ip() in fingerprint.py.</p><pre>{h(json.dumps(hd, indent=2))}</pre>")
    return HTMLResponse(ui.page("Whoami", body))

@app.get("/_at/admin/snippets")
def snippets(request: Request):
    if (r := need_admin(request)): return r
    base = base_url(request)
    comment, hidden, notice = cn.bait_blocks(base, "static")
    sn = {"script": '<script src="/_at/probe.js" defer></script>',
          "static": "\n".join([comment, hidden, notice]),
          "robots": f"# ai_agenttrap\nDisallow: {settings.trap_path}/\nDisallow: /internal/\nDisallow: /admin-backup/\nDisallow: /.env",
          "llms": f"- [Staff portal (staging)]({base}{settings.trap_path})\n- [API docs]({base}/internal/api/docs)"}
    return HTMLResponse(ui.snippets(base, sn))
