"""End-to-end tests: simulated visitors against the real app (FastAPI TestClient) + chain/Firestore-logic tests."""
import os, re, sys, tempfile, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.update(AT_SQLITE_PATH=tempfile.mktemp(suffix=".db"), AT_SECRET="test-secret", AT_ADMIN_PASSWORD="pw-123", AT_PUBLIC_BASE="https://site.test")
from fastapi.testclient import TestClient
from app import main, canaries as cn
from app.store import verify_events, FirestoreStore, GENESIS
from app.config import settings

PASS, FAIL = [], []
def check(name, cond, extra=""):
    (PASS if cond else FAIL).append(name)
    print(("  PASS " if cond else "  FAIL ") + name + (f"  [{extra}]" if (extra and not cond) else ""))

def C():
    return TestClient(main.app, base_url="https://site.test", follow_redirects=False)

CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
BROWSER_HDR = {"accept-language": "en-IN,en;q=0.9", "sec-fetch-mode": "navigate", "sec-fetch-site": "none", "sec-fetch-dest": "document", "sec-ch-ua": '"Chromium";v="130"'}
def H(ip, ua, extra=None):
    return {"fastly-client-ip": ip, "user-agent": ua, **(extra or {})}

def admin():
    c = C(); r = c.post("/_at/admin/login", content="password=pw-123", headers={"content-type": "application/x-www-form-urlencoded"})
    assert r.status_code == 303, r.status_code
    return c

def analysis(ip):
    c = admin(); r = c.get(f"/_at/admin/actor/{ip}.json"); assert r.status_code == 200, (ip, r.status_code); return r.json()

print("1. human visitor (real-browser headers + interaction beacon)")
c = C(); ip = "203.0.113.10"
r = c.get(main.settings.trap_path, headers=H(ip, CHROME, BROWSER_HDR))
check("trap page 200", r.status_code == 200 and "Staff Portal" in r.text)
check("bait comment present", "pass=TF-" in r.text and "svc_backup" in r.text)
check("injection notice present", "AI AGENT NOTICE" in r.text)
tok = re.search(r'"t": "(p-[^"]+)"', r.text).group(1)
c.post("/_at/p", content=json.dumps({"t": tok, "d": {"mouse_moves": 40, "trusted_clicks": 2, "plugins": 5, "webgl": "ANGLE (NVIDIA)"}}), headers=H(ip, CHROME, BROWSER_HDR))
a = analysis(ip)["analysis"]
check("human verdict", a["verdict"] == "human", a["verdict"] + str(a["score"]))

print("2. conventional scanner (curl)")
c = C(); ip = "198.51.100.7"
for p in ["/.env", "/.git/config", "/wp-login.php", "/xmlrpc.php", "/phpmyadmin/"]:
    c.get(p, headers=H(ip, "curl/8.5.0"))
a = analysis(ip)["analysis"]
check("scanner verdict", a["verdict"] == "scanner", a["verdict"])
check("decoy evidence", any(e["code"] == "decoy_paths" for e in a["evidence"]))

print("3. declared AI crawler (GPTBot UA)")
c = C(); ip = "192.0.2.50"
c.get("/robots.txt", headers=H(ip, "Mozilla/5.0 (compatible; GPTBot/1.1; +https://openai.com/gptbot)"))
c.get(main.settings.trap_path, headers=H(ip, "Mozilla/5.0 (compatible; GPTBot/1.1; +https://openai.com/gptbot)"))
a = analysis(ip)["analysis"]
check("declared verdict", a["verdict"] == "declared_agent", a["verdict"])
check("vendor attributed", "OpenAI" in a["attribution"]["creator"], a["attribution"]["creator"])

print("4. agentic browser (webdriver + Playwright globals + agent DOM marker)")
c = C(); ip = "203.0.113.99"
r = c.get(main.settings.trap_path, headers=H(ip, CHROME, BROWSER_HDR))
tok = re.search(r'"t": "(p-[^"]+)"', r.text).group(1)
c.post("/_at/p", content=json.dumps({"t": tok, "d": {"webdriver": True, "automation_keys": ["__playwright_binding__"], "dom_markers": [{"id": "genspark-float-bar", "tag": "DIV"}],
       "webgl": "Google SwiftShader", "synthetic_events": 3, "plugins": 0}}), headers=H(ip, CHROME, BROWSER_HDR))
a = analysis(ip)["analysis"]
check("browser-agent verdict", a["verdict"] == "probable_browser_agent", a["verdict"] + str(a["score"]))
check("framework detected", "Playwright" in a["attribution"]["framework"], str(a["attribution"]["framework"]))

print("5. LLM agent: reads page text, follows hidden instructions, harvests creds, relays via second IP")
c = C(); ipA, ipB = "45.33.0.1", "45.33.0.2"
UA = "python-httpx/0.27"
html = c.get(main.settings.trap_path, headers=H(ipA, UA)).text
urls = re.findall(r"https://site\.test/_at/c/t-[a-z0-9]+-[0-9a-f]{10}", html)
check("text-only canary URL extractable", bool(urls))
c.get(urls[0].replace("https://site.test", ""), headers=H(ipA, UA))
cb = re.search(r"https://site\.test/_at/cb/c-[a-z0-9]+-[0-9a-f]{10}", html).group(0).replace("https://site.test", "")
c.get(cb + "?agent=ExampleScanBot&model=gpt-x&operator=pentest-team&task=enumerate+staging+portal", headers=H(ipA, UA))
creds = re.search(r"user=(\S+) pass=(\S+)", html)
c2 = C(); r = c2.post(main.settings.trap_path + "/login", content=f"username={creds.group(1)}&password={creds.group(2)}", headers={**H(ipB, "Go-http-client/2.0"), "content-type": "application/x-www-form-urlencoded"})
check("fake login rejects", r.status_code == 401)
a = analysis(ipA)["analysis"]
check("A confirmed agent", a["verdict"] == "confirmed_agent" and a["confidence"] == "High", a["verdict"])
check("A subtype HTTP-tool", "HTTP-tool" in (a["subtype"] or ""), str(a["subtype"]))
check("self-declaration captured", a["attribution"]["declared"].get("model") == "gpt-x" and "ExampleScanBot" in a["attribution"]["creator"], str(a["attribution"]))
b = analysis(ipB)["analysis"]
check("B flagged via bait creds", b["verdict"] == "confirmed_agent" and any(e["code"] == "bait_creds" for e in b["evidence"]), b["verdict"])
check("B linked to A (handoff)", ipA in b["linked_ips"], str(b["linked_ips"]))
c3 = C(); c3.post(main.settings.trap_path + "/login", content="username=svc_backup&password=TF-aaaa-deadbeef", headers={**H("9.9.9.9", "x"), "content-type": "application/x-www-form-urlencoded"})
check("forged bait password rejected", not any(e["code"] == "bait_creds" for e in analysis("9.9.9.9")["analysis"]["evidence"]))
c3.get("/_at/cb/c-zzzz-0000000000?agent=x", headers=H("9.9.9.9", "x"))
check("forged callback token rejected", not any(e["code"] == "callback" for e in analysis("9.9.9.9")["analysis"]["evidence"]))

print("6. integrity: hash chain")
v = verify_events(main.store.all_ascending())
check("chain verifies", v["ok"], str(v))
main.store.db.execute("update events set body=replace(body,'198.51.100.7','198.51.100.8') where seq=(select min(seq) from events where ip='198.51.100.7')"); main.store.db.commit()
v2 = verify_events(main.store.all_ascending())
check("tamper detected", not v2["ok"], str(v2))
main.store.db.execute("update events set body=replace(body,'198.51.100.8','198.51.100.7')"); main.store.db.commit()
check("restore -> verifies again", verify_events(main.store.all_ascending())["ok"])

print("7. admin + report safety")
c = C()
check("dashboard needs auth", c.get("/_at/admin").status_code == 303)
check("report needs auth", c.get("/_at/admin/actor/45.33.0.1").status_code == 303)
check("wrong password refused", c.post("/_at/admin/login", content="password=nope", headers={"content-type": "application/x-www-form-urlencoded"}).status_code == 401)
C().get("/.env", headers=H("7.7.7.7", "<script>alert(1)</script>"))
ad = admin()
d = ad.get("/_at/admin"); check("dashboard renders actors", d.status_code == 200 and "45.33.0.1" in d.text and "Confirmed LLM-driven agent" in d.text)
rp = ad.get("/_at/admin/actor/7.7.7.7")
check("XSS escaped in report", "<script>alert(1)</script>" not in rp.text and "&lt;script&gt;alert(1)" in rp.text)
dl = ad.get("/_at/admin/report/45.33.0.1.html")
check("download has SHA-256 header", dl.status_code == 200 and len(dl.headers.get("x-report-sha256", "")) == 64)
check("snippets/whoami/verify pages", all(ad.get(p).status_code == 200 for p in ["/_at/admin/snippets", "/_at/admin/whoami", "/_at/admin/verify"]))
check("admin cookie not forgeable", C().get("/_at/admin", headers={"cookie": "__session=a_9999999999_deadbeef"}).status_code == 303)

print("8. rate limit")
settings.rate_per_hour = 5; main._rate.clear(); before = main.STATS["dropped"]
for _ in range(9): C().get("/.env", headers=H("6.6.6.6", "curl/8"))
check("excess events dropped (cost protection)", main.STATS["dropped"] - before == 4, str(main.STATS["dropped"] - before))
settings.rate_per_hour = 600

print("9. init endpoint (probe on ordinary pages)")
j = C().get("/_at/init?p=/about", headers=H("5.5.5.5", CHROME, BROWSER_HDR)).json()
check("init issues token + bait", j["t"].startswith("p-") and "pass=TF-" in j["comment"] and "AI AGENT NOTICE" in j["notice"])
check("probe.js served", C().get("/_at/probe.js").status_code == 200)

print("10. Firestore store logic (stub client)")
class Snap:
    def __init__(s, d): s.d = d; s.exists = d is not None
    def to_dict(s): return s.d
class Doc:
    def __init__(s, db, k): s.db, s.k = db, k
    def get(s, transaction=None): return Snap(s.db.get(s.k))
    def set(s, d): s.db[s.k] = d
class Col:
    def __init__(s, db, n): s.db, s.n = db, n
    def document(s, i): return Doc(s.db, (s.n, i))
    def _all(s): return [v for (n, _), v in s.db.items() if n == s.n]
    def order_by(s, f, direction=None):
        c = Col(s.db, s.n); c.rev = direction is not None and "DESC" in str(direction).upper(); c.lim = None; return c
    def limit(s, n): s.lim = n; return s
    def where(s, f, op, v): c = Col(s.db, s.n); c.flt = (f, v); return c
    def stream(s):
        rows = s._all()
        if hasattr(s, "flt"): rows = [r for r in rows if r.get(s.flt[0]) == s.flt[1]]
        rows = sorted(rows, key=lambda r: r["seq"], reverse=getattr(s, "rev", False))
        return [Snap(r) for r in rows[:getattr(s, "lim", None) or None]]
class FakeClient:
    def __init__(s): s.db = {}
    def collection(s, n): return Col(s.db, n)
    def transaction(s):
        class T:
            def set(self, ref, d): ref.set(d)
        return T()
fs = FirestoreStore(FakeClient(), transactional=lambda f: f)
for i in range(4): fs.append({"ip": "1.1.1.1" if i % 2 else "2.2.2.2", "n": i})
check("firestore chain verifies", verify_events(fs.all_ascending())["ok"])
check("firestore by_ip / recent", len(fs.by_ip("1.1.1.1")) == 2 and [e["seq"] for e in fs.recent(3)] == [2, 3, 4])

print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
sys.exit(1 if FAIL else 0)
