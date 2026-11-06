"""IP intelligence (RDAP + reverse DNS + Tor exit list). Called at report time, cached in the store."""
import ipaddress, json, socket, threading, time, urllib.request
from .signatures import HOSTING_HINTS

_tor = {"at": 0, "ips": set()}
TTL = 7 * 86400

def _get(url, timeout=4):
    req = urllib.request.Request(url, headers={"User-Agent": "ai_agenttrap/1.0 (research honeypot)", "Accept": "application/json, text/plain"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read(2_000_000).decode("utf-8", "replace")

def _rdns(ip, timeout=2.0):
    box = {}
    def run():
        try:
            box["v"] = socket.gethostbyaddr(ip)[0]
        except Exception:
            box["v"] = None
    t = threading.Thread(target=run, daemon=True); t.start(); t.join(timeout)
    return box.get("v")

def _tor_set():
    if time.time() - _tor["at"] > 6 * 3600:
        try:
            _tor["ips"] = {l.strip() for l in _get("https://check.torproject.org/torbulkexitlist").splitlines() if l and not l.startswith("#")}
            _tor["at"] = time.time()
        except Exception:
            _tor["at"] = time.time() - 5 * 3600  # retry in ~1h
    return _tor["ips"]

def parse_rdap(j: dict) -> dict:
    out = {"name": j.get("name"), "handle": j.get("handle"), "country": j.get("country"), "type": j.get("type"),
           "range": f"{j.get('startAddress','?')} - {j.get('endAddress','?')}"}
    c = j.get("cidr0_cidrs") or []
    if c:
        c0 = c[0]
        out["cidr"] = f"{c0.get('v4prefix') or c0.get('v6prefix')}/{c0.get('length')}"
    orgs = []
    for e in j.get("entities", []) or []:
        for item in (e.get("vcardArray") or [None, []])[1]:
            if item and item[0] == "fn":
                orgs.append(item[3])
    if orgs:
        out["org"] = orgs[0]
    return out

def lookup(ip, store, refresh=False, online=True):
    cached = store.get_intel(ip)
    if cached and not refresh and time.time() - cached.get("at", 0) < TTL:
        return cached
    d = {"ip": ip, "at": time.time(), "global": False, "rdns": None, "rdap": {}, "tor_exit": False, "hosting": False, "errors": []}
    try:
        d["global"] = ipaddress.ip_address(ip).is_global
    except Exception:
        pass
    if online and d["global"]:
        d["rdns"] = _rdns(ip)
        try:
            d["rdap"] = parse_rdap(json.loads(_get(f"https://rdap.org/ip/{ip}")))
        except Exception as e:
            d["errors"].append(f"rdap: {type(e).__name__}")
        d["tor_exit"] = ip in _tor_set()
        blob = " ".join(str(x) for x in [d["rdns"], d["rdap"].get("name"), d["rdap"].get("org")]).lower()
        d["hosting"] = any(h in blob for h in HOSTING_HINTS)
    if d["global"] and online:
        store.set_intel(ip, d)
    return d
