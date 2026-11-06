import ipaddress
from .signatures import parse_ua

KEEP = ("user-agent accept accept-language accept-encoding referer origin from dnt via cache-control pragma "
        "upgrade-insecure-requests sec-fetch-site sec-fetch-mode sec-fetch-dest sec-fetch-user sec-ch-ua "
        "sec-ch-ua-mobile sec-ch-ua-platform signature-agent signature-input signature content-type "
        "x-forwarded-for fastly-client-ip x-forwarded-host x-requested-with").split()

def _valid(ip):
    try:
        return str(ipaddress.ip_address(ip.strip()))
    except Exception:
        return None

def client_ip(request) -> str:
    """Firebase Hosting (Fastly) -> Cloud Run. Prefer CDN-set header; raw XFF is always logged separately."""
    h = request.headers
    v = _valid(h.get("fastly-client-ip", ""))
    if v:
        return v
    xff = h.get("x-forwarded-for", "")
    if xff:
        v = _valid(xff.split(",")[0])
        if v:
            return v
    return request.client.host if request.client else "0.0.0.0"

def safe_headers(request) -> dict:
    h = request.headers
    return {k: h[k][:300] for k in KEEP if k in h}

def header_anomalies(hdr: dict) -> list:
    """Cheap header-level signals. Returns [(code, title, points, detail)]."""
    out = []
    ua = hdr.get("user-agent", "")
    p = parse_ua(ua)
    claims_browser = "mozilla/" in ua.lower() and not p["crawler"]
    if claims_browser and "sec-fetch-mode" not in hdr and "chrome/" in ua.lower():
        out.append(("chrome_no_sec_fetch", "Chrome UA without Sec-Fetch-* headers", 10,
                    "A real Chrome sends Sec-Fetch-* on navigations; absence suggests a scripted client spoofing the UA."))
    if claims_browser and "accept-language" not in hdr:
        out.append(("no_accept_language", "Browser UA without Accept-Language", 8, "Real browsers always send it."))
    if not ua:
        out.append(("empty_ua", "Empty User-Agent", 10, "Scripted client."))
    if "signature-agent" in hdr or "signature-input" in hdr:
        out.append(("web_bot_auth", "Web Bot Auth signature headers present", 45,
                    "Signature-Agent: %s (claimed; signature not cryptographically verified here)" % hdr.get("signature-agent", "?")))
    return out
