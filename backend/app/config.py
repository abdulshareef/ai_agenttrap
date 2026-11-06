import os

def _e(k, d=""):
    return os.environ.get(k, d)

class Settings:
    store = _e("AT_STORE", "sqlite")                      # sqlite | firestore
    sqlite_path = _e("AT_SQLITE_PATH", "/tmp/agenttrap.db")
    secret = _e("AT_SECRET", "dev-only-secret-change-me")  # HMAC key for tokens + admin cookie
    admin_password = _e("AT_ADMIN_PASSWORD", "")           # empty = admin disabled
    public_base = _e("AT_PUBLIC_BASE", "").rstrip("/")     # e.g. https://talfor.in
    org = _e("AT_ORG", "TALFOR")
    org_domain = _e("AT_ORG_DOMAIN", "talfor.in")
    trap_path = "/" + _e("AT_TRAP_PATH", "staff-portal").strip("/")
    rate_per_hour = int(_e("AT_RATE_PER_IP_HOUR", "600"))  # stored events per IP per hour
    injection = _e("AT_ACTIVE_INJECTION", "1") == "1"      # reverse prompt-injection notice on/off

settings = Settings()

# Fail closed in production: never run on Firestore with the dev signing key or a weak admin password.
if settings.store == "firestore" and (settings.secret == "dev-only-secret-change-me" or len(settings.admin_password) < 12):
    raise RuntimeError("AT_STORE=firestore requires a strong AT_SECRET and AT_ADMIN_PASSWORD (12+ characters).")
