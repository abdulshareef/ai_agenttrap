# Security policy

ai_agenttrap is an internet-facing honeypot, so its own hardening matters.

**Reporting a vulnerability:** please use GitHub's private "Report a vulnerability" (Security tab) on this repository. Do not open a public issue. Expect an acknowledgement within a few days.

**Hardening built in:** HMAC-signed tokens and admin cookie; fail-closed startup on Firestore without a strong `AT_SECRET` / `AT_ADMIN_PASSWORD`; all attacker-controlled text is HTML-escaped in reports; captured passwords are masked (only bait credentials are stored in full); per-IP write rate limit; Firestore rules deny all client access.

**Operator checklist:** keep `--max-instances` low, use Secret Manager for secrets, restrict who has the admin password, never reuse real credentials as bait, and review the Whoami page after deployment.

**Out of scope:** findings that require you to run the honeypot against systems you do not own.
