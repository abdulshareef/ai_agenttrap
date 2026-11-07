# ai_agenttrap

[![CI](https://github.com/abdulshareef/ai_agenttrap/actions/workflows/ci.yml/badge.svg)](https://github.com/abdulshareef/ai_agenttrap/actions)
![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)
![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)
![Serverless](https://img.shields.io/badge/deploy-Firebase%20%2B%20Cloud%20Run-orange.svg)

**An open-source honeypot that catches agentic AI doing reconnaissance on your website, identifies what it is, and writes the case report.**

AI agents now crawl, probe and map websites on their own: LLM-driven pentest tools, AI browsers acting for a user, and AI training/search crawlers. Classic bot detection was not built to tell these apart. ai_agenttrap exploits the one thing an LLM agent does that a script does not: **it reads text and acts on it.** It plants content that only something reading page text would follow, then records what came back.

## Objectives

1. **Detect** AI-agent reconnaissance against your own site with high-confidence, low-noise signals.
2. **Classify** the visitor: LLM-driven agent, agentic browser, declared AI crawler, conventional scanner, or human.
3. **Attribute** who built or operates it (vendor, framework, self-declared model/operator/task), with honest confidence and clear "claimed vs verified" labelling.
4. **Preserve evidence** in a tamper-evident, hash-chained log, with per-IP reports that can be handed to a client, a court, or a SOC.
5. **Stay accessible:** serverless, scales to zero, no third-party services or API keys, deployable by a small team in an afternoon.
6. **Be a research platform:** transparent signatures, reproducible simulated-visitor tests, open to community contributions.

## How it works

| Layer | What it does | Strength |
|---|---|---|
| Passive | IP, rDNS, RDAP network/org/country, Tor exit list, UA classification, Web Bot Auth headers, header anomalies | weak to medium |
| Browser probe | WebDriver/Playwright/Selenium artifacts, agent UI injected into the DOM, software WebGL, untrusted input events | medium to strong |
| Semantic canaries | Per-visit signed URLs hidden in a link, in an HTML comment, in a fake `.env`, API docs and `llms.txt`. A comment-only URL is fetched only by something that read and acted on text | strong |
| Reverse prompt injection | Hidden notice asking an AI agent to disclose itself (agent, model, operator, task) via a callback URL. Asks for no secrets. A callback = confirmed LLM agent | strongest |
| Bait credentials | Per-visit fake credentials; any use is flagged, and use from a different IP reveals agent **handoff** | strong |
| Behaviour | Regular timing, bursts, path breadth, tool switching (curl then Python then browser), ignoring robots.txt | supporting |

```
Internet -> Firebase Hosting -> Cloud Run (FastAPI) -> Firestore
              |                    |-- trap page, decoys, canaries, callback, probe beacon
              |                    |-- scoring + attribution engine
              |                    `-- admin dashboard + per-IP reports (HTML / JSON / print-to-PDF)
              `-- your existing site, unchanged (one <script> tag to add the probe)
```

Every event is appended to a **SHA-256 hash chain** (each record embeds the previous record's hash). *Verify chain* detects edits and deletions.

## Quick start (local, SQLite)

```bash
cd backend
pip install -r requirements.txt httpx
AT_ADMIN_PASSWORD=change-me AT_PUBLIC_BASE=http://localhost:8080 uvicorn app.main:app --port 8080
# trap page:  http://localhost:8080/staff-portal
# dashboard:  http://localhost:8080/_at/admin
python tests/run_tests.py
```

Production deployment on Firebase Hosting + Cloud Run + Firestore: **[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)**.

## Status and honest limits

- Verdicts are heuristic. User-Agent strings and self-declared fields are attacker/LLM-controlled, so they are reported as claims.
- Behind Firebase Hosting there is no TLS/JA3 view; for that, put a Cloudflare or nginx edge in front.
- A well-aligned agent may ignore the disclosure request; no callback does not mean "not an agent".
- Tested: 35 end-to-end checks with simulated visitors (human, curl scanner, GPTBot, Playwright-style browser, LLM agent with IP handoff), tamper detection, XSS escaping, rate limiting, probe in jsdom. Not yet tested against live agent products in the wild. Reports of real captures are very welcome.

## Roadmap

- Verify declared crawlers against vendor-published IP ranges and Web Bot Auth signatures
- Edge mode (Cloudflare Worker / nginx) for TLS/JA3 and header-order fingerprints
- Alerting (email, Telegram, Slack) and SIEM export (syslog / Wazuh / STIX)
- Native PDF export and signed report bundles
- Retention and archive tooling with DPDP/GDPR-friendly defaults
- Community signature feed for new agent browsers and frameworks

## Responsible use

Run it only on infrastructure you own or are authorised to instrument. The page performs no exploitation and bait credentials open nothing. IP addresses are personal data under laws such as India's DPDP Act 2023 and the GDPR: publish a notice, set a retention period, and restrict admin access. See [SECURITY.md](SECURITY.md).

## Contributing

Signatures, detectors, tests and docs are all welcome: see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT. See [LICENSE](LICENSE).

---
Built by **TALFOR Cybersecurity & Digital Forensics**, Bengaluru ([talfor.in](https://talfor.in)).
