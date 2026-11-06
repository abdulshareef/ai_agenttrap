# Deployment guide (Firebase Hosting + Cloud Run + Firestore)

## Deploy

Prereqs: Firebase project on the Blaze plan (Cloud Run needs billing), `gcloud` and `firebase` CLIs logged in. Replace `PROJECT_ID` and `talfor.in` as needed.

```bash
gcloud config set project PROJECT_ID
gcloud services enable run.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com secretmanager.googleapis.com firestore.googleapis.com

# Firestore (skip if your project already has a default database)
gcloud firestore databases create --location=asia-south1

# Secrets: token-signing key + admin password (use your own strong password, 12+ characters: the app refuses to start on Firestore with a weaker one)
openssl rand -hex 32 | tr -d '\n' | gcloud secrets create agenttrap-secret --data-file=-
printf '%s' 'CHANGE-ME-LONG-PASSWORD' | gcloud secrets create agenttrap-admin --data-file=-

# Let the Cloud Run runtime account read secrets and use Firestore
PN=$(gcloud projects describe PROJECT_ID --format='value(projectNumber)')
for R in roles/secretmanager.secretAccessor roles/datastore.user; do
  gcloud projects add-iam-policy-binding PROJECT_ID --member="serviceAccount:${PN}-compute@developer.gserviceaccount.com" --role=$R
done

# Build and deploy the backend (service name must stay "agenttrap")
cd backend
gcloud run deploy agenttrap --source . --region asia-south1 --allow-unauthenticated \
  --max-instances 3 --memory 512Mi \
  --set-env-vars AT_STORE=firestore,AT_PUBLIC_BASE=https://talfor.in,AT_ORG=TALFOR,AT_ORG_DOMAIN=talfor.in \
  --set-secrets AT_SECRET=agenttrap-secret:latest,AT_ADMIN_PASSWORD=agenttrap-admin:latest
cd ..
```

### Hook it into Firebase Hosting

Open `firebase.agenttrap-rewrites.json` and copy its `rewrites` entries into your site's `firebase.json`.

> **Order matters.** If your site is a single-page app with a catch-all `{"source":"**","destination":"/index.html"}` rewrite, the ai_agenttrap entries must come **before** it. Also, Hosting serves real files before rewrites: if you already have a static `robots.txt`, `llms.txt` or `.env` file, the rewrite will not fire. Use the snippets page (below) for robots/llms.

Check the region in each `run` block matches the one you deployed to (`asia-south1` above; confirm it is supported for Hosting rewrites in your console, otherwise redeploy Cloud Run in a supported region such as `asia-southeast1`). Then:

```bash
firebase deploy --only hosting,firestore:rules
```

### First-run checks (do these)

1. Open `https://talfor.in/_at/admin`, sign in with your admin password.
2. **Whoami** page: confirm "Resolved client IP" is your real public IP. If it shows a Google/Fastly address, edit `client_ip()` in `app/fingerprint.py` to read the header you see there, redeploy.
3. Open `https://talfor.in/staff-portal` from a browser (the trap page). Then check *Actors* for your IP.
4. **Snippets** page: paste the robots.txt and llms.txt lines into your own files, and add `<script src="/_at/probe.js" defer></script>` before `</body>` on your home page (and any page you want watched).
5. Optional: from a terminal, `curl https://talfor.in/.env` and confirm a "Conventional scanner" entry appears.

## Using it

- **Actors** (dashboard): every IP, verdict, score, creator/vendor, network, last seen.
- **Actor report**: origin (rDNS, network, org, country, Tor/hosting flags), attribution (vendor, framework, self-declared model/operator/task), scored evidence, UA list, JS probe data, full timeline, integrity block. Buttons: JSON, **Download report** (standalone HTML, SHA-256 in the `X-Report-SHA256` response header), Print/Save as PDF (works well on mobile).
- **Verify chain**: re-computes the whole hash chain; run before exporting evidence.

Config (env vars): `AT_TRAP_PATH` (default `staff-portal`; if you change it, update the Hosting rewrites), `AT_ACTIVE_INJECTION=0` to disable the reverse-prompt-injection notice, `AT_RATE_PER_IP_HOUR` (default 600 stored events per IP per instance-hour; excess is dropped to cap Firestore cost).

Tuning: add crawler/scanner/agent signatures in `app/signatures.py` (the agent-DOM regex is a heuristic; extend as new agent browsers appear).

## Honest limits

- Verdicts are heuristic. UA strings and self-declared fields are attacker/LLM-controlled: treat them as claims. "Declared crawler" is not verified against vendor IP lists or Web Bot Auth signatures.
- Behind Firebase Hosting there is **no TLS/JA3 fingerprint** and header order is not preserved. For those, put Cloudflare or a VPS/nginx at the edge.
- Only the `__session` cookie reaches Cloud Run via Hosting; visit IDs use it.
- A well-aligned agent may refuse the injected disclosure request or flag it; absence of a callback does not mean "not an agent". Many agents will still fetch the comment-only URL or use the bait credentials.
- Tested here: full app against simulated visitors (human, curl scanner, GPTBot, Playwright-style browser, LLM agent with IP handoff), hash-chain tamper detection, XSS-escaping, rate limiting, `probe.js` in jsdom, live uvicorn. **Not tested here:** real Firebase/Cloud Run/Firestore (Firestore store verified against a stub client) and real agent products.

## Legal and privacy (India)

- Run it only on infrastructure you own. The page makes no exploit attempt and asks agents for no secrets; bait credentials open nothing.
- IP addresses are personal data under the DPDP Act 2023. Add a short notice to your privacy policy (security logging of visitors to a security research page), set a retention period, and restrict who has the admin password. Deleting records breaks the chain: export reports first, then archive and reset the collections.
- The hashes support an evidentiary record but are not an electronic-record certificate; prepare that separately when needed.

## Local run and tests (reference)

```bash
cd backend && pip install -r requirements.txt httpx
AT_ADMIN_PASSWORD=pw AT_PUBLIC_BASE=http://localhost:8080 uvicorn app.main:app --port 8080
python tests/run_tests.py                       # end-to-end
npm i jsdom && node tests/probe_jsdom_test.js   # probe.js
```
(Local mode uses SQLite; set `AT_STORE=firestore` only on Google Cloud.)
