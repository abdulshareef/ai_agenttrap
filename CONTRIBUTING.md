# Contributing

Thanks for helping. Good first contributions: new crawler/scanner/agent signatures, detection ideas, report improvements, docs, tests.

## Dev setup
```bash
cd backend && pip install -r requirements.txt httpx
python tests/run_tests.py
npm i jsdom && node tests/probe_jsdom_test.js
```

## Guidelines
- **Signatures** live in `backend/app/signatures.py`. Cite where a User-Agent or DOM marker comes from (vendor docs or an observed capture) in the PR.
- Every detector must have a test in `tests/run_tests.py` (a simulated visitor that should trigger it, and one that should not).
- Keep verdicts honest: heuristics are labelled as claims, and nothing is reported as verified unless it is cryptographically or protocol verified.
- Privacy: collect only IP, request metadata and the JS probe fields already listed. No fingerprinting beyond automation detection.
- Scope: this project detects and documents visitors to **your own** site. Offensive features (exploitation, active attacks on visitors, data exfiltration) will not be merged.
- Keep PRs small, run the tests, describe what you observed.

By contributing you agree your contribution is licensed under the MIT license.
