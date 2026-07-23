# Manual Test Checklist

For a pre-submission or pre-demo sanity pass, in addition to the automated suite
(`pytest`, 249 tests, ~90% coverage). Automated tests prove the logic is correct in
isolation; this checklist proves the assembled application actually works the way a
user experiences it.

## Setup

- [ ] `cp .env.example .env`, leave all values at default
- [ ] `pip install -r requirements.txt` succeeds cleanly
- [ ] `uvicorn app.main:app --reload` starts with no errors
- [ ] `http://127.0.0.1:8000/health` returns `{"status": "ok"}`
- [ ] `http://127.0.0.1:8000/docs` renders the OpenAPI UI

## Golden path

- [ ] `/` loads, shows the config-status line, no demo/offline banner errors
- [ ] Click "Legitimate" sample button → textarea fills with the sample content
- [ ] Click "Analyze" → results page renders within a few seconds
- [ ] Verdict card shows **Likely Legitimate based on available header evidence**,
      score 0
- [ ] Identity table shows From/Return-Path/Message-ID with matching domains
- [ ] Auth matrix shows SPF/DMARC recorded as `pass`
- [ ] Mail-route timeline renders two hops, oldest first, with the PGP-gateway origin
      hop correctly showing no `from` claim rather than being dropped
- [ ] IOC table renders with defanged values by default; toggling "show real values"
      reveals the un-defanged form
- [ ] Raw parsed headers table shows every field including duplicates, in order
- [ ] "Download JSON" and "Download Markdown" both produce non-empty, well-formed
      output

## Other three samples

- [ ] Phishing sample → **Likely Phishing**, score ≥50, `IDN-001`/`IDN-002` findings
      visible with expandable evidence/legitimate-explanation/action text
- [ ] Possible-BEC sample → **Possible BEC / Impersonation** (never "Confirmed"
      anywhere on the page), `BEC-001` is the headline finding
- [ ] Malformed sample → does **not** crash, produces a **Suspicious** verdict, parse
      warnings are visible in the raw-headers panel

## Input handling

- [ ] Submitting with an empty textarea shows a clear on-page error, not a blank
      reload or a 500
- [ ] Pasting a header well over 256 KiB shows a clear "exceeds the limit" error
- [ ] Uploading a `.eml` file with a body: verify the results page reflects that a
      body was supplied (DKIM scope, if a `DKIM-Signature:` is present, should read
      "signed headers and body hash" rather than "headers only")
- [ ] Uploading a file with a disallowed extension (e.g. `.exe`) is rejected with a
      clear message, not silently ignored

## Security spot-checks

- [ ] View source on the results page for the phishing sample (or paste a header with
      `<script>alert(1)</script>` in the Subject) — confirm no `<script>` tag appears
      unescaped anywhere in the rendered HTML
- [ ] Browser dev tools → Network tab → confirm response headers include
      `Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`
- [ ] Attempt `GET /samples/../requirements.txt` (or similar traversal) → 404, not the
      file contents
- [ ] Submit the form twice in quick succession without reloading `/` (reusing a stale
      CSRF cookie/token pair after clearing cookies) → rejected with a 400, not a
      silent bypass

## Demo mode

- [ ] Set `DEMO_MODE=true`, `ENRICHMENT_ENABLED=false`, restart
- [ ] Demo-mode banner is visible on every page
- [ ] Analyzing the phishing sample shows threat-intel rows labelled **Demo Fixture**
- [ ] Analyzing a custom/hand-typed header (not one of the four samples) shows
      `disabled` for every intel provider, never a fabricated result

## Docker

- [ ] `docker build -t email-header-analyzer .` completes without errors
- [ ] `docker run -p 8000:8000 --env-file .env email-header-analyzer` starts and
      `docker ps` eventually shows `(healthy)`
- [ ] `curl http://127.0.0.1:8000/health` from the host succeeds
- [ ] Container logs show no permission-denied warnings on startup (regression check
      for the `tldextract` cache-write issue documented in `STATUS.md`)

## Quality gate

- [ ] `ruff check .` → all checks passed
- [ ] `pytest -q` → all tests passed
- [ ] `pytest --cov=app --cov-report=term-missing` → ≥80% overall, ≥85% on `app/core`
