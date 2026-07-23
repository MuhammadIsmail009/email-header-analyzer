# Reference Repositories — Study, Licence Audit and Reuse Decisions

**Audit date:** 2026-07-23
**Auditor:** M. Ismail (SOC Internee, Ebryx)
**Purpose:** Record every project studied while building this tool, the licence that
actually governs it, and whether any code was reused.

## Method

Licences were verified by fetching the actual licence file from
`raw.githubusercontent.com` — not by reading the GitHub sidebar badge, not by trusting a
README claim. This distinction turned out to matter twice (see §2 and §3 below).

For each repository the following were checked:

1. `LICENSE`, `LICENSE.md`, `LICENSE.txt`, `COPYING` at the default branch
2. The recursive git tree, to confirm absence rather than assume it
3. The GitHub REST API `license` field
4. Any licence claim in the README, compared against the file

**Reuse rule applied throughout:** no code, template, configuration, regex or test
fixture was copied from any repository below. Every idea adopted was reimplemented from
the described concept. This project is MIT licensed and contains no third-party code.

---

## Licence summary

| # | Repository | Licence file found | **Governing licence** | GitHub reports | Code copied? |
|---|---|---|---|---|---|
| 1 | `mailtower-app/email-header-analyzer` | `LICENSE` | **MIT** | MIT ✅ | No |
| 2 | `cyberdefenders/email-header-analyzer` | `LICENSE.md` | **GPL-3.0** | `NOASSERTION` ⚠️ | No |
| 3 | `akajhon/MailHeaderDetective` | `LICENSE` | **GPL-3.0** | GPL-3.0 (README claims MIT) ⚠️ | No |
| 4 | `useru1k/email-analysis` | none | **All rights reserved** | `null` | No |
| 5 | `haseebtariq368/Emaul-Header-Analyzer` | none | **All rights reserved** | `null` | No |
| 6 | `muhammadahmadabid019-commits/SentinelMail` | none | **All rights reserved** | `null` | No |
| 7 | `GOVCERT-LU/eml_parser` | `LICENSE` | **AGPL-3.0** | AGPL-3.0 | No — dependency rejected |
| 8 | `sublime-security/sublime-rules` | `LICENSE` | **MIT** | MIT ✅ | No — taxonomy vocabulary only |

**Only one repository studied (mailtower, MIT) permits code reuse. Nothing was taken from
it regardless.** Four of the eight grant no rights at all.

---

## 1. `mailtower-app/email-header-analyzer`

| | |
|---|---|
| URL | https://github.com/mailtower-app/email-header-analyzer |
| Stars / forks | 6 / 1 |
| Last push | 2026-01-25 (active) |
| Stack | Vue 3 + TypeScript + Quasar, Docker + nginx. No backend. |
| Live instance | https://mailheader.mailtower.app |
| **Licence** | **MIT** — verified, canonical 21-line text, `Copyright (c) 2024 MAILTOWER`. README claim matches the file. |
| **Code copied** | **No.** Permitted, but not needed. |

### Useful concepts

- **Zero-transmission privacy model.** Everything runs client-side; the pitch is "your
  data never leaves your device." For a SOC tool this is a genuine feature, not a
  limitation — analysts handling real phishing reports are frequently *forbidden* from
  submitting customer email to third parties. **Adopted as the offline-by-default posture.**
- **Typed hop model** (`ReceivedHeaderParts`) separating the raw header line from parsed
  parts. Far more testable than a dict-of-tuples. **Adopted as the `ReceivedHop` model.**
- **Hop delay computed from real `Date` deltas in the presentation layer**, not baked into
  the parser. This is the *correct* arithmetic — see §2 for the bug it avoids.
- **Dependency-free responsive SVG hop diagram.** No chart library, no CDN, no CSP
  exceptions. **Adopted in principle** — our timeline is CSS + GSAP rather than SVG, but
  the "no charting dependency" decision is the same.
- Token-scan parsing (`indexOf`/`slice` on `from `/`by `/`with `/`id `) instead of one
  mega-regex — readable and immune to catastrophic backtracking.

### Weaknesses

- Six stars, solo project, no visible test suite.
- Delay data and the route diagram live in different components, so "where did it stall"
  requires reading both.
- No negative-delay handling and no aggregate total.
- No SPF/DKIM/DMARC verification — being fully client-side, it cannot do DNS at all.
- 288 KB `package-lock.json` for a small app; large supply-chain surface.

### Attribution required

None, since no code was reused. Had any been, the MIT notice and copyright line would
need to be preserved.

---

## 2. `cyberdefenders/email-header-analyzer` (MHA)

| | |
|---|---|
| URL | https://github.com/cyberdefenders/email-header-analyzer |
| Hosted | https://mha.cyberdefenders.org |
| Stars / forks | 695 / 166 — the most-starred pure header analyzer |
| Last push | 2023-04-11 (dormant ~3 years) |
| Stack | Python 3 + Flask, `HeaderParser`, `dateutil`, `IPy`, `geoip2`, `pygal`, Bootstrap |
| **Licence** | **GPL-3.0** — strong copyleft |
| **Code copied** | **No — prohibited.** This project is MIT; GPL code cannot be incorporated. |

### ⚠️ Licence trap #1 — GitHub reports the licence incorrectly

There is no plain `LICENSE` file (404). The grant lives in **`LICENSE.md`**, which
contains the full GNU GPL v3 text — but *reformatted as Markdown* (`# Preamble`, `====`
underlines, reflowed paragraphs). GitHub's `licensee` matcher cannot fingerprint the
reformatted text against the canonical plain-text GPL, so the API returns
`spdx_id: "NOASSERTION"` and the sidebar shows **"Other"**.

The README contains no licence statement at all, so `LICENSE.md` is the sole and
controlling grant.

**Anyone trusting GitHub's UI here would conclude the licence is unknown or negligible.
It is full strong copyleft, and it governs the most-forked codebase in this space (166
forks).** A meaningful number of those derivatives are likely non-compliant.

### Lineage

This *is* `lnxg33k/email-header-analyzer`, not a fork of it. Requesting the `lnxg33k`
path follows GitHub's rename redirect and returns the identical object — same 695 stars,
same `created_at` 2016-04-25, `fork: false`. The original author transferred the repo to
the CyberDefenders organisation. There is no separate upstream to licence-check.

### Useful concepts

- **The hop table schema is the de-facto standard** — Hop / From / By / With / Time /
  Delay. Every other tool reproduces it. **Adopted for analyst familiarity.**
- **Reverse-indexing hops so hop 1 = origin.** **Adopted.**
- **Total-delay headline** ("Total Delay is: X") as an immediate stalled-or-not signal.
  **Adopted**, but computed from positive deltas only (see below).
- Bundling GeoLite2 for **offline** country attribution — no API key, no rate limit.
  Better suited to IR work than live geo API calls. *Not adopted; see weakness 1.*
- The README's competitive framing against Google Messageheader ("not showing all the
  hops"), MXToolbox ("not accurate and slow") and Microsoft MHA ("broken UI") is a useful
  list of failure modes to design against.

### Weaknesses — including one significant correctness bug

1. **`delay = (org_time - next_time).seconds` is wrong.** `timedelta.seconds` is the
   *within-day remainder* (0–86399), not total elapsed time. For a negative timedelta
   Python normalises days downward, so a 1-second backwards clock skew becomes
   `days=-1, seconds=86399` and is reported as **86,399 seconds of delay**. The guard
   `if delay < 0: delay = 0` is dead code, because `.seconds` is never negative. A genuine
   25-hour delay reports as 1 hour. The correct call is `.total_seconds()`.
   **This is the single most-copied snippet in this ecosystem** — MailHeaderDetective
   inherited it verbatim. *This project uses `.total_seconds()`, clamps negatives, and
   surfaces them as an explicit clock-skew annotation. Covered by regression test
   `test_negative_delay_reported_as_skew_not_86399`.*
2. **`{{ chart|safe }}`** disables Jinja autoescaping on the hop chart. Hop labels are
   attacker-controlled header text flowing into a raw-rendered SVG — an injection surface
   in a tool whose entire input is hostile by definition.
3. **Bare `except IndexError: pass`** around hop construction. Malformed headers are
   silently dropped and the analyst sees an incomplete chain with no warning. Unacceptable
   in forensics. *This project emits a parse warning per malformed hop and never discards
   one silently.*
4. **Single fragile mega-regex** `from\s+(.*?)\s+by(.*?)...` for `Received` structure. Real
   headers from Exchange, Postfix, Zimbra and O365 vary widely; anything unmatched vanishes.
   In particular **a `Received:` line with no `from` clause is dropped entirely** — a
   common shape for locally-injected mail from encryption gateways and internal submission
   agents, meaning the origin hop disappears. *Covered by regression test
   `test_by_only_received_line_is_not_dropped`.*
5. IPv4-only IP regex — IPv6 hops invisible.
6. Country-level GeoIP only, from a bundled `.mmdb` that goes stale; MaxMind's
   redistribution terms are their own compliance question.
7. Everything in one 7 KB `server.py`. No separation of parser / enrichment / presentation,
   no unit tests.
8. Dormant since April 2023; mixed local/CDN assets that break in air-gapped environments.

---

## 3. `akajhon/MailHeaderDetective`

| | |
|---|---|
| URL | https://github.com/akajhon/MailHeaderDetective |
| Stars / forks | 14 / 9 |
| Last push | 2024-05-05 (dormant) |
| Stack | Python 3.8+, Flask, `httpx`, `geoip2`, `dnspython`, `extract_msg`, `pygal` |
| **Licence** | **GPL-3.0** |
| **Code copied** | **No — prohibited.** |

### ⚠️ Licence trap #2 — README contradicts the LICENSE file

- `LICENSE` contains the **canonical plain-text GNU GPL v3**. GitHub's API and sidebar
  both correctly report `GPL-3.0`.
- **The README states: "Mail Header Detective is licensed under the MIT License."**

The LICENSE file is the actual grant instrument; a passing sentence in a README is not a
licence. Furthermore, the README elsewhere states the project *"was created with the
intention of improving and continuing the development of the `email-header-analyzer`
project"* — i.e. it is a self-declared derivative of GPL-3.0 code (§2). The author
therefore could not validly have relicensed the combined work to MIT even if they had
intended to. **Treat as GPL-3.0. The MIT claim must not be relied upon.**

Code-level confirmation of the derivation: identical `HeaderParser` filtering, the
identical `from\s+(.*?)\s+by(.*?)` regex, the identical `.seconds` delay bug, the identical
Pygal chart, and a `templates/index.html` that is a superset of MHA's.

### Useful concepts

- **Concurrent multi-source enrichment** via `ThreadPoolExecutor` — four IP reputation
  services in the wall-clock time of the slowest rather than the sum. **Adopted**, as
  `asyncio` + `httpx.AsyncClient` with a bounded semaphore.
- **Indicator-type module split** (`ip_checker` / `url_checker` / `email_checker` /
  `hash_verify`), each returning a normalised dict. This is the structural fix MHA needed.
  **Adopted** as the provider-protocol design in `app/integrations/`.
- **Consensus across providers rather than a single oracle.** Four independent verdicts
  are more defensible in a write-up than one VirusTotal score. **Adopted.**
- **Traffic-light cell colouring** for scanning many indicators at once. **Adopted with a
  correction** — colour is always paired with a text label, never used alone.
- **Live DNS SPF/DMARC record lookup** (`dns.resolver.resolve('_dmarc.'+domain, 'TXT')`)
  rather than only echoing `Authentication-Results`. The only reference project to attempt
  independent verification at all. **Adopted and extended substantially** — this project
  evaluates SPF against the connecting IP and verifies DKIM signatures, rather than merely
  confirming a record exists.
- `.msg` support via `extract_msg`. *Not adopted — out of scope for a header-only tool.*

### Weaknesses

1. The MIT-in-README / GPL-in-LICENSE contradiction, compounded by being a GPL derivative.
2. **Inherited MHA's `.seconds` delay bug verbatim** while claiming to improve on MHA.
3. Inherited `{{ chart|safe }}`.
4. **No caching whatsoever** — every submission re-queries all four APIs. Re-analysing the
   same header burns quota fourfold.
5. **No rate limiting, retry or backoff.** VirusTotal's free tier is 4 req/min; a
   twelve-hop header hits 429s and the code has no handling beyond returning `"Error"`.
6. Error handling is `try/except` → `print()` → return `"Error"`. Errors go to stdout, so
   the analyst **cannot distinguish "clean" from "the API key was wrong."** *This project
   models eight distinct provider statuses precisely to avoid this.*
7. Five mandatory API keys in a `.env` **inside the source tree** (`mhd/modules/.env`).
8. Every IP, URL, sender address and attachment hash from a customer's email is shipped to
   five third parties with no disclosure or opt-in.

---

## 4. `useru1k/email-analysis`

| | |
|---|---|
| URL | https://github.com/useru1k/email-analysis |
| Stars / forks | 2 / 3 |
| Last push | 2026-06-09 |
| Stack | FastAPI + Jinja2 + Pydantic, `dnspython`, `tldextract`, `python-whois`, `yara-python` |
| **Licence** | **NONE — all rights reserved** |
| **Code copied** | **No — prohibited.** |

### Licence

`LICENSE`, `LICENSE.md`, `LICENSE.txt` and `COPYING` all return HTTP 404 and are absent
from the recursive tree. GitHub API `license` is `null`. `pyproject.toml` has no `license`
field. The README makes no claim.

Under default copyright, absence of a licence means **no rights are granted** beyond
GitHub's ToS (viewing and forking within GitHub). Referenced for ideas only.

### Useful concepts

- **Explicit online/offline mode split** — degrades to purely local heuristics when no API
  keys or no egress. The best idea in the repository. **Adopted as the core posture.**
- **Local cache of VirusTotal results**, directly fixing MailHeaderDetective's defect.
  **Adopted** as a TTL cache.
- **Transparent score with a per-factor breakdown**, not just a number. **Adopted and
  extended** — every finding carries rule ID, evidence, rationale and a legitimate
  explanation.
- **Sub-score saturation**: `min(25, risky_count × 8)` prevents one newsletter with 30
  tracking links pinning the score at 100. **Adopted as per-category caps.**
- stdlib `ipaddress` validation with IPv6 normalisation and order-preserving dedupe —
  strictly better than MHA/MHD's IPv4-only regex. **Adopted.**
- Cleanest service-per-concern layout of the Python projects reviewed.

### Weaknesses

1. No licence — legally unusable as a code source.
2. **`app/venv/` is committed to the repository.** A full virtualenv in version control:
   bloats clones, leaks absolute local paths, ships platform-specific binaries.
3. Duplicate dependency declarations — `pyproject.toml` *and* `app/requirement.txt`
   (misspelled). Guaranteed to drift.
4. **No hop chain or delay analysis at all.** `Received` headers are mined only for IP
   addresses; timestamps, ordering and the `by`/`from` relationship are discarded. The
   richest forensic artefact in an email, thrown away.
5. **Scoring weights are arbitrary and uncalibrated**, and nothing ever *lowers* a score.
   A legitimate newsletter with a broken DMARC record scores 20–40 with no compensating
   signal. High false-positive rate by construction.
6. **Missing SPF/DKIM/DMARC scored identically to failing** — very different signals;
   conflating them punishes small legitimate senders.
7. `yara-python` declared as a dependency with no rules directory present.

---

## 5. `haseebtariq368/Emaul-Header-Analyzer` — fellow intern

| | |
|---|---|
| URL | https://github.com/haseebtariq368/Emaul-Header-Analyzer |
| Stars | 0 · **1 commit**, squashed, authored `haseeb@example.com` |
| Created / pushed | 2026-07-22 |
| Stack | FastAPI + Pydantic + **synchronous `requests`**; vanilla-JS SPA, no templating |
| Tests | **None** — three ad-hoc `print()` scripts, not collectible, no CI |
| **Licence** | **NONE — all rights reserved** |
| **Code copied** | **No — prohibited.** Behavioural reference only. |

Treated as a behavioural and feature reference only, per assignment guidance. No
permission was sought or granted, and no licence exists.

### Useful concepts

- **Hop-order reversal for UX** so the UI reads origin → delivery chronologically.
- **BEC as a distinct verdict rather than a score band** — recognising that typosquat plus
  *passing* authentication is the dangerous case, the one that beats auth-only filters.
  Conceptually the sharpest idea in the repository. **Adopted, with the wording corrected
  to "Possible BEC / Impersonation"** — header evidence alone cannot confirm BEC.
- **Reputation as a two-way signal** — high sender reputation *subtracts* risk rather than
  risk only ever accumulating. **Adopted as risk-reducing factors.**
- **Quota-conscious enrichment** — per-provider query caps. **Adopted.**
- Its `verify.py` documents real parsing bugs encountered (timestamp fragments matched as
  IPs, Gmail queue IDs treated as public IPs, `header.from` artefacts in extracted
  domains). **Adopted as test cases**, since they are genuine edge cases.

### Weaknesses — recorded because this project deliberately avoids each one

1. **Fabricates threat intelligence.** With no API key every provider returns invented
   data: AbuseIPDB returns `"isp": "Simulated ISP Corp"`; EmailRep synthesises a profile
   from string heuristics (`days_since_domain_creation = 45` if the domain contains
   phishing keywords; `= 5` with `malicious_activity = True` for typosquats of
   paypal/microsoft/google). This is not a stub — it manufactures plausible-looking
   intelligence.
2. **Keyword-theatre sandbox.** Deep-scan verdicts are assigned by substring match
   (`if any(bad in url for bad in ["malicious","phish","bad","virus"])`), returning
   **procedurally generated SVG "screenshots"** captioned `WARNING: Phishing Site
   Detonated`. A fabricated screenshot of a fabricated detonation is actively misleading
   evidence in a SOC context.
3. **Silent fallback to mock on live-API failure** — an outage degrades into fabricated
   results with no hard failure. The analyst cannot distinguish "clean" from "invented."
4. **Country-based risk scoring.** `HIGH_RISK_COUNTRIES = ["Russia","China","North
   Korea","Iran"]`, **+15 points**. Geographic origin is a proxy for nationality, not for
   maliciousness; it penalises legitimate mail and is defeated by any attacker renting a
   US VPS. *Explicitly prohibited in this project and asserted by test
   `test_country_never_contributes_to_score`.*
5. **DKIM is not verified.** `auth_analyzer.py` regex-scrapes `Authentication-Results`.
   No `_domainkey` lookup, no signature check. The README markets "SPF/DKIM/DMARC
   analysis" without the caveat. It also adds +20 for a *missing* `Authentication-Results`,
   meaning the entire authentication pillar rests on trusting a header that any pasted
   sample can simply contain.
6. **`allow_origins=["*"]` with `allow_credentials=True`** — an invalid and dangerous CORS
   combination.
7. **`time.sleep(15)` inside a synchronous route handler.** Routes are `def`, not
   `async def`, so each analysis occupies a threadpool worker for 100+ seconds. Trivially
   exhausted.
8. **XSS**: `innerHTML` used with analysis output, and
   `onclick="window.open('${s.url}', '_blank')"` interpolating attacker-controlled URLs
   extracted from the submitted email.
9. Unbounded in-memory rate-limiter and job dicts with no eviction; the IP-based limiter is
   spoofable behind a proxy.
10. **Source files inside the served static directory** — `static/verify.py`,
    `static/requirements.txt`, `static/.env.example` sit under a `StaticFiles` mount at
    `/`. A real `.env` placed there would be publicly served.

---

## 6. `muhammadahmadabid019-commits/SentinelMail` — fellow intern

| | |
|---|---|
| URL | https://github.com/muhammadahmadabid019-commits/SentinelMail |
| Stars | 0 · 2 commits, authored by two different accounts |
| Created / pushed | 2026-07-21 / 2026-07-22 |
| Stack | Flask 3 app factory, SQLAlchemy + Alembic, Redis, Celery, `httpx`, Jinja2 |
| Tests | pytest — 47 unit + 2 integration modules; repo claims 696 tests at 93% coverage |
| **Licence** | **NONE — all rights reserved** |
| **Code copied** | **No — prohibited.** Behavioural reference only. |

The strongest reference project reviewed, and the bar this work is measured against.

### Useful concepts

- **Framework-free domain core.** `app/core/` has zero Flask imports and is testable
  standalone; everything framework-shaped lives in blueprints and services. The most
  reusable idea in the repository. **Adopted — `app/core/` here imports no FastAPI.**
- **"Correlate, don't override" verdict logic.** Named evidence *combinations* decide the
  verdict *before* score thresholds apply; the numeric score is a fallback, not the
  authority. Notably, trusted-auth + malicious-IOC is deliberately **dampened to
  Suspicious** rather than escalated — a genuinely thoughtful false-positive control.
  **Adopted as the core verdict architecture.**
- **Providers fail loudly and never fabricate.** A missing key means the provider is never
  instantiated; failures surface as `DEGRADED` / `UNAVAILABLE` health records so the
  analyst always knows what was actually queried. Direct contrast with §5.
  **Adopted and extended to eight explicit statuses.**
- **IOC pipeline as discrete stages** — extract → normalize (defang reversal,
  `hxxp://` → `http://`) → validate, with only `VALID` IOCs queried and
  `(normalized_value, type)` deduplication before lookup. **Adopted.**
- **Two-gate provider enablement** — an `*_ENABLED` flag *and* a non-empty key.
  **Adopted.**
- Honest DKIM scoping stated in the code itself: *"No cryptographic signature verification
  is performed here… that work was already done by the receiving MTA."* Correct and
  admirable — **and precisely the limitation this project removes.**
- Real security hygiene: CSRF with a dedicated error handler, `nosniff`, `X-Frame-Options:
  DENY`, CSP restricted to `'self'`, per-request correlation IDs echoed as `X-Request-ID`,
  content-negotiated error handlers. **Adopted.**
- **No CORS at all** — server-rendered and same-origin, so `flask-cors` is not even a
  dependency. Correct, and the right answer for this architecture too. **Adopted.**

### Weaknesses — recorded because this project deliberately avoids each one

1. **Documentation contradicts the code in both directions.** The README claims "Phase 1,
   pipeline ships in Phases 2–5" when the full pipeline exists; `PROJECT_REPORT.md` claims
   no persistence and an unimplemented `risk_engine` when models, a store, a blueprint,
   templates, a migration and a full rule engine all exist. *Anyone auditing this repo from
   its documentation will be wrong.* — `STATUS.md` here is updated at the end of every
   phase for exactly this reason.
2. **No caching**, despite shipping Flask-Caching, Redis, `core/threat_intel/cache.py` and
   `models/ti_result_cache.py`. Every submission re-queries every provider from scratch.
3. **Celery scaffolded but never wired**; threat intel runs synchronously in-request.
4. **Unused infrastructure**: PostgreSQL, Redis, Celery, Alembic migrations, `api_key` and
   `audit_log` models, and a `require_api_key` decorator that protects no routes. *This
   project ships no database, no queue and no cache server — see `docs/ARCHITECTURE.md`.*
5. Rate limiter initialised app-wide but no decorators on the analyzer route.
6. Three provider modules are stubs while the README lists them as integrations.
7. `core/report/pdf_renderer.py` never implemented despite "printable reports" being a
   headline feature.
8. **The `/report/` endpoint requires re-submitting the entire raw email as a URL query
   parameter.** The full message — including any sensitive content — lands in browser
   history, proxy logs and server access logs. A real data-exposure defect. *This project
   forbids raw headers in URLs and asserts it in `test_raw_header_never_in_url`.*
9. `.claude/settings.json` committed — agent tooling configuration left in the repository.

---

## 7. `GOVCERT-LU/eml_parser` — dependency evaluated and rejected

| | |
|---|---|
| URL | https://github.com/GOVCERT-LU/eml_parser · PyPI `eml-parser` 3.0.3 (2026-07-19) |
| **Licence** | **AGPL-3.0-or-later** |
| **Used?** | **No — rejected on licence grounds.** |

Technically the best open implementation of `Received:` decomposition available, maintained
by a national CERT. Rejected because **AGPL-3.0 §13 triggers on conveying the work over a
network**, which is exactly what this FastAPI application does. Importing it would oblige
this project to be offered under AGPL-3.0 to all its users.

Consequence: **the `Received:` parser in this project is written from scratch** against the
RFC 5321 §4.4 grammar, plus documented handling of real-world deviations. Approximately 300
lines, and defensible.

The same reasoning excludes `emalderson/ThePhish`, `TheHive-Project/Cortex-Analyzers` and
`intelowlproject/IntelOwl`, all AGPL-3.0. Their *interface designs* were studied; no code
was taken.

---

## 8. `sublime-security/sublime-rules` — vocabulary reused

| | |
|---|---|
| URL | https://github.com/sublime-security/sublime-rules |
| Stars | ~369 · updated daily |
| **Licence** | **MIT** |
| **Code copied** | **No.** Classification vocabulary referenced only. |

Detections-as-code: YAML rules in MQL, each carrying `name`, `severity`, `tags`, `source`.

### Useful concepts

- **Externalising heuristics into declarative rule files** with stable IDs, severities and
  human descriptions, so the verdict card can list *which rules fired* and why. Analysts
  distrust an opaque score and trust a named rule. **Adopted — see `app/core/rules/*.yaml`.**
- The rule **taxonomy** (BEC, brand impersonation, lookalike domain, vendor fraud,
  credential phish) is a ready-made classification vocabulary and is MIT licensed.
  **Category names referenced; no rule content copied.**

---

## 9. Other prior art reviewed (no code reused from any)

| Tool | Licence | Concept adopted |
|---|---|---|
| [`microsoft/MHA`](https://github.com/microsoft/MHA) | MIT | The four-view information architecture (Summary / Received / Antispam Reports / Other Headers); the "Other Headers" raw escape hatch; "copy analysis to clipboard"; **the `X-Forefront-Antispam-Report` / `X-Microsoft-Antispam` field decoder**, which almost no open-source tool implements |
| [`ninoseki/eml_analyzer`](https://github.com/ninoseki/eml_analyzer) | MIT | Threat intel as optional, key-gated enrichers that degrade gracefully. *SpamAssassin sidecar not adopted — requires the message body, out of scope* |
| PhishTool (hosted) | proprietary | Verdict card with analyst-assignable verdict and notes; side-by-side identity block for eyeballing `From` / `Reply-To` / `Return-Path` mismatch |
| Google Admin Toolbox Messageheader | proprietary | UTC normalisation across hops with the delay location called out explicitly |
| MXToolbox Email Header Analyzer | proprietary | Blacklist status presented alongside authentication results |
| [`domainaware/checkdmarc`](https://github.com/domainaware/checkdmarc) | Apache-2.0 | **Used as a dependency** — validates SPF including the RFC 7208 ten-lookup limit, and DMARC policy/`rua`/`pct`/`sp` |
| [`dkimpy`](https://pypi.org/project/dkimpy/) | BSD-like | **Used as a dependency** — RFC 6376/8301/8463 DKIM and RFC 8617 ARC verification |
| `pyspf` | BSD-ish | **Used as a dependency** — evaluates SPF against the connecting IP rather than trusting the header |
| ~~mailheader.org~~ | — | **Defunct** — now 308-redirects to an unrelated site. Not cited as live prior art |
| `certego/BuffaLogs` | — | Reviewed and found irrelevant — detects impossible-travel *login* anomalies, not email |

---

## Declaration

No source code, template, stylesheet, configuration file, regular expression or test
fixture from any repository listed above appears in this project. Concepts adopted were
reimplemented from their description. This project is licensed MIT (see `LICENSE`) and
carries no third-party copyright obligations.

Third-party *dependencies* are used under their own licences and are listed with those
licences in `requirements.txt` and `docs/ARCHITECTURE.md`. All are permissive
(MIT / BSD / Apache-2.0 / MPL-2.0); no copyleft dependency is present.
