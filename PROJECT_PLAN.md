# PROJECT PLAN — Email Header Analyzer with Threat Intelligence

**Owner:** M. Ismail — SOC Internee, Ebryx
**Reviewer:** Syed Jawad
**Started:** 2026-07-23
**Licence:** MIT

---

## 1. What this is

A web tool that takes a raw email header, reconstructs what happened to the message, and
produces an explainable verdict a SOC analyst can defend in a ticket.

It automates a manual workflow the author performed by hand first (documented separately in
the Ebryx case report and study guide, which are **not** part of this repository). The tool
is deliberately small enough to be understood end to end and explained under questioning.

**Design goal, stated plainly:** every claim the tool makes on screen must be one the
analyst can justify from the evidence shown next to it. No opaque scores, no fabricated
intelligence, no verdict without its reasons.

---

## 2. Deviations from the original build brief

The brief (authored in ChatGPT/Codex) was used as the requirements baseline. It is a good
spec. The following changes were made after auditing the six reference repositories and the
wider prior art, and each is justified here rather than silently applied.

| # | Brief said | This project does | Why |
|---|---|---|---|
| D1 | Parse recorded auth results; say "Recorded SPF result: pass"; do not claim independent verification | **Independently verifies** SPF, DKIM and DMARC against live DNS, and displays asserted vs verified side by side | The brief permits this explicitly *"unless live DNS verification is implemented"*. It is implemented. All six reference projects are parse-only, so this is the primary differentiator — and it mirrors the manual method (SPF TXT retrieval, `_dmarc` policy lookup, forward/reverse DNS, DNSBL) the author already performs by hand |
| D2 | Stack list: stdlib `email`, `dnspython`, `tldextract` | **Adds** `dkimpy` (BSD), `pyspf` (BSD), `checkdmarc` (Apache-2.0), `publicsuffixlist` (MPL-2.0) | Required by D1. Reimplementing SPF `include:` recursion with correct void-lookup and permerror semantics, or DKIM canonicalisation, is a multi-week trap with a high chance of being subtly wrong |
| D3 | `tldextract` for organisational-domain comparison | `tldextract` **with `suffix_list_urls=()` and a bundled PSL snapshot** | By default `tldextract` fetches the Public Suffix List over HTTP on first use and caches to `$HOME`. A security tool making an unannounced outbound request at analysis time is unacceptable in a SOC and would be a finding against us |
| D4 | `DEMO_MODE=true` default | **`ENRICHMENT_ENABLED=false` (offline) by default**, with demo fixtures separate | Offline-by-default is both safer and a genuine differentiator. Analysts handling real phishing reports are often *forbidden* from submitting customer indicators to third parties, and per-recipient tracking URLs submitted to a scanner can tip off the attacker that a campaign was detected |
| D5 | Risk rules as a Python configuration module | Rules declared in **YAML** with stable IDs, loaded and validated at startup | Lets the verdict card list *which rules fired* by ID, makes rules reviewable by a non-Python-reading analyst, and makes the scoring table auditable. Concept from `sublime-security/sublime-rules` (MIT) |
| D6 | — (not mentioned) | **Adds a Microsoft anti-spam header decoder** (`X-Forefront-Antispam-Report`, `X-Microsoft-Antispam`: SCL, BCL, CAT, SFV, CIP, CTRY, PTR, H) | Microsoft documents these publicly; it is a lookup table plus ~100 lines. Essentially no open-source tool decodes them, and any real corporate phishing sample has them |
| D7 | Bootstrap 5 or lightweight custom CSS | **Custom CSS + GSAP/ScrollTrigger**, no CSS framework, no CDN | Everything served locally so the tool works air-gapped and needs no CSP exceptions. Two reference projects break entirely without CDN access |
| D8 | `GET /reports/{id}.json` if held in memory | Implemented, with a **bounded TTL cache and opaque random IDs** | Kept, but hardened. SentinelMail's report endpoint re-submits the entire raw email as a URL query parameter, putting message content into browser history and proxy logs. Raw headers never appear in a URL here |
| D9 | Optional VirusTotal | Implemented, cached-lookups only | Cheap once the provider protocol exists. No submission, no detonation, no file upload |
| D10 | — | **SpamAssassin sidecar explicitly rejected** | Requires the message body; this is a header-only tool. Recorded in `docs/LIMITATIONS.md` rather than left as an implied gap |

Everything else in the brief is followed as written. In particular the prohibitions are
followed exactly: no fabricated intelligence, no country-based scoring, no "BEC Confirmed",
no wildcard CORS, no database, no queue, no active URL fetching.

---

## 3. Architecture

```
app/
  main.py              FastAPI app, middleware, security headers, error handlers
  config.py            pydantic-settings; all env vars, all limits
  dependencies.py      DI wiring — services constructed once, injected into routes
  routes/
    web.py             Jinja2-rendered form + results
    api.py             typed JSON API
  core/                *** NO FastAPI IMPORTS — pure, testable, framework-free ***
    models.py          frozen Pydantic models
    header_parser.py   stdlib email + policy.default; folding, duplicates, encoded words
    received_parser.py Received: grammar (RFC 5321 §4.4) + real-world deviations
    authentication_parser.py   Authentication-Results (RFC 8601), Received-SPF, DKIM-Signature, ARC
    verification/      *** the differentiator ***
      spf_verifier.py    live SPF TXT retrieval + evaluation against connecting IP
      dkim_verifier.py   _domainkey retrieval + signature verification
      dmarc_verifier.py  policy retrieval + alignment computed here, not read from a header
      dns_checks.py      forward/reverse consistency, DNSBL
    identity_analyzer.py   From / Sender / Return-Path / Reply-To / Message-ID comparison
    domain_analyzer.py     PSL org-domain, IDNA, lookalike, mixed-script
    vendor_headers.py      Microsoft anti-spam decoder (D6)
    ioc_extractor.py       extract → normalize → validate → defang
    risk_engine.py         YAML rules → findings → score
    verdict.py             correlate-don't-override verdict selection
    recommendations.py     analyst next steps
    rules/*.yaml           rule definitions with stable IDs
  integrations/        provider protocol + abuseipdb / emailrep / virustotal
  services/            analysis / enrichment / report orchestration
  templates/  static/
```

**The `app/core` boundary is enforced by a test**, not by convention: `test_core_has_no_web_imports`
walks every module under `app/core/` and asserts none imports `fastapi`, `starlette` or `jinja2`.

### Why there is no database

There is nothing to persist. Analysis is a pure function of the submitted header plus
cached intel lookups. Reports live in a bounded in-memory TTL cache. Adding PostgreSQL,
Redis or Celery would add operational surface with no user-visible benefit — the failure
mode observed in one reference project, which ships all three and uses none of them.

---

## 4. The three-layer authentication model (D1)

This is the core intellectual content of the tool, so it is specified precisely.

For each of SPF, DKIM and DMARC the tool reports three separate things and shows where they
disagree:

| Layer | Question | Source | Trustworthy? |
|---|---|---|---|
| **Asserted** | What did the receiving MTA say? | `Authentication-Results`, `Received-SPF` | **Only if the `authserv-id` matches configured trusted infrastructure.** RFC 8601 §7.1 warns these are forgeable — an attacker can paste `Authentication-Results: yourcompany.com; spf=pass` into their own message |
| **Verified** | Is that claim actually true? | Live DNS, evaluated by us | Yes — this is our own result |
| **Aligned** | Does it match the *visible* `From:` domain? | Computed by us via PSL | Yes. This is the check that catches ESP-relayed spoofing, where SPF legitimately passes on `sendgrid.net` while `From:` says `yourbank.com` |

**DKIM verification is staged honestly by available evidence:**

| Input | What is verified | Wording used on screen |
|---|---|---|
| Headers only | Public key retrieved from `s._domainkey.<d>`; RSA/Ed25519 signature verified over the signed header set | "Signature valid over signed headers. Body integrity not checked — headers-only input." |
| Full `.eml` | Signature **and** body hash (`bh=`), via `dkimpy` | "DKIM cryptographically verified, body hash included." |
| Key not retrievable | Nothing | "Public key not retrievable — verification not possible." **Never rendered as a pass or a fail.** |

**Offline mode disables all of the above** and the tool reverts to the honest parse-only
wording — "Recorded SPF result: pass (asserted by mx.google.com, not independently
verified)". The mode is shown in a persistent banner and recorded in every export.

---

## 5. Correctness commitments

Each is a defect observed in a reference project, and each is asserted by a named test.

| Commitment | Test |
|---|---|
| Hop delay uses `.total_seconds()`, never `timedelta.seconds` | `test_negative_delay_reported_as_skew_not_86399` |
| Negative delays are surfaced as clock skew, never silently clamped or hidden | `test_clock_skew_annotated_not_swallowed` |
| Cumulative transit counts positive deltas only | `test_total_transit_ignores_negative_hops` |
| A `Received:` line with no `from` clause is still parsed as a hop | `test_by_only_received_line_is_not_dropped` |
| Malformed hops produce a warning, never a silent drop | `test_malformed_hop_emits_warning` |
| Field lookup is case-insensitive (`Message-Id` vs `Message-ID`) | `test_message_id_lowercase_d_is_found` |
| Trailing root dot on an FQDN does not defeat domain comparison | `test_trailing_dot_fqdn_matches` |
| Nested parentheses inside `Authentication-Results` parse correctly | `test_nested_parens_in_auth_results` |
| Non-standard timezone parenthetical `+0300 (+03)` parses | `test_nonstandard_tz_parenthetical` |
| Duplicate singleton headers (two `From:`) are a finding, not silently first-wins | `test_duplicate_from_is_a_finding` |
| Country never contributes to the score | `test_country_never_contributes_to_score` |
| Unavailable / unknown / disabled intel never becomes a clean finding | `test_unavailable_intel_is_informational_only` |
| Raw header never appears in a URL or query string | `test_raw_header_never_in_url` |
| Raw header never appears in logs at default level | `test_raw_header_not_logged` |
| `app/core/` imports no web framework | `test_core_has_no_web_imports` |

The first nine come from real header shapes that break naive parsers. They are derived from
structural patterns, not from any customer data.

---

## 6. Verdict model

Verdict is chosen by **named evidence correlation first, numeric threshold only as
fallback** — concept adopted from SentinelMail, whose stated principle is "correlate, don't
override".

```
if trusted_auth_failure and (malicious_intel or lookalike_domain):   Likely Phishing
if auth_passes and impersonation_signals and reply_path_diverges:    Possible BEC / Impersonation
if trusted_auth_pass and malicious_intel:                            Suspicious   (dampened, not escalated)
if trusted_auth_pass and clean_intel and no_identity_anomaly:        Likely Legitimate
if insufficient_evidence:                                            Inconclusive
otherwise:                                                           score thresholds
```

Trusted-auth + malicious-intel being *dampened* rather than escalated is deliberate: it is
the shared-infrastructure false-positive case, and treating it as phishing is how these
tools generate noise.

Verdicts are always phrased against available evidence — "Likely Legitimate based on
available header evidence", never "safe". "Possible BEC / Impersonation", never "BEC
Confirmed": header evidence cannot establish business context, and BEC routinely originates
from genuinely compromised accounts that pass every authentication check.

---

## 7. Interface

Server-rendered Jinja2, custom CSS, vanilla JS, GSAP + ScrollTrigger. Dark SOC-console
aesthetic. No CSS framework, no CDN, no build step.

Information architecture adapted from `microsoft/MHA`'s four-view split, with a verdict card
above and an IOC table below:

1. **Verdict card** — verdict chip, score, confidence, and the named rules that fired, each
   expandable to evidence / why it matters / possible legitimate explanation / recommended action
2. **Identity block** — `From` / `Sender` / `Return-Path` / `Reply-To` / `Message-ID` with
   mismatches visually linked and annotated
3. **Authentication matrix** — SPF/DKIM/DMARC/ARC × asserted | verified | aligned | asserted-by
4. **Hop timeline** — oldest first (reversal labelled), UTC-normalised with original offset
   on hover, proportional delay bars, drawn trust boundary
5. **Filter reports** — decoded Microsoft anti-spam headers where present
6. **IOC table** — defanged by default, refang toggle, async per-source intel badges
7. **Raw headers** — every field including ones we did not model
8. **Export** — JSON and Markdown, both recording whether intel was live, fixture,
   unavailable or disabled

Accessibility: severity is always carried by a text label and shape as well as colour.
All motion respects `prefers-reduced-motion`.

---

## 8. Phases

| Phase | Content | Gate | Model |
|---|---|---|---|
| **0** | Repo inspection, reference audit, this plan, `STATUS.md`, `AGENTS.md` | Licence audit complete | Opus |
| **1** | FastAPI scaffold, config, health, base template, input form, Docker | App runs, `/health` green | Opus |
| **2** | Header parser, Received parser, authentication parser + tests | §5 commitments 1–10 pass | Opus |
| **3** | IOC extraction, domain/PSL analysis, identity analysis, vendor headers + tests | Extraction and alignment tests pass | Sonnet high |
| **4** | Live verification layer — SPF, DKIM, DMARC, DNS, DNSBL + tests (DNS fully mocked) | Asserted-vs-verified disagreement is detected and displayed | Opus |
| **5** | Provider protocol, AbuseIPDB, EmailRep, VirusTotal, async + cache + demo fixtures | No fabrication; all 8 statuses reachable in tests | Sonnet high |
| **6** | YAML rules, risk engine, verdict, recommendations + boundary tests | Verdict matrix tests pass | Opus |
| **7** | Full UI, GSAP motion, exports | XSS payload in Subject renders inert | Sonnet high |
| **8** | Security headers, rate limiting, request limits, log review, Ruff, coverage | Coverage targets met or shortfall explained | Sonnet high |
| **9** | Docs, samples + expected-result companions, demo script, CI, Docker | All deliverables present | Sonnet med |
| **10** | Adversarial final audit | Honest self-review complete | Opus |

Targets: ≥85% coverage on `app/core`, ≥80% overall. Tests never require network or API keys.

---

## 9. Samples

Synthetic only. RFC 2606 reserved domains, RFC 5737 documentation IP ranges, fictional
names. No real header, from any source, enters this repository.

- `legitimate_header.txt` — passes cleanly; structurally realistic (encryption-gateway
  origin hop with no `from` clause, SPF `-all`, DMARC `p=quarantine` relaxed alignment, no
  DKIM signature, TLS on the delivery hop)
- `phishing_header.txt` — trusted DMARC failure, lookalike domain, hostile IOCs
- `possible_bec_header.txt` — authentication passes, infrastructure clean, identity
  inconsistencies and a divergent reply path
- `malformed_header.txt` — exercises warning paths without crashing
- `realistic_legitimate.txt` — a redacted real-world capture: byte-level structure retained,
  all identifying values replaced with documentation equivalents

`samples/private/` is gitignored, for analysts to drop genuine headers locally.

---

## 10. Out of scope — stated, not implied

Message body, attachments, URL fetching or detonation, `.msg`, IMAP ingestion, SpamAssassin,
machine learning, geolocation as a risk signal, case-management integration,
authentication/multi-tenancy, persistence.

Documented with reasoning in `docs/LIMITATIONS.md`.
