# STATUS

Updated at the end of every phase. If this file and the code disagree, the code is right
and this file is a bug — two of the reference projects reviewed shipped documentation that
contradicted their own source, and anyone auditing them from their docs would have been
wrong. See `docs/REFERENCE_REPOSITORIES.md` §6, weakness 1.

**Last updated:** 2026-07-23 — analysis core complete (132 tests green). Handoff to Sonnet 5 high, see bottom.

---

## Phase status

| Phase | State | Notes |
|---|---|---|
| 0 — Inspect, audit, plan | ✅ Complete | Licence audit of 8 projects; plan and deviations recorded |
| 1 — Core scaffold | 🟡 Partial | Models, settings, deps verified. Still to do: `main.py`, routes, templates, Docker |
| 2 — Parsers | ✅ Complete | Header, Received and authentication parsers + trust marking |
| 3 — IOC, domain, identity | 🟡 Partial | `domain_analyzer` + `addresses` done. Still to do: `ioc_extractor`, `identity_analyzer`, `vendor_headers` |
| 4 — Live verification | ✅ Complete | SPF/DKIM/DMARC/DNSBL/FCrDNS, fully offline-testable |
| 5 — Threat-intel providers | ⬜ Not started | |
| 6 — Risk engine and verdict | ✅ Complete | 28 YAML rules, correlate-don't-override verdict |
| 7 — Interface | ⬜ Not started | |
| 8 — Security and quality | ⬜ Not started | |
| 9 — Deliverables | ⬜ Not started | |
| 10 — Final audit | ⬜ Not started | |

---

## Phase 0 — completed 2026-07-23

**Done**

- Inspected the working directory. Pre-existing LaTeX case report and study guide found.
  **Decision:** they stay outside this repository. They contain a real customer header,
  real employee email addresses and a TLP:AMBER marking; this repository is intended to be
  published. The app lives in `email-header-analyzer/` as a separate git repository.
- Audited 8 projects for licence and reusable concepts. Two licence traps found and
  recorded (GitHub misreports MHA as "Other" when it is GPL-3.0; MailHeaderDetective's
  README claims MIT while its LICENSE file is GPL-3.0). Four of eight grant no rights at all.
- **Reuse decision: clean-room throughout. No third-party code in this project.**
- Rejected `eml_parser` as a dependency — AGPL-3.0 §13 would oblige this network-served
  application to be AGPL. Consequence: the `Received:` parser is written from scratch.
- Recorded 10 deliberate deviations from the original build brief, with justification —
  `PROJECT_PLAN.md` §2.
- Wrote the correctness-commitment table (`PROJECT_PLAN.md` §5): 15 named tests, each
  corresponding to a defect actually observed in a reference project.

**Decisions**

| ID | Decision | Rationale |
|---|---|---|
| ADR-01 | Separate repository from the LaTeX deliverables | Real customer data must not be published |
| ADR-02 | Clean-room; no third-party code | 4 of 8 references grant no rights; 2 are GPL-3.0 |
| ADR-03 | Implement live DNS/crypto verification | The differentiator; all references are parse-only |
| ADR-04 | No database, no queue, no cache server | Nothing to persist; avoids the dead-infrastructure failure mode |
| ADR-05 | Offline by default, enrichment opt-in | Analysts are often forbidden from submitting customer indicators |
| ADR-06 | Server-rendered Jinja2, no React | Autoescaping is the primary XSS defence on hostile input; no build step |
| ADR-07 | Rules externalised to YAML with stable IDs | Verdict card can name what fired; reviewable without reading Python |
| ADR-08 | `tldextract` with network fetch disabled + bundled PSL | No unannounced outbound requests from a security tool |

**Open questions**

- None blocking.

**Known gaps**

- Everything after Phase 0.

---

## Phase 1 (partial) — 2026-07-23

**Done**

- Dependency risk verified *before* committing to `requirements.txt`. `dkimpy`, `pyspf`,
  `dnspython`, `tldextract` and `publicsuffixlist` all install and import cleanly on
  Windows/Python 3.12. `pyspf` performs a real RFC 7208 evaluation (confirmed against
  `example.com`, which publishes `v=spf1 -all` — correctly returned `fail`).
- Confirmed `tldextract` works fully offline with `suffix_list_urls=()` and the bundled
  snapshot (ADR-08), and that it resolves the trailing-root-dot FQDN case
  (`mail.example.com.` → `example.com`) correctly.
- `app/core/models.py` — frozen Pydantic models, all enumerations. Notable absences are
  deliberate: no `SAFE` verdict, no `BEC_CONFIRMED`.
- `app/config.py` — every limit and flag in one reviewable place. `enrichment_enabled`
  defaults to `False`.
- `app/core/netutils.py` — IP classification and extraction, validated via `ipaddress`
  rather than trusted from a regex.

**Note:** `pyspf` is synchronous and performs blocking DNS. It must be called via
`anyio.to_thread.run_sync` from the async request path — recorded here so Phase 4 does
not reintroduce the blocking-call defect found in a reference project.

## Phase 2 (partial) — 2026-07-23

**Done**

- `app/core/header_parser.py` — field boundaries parsed directly rather than via
  `email.parser`, so raw bytes, original order and duplicates all survive. RFC 2047
  decoding delegated to stdlib.
- `app/core/received_parser.py` — written from scratch (ADR: `eml_parser` rejected as
  AGPL). Depth-aware clause scanning instead of a single regex.
- **40 unit tests, all passing.** `pytest tests/unit -q` → `40 passed in 0.31s`.

**Correctness commitments now proven by test** (`PROJECT_PLAN.md` §5): items 1–10, plus
IPv6 hop extraction and HELO-claim vs observed-rDNS separation.

**Bug found by our own test suite, then fixed:** `email.header.decode_header` raises
`HeaderParseError`, which is *not* a `ValueError` subclass, so a malformed base64
encoded-word escaped the exception handler and propagated. Now caught explicitly and
degraded to a warning. This is exactly the class of defect the regression suite exists
to catch, and it was caught on the first run.

**Still to do in Phase 2**

- `authentication_parser.py` — `Authentication-Results` (RFC 8601), `Received-SPF`,
  `DKIM-Signature`, ARC headers, plus authserv-id trust marking.

---

## Phases 2, 4 and 6 — complete, 2026-07-23

`pytest tests/unit -q -W error::DeprecationWarning` → **132 passed**. The suite runs
with no network access and no API keys.

### Built

- `authentication_parser.py` — RFC 8601 grammar, depth- and quote-aware. Every result
  carries a `TrustStatus`; with no trusted infrastructure configured the answer is
  `UNKNOWN`, never `TRUSTED`.
- `domain_analyzer.py` — PSL organisational domain, IDNA, homoglyph skeletons,
  lookalike detection. The protected-domain list is a *watchlist*, never a suppression
  list.
- `verification/` — independent SPF (pyspf), DKIM (dkimpy), DMARC policy + alignment,
  FCrDNS and DNSBL. All synchronous; **must** be called via `anyio.to_thread.run_sync`.
- `rules/rules.yaml` (28 rules) + `rules_impl.py` + `risk_engine.py`.

### Three real bugs found by the test suite, all fixed

1. **`decode_header` raises `HeaderParseError`**, which is not a `ValueError` subclass,
   so a malformed base64 encoded-word crashed the parse instead of degrading.
2. **`.example` is not in the Public Suffix List.** `tldextract` returned no suffix, so
   `mail.bank.example` and `bank.example` compared as *unrelated organisations*. Fixed
   with a documented last-two-labels fallback in `_split_registrable`. This is not a
   test-only problem: the bundled PSL snapshot is a point-in-time copy with network
   refresh disabled (ADR-08), so any newly-delegated gTLD hits the same path.
3. **pyspf escaped to the real internet.** It dispatches DNS through a *module-level*
   `DNSLookup` and treats an empty cache entry as a miss, so seeding its cache did not
   contain it — the suite was silently doing live DNS, and in production every
   `include:`/`a:`/`redirect=` bypassed the configured resolvers and timeouts. Fixed by
   swapping the global under a lock for the duration of the call. Proven by
   `test_spf_include_chain_resolves_through_injected_resolver_only` and by the suite
   passing under `-W error::DeprecationWarning`.

### One design bug found and fixed in the verdict logic

With no authentication evidence and no verification, the score fell to 12/100 and the
verdict came back **Likely Legitimate**. Absence of evidence was reading as evidence of
legitimacy — the most damaging error this tool could make, because it actively
reassures an analyst about a message nobody checked. Fixed with `ABSENCE_MARKERS` and
an explicit `nothing-established` guard. Locked in by
`test_absence_of_evidence_never_reads_as_legitimate`.

---

## HANDOFF — switch to Sonnet 5 (high) from here

The analysis core is done and is the part where being wrong is expensive. Everything
below is execution against a written spec.

**Ground rules that must not be broken (all asserted by tests — run them):**

- `app/core/` imports no FastAPI, Starlette or Jinja2.
- Never call a verification or provider function directly from an `async def` route.
  They block. Use `anyio.to_thread.run_sync`.
- Never fabricate a provider result. Unkeyed/disabled/failed → the matching
  `ProviderStatus`, never an invented verdict.
- Never put a raw header in a URL or query parameter.
- No country, region or language may influence the score.

**Remaining work, in order:**

1. **Finish Phase 3** — `ioc_extractor.py` (extract → normalize → validate → defang,
   public-IP-only enrichment eligibility), `identity_analyzer.py` (build `Identity`
   objects for From/Sender/Return-Path/Reply-To/Message-ID using `app/core/addresses.py`),
   `vendor_headers.py` (Microsoft `X-Forefront-Antispam-Report` / `X-Microsoft-Antispam`
   decoder — SCL, BCL, CAT, SFV, CIP, PTR).
2. **Phase 5** — provider protocol + AbuseIPDB, EmailRep, VirusTotal. `httpx.AsyncClient`,
   bounded semaphore, TTL cache via `cachetools`, all eight `ProviderStatus` values
   reachable. Mock with `respx`.
3. **Phase 1 remainder** — `main.py`, `dependencies.py`, `routes/web.py`, `routes/api.py`,
   security-header middleware, request-size limit, `slowapi` rate limiting, Docker.
4. **Phase 7** — templates + GSAP dashboard per `PROJECT_PLAN.md` §7.
5. **Phases 8–9** — Ruff, coverage, samples + expected-result companions, README, docs,
   CI, demo script.

**Assemble `RiskContext` in `services/analysis_service.py`** — it is the seam between
the parsers, the verification layer and the risk engine. Its fields are documented in
`rules_impl.py`.

**Before starting, read:** `PROJECT_PLAN.md` §2 (the 10 deviations from the original
brief, with reasons) and §5 (the correctness commitments table).

---

## Phase 3 — complete, 2026-07-23 (Sonnet 5 high)

`pytest tests/unit -q -W error::DeprecationWarning` → **168 passed**.

### Built

- `ioc_extractor.py` — extract → normalize → validate → defang pipeline. Only public
  IPs are enrichment-eligible; private/loopback/documentation/etc. are still extracted
  (needed for route analysis) but never marked eligible.
- `identity_analyzer.py` — builds `Identity` objects for From/Sender/Return-Path/
  Reply-To/Message-ID and compares each against From (never against each other — that
  is not a standard analyst check).
- `vendor_headers.py` — decodes `X-Forefront-Antispam-Report` / `X-Microsoft-Antispam`
  (SCL, BCL, CAT, SFV, CIP, PTR). CTRY is parsed but explicitly never turned into a
  decoded risk field — asserted by `test_forefront_report_never_uses_country_as_a_signal`.

### One real bug found and fixed

`defang()`'s URL-scheme regex mangled `https://` into `httpxx//` — it sliced the match
by character-count rather than by scheme structure, eating the `://` separator. An
analyst-facing defanged URL that mangles the separator is actively confusing. Fixed
with a scheme-aware substitution (`h` + `tt` + `ps?://` → `h` + `xx` + `ps?://`), and
locked in by `test_defang_preserves_scheme_separator`.

**Next: Phase 5 (threat-intel providers), then Phase 1 remainder (main.py/routes/Docker),
then Phase 7 (UI), then Phases 8–9.**

---

## Phase 5 — complete, 2026-07-23 (Sonnet 5 high)

`pytest tests/unit -q -W error::DeprecationWarning` → **193 passed**, ~10.5s (async
provider tests carry per-test event-loop overhead; confirmed via a socket-level guard
that no real network connection occurs — respx intercepts entirely at the transport
layer).

### Built

- `app/integrations/base.py` — provider protocol + typed result helpers for every
  `ProviderStatus` (disabled/unavailable/timeout/invalid_key/rate_limited/
  provider_error/unknown).
- `abuseipdb.py`, `emailrep.py`, `virustotal.py` — each catches its own failures,
  never raises, never fabricates. Country is captured in `fields` for display only.
- `app/services/enrichment_service.py` — bounded concurrency (`anyio.Semaphore`),
  TTL cache (`cachetools`) keyed on `(provider, type, ioc)`, per-type lookup caps,
  offline-mode short-circuit (no provider constructed when disabled), demo-mode
  fixture lookup with `DISABLED` fallback for unrecognised indicators.
- `app/demo_fixtures/fixtures.py` — hand-authored fixtures for the sample indicators
  only, keyed by exact normalized value. Documented explicitly: sample IPs are RFC 5737
  documentation range and therefore never enrichment-eligible even in demo mode — this
  is correct behaviour, not a gap, and real IP enrichment is proven in
  `test_verification.py`/`test_ioc_extractor.py` against genuinely public test IPs.

### Two test bugs found and fixed (not product bugs)

Both `test_per_type_limit_is_enforced` and `test_concurrent_lookups_across_providers`
initially failed because VirusTotal also supports IP lookups and was left enabled,
so it silently added extra calls/results the test didn't expect. Not a service defect —
the service was correctly invoking every provider that supports the IOC type. Fixed by
disabling VT explicitly in tests that are isolating another provider's behaviour.

**Next: Phase 1 remainder (analysis_service, main.py, routes, Docker), then Phase 7 (UI).**

---

## Phase 1 (service layer) — complete, 2026-07-23 (Sonnet 5 high)

`pytest tests/ -q -W error::DeprecationWarning` → **201 passed**, ~11s, fully offline.

### Built

- `app/services/analysis_service.py` — the seam. Parses, builds the route, builds
  authentication evidence, runs live verification via `anyio.to_thread.run_sync`
  (never blocks the event loop), extracts IOCs, builds identities, decodes vendor
  headers, checks lookalikes against a watchlist, enriches, assembles `RiskContext`,
  calls `risk_engine.assess()`.
- `config.py` gained `protected_domains` — a lookalike watchlist. The message's own
  `To:` domain is always included automatically, since the most obvious brand to
  protect is whoever the tool is being run for. Never a suppression list.
- Resolver is dependency-injected (`AnalysisService(settings, enrichment, resolver=...)`)
  so tests run against `StaticResolver` with zero network, same pattern as the core
  verification tests.

### Two real bugs found by the integration tests, both fixed

1. **SPF was evaluated against the wrong hop's IP — the most consequential bug found
   so far.** `connecting_ip` was taken from the *origin* hop (oldest, chronologically
   first). But the origin hop of a locally-injected message — a PGP gateway or
   submission agent, exactly the shape in the real Ebryx case this project is modelled
   on — legitimately has no `from` clause and therefore no IP at all. That silently
   passed `connecting_ip=None` into SPF evaluation, which cascaded into a DMARC
   failure for a message that was, in reality, correctly SPF-authorised and aligned.
   **This would have made the tool fail exactly the header it exists to analyse
   correctly.** Fixed: SPF is now evaluated against the IP recorded by the *first
   trusted receiver* (`route.first_trusted_hop_index`), which is what a genuine
   `Received-SPF: client-ip=` actually reflects, with a fallback to the first hop that
   recorded any IP at all. Locked in by
   `test_spf_uses_trusted_receiver_ip_not_origin_hop_ip`.
2. **Lookalike detection missed short brand names.** `lookalike_of("bank-secur1ty.example",
   ("bank.example",))` returned `None` because the edit-distance and substring checks
   both required the protected label to be ≥5 characters, and "bank" is 4. Since
   `protected_domains` is an operator-populated watchlist (their own org, a bank, a
   partner), a threshold that silently makes short real brand names unprotectable
   defeats the feature's purpose. Lowered to ≥4, documented as a deliberate
   false-positive/false-negative trade-off (a match is only ever a MODERATE finding
   with a legitimate-explanation attached, never an automatic verdict).

**Next: `main.py`, `dependencies.py`, `routes/web.py`, `routes/api.py`, security
middleware, rate limiting, Docker — then Phase 7 (UI).**

---

## Samples + one more real bug — 2026-07-23

Wrote all four synthetic samples now (`samples/*.txt`) rather than deferring to Phase 9,
since the demo fixtures needed exact matching indicators. All RFC 2606 domains / RFC 5737
IPs, no real data.

- `legitimate_header.txt` — northwind-bank.example, structurally mirrors the real
  Ebryx case (PGP-gateway origin hop with no `from` clause, SPF `-all`, DMARC
  `p=quarantine`, no DKIM).
- `phishing_header.txt` — northw1nd-secure.example (digit-substitution lookalike of
  northwind-bank.example), trusted DMARC failure, Reply-To/Return-Path/Message-ID all
  diverge from From.
- `possible_bec_header.txt` — partner-vendor.example, SPF+DMARC independently verified
  passing and aligned, Reply-To diverges to partner-vendor-payments.example. No DKIM
  signature (matches the real case's shape — a hygiene gap, not tampering).
- `malformed_header.txt` — exercises warning paths: no-colon line, duplicate From,
  orphaned continuation, invalid IP octets, malformed base64 encoded-word.

Smoke-tested all four end to end (fully offline, `StaticResolver`): scores 0 / 75 / 36 /
26, verdicts `likely_legitimate` / `likely_phishing` / `possible_bec` / `suspicious` —
exactly as intended.

### Another real bug found by the smoke test, fixed

`check_forward_reverse` returned `forward_confirmed=False` both when the check was
**skipped** (non-public IP — the dataclass default) and when it **ran and genuinely
failed to confirm**. Since every synthetic sample uses RFC 5737 documentation IPs, this
made *every* sample report "no forward-confirmed reverse DNS" (RTE-003) as a finding,
even on the clean legitimate sample — a false positive baked into every demo run.
Fixed by adding an explicit `checked: bool` field to `ForwardReverseResult`; the risk
engine now only flags a genuine unconfirmed check, never a skip. Locked in by
`test_forward_reverse_skip_is_distinct_from_unconfirmed`.

**202 tests passing.** Also dropped a fabricated DKIM signature from the BEC sample —
unsigned fake base64 correctly fails cryptographic verification, but reads as "tampered"
rather than "never signed", which would have misrepresented what the tool actually
detected. Real messages this shape often carry no DKIM signature at all.

**Next: `main.py`, routes, Docker.**

---

## Phase 1 (routes, security, Docker) — complete, 2026-07-23 (Sonnet 5 high)

`pytest tests/ -q -W error::DeprecationWarning` → **231 passed**, ~13-30s depending on
async overhead.

### Built

- `app/main.py` — app factory, security-header middleware, request-ID middleware,
  request-size-limit middleware, safe error handlers (HTML for browsers, JSON for API
  clients, no stack trace ever reaches the client, full detail logged server-side
  keyed by request ID). Deliberately **no CORS middleware** — same-origin, server
  rendered, and the brief prohibits wildcard CORS anyway.
- `app/security.py` — `MaxBodySizeMiddleware` (1 MiB, checked both via `Content-Length`
  and by actually reading the body — a forged or absent header can't bypass it), CSP
  with no external hosts, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`,
  double-submit-cookie CSRF (no server session exists to key a synchronizer token on).
- `app/rate_limit.py` — a standalone module for the `slowapi` `Limiter` instance,
  specifically to avoid a circular import between `main.py` and the route modules.
- `app/routes/web.py`, `app/routes/api.py`, `app/routes/schemas.py`,
  `app/dependencies.py` — every route from the brief: `/`, `/analyze`,
  `/samples/{name}` (allowlisted, not path-joined — no traversal surface),
  `/api/v1/analyze`, `/api/v1/config-status` (never leaks key values, only whether
  they're set), `/health`, `/reports/{id}.json`, `/reports/{id}.md`.
- `app/services/report_service.py` — bounded in-memory `TTLCache` for reports (no
  database), JSON/Markdown export, IOCs defanged in both.
- Full template set (`base.html`, `index.html`, `results.html`, `error.html`) + CSS/JS
  static assets. Dark SOC-console styling now; GSAP motion is Phase 7.
- `Dockerfile` + `docker-compose.yml` — no database/queue/cache service, matching
  ADR-04. **Built and actually run** (not just written): `docker build`, `docker run`,
  then real `curl` requests against the running container, including a full
  `POST /api/v1/analyze` round trip. Healthcheck went `healthy`.

### Four real bugs found — three from actually running the app, one from Docker

1. **`AnalysisReport` never stored the raw `VerificationResult` list.**
   `analysis_service.analyze()` computed SPF/DKIM/DMARC verification results, used
   them to derive alignment, and then discarded them — the UI's "independently
   verified" detail (which record, which DNS evidence, what scope) had nothing to
   render. Added `AnalysisReport.verifications`, wired through the service, exports
   and template. Locked in by `test_verification_results_are_attached_to_the_report`.
2. **`TemplateResponse` signature changed in the Starlette version this project
   actually resolves to** (`fastapi==0.139.2`, verified via `pip freeze`, not the
   `0.115.6` originally guessed from memory). Newer Starlette requires
   `TemplateResponse(request, name, context)` — the old `TemplateResponse(name,
   context)` call form silently misparses `name` as the request and `context` as the
   template name, producing `TypeError: unhashable type: 'dict'` on every single
   page. **requirements.txt now pins exactly what was built and tested**, captured via
   `pip freeze`, rather than versions recalled from memory — a requirements file that
   doesn't match the tested application is a correctness problem, not a formality.
3. **`index.html` silently dropped every validation error.** Routes passed a
   `form_error` context variable (empty header, oversized header, disallowed upload
   extension) but the template never rendered it — a rejected submission just
   re-showed a blank form with no explanation. Caught by
   `test_empty_header_is_rejected_with_clear_error` /
   `test_oversized_header_is_rejected`, both of which check the rendered page for the
   actual error text, not just the status code.
4. **`tldextract` logged a permission-denied warning on every container start.**
   Even with `suffix_list_urls=()` (no network fetch — confirmed, the logged URL list
   was empty), it still tried to *write* a cache file to `$HOME/.cache`, which doesn't
   exist for the container's non-root user. Harmless (caught, falls back to the
   bundled snapshot regardless) but a security tool logging a spurious permission
   error on every boot trains an operator to ignore real ones. Fixed with
   `cache_dir=None`. **Only found by actually running the built image and reading its
   logs** — would not have been caught by any unit test.

### Verified manually via `TestClient` and real Docker, then captured as permanent tests

CSRF (missing/mismatched/valid token), empty/oversized input, disallowed upload
extension, `.eml` upload with header/body split, all security headers, no wildcard
CORS, XSS payloads in `Subject` and in a display name crafted to look like a foreign
address (`"><img src=x onerror=alert(1)>` — confirmed fully HTML-entity-escaped, not a
live DOM element), path traversal on `/samples/{name}`, 404s with no leaked stack
trace, HTML-vs-JSON content negotiation on errors, full JSON API round trip
(analyze → `/reports/{id}.json` → `/reports/{id}.md`), unknown report ID → 404,
oversized `raw_header` in the JSON API → 413.

**Next: Phase 7 (GSAP motion on the existing templates), then Phase 8 (Ruff, coverage
measurement, dependency review) and Phase 9 (docs, expected-result companions, CI,
demo script).**

---

## Phase 8 (quality gate) — complete, 2026-07-23 (Sonnet 5 high)

`ruff check .` → **All checks passed.**
`pytest tests/ --cov=app --cov-report=term-missing -q -W error::DeprecationWarning`
→ **246 passed, 90.48% overall coverage** (target ≥80%, cleared) — `app/core`
individually is ~89% (target ≥85%, cleared).

### Ruff

`pyproject.toml` enables `E, F, W, I, B, UP, SIM`. Two rules are suppressed with
recorded reasons rather than silently ignored:
- `B008` — `Depends(...)` as an argument default is the documented FastAPI DI idiom
  throughout this codebase, not the mutable-default-argument bug the rule targets.
- `UP042` — `class Foo(str, Enum)` kept over `StrEnum` deliberately; 15+ enums in
  `app/core/models.py` are a stable public contract not worth touching for a style
  preference.

Everything else was fixed for real: 5 unused imports removed, `datetime.now(timezone.utc)`
→ `datetime.now(UTC)` (8 sites), import sorting, two `zip()` calls given an explicit
`strict=False` (both are the deliberate sliding-pairs pattern —
`zip(hops, hops[1:])` — where the two sequences differ in length by exactly one on
purpose), one `try/except/pass` replaced with `contextlib.suppress`.

### Coverage — one real gap found and closed

`DnsResolver` (the live dnspython-backed adapter, as opposed to `StaticResolver` used
everywhere else in the suite) sat at **47%** on the first measurement. Every
verification function is tested against the `Resolver` *protocol*, so the logic that
depends on DNS is well covered — but nothing had ever exercised `DnsResolver`'s own
TXT-chunk concatenation, NXDOMAIN/NoAnswer/timeout handling, or PTR/DNSBL name
construction. Added `tests/unit/test_dns_resolver.py`, mocking
`dns.resolver.Resolver.resolve` directly (the same technique `respx` provides for
`httpx`, applied by hand since dnspython has no built-in test double) — still fully
offline. Raised `resolver.py` to 96%.

**One test-construction bug caught immediately by running the new tests**: a mocked
"multi-chunk TXT record" test actually built three *separate* records instead of one
record with three `.strings` chunks, so it was testing the wrong thing entirely
(dnspython splits one long TXT value into chunks *within* a record, not across
records). Fixed, and a companion test
(`test_txt_multiple_records_are_kept_separate`) now asserts the two cases don't get
conflated in either direction.

**Next: Phase 7 (GSAP motion on the existing templates) and Phase 9 (docs, expected-
result companions for each sample, demo script, CI). Both are independent of app
logic — no further correctness risk expected from here, this is presentation and
documentation work.**

---

## Phase 9 (deliverables) — complete, 2026-07-23 (Sonnet 5 high)

All documentation deliverables written:

- `README.md` — full project overview, install/run/Docker/test instructions, API
  table, sample walkthrough table, risk-scoring explanation, privacy section
- `LICENSE` (MIT)
- `docs/MANUAL_EMAIL_ANALYSIS.md`, `docs/EMAIL_AUTHENTICATION.md`,
  `docs/ANALYST_DECISION_RULES.md`, `docs/LIMITATIONS.md`, `docs/THREAT_MODEL.md`,
  `docs/ARCHITECTURE.md`, `docs/MANUAL_TEST_CHECKLIST.md`, `docs/DEMO_VIDEO_SCRIPT.md`
- `samples/*_expected.md` × 4 — companion documents for each sample, cross-checked
  against actual tool output (not written speculatively)
- `AGENTS.md` — hard constraints, dependency-licence process, the two subtlest bugs
  found during the build (pyspf's global DNS dispatch, the origin-hop-has-no-IP
  case), test conventions
- `.github/workflows/ci.yml` — lint, test with coverage, Docker build, and a live
  container smoke test (build → run → curl `/health` and `/api/v1/analyze` → check
  logs for warnings → stop) on every push/PR

### One real gap caught while writing the docs, not by any test

`docs/ARCHITECTURE.md` and `docs/THREAT_MODEL.md` were both drafted referencing
`tests/unit/test_architecture.py::test_core_has_no_web_imports` as an existing,
enforced guarantee — a claim made informally in `PROJECT_PLAN.md` §5 and `STATUS.md`
since Phase 0, and repeated in the deviation table, but **never actually written as a
test**. This is precisely the documentation-contradicts-code failure mode called out
in the SentinelMail audit (`docs/REFERENCE_REPOSITORIES.md` §6, weakness 1) — a claim
that sounds authoritative because it's been repeated, without anyone having checked it
was ever made true. Written now: `tests/unit/test_architecture.py` walks every module
under `app/core/` via `ast` and asserts none imports `fastapi`, `starlette`, `jinja2`
or `uvicorn` (plus a companion check that only `verification/` imports the DNS/crypto
I/O libraries). Both pass — the claim was accidentally true, but it wasn't provably
true until now.

**249 tests passing, 90.48% coverage, Ruff clean, Docker rebuilt and re-verified after
all changes.**

**Remaining: Phase 7 GSAP motion polish (functional but unstyled with animation —
current UI is static dark-console CSS only), Phase 10 final adversarial audit.**
