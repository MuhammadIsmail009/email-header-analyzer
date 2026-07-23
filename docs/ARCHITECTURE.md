# Architecture

## Why it's this small

There is no database, message queue, or cache server. Analysis is a pure function of
the submitted header (plus small, bounded in-memory caches for reports and threat-intel
lookups). One reference project studied for this build ships PostgreSQL, Redis and
Celery and uses none of them meaningfully in the actual analysis path
(`docs/REFERENCE_REPOSITORIES.md` §6) — that failure mode is avoided here by simply
not adding infrastructure the application doesn't need.

## Layering

```
routes/           FastAPI-aware. Parses HTTP input, calls services, renders templates.
  ↓
services/          Orchestration. Sequences core calls, decides *when* to hit the
                    network (DNS, HTTP), assembles the final report.
  ↓
core/              Framework-free. Pure functions and immutable models. No FastAPI,
                    Starlette or Jinja2 import anywhere in this package — enforced
                    by tests/unit/test_architecture.py::test_core_has_no_web_imports.
```

The boundary between `core` and everything above it is the single most important
structural decision in this codebase: `core` can be tested, understood, and reused
entirely independently of the web layer, which is what let the analysis logic (Phases
2, 4, 6) be built and fully tested before a single HTTP route existed.

## `app/core` — the analysis engine

| Module | Responsibility |
|---|---|
| `models.py` | Every domain type, frozen Pydantic models. No behaviour. |
| `header_parser.py` | RFC 5322 field parsing: folding, duplicates, RFC 2047 decoding. Built directly rather than via `email.parser`, so raw bytes, order and duplicates all survive. |
| `received_parser.py` | `Received:` chain decomposition and route reconstruction — written from scratch (see below). |
| `authentication_parser.py` | `Authentication-Results` / `Received-SPF` / `DKIM-Signature` / ARC parsing, plus authserv-id trust marking. |
| `domain_analyzer.py` | PSL organisational domain, IDNA, homoglyph/lookalike detection. |
| `identity_analyzer.py` | Builds and compares From/Sender/Return-Path/Reply-To/Message-ID. |
| `ioc_extractor.py` | Extract → normalize → validate → defang pipeline. |
| `vendor_headers.py` | Microsoft anti-spam header decoder. |
| `verification/` | Live SPF/DKIM/DMARC/DNSBL/FCrDNS checks — the only part of `core` that performs I/O (DNS), and it does so synchronously and testably via an injected `Resolver`. |
| `risk_engine.py`, `rules_impl.py`, `rules/rules.yaml` | Findings, scoring, verdict selection. |

### Why `Received:` is hand-written

`eml_parser` (GOVCERT-LU) is the best open implementation of `Received:` parsing
available and was seriously considered. It is AGPL-3.0-or-later, and §13 of that
licence triggers on serving the work over a network — exactly what this FastAPI
application does. Using it would have obliged this entire project to be AGPL. The
parser here is a from-scratch implementation (~300 lines) against the RFC 5321 §4.4
grammar plus documented real-world deviations (see `docs/REFERENCE_REPOSITORIES.md` §7
and the module docstring in `received_parser.py`).

### The `Resolver` protocol

`app/core/verification/resolver.py` defines a `Resolver` protocol with two
implementations: `DnsResolver` (real, dnspython-backed) and `StaticResolver`
(in-memory, for tests). Every verification function (`verify_spf`, `verify_dkim`,
`verify_dmarc`, `check_forward_reverse`, `check_dnsbl`) takes a `Resolver` as a
parameter rather than constructing one itself — this is what makes the entire
verification layer testable without a live network connection, and it is why the test
suite requires neither internet access nor API keys.

One subtlety worth recording: `pyspf` dispatches DNS through a *module-level* global
(`spf.DNSLookup`), not through an object it was constructed with. `verify_spf`
temporarily swaps that global for an adapter over the injected resolver, under a lock
(analyses run concurrently in a thread pool, so two swapping the same global
unsynchronised would let one analysis's SPF evaluation resolve through another's
resolver). Without this, `pyspf` silently reaches the real internet for anything not
pre-seeded into its own internal cache — discovered during development when a test
run emitted an unexpected `DeprecationWarning` from `dns.resolver.query`, which turned
out to mean live DNS was actually happening. See `spf_verifier.py` for the full
account.

## `app/services` — orchestration

`analysis_service.py` is the seam: it calls every `core` parser, decides whether live
verification runs (`anyio.to_thread.run_sync`, since `pyspf`/`dkimpy`/`dnspython` are
all blocking libraries — this is the correctness detail one reference project got
wrong with a `time.sleep(15)` inside a synchronous route handler), decides which IOCs
get enriched, and assembles the final `RiskContext` handed to `risk_engine.assess()`.

`enrichment_service.py` owns bounded concurrency (`anyio.Semaphore`), TTL caching
(`cachetools`), per-type lookup limits, and demo-mode fixture lookup — the providers
themselves (`app/integrations/`) know nothing about any of that; they just perform one
lookup and report one of eight `ProviderStatus` values.

`report_service.py` holds the bounded in-memory report cache and the JSON/Markdown
exporters.

## `app/routes` — the web layer

`web.py` (server-rendered HTML, CSRF-protected form) and `api.py` (typed JSON) are
thin: they validate size/shape, call a service, and render or return. No analysis
logic lives here.

## Why server-rendered Jinja2, not a JS framework

Two reasons, both load-bearing rather than stylistic:

1. **Autoescaping is the primary XSS defence** for input that is, by definition,
   entirely attacker-controlled (every value in a submitted header). A framework with
   a build step adds a second templating surface to keep safe; Jinja2's autoescaping
   handles it in one place, verified by tests that submit real `<script>` and
   `onerror` payloads and assert they render as inert text.
2. **No build step** means `docker compose up` is genuinely all that's required, and
   the tool works in an air-gapped SOC environment with no CDN dependency — several
   reference projects break entirely without internet access to fetch Bootstrap,
   FontAwesome, or similar from a CDN.

## Security posture summary

Full detail in `docs/THREAT_MODEL.md`. In brief: no CORS (same-origin only), CSP with
no external hosts and no `unsafe-inline` scripts, double-submit-cookie CSRF (no
server session exists to key a synchronizer token on), request-size limiting enforced
by actually reading the body (not trusting `Content-Length` alone), and raw header
content never placed in a URL or query string anywhere in the application.
