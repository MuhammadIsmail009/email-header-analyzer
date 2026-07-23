# Threat Model

## Assets

1. **Submitted header/`.eml` content** — may contain real recipient addresses,
   internal hostnames, routing detail, and occasionally sensitive business content in
   subject lines.
2. **Extracted indicators** (IPs, domains, URLs, emails) — sent to third parties only
   when enrichment is explicitly enabled.
3. **Third-party API keys** (AbuseIPDB, EmailRep, VirusTotal) — must never leak to a
   client or into logs.
4. **Generated reports** — held briefly in an in-memory cache, retrievable by an
   opaque ID.

## Sensitive information in email headers

**Risk:** headers routinely contain internal hostnames, employee names/addresses,
mail-gateway software versions, and organisational structure (via `Received:` chains
and `X-` headers). This is genuine intelligence about a target organisation.

**Mitigations:**
- Raw header content is never placed in a URL or query string (only opaque report IDs
  are, and only for previously-generated reports) — see `test_raw_header_never_appears_in_a_url_path_or_query_param`.
- Raw headers are not logged (`LOG_RAW_HEADERS` defaults to and should remain `false`).
- Reports live in a bounded, short-TTL in-memory cache, not a database — nothing
  persists past a restart or the TTL.

**Residual risk:** anyone who can reach a deployed instance can submit headers to it.
There is no built-in authentication (see `docs/LIMITATIONS.md`) — deploy behind
appropriate network controls for anything beyond a trusted single-team internal tool.

## Third-party indicator disclosure

**Risk:** submitting an extracted indicator (especially a URL) to a public reputation
service can itself be a disclosure — phishing URLs are frequently unique per
recipient, and a lookup can signal to the attacker that their campaign was detected.

**Mitigations:**
- `ENRICHMENT_ENABLED=false` by default; nothing leaves the process unless explicitly
  turned on.
- A persistent UI banner states when enrichment is active.
- Only enrichment-*eligible* indicators (public IPs; all domains/URLs/emails) are ever
  submitted — private, loopback, link-local, reserved, and documentation-range
  addresses never are, regardless of the enrichment setting.
- Per-analysis lookup caps (`MAX_IP_LOOKUPS` etc.) bound exposure even when enabled.

## API-key leakage

**Risk:** a misconfigured error path, log statement, or API response could leak a
configured provider key.

**Mitigations:**
- `/api/v1/config-status` reports only *whether* a provider is configured
  (`provider_enabled(...)` returns a bool), never the key value — asserted by
  `test_config_status_never_leaks_key_values`.
- Provider HTTP errors are summarised (`f"HTTP {status_code}"`) rather than echoing
  raw response bodies that could contain reflected request data.
- The unhandled-exception handler in `main.py` never returns exception text or a
  stack trace to the client; full detail goes to the server log only, keyed by
  request ID.

## Cross-site scripting (XSS)

**Risk:** by definition, every value this tool renders — sender names, subject lines,
raw header field values — is attacker-controlled. Two reference projects studied for
this build (`docs/REFERENCE_REPOSITORIES.md` §2, §3) have real XSS surfaces from
exactly this input class (`{{ chart|safe }}` disabling autoescaping on hop labels;
`innerHTML` and an `onclick` handler built from attacker-controlled URLs).

**Mitigations:**
- Jinja2 autoescaping is on by default and never disabled anywhere in this project —
  confirmed by grep audit and by `test_xss_payload_in_subject_is_rendered_inert` and
  `test_xss_payload_in_display_name_is_rendered_inert`, which assert a `<script>` tag
  and an `onerror`-bearing `<img>` tag both render as inert escaped text.
- CSP (`Content-Security-Policy: default-src 'self'; script-src 'self'; ...`) with no
  `unsafe-inline` for scripts, so even a successful injection cannot execute inline
  JavaScript.
- No dynamic `innerHTML` writes anywhere in `static/js/`; DOM updates use
  `textContent`.

## Server-side request forgery (SSRF)

**Risk:** an analyzer that fetches attacker-supplied URLs, or resolves attacker-
influenced hostnames against internal infrastructure, is a classic SSRF vector.

**Mitigations:**
- Extracted URLs are **never fetched** — no code path in this project performs an
  outbound request to a URL extracted from a header. Enrichment providers query the
  provider's own API about the indicator; they do not visit the indicator itself.
- DNS resolution (for SPF/DKIM/DMARC/PTR/DNSBL) targets domains derived from the
  message, resolved against configured public resolvers (`DNS_RESOLVERS`) — not
  against arbitrary attacker-supplied URLs, and the resolver itself has no code path
  that fetches HTTP content.

## Parser denial of service

**Risk:** a maliciously crafted header (deeply nested comments, pathological regex
input, an enormous single field) could hang or crash the parser.

**Mitigations:**
- `MAX_HEADER_BYTES` (256 KiB) and `MAX_REQUEST_BYTES` (1 MiB) are enforced by
  `MaxBodySizeMiddleware` before any parsing occurs, checking both `Content-Length`
  and the actual body size (a forged or missing header cannot bypass it).
- Parsing regexes in `received_parser.py` and `authentication_parser.py` use
  depth-tracked character scanning rather than nested-quantifier regex patterns,
  specifically to avoid catastrophic backtracking.
- `test_very_long_single_header_does_not_hang` exercises a 100,000-character field.

## Excessive API consumption

**Risk:** a large header with many indicators could exhaust third-party API quota in
one submission.

**Mitigations:**
- Per-type lookup caps (`MAX_IP_LOOKUPS`, `MAX_DOMAIN_LOOKUPS`, `MAX_URL_LOOKUPS`,
  `MAX_EMAIL_LOOKUPS`) bound how many indicators of each type are submitted per
  analysis, regardless of how many were extracted.
- A TTL cache (`app/services/enrichment_service.py`) prevents re-querying the same
  indicator across analyses within the cache window.
- Rate limiting (`slowapi`, `RATE_LIMIT_ANALYZE`) bounds how often `/analyze` can be
  called per client.

## Log leakage

**Risk:** verbose logging could capture header content, keys, or PII.

**Mitigations:**
- `LOG_RAW_HEADERS` defaults to `false` and is documented as something that should
  stay that way outside a controlled debugging session.
- The only routine log line per request carries a request ID, not payload content.
- Unhandled exceptions are logged server-side with full detail (necessary for
  debugging) but never returned to the client.

## False positives and false negatives

**Risk:** any automated tool will sometimes be wrong in both directions.

**Mitigations (see also `docs/ANALYST_DECISION_RULES.md`):**
- Every finding carries a mandatory "legitimate explanation" — the tool actively
  argues against its own suspicion, not just for it.
- Per-category score caps prevent one noisy category from dominating a verdict.
- Trusted-and-verified authentication combined with a single adverse intelligence hit
  is deliberately dampened to `Suspicious` rather than escalated — the most common
  false-positive shape (shared infrastructure) is explicitly modelled, not ignored.
- No verdict claims certainty ("Likely," never "Confirmed" or "Safe").

## Untrusted `Authentication-Results` and manipulated `Received:` headers

Both are treated as attacker-forgeable by design, not as an incident. See
[`docs/EMAIL_AUTHENTICATION.md`](EMAIL_AUTHENTICATION.md) and
[`docs/ANALYST_DECISION_RULES.md`](ANALYST_DECISION_RULES.md) — trust marking against
configured infrastructure, and independent DNS-based re-verification, exist
specifically to not have to trust these values at face value.

## Malicious threat-intelligence responses

**Risk:** a compromised or malicious provider endpoint could return a crafted
response intended to exploit the client parsing it.

**Mitigations:**
- Every provider response is parsed defensively (`response.json()` inside a
  `try/except (KeyError, ValueError)`, never `eval`, never dynamic code execution).
- Provider `fields` dicts are typed as plain data and rendered through Jinja2's
  autoescaping — never interpreted as markup or executed.
- A malformed response degrades to `ProviderStatus.PROVIDER_ERROR`, never a crash.

## Out of scope for this threat model

Denial-of-service at the network/infrastructure layer (load balancing, DDoS
protection), physical security, and supply-chain compromise of a pinned dependency
(mitigated only by pinning exact versions in `requirements.txt` and using
permissively-licensed, actively-maintained packages — see `docs/REFERENCE_REPOSITORIES.md`).
