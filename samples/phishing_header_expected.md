# Expected result — `phishing_header.txt`

Synthetic sample. `northw1nd-secure.example` is a deliberate digit-substitution
lookalike of `northwind-bank.example` (the domain used in `legitimate_header.txt`) —
authored specifically to demonstrate `IMP-001` when `northwind-bank.example` is
configured in `PROTECTED_DOMAINS`, or when the sample is analysed with `To:
alice@northwind-bank.example` present (the recipient's own domain is always
in the watchlist automatically).

## Expected parsed fields

| Field | Value |
|---|---|
| From | "Northwind Bank Security" <alerts@northw1nd-secure.example> |
| Return-Path | bounce@mailer-relay.example.net (different organisation than From) |
| Reply-To | support@secure-verify-alerts.example (different organisation than From) |
| Message-ID | @relay-host-9.example.net (unrelated to sending infrastructure) |
| Received hops | 1 — `unknown` HELO claim from `198.51.100.9` |

## Expected authentication interpretation

- SPF: recorded `fail` — `northw1nd-secure.example` does not authorise
  `198.51.100.9`
- DKIM: absent
- DMARC: recorded `fail` — neither SPF nor DKIM passed and aligned
- `mx.example.org` must be configured trusted for these to be marked `TRUSTED`; if it
  is not, `AUTH-004`-style untrusted-pass logic does not apply here since the
  assertion is itself a *fail*, not a forged pass (see
  `docs/ANALYST_DECISION_RULES.md` — untrusted failures never score, only untrusted
  *passes* do; this sample's assertions are failures either way)

## Expected IOC set

`northw1nd-secure.example` (domain, lookalike), `secure-verify-alerts.example`
(domain), `mailer-relay.example.net` (domain), `relay-host-9.example.net` (domain),
`alerts@northw1nd-secure.example` / `support@secure-verify-alerts.example` /
`bounce@mailer-relay.example.net` (emails), `198.51.100.9` (IP — **not**
enrichment-eligible, RFC 5737 documentation range).

## Expected findings (demo mode)

- `IDN-001` — Reply-To points to a different organisation than From (+18)
- `IDN-002` — Return-Path organisation differs from From (+8)
- `IDN-003` — Message-ID domain unrelated to sending infrastructure (+8)
- `REP-001` — poor/suspicious sender reputation (demo fixture, +18)
- `TI-003` — single provider reports the domain malicious (demo fixture, +15)
- `AUTH-009` — no DMARC policy published for the lookalike domain's actual DNS state
  in a live run (weight varies; not present in the offline/demo smoke test since the
  synthetic DNS records provided during testing supply an `spf1 -all` record)
- `IMP-001` — lookalike domain, **only if** `northwind-bank.example` is in the
  watchlist (via `PROTECTED_DOMAINS` or a `To:` header at that domain)
- `RTE-003` / `RTE-004` — route/encryption hygiene observations, low weight

## Expected verdict

**Likely Phishing.** Score: **≥50/100** (observed **75/100** in the reference smoke
test with the full trust/watchlist configuration described in
`tests/integration/test_samples.py`).

## False-positive considerations

If `northwind-bank.example` is not in the watchlist and the recipient's `To:` domain
isn't set to it, `IMP-001` will not fire and the score will be correspondingly lower —
the remaining identity-mismatch and reputation findings are sufficient on their own to
reach `Likely Phishing` in the reference configuration, but a bare-minimum
configuration (no trust boundary, no enrichment) will score lower and may land in
`Suspicious` instead. This is expected: without independent verification or threat
intelligence, the tool has correspondingly less evidence to work with.

## Limitations

Demo-mode threat-intelligence findings (`REP-001`, `TI-003`) reflect hand-authored
fixture data for this specific sample, clearly labelled `Demo Fixture` in the UI and
in exports — they are not live lookups unless `ENRICHMENT_ENABLED=true` with real API
keys is configured, in which case results will differ (and may differ from this
document, since these domains do not exist on the real internet to be looked up).
