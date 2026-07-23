# Expected result — `possible_bec_header.txt`

Synthetic sample. Deliberately clean infrastructure — genuinely authenticated,
genuinely aligned — with the *only* signal being a Reply-To that diverges to a
different, newly-registered-looking domain. This is the shape the risk engine's
`BEC-001` rule exists to catch: authentication alone cannot distinguish this from a
completely legitimate vendor email, and header evidence alone cannot confirm it either
way — hence "Possible," never "Confirmed."

## Expected parsed fields

| Field | Value |
|---|---|
| From | Partner Vendor Finance Team <invoices@partner-vendor.example> |
| Return-Path | invoices@partner-vendor.example (exact match to From) |
| Reply-To | accounts@partner-vendor-payments.example (different organisation than From) |
| Message-ID | @mail.partner-vendor.example (same infrastructure as sender) |
| Received hops | 1 — TLS 1.3 delivery hop from `203.0.113.44` |

Note: this sample intentionally carries **no `DKIM-Signature:` header** — an earlier
draft included a fabricated one, which was removed because an unsigned fake signature
correctly fails cryptographic verification but reads as "tampered" rather than "never
signed," which would misrepresent what the tool actually detected. Real messages of
this shape often carry no DKIM signature at all, matching the manually-analysed case
this tool's design was informed by.

## Expected authentication interpretation

- SPF: recorded `pass`; independently verified `pass` against `203.0.113.44`
- DKIM: absent (see above)
- DMARC: recorded `pass`; independently verified `pass` via SPF, aligned exactly with
  `partner-vendor.example`; policy `p=reject`
- Requires `TRUSTED_RECEIVER_DOMAINS=example.org` for `TRUSTED` marking

## Expected IOC set

`partner-vendor.example` (domain), `partner-vendor-payments.example` (domain, the
Reply-To divergence), `mail.partner-vendor.example` (domain, from Received),
`invoices@partner-vendor.example` / `accounts@partner-vendor-payments.example`
(emails), `203.0.113.44` (IP — not enrichment-eligible, RFC 5737 documentation range).

## Expected findings (demo mode)

- `BEC-001` — authentication passes but sender identity is internally inconsistent
  (+28) — the decisive finding
- `IDN-001` — Reply-To points to a different organisation than From (+18)
- `REP-001` — Reply-To address reputation is poor/unestablished (demo fixture, +18)
- `AUTH-010` — all three controls independently verified passing and aligned
  (risk-reducing, −18)
- `REP-002` — From address has an established positive reputation (demo fixture,
  risk-reducing, −10)

## Expected verdict

**Possible BEC / Impersonation.** Score: **36/100** in the reference smoke test — note
the *pattern match* (`BEC-001` firing) decides this verdict directly, not the numeric
score; a lower score than the phishing sample is expected and correct, because this
sample's authentication is genuinely clean. The verdict label never reads "BEC
Confirmed" (asserted by `tests/unit/test_risk_engine.py::test_bec_verdict_is_never_labelled_confirmed`).

## False-positive considerations

This exact pattern — clean, aligned authentication plus a Reply-To divergence — is
also produced by entirely legitimate configurations: a vendor using a separate
accounts-payable domain, an outsourced billing provider, or a ticketing system that
redirects replies. The mandatory `legitimate_explanation` on `IDN-001` and `BEC-001`
states this directly. The recommended action is to verify out-of-band (a known phone
number, not one supplied in the message) — this sample is a prompt to check, not proof
of compromise.

## Limitations

Reply-To divergence is a real and common social-engineering technique, but this
sample's DNS records (`partner-vendor.example` publishing a clean SPF/DMARC posture)
are entirely consistent with either a genuine vendor or a genuinely compromised vendor
account — headers cannot distinguish the two.
