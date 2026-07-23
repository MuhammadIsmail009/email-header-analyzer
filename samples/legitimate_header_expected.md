# Expected result — `legitimate_header.txt`

Synthetic sample. Structurally mirrors a real-world shape (encryption-gateway origin
hop, TLS delivery hop, hard-fail SPF, quarantine DMARC) without containing any real
data — every domain is RFC 2606 reserved (`northwind-bank.example`), every IP is RFC
5737 documentation range (`203.0.113.0/24`).

## To reproduce

Requires `TRUSTED_RECEIVER_DOMAINS=example.org` and, for full independent
verification, DNS records for `northwind-bank.example` matching what the sample
implies (`v=spf1 ip4:203.0.113.15 -all`; `_dmarc.northwind-bank.example` →
`v=DMARC1; p=quarantine; pct=90; adkim=r; aspf=r`). Without those DNS records
reachable, verification will report `error`/`not_possible` rather than `pass` — this
is correct behaviour (see `docs/EMAIL_AUTHENTICATION.md`), not a bug; the automated
test (`tests/integration/test_samples.py`) supplies these records via a
`StaticResolver` so it runs fully offline.

## Expected parsed fields

| Field | Value |
|---|---|
| From | Northwind Bank Billing <billing@northwind-bank.example> |
| Return-Path | billing@northwind-bank.example (exact match to From) |
| Reply-To | absent |
| Message-ID | @keys1.northwind-bank.example (same infrastructure as sender) |
| Received hops | 2 — origin (no `from` clause, PGP-gateway style) → TLS delivery hop |

## Expected authentication interpretation

- SPF: recorded `pass`; independently verified `pass` against `203.0.113.15`
  (authorised by `-all` hard-fail record)
- DKIM: absent — a hygiene gap, not a failure (DMARC only needs one of SPF/DKIM)
- DMARC: recorded `pass`; independently verified `pass` via SPF, aligned exactly with
  `northwind-bank.example`; policy `p=quarantine, pct=90`
- All three authentication assertions come from `mx.example.org`, which must be
  configured as trusted (`TRUSTED_RECEIVER_DOMAINS`) for `TRUSTED` marking

## Expected IOC set

`northwind-bank.example` (domain), `mx.example.org` (domain, from Received),
`billing@northwind-bank.example` (email), `203.0.113.15` (IP — **not** enrichment
eligible, RFC 5737 documentation range).

## Expected findings

- `AUTH-010` — all three controls passed and aligned, verified independently
  (risk-reducing, −18)
- `REP-002` — established positive sender reputation (demo mode only, risk-reducing,
  −10)
- `TI-004` — informational, zero-weight (some indicators not enrichment-eligible /
  not checked)

No positive-weight findings fire.

## Expected verdict

**Likely Legitimate based on available header evidence.** Score: **0/100**.
Confidence: low in offline/no-verification mode, rising to medium/high with
verification enabled and multiple corroborating categories.

## False-positive considerations

None expected for this sample as authored. If `TRUSTED_RECEIVER_DOMAINS` is left
unset, authentication trust drops to `unknown` and the `AUTH-010` risk-reducing
finding will not fire (score stays 0 regardless, since there is nothing else to
score) — configure the trust boundary to see the full "clean and verified" story.

## Limitations

A verified-clean result here means the header is internally consistent and
authenticated correctly — it does not mean the sender's mailbox has not been
compromised, and it says nothing about message body content, which is out of scope
for this tool (see `docs/LIMITATIONS.md`).
