# Email Authentication — SPF, DKIM, DMARC, ARC

How the three authentication mechanisms actually work, and precisely what this tool
does and does not verify about each of them.

## SPF — Sender Policy Framework (RFC 7208)

**What it checks:** whether the IP address that connected to the receiving mail
server is authorised to send mail for the domain in the *envelope sender*
(`MAIL FROM`, sometimes called the "bounce address" or `Return-Path:`) — **not** the
visible `From:` header.

**Record syntax.** A domain publishes SPF as a DNS TXT record:

```
v=spf1 ip4:203.0.113.15 include:_spf.example-provider.com -all
```

- `v=spf1` — version marker, mandatory first token.
- Mechanisms (`ip4:`, `ip6:`, `a`, `mx`, `include:`, `exists:`) each describe a set of
  authorised senders.
- Qualifiers prefix a mechanism and set the result if it matches: `+` (pass, the
  default if omitted), `-` (fail / hard fail), `~` (softfail), `?` (neutral).
- The catch-all `all` at the end sets the result for everything not otherwise matched.
  `-all` is a hard fail policy (reject anything not explicitly listed); `~all` is a
  soft fail (accept but mark); `?all` takes no position.

**Evaluation, roughly:** the receiver walks the mechanisms left to right against the
connecting IP; the first match decides the result. `include:` recursion has a hard
limit of **10 DNS lookups** (RFC 7208 §4.6.4) — a record that exceeds it evaluates to
`permerror`, and this is a real, frequently-encountered misconfiguration.

**Limitations:** SPF authenticates the envelope sender, which the recipient never
sees. An attacker can pass SPF cleanly by using their own, correctly-configured
domain as the envelope sender while the visible `From:` claims to be someone else —
this is why DMARC alignment (below) matters, not SPF alone.

**What this tool does:** with `VERIFICATION_ENABLED=true`, retrieves the sender
domain's SPF record via DNS and evaluates it against the actual connecting IP using
`pyspf` — a complete RFC 7208 implementation including the ten-lookup limit. This is
labelled "independently verified" in the UI. With verification off, only the
*recorded* `Received-SPF:`/`Authentication-Results` value is shown, labelled as such.

## DKIM — DomainKeys Identified Mail (RFC 6376)

**What it checks:** that a specific set of header fields (and optionally the body)
have not been altered since a designated domain signed them, using RSA or Ed25519.

**The `DKIM-Signature:` header, tag by tag:**

| Tag | Meaning |
|---|---|
| `v=` | Version (always `1`) |
| `a=` | Signing algorithm, e.g. `rsa-sha256` |
| `c=` | Canonicalization for header/body, `simple` or `relaxed` |
| `d=` | The **signing domain** — compare this to `From:` for alignment, not identity |
| `s=` | Selector — the public key is published at `<selector>._domainkey.<d>` |
| `h=` | Colon-separated list of headers covered by the signature |
| `bh=` | Base64 body hash |
| `b=` | Base64 signature value, computed over the `h=` headers plus this header itself |

**Verification, in principle:** fetch the TXT record at `<s>._domainkey.<d>`, extract
the public key (`p=` tag), and verify `b=` against a canonicalised reconstruction of
the signed headers. If `bh=` is present, the body is hashed the same way and compared.

**What this tool does — staged honestly by available evidence:**

| Input | What is verified |
|---|---|
| Headers only (pasted text) | The `b=` signature is verified over the signed headers, after retrieving the real public key from DNS. This proves the signed headers are authentic and unmodified. **The body hash is not checked**, because there is no body. |
| Full `.eml` upload | Both the header signature and the body hash (`bh=`) are verified — complete DKIM validation. |
| No `DKIM-Signature:` present | Reported as absent, never as a failure — DMARC only needs SPF *or* DKIM to pass. |

This distinction matters: most tools either claim full DKIM verification from headers
alone (overclaiming — they cannot have checked the body) or refuse to attempt any
cryptographic check at all (underclaiming — the header signature alone is still real
evidence). This tool states precisely which was done.

**A signature failing does not always mean tampering.** Mailing lists and forwarders
that add a subject prefix or footer break the signature legitimately. Check for an
ARC chain (below) before concluding compromise.

## DMARC — Domain-based Message Authentication, Reporting and Conformance (RFC 7489)

**What it checks:** whether SPF *or* DKIM passed **and aligns** with the visible
`From:` domain. Alignment, not mere passing, is the entire point of DMARC — it is
the mechanism that closes the gap SPF and DKIM leave open on their own (an attacker
using their own authenticated domain in the envelope/signature while `From:` claims
someone else's).

**Record syntax**, published at `_dmarc.<domain>`:

```
v=DMARC1; p=quarantine; pct=90; adkim=r; aspf=r; rua=mailto:reports@example.com
```

- `p=` — policy for messages that fail: `none` (monitor only), `quarantine`, `reject`.
- `pct=` — percentage of failing mail the policy applies to (rollout control).
- `adkim=` / `aspf=` — alignment mode: `r` (relaxed — organisational domain match is
  enough) or `s` (strict — exact domain match required).
- `sp=` — policy for subdomains, if different from the main policy.

**Alignment, concretely:** relaxed mode means `mail.example.com` aligns with
`example.com` (same organisational domain); strict mode requires an exact match.

**Fallback lookup:** if a subdomain publishes no DMARC record of its own, RFC 7489
§6.6.3 requires checking its organisational domain's record instead. Skipping this
step makes every subdomain of a protected domain look unprotected.

**What this tool does:** retrieves the record via DNS (with the organisational-domain
fallback), and computes alignment itself against the actual `From:` domain and the
actual SPF/DKIM results obtained above — never reading a `dmarc=pass` string and
trusting it at face value.

## ARC — Authenticated Received Chain (RFC 8617)

**What it does:** allows an intermediary (a mailing list, a forwarding service) to
seal the authentication state *as it saw it* before modifying the message, so a later
receiver can see what SPF/DKIM/DMARC looked like at that point — even though its own
evaluation of the (now-modified) message would fail.

**What this tool does:** detects and summarises the ARC chain (`ARC-Seal:` instances,
the most recent `cv=` — chain validation — value) and explains what it means, but
does **not** independently validate the ARC seals themselves. Presence of a plausible
ARC chain is context that a legitimate forward likely explains an otherwise-failing
SPF/DKIM/DMARC result, not proof of it.

## How the three work together

```
SPF pass?  ─┐
             ├─→ aligned with From:? ─→ DMARC pass
DKIM pass? ─┘
```

One aligned pass is sufficient for DMARC. A message can fail SPF entirely (common
after forwarding) and still pass DMARC cleanly via an aligned DKIM signature, or vice
versa — this is normal and not itself suspicious.

## What none of this proves

Authentication proves the message came from infrastructure authorised by the domain
it claims to be from (or, for DKIM, that specific content wasn't altered in transit).
It says nothing about:

- Whether the sending account was compromised
- Whether the domain itself is trustworthy (a freshly registered lookalike domain can
  publish perfectly correct SPF/DKIM/DMARC for itself)
- Whether the *content* of the message is malicious

This is why the risk engine (see [`ANALYST_DECISION_RULES.md`](ANALYST_DECISION_RULES.md))
treats a clean, verified pass as risk-reducing, not as a "safe" verdict.
