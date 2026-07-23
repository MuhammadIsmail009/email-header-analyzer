# Manual Email Header Analysis

How to investigate a raw email header by hand — the process this tool automates. Read
this before trusting the tool's output; understanding the manual method is what lets
you catch a case the automation gets wrong.

## Evidence collection

**Get the original raw header, not a forward.** When a message is forwarded, most mail
clients rewrite or drop headers — `Received:` chains get truncated, `Authentication-Results`
disappears or is replaced with the forwarder's own, and the original `From:` can be
buried inside the forwarded body as plain text instead of a real header. Ask the
reporting user for "view source" / "show original" output, or pull the message
server-side (mailbox export, EDR/mail-gateway log) rather than relying on what arrives
in an internal forward.

**Preserve evidence before you touch it.** Copy the raw header to a working file before
running any tool against it, pasting it into a browser, or "cleaning it up." A header
is a forensic artifact; treat it like one until you've concluded it isn't.

## Identity fields — what each one actually means

| Field | What it is | Who controls it |
|---|---|---|
| `From:` | The display sender the recipient sees | The message author (or forger) — arbitrary text |
| `Sender:` | Who actually submitted the message, if different from `From:` | The submitting agent (e.g. an assistant sending on behalf of an executive) |
| `Return-Path:` | The envelope sender bounces go to | Set by the last relay; frequently the mailing platform, not the author |
| `Reply-To:` | Where a *reply* is redirected | The message author — no relationship to `From:` is enforced |
| `Message-ID:` | A unique identifier assigned at composition, `<local@domain>` | Normally the sending system's own domain |
| Envelope sender (`MAIL FROM`) | The SMTP-level sender, what SPF actually checks | Not visible in the header directly — inferred from `Return-Path:` or `Authentication-Results` `smtp.mailfrom=` |
| Display name | The friendly name shown instead of an address | Fully attacker-controlled free text — "PayPal Support" can point anywhere |
| SMTP HELO identity | The hostname a connecting server announces itself as | Self-reported by the connecting host; not verified on its own |

**Mismatches are indicators, not proof.** A `Reply-To:` pointing somewhere other than
`From:` is exactly the mechanism business-email-compromise attacks use to redirect
replies — and it is also exactly what a support ticketing system, mailing list, or
no-reply sender does legitimately. One mismatch, considered alone, tells you very
little. What matters is the *combination*: does the mismatch coincide with
authentication that only weakly ties back to the visible sender, or with a lookalike
domain, or with an unusual request?

## The Received chain

- `Received:` headers are stacked **newest first** — each relay prepends its own line
  above everything already there. To reconstruct the actual delivery order, read from
  the bottom up.
- The hostname after `from` in each line is **self-reported** by the connecting host —
  treat it as a claim. The bracketed IP address next to it (`[203.0.113.15]`) is
  **observed** by the receiving server and is the one part of the line you can trust.
- Anything above the point where the message entered infrastructure you actually
  control is a claim an attacker could have fabricated. The first hop handled by
  infrastructure you trust — not the bottom-most line — is where corroboration starts.
- Private IPs (`10.0.0.0/8`, `192.168.0.0/16`, etc.) inside a chain are completely
  normal for internal relays, load balancers and security appliances.
- Timestamps should move forward (or stay roughly flat) as you read down the stack.
  A backwards jump is usually clock skew between two servers' clocks, not evidence of
  tampering — but it is worth noting, especially if it's large.

## Authentication in one line

- **SPF** checks whether the *connecting IP* is authorised to send for the *envelope
  sender's* domain — not the visible `From:` domain.
- **DKIM** validates that specific listed headers (and optionally the body) match a
  cryptographic signature from the *signing* domain — which may or may not be the
  `From:` domain.
- **DMARC** requires SPF *or* DKIM to both pass **and** align with the visible
  `From:` domain, and tells receivers what to do on failure (`p=none` / `quarantine`
  / `reject`).
- **ARC** preserves the authentication picture across a legitimate forward or mailing
  list, which is what makes it possible to distinguish "SPF failed because of
  forwarding" from "SPF failed because this is spoofed."
- `Authentication-Results` is only trustworthy when you know it was added by
  infrastructure you actually control — anyone can put arbitrary `spf=pass` text into
  a header they control (RFC 8601 §7.1). Check *who* asserted it (the `authserv-id`
  before the first `;`) before believing it.
- All three passing does **not** mean the message is safe. A compromised but genuine
  mailbox, or an attacker who legitimately owns a lookalike domain, passes every
  check here.

## Threat intelligence, briefly

- A clean reputation result does not prove legitimacy — it may mean the provider has
  no data, not that the indicator is safe.
- An "unknown" result is not a clean result. Treat it as no information.
- Shared cloud infrastructure (major email/hosting providers) can produce false
  positives on IP reputation lookups that have nothing to do with the specific
  message.
- Provider data can be stale; a listing from months ago may no longer reflect current
  reality, and the reverse — a recently compromised, previously-clean host — is
  equally possible.
- Never paste an entire raw header into a public reputation tool. Extract only the
  specific indicator (IP, domain, URL, hash) you need to check.

## BEC — a specific caution

Business email compromise commonly uses **legitimate or compromised accounts**, which
means it routinely passes SPF, DKIM and DMARC cleanly. Header-only analysis cannot
confirm business context (was this payment actually expected? does this vendor
relationship exist?) — it can only surface *inconsistency*: a reply path that diverges
from the sending organisation, a lookalike domain, a display name that doesn't match
the underlying address. Call it "Possible BEC / Impersonation" and escalate for
verification through an out-of-band channel. Never call it "BEC Confirmed" from
headers alone.

See also: [`EMAIL_AUTHENTICATION.md`](EMAIL_AUTHENTICATION.md) for authentication
detail, [`ANALYST_DECISION_RULES.md`](ANALYST_DECISION_RULES.md) for how this tool
turns the above into scored findings, and [`LIMITATIONS.md`](LIMITATIONS.md) for what
neither the manual process nor the tool can tell you.
