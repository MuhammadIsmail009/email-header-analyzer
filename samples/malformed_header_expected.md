# Expected result — `malformed_header.txt`

Synthetic, deliberately broken. This sample exists to exercise warning paths, not to
represent a realistic phishing or legitimate message — its purpose is proving the
parser degrades gracefully on damaged input rather than crashing, and that nothing is
silently discarded.

## Deliberate defects, one per line

| Line | Defect | Expected handling |
|---|---|---|
| `From: Alice <alice@bank.example` | Missing closing `>` | Retained; address extraction is best-effort |
| `Date Wed, ...` | No colon separator | Retained as `(unparsable)`, warning emitted, **not dropped** |
| `Message-ID <no-angle-brackets-here>` | No colon separator | Same — retained as `(unparsable)` |
| `From: Second.From@evil.example` | Duplicate singleton field | Both `From:` values retained (never silently take-the-first); flagged as a duplicate-singleton warning |
| `   orphaned continuation...` | Starts with whitespace | Per RFC 5322 §2.2.3, a line starting with whitespace is a **folding continuation of the preceding field**, not an orphan — this line correctly folds into the second `From:` value rather than becoming a standalone warning. (Orphaned-continuation handling with no preceding field at all is exercised separately in `tests/unit/test_header_parser.py::test_orphaned_continuation_line_is_retained`.) |
| `Received: totally malformed...` | No recognisable `from`/`by`/timestamp structure | Retained as a hop with warnings, not dropped |
| `Received: from a.example.com (b.example.net [999.999.999.999]) by c.example.org;` | Invalid IPv4 octet (`999`) | `999.999.999.999` fails `ipaddress` validation and is correctly excluded from extracted IPs; the hop itself is still retained with `primary_ip=None` |
| `X-Weird-Encoding: =?utf-8?B?not-valid-base64!!!?=` | Malformed RFC 2047 encoded-word | Degrades to the raw text plus a warning (see the `HeaderParseError` handling documented in `app/core/header_parser.py`), not a crash |

## Expected parsed fields

Exactly as reproduced in this sample: 9 header entries including two `(unparsable)`
placeholders (for the two colon-less lines) and two `From:` fields (the duplicate).
Nothing from the original 9 lines is silently dropped.

## Expected warnings (verbatim, order may vary)

- `line 4: line is not a valid header field and was retained as unparsable`
- `line 5: line is not a valid header field and was retained as unparsable`
- `header 'from' appears 2 times; RFC 5322 §3.6 permits at most one. Mail clients may disagree about which is displayed.`
- A hop-level warning on the "totally malformed" `Received:` line (no timestamp /
  no recognisable clause structure)

## Expected IOC set

`bank.example`, `evil.example`, `a.example.com`, `b.example.net`, `c.example.org`
(domains); `alice@bank.example`, `Second.From@evil.example` (emails). **No IP** is
extracted from the deliberately invalid `999.999.999.999` — this is correct behaviour,
not a gap.

## Expected findings

- `IDN-005` — duplicate singleton header present (+14)
- `AUTH-005` — no authentication evidence present at all (+12) — this sample carries
  no `Authentication-Results`/`Received-SPF` at all
- `TI-004` — informational, zero-weight

## Expected verdict

**Suspicious.** Score: **~26/100** in the reference smoke test (offline, no
verification — verification should be disabled for this sample since its `Received:`
data is not a coherent basis for a live DNS check). The duplicate `From:` header alone
is a real, if weak-to-moderate, indicator; combined with a complete absence of
authentication evidence it is enough to clear the `Suspicious` threshold without any
single finding being decisive.

## False-positive considerations

None of the individual defects here are inherently malicious — malformed headers are
also produced by broken mail software, lossy copy-paste, or manual redaction before
sharing with a SOC team. What this sample demonstrates is that the tool surfaces every
defect as an explicit warning rather than silently repairing or discarding evidence,
so an analyst can judge for themselves whether the damage is benign or itself
suspicious.

## Limitations

This sample is not a realistic attack sample — it is a parser stress test. Its
"Suspicious" verdict reflects genuine header irregularities, not evidence of a
phishing attempt specifically.
