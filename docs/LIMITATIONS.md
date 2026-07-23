# Limitations

Stated honestly and in full. Each boundary below is a deliberate scope decision, not
an oversight — the reasoning is included so a reviewer can judge whether the trade-off
was the right one, not just that one was made.

## This is a header-only tool

- **No message body analysis.** URLs, attachments, and body text are not inspected.
  A message with a perfectly clean header and a malicious attachment or body will not
  be flagged by anything here. This was a deliberate assignment-scope boundary, and
  a real triage workflow needs a body-aware step downstream of this tool.
- **No attachment inspection.** No hashing, no sandboxing, no static analysis of
  attached files.
- **No active URL fetching, following, or detonation.** Extracted URLs are shown
  defanged and, if enrichment is enabled, checked against cached third-party reports
  only (VirusTotal's *existing* report for that URL, not a fresh submission). This
  tool never visits a URL itself.

## No independent verification of DKIM body integrity from a pasted header

DKIM's body hash (`bh=`) can only be checked against an actual body. With headers
only, this tool verifies the cryptographic signature over the *signed headers*, which
proves those headers are authentic and unmodified — but it does not and cannot confirm
body integrity without the body. Upload the full `.eml` for complete verification. The
UI states which was actually performed; see
[`docs/EMAIL_AUTHENTICATION.md`](EMAIL_AUTHENTICATION.md).

## No independent validation of ARC seals

The ARC chain is parsed and its `cv=` (chain validation) status is summarised and
explained, but the cryptographic seals themselves are not independently re-verified.
A plausible ARC chain is treated as context suggesting forwarding explains an
otherwise-failing result — not as proof.

## Threat intelligence is necessarily incomplete

- Three providers are integrated (AbuseIPDB, EmailRep, optional VirusTotal). Real SOC
  tooling typically draws on more sources; this reflects assignment scope, not a
  belief that three is sufficient for production triage.
- All three are *reputation and cached-report* lookups. None performs active
  scanning, sandboxing, or detonation.
- Provider data can be stale in both directions: a stale "clean" result and a stale
  "malicious" result are both possible. Every result records when it was retrieved.
- Free-tier or unconfigured deployments will show most enrichment as `disabled` — by
  design, this degrades to local structural analysis rather than failing, but local
  analysis alone cannot corroborate an indicator's reputation.

## No case management or persistence

Reports live in a bounded, short-lived in-memory cache and are not persisted to a
database. This was a deliberate decision (see `PROJECT_PLAN.md` §2, D8) to avoid
unnecessary infrastructure — but it also means:

- Restarting the application discards all prior reports.
- There is no audit trail of past analyses beyond what an analyst exported.
- There is no multi-analyst workflow, case assignment, or ticket integration.

A real deployment that needs any of the above should treat this tool as one step that
feeds a case-management system, not as the system of record itself.

## No authentication or multi-tenancy

The application has no login, no per-user access control, and no tenant isolation.
Anyone who can reach the deployment can submit analyses and (within the report cache's
TTL) retrieve any report by its opaque ID. This is acceptable for a single-analyst or
trusted-team internal deployment; it is not acceptable to expose publicly without
adding an authentication layer in front of it.

## No machine learning

Every finding is a deterministic, declared rule (`app/core/rules/rules.yaml`) — never
a model prediction. This is an explainability decision as much as a scope one: a rule
can state exactly why it fired and what the alternative innocent explanation is; a
model score generally cannot, at least not without substantially more infrastructure
than this project's scope justifies.

## Domain reputation heuristics are approximate

- The Public Suffix List snapshot bundled with `tldextract` is frozen at build time
  (network refresh is deliberately disabled — see `docs/THREAT_MODEL.md`). A newly
  delegated top-level domain unknown to that snapshot falls back to a last-two-labels
  heuristic (`app/core/domain_analyzer.py::_split_registrable`), which is usually but
  not always correct.
- Lookalike-domain detection (`app/core/domain_analyzer.py::lookalike_of`) uses
  edit-distance and homoglyph-skeleton matching against an operator-configured
  watchlist. Detection thresholds are tuned to catch short real-world brand names
  (4+ characters) at the cost of a higher false-positive rate on coincidental
  similarity — a deliberate trade-off, documented in the function's own docstring.

## Verdict wording is deliberately conservative

There is no "Safe" verdict and no "BEC Confirmed" verdict — see
[`docs/ANALYST_DECISION_RULES.md`](ANALYST_DECISION_RULES.md) for why. This means the
tool will sometimes produce a hedged-sounding result (e.g. "Likely Legitimate based on
available header evidence") in a case a human analyst would confidently call safe.
That hedging is intentional: header evidence genuinely cannot rule out account
compromise, and overclaiming certainty here is a worse failure mode than under-claiming
it.

## Windows-specific testing note

Development and testing for this project were carried out on Windows. Docker builds
were verified on Windows with Docker Desktop; Linux container behaviour is expected to
be equivalent (the image is `python:3.12-slim`, no Windows-specific code paths exist
anywhere in the application), but has not been independently confirmed on a native
Linux host as part of this submission.
