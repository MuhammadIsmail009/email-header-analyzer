# Analyst Decision Rules

How this tool turns parsed evidence into a score and a verdict. This document
describes the actual logic in `app/core/risk_engine.py`, `app/core/rules_impl.py` and
`app/core/rules/rules.yaml` — if this document and the code ever disagree, the code is
authoritative and this document has drifted (see `STATUS.md` for why that distinction
matters).

## Why rules live in YAML

Every rule's identity, weight, severity, category, evidence text, legitimate
explanation and recommended action are declared in `app/core/rules/rules.yaml` — not
buried in Python conditionals. This means:

- The verdict card can name *exactly which rule* fired (`AUTH-001`, `BEC-001`, ...),
  not just show an opaque number.
- An analyst who doesn't read Python can review what every rule claims and what it
  costs.
- Every rule is validated at startup: a rule with no matching predicate function, or a
  predicate with no matching rule definition, is a hard error — not a silently
  half-working feature.

The *matching logic* (does this rule fire, given the evidence?) is Python, in
`rules_impl.py`, registered against each rule's ID. A pure-YAML condition language was
considered and rejected: expressing "SPF passed but its domain doesn't share an
organisational domain with the visible From, and the assertion came from trusted
infrastructure" as a YAML expression is harder to read than the Python it replaces,
and cannot be unit-tested directly.

## Rule anatomy

Every rule declares, and every finding therefore carries:

| Field | Purpose |
|---|---|
| `id` | Stable identifier (`AUTH-001`, `IDN-003`, ...) — referenced in tests, docs, exports |
| `title` | One-line summary |
| `category` | One of: authentication, sender_identity, domain_alignment, mail_route, header_anomalies, threat_intelligence, email_reputation, impersonation, possible_bec |
| `strength` | informational / weak / moderate / strong / critical |
| `weight` | Points contributed to the score. **Negative weights reduce risk.** |
| `why` | Why an analyst should care |
| `legitimate` | **Mandatory.** The innocent explanation for this same evidence |
| `action` | What to do next |

The `legitimate` field is enforced, not optional — asserted by
`test_every_rule_has_a_legitimate_explanation`. Most individual indicators have an
innocent reading (a third-party mailing platform, a CRM, a support ticketing system, a
forwarder), and a tool that reports suspicion without the alternative trains analysts
to over-escalate.

## Scoring

```
score = Σ (per-category: min(category_total, category_cap))  +  Σ (negative contributions)
clamped to [0, 100]
```

**Category caps** (`rules.yaml`, `category_caps:`) stop one noisy category dominating
the score — six minor route observations must not outscore one verified DMARC
failure:

| Category | Cap |
|---|---|
| authentication | 45 |
| impersonation | 35 |
| threat_intelligence | 40 |
| sender_identity | 30 |
| possible_bec | 30 |
| domain_alignment | 25 |
| mail_route | 20 |
| email_reputation | 20 |
| header_anomalies | 15 |

Risk-*reducing* findings (negative weight — a genuinely clean, verified-aligned
authentication result; an established positive sender reputation) are applied **after**
capping, so they are never absorbed by a cap they didn't contribute to.

## Hard constraints, enforced by tests

- **No rule may key on country, region, language or nationality.** Geographic origin
  is a proxy for nationality, not for maliciousness, and is defeated by renting
  infrastructure in whichever country looks "safe." Asserted by
  `test_no_rule_mentions_country_or_nationality` and
  `test_country_never_contributes_to_score` — the latter constructs a threat-intel
  result carrying a country field and asserts the score is identical with or without
  it.
- **Unavailable, disabled, unknown or errored intelligence is never evidence of
  cleanliness.** Only `ProviderStatus.SUCCESS` and `DEMO_FIXTURE` are "actionable"
  (`ThreatIntelResult.is_actionable`); everything else contributes zero score and
  surfaces only as an entry in "missing evidence." Asserted by
  `test_unavailable_intel_is_informational_only` across all seven non-success statuses.
- **An untrusted authentication *failure* never scores.** Only an untrusted *pass*
  is suspicious (`AUTH-004`) — nobody forges a failure against themselves. Asserted by
  `test_untrusted_pass_scores_but_untrusted_fail_does_not`.
- **Absence of evidence is never treated as evidence of legitimacy.** If nothing was
  recorded and verification wasn't performed, the verdict is `Inconclusive`, not
  `Likely Legitimate` — a low score from finding nothing is not the same as a low
  score from finding something and clearing it. Asserted by
  `test_absence_of_evidence_never_reads_as_legitimate`.

## Verdict selection — correlation first, thresholds as fallback

The verdict is **not** simply "score ≥ threshold." Named evidence *combinations* are
checked first, in this order, and only fall through to score thresholds when nothing
more specific matches:

1. **Insufficient evidence** → `Inconclusive`. Nothing was recorded, no route exists,
   verification wasn't performed, and no substantive finding fired.
2. **Authenticates but internally inconsistent** (`BEC-001`) → `Possible BEC /
   Impersonation`. Requires *both* a passing authentication signal *and* an identity
   inconsistency (diverging reply path, lookalike domain, or a display name
   misrepresenting the real address). Authentication failure plus a mismatch is
   ordinary phishing, not this pattern — BEC and lookalike-domain impersonation are
   distinguished by the fact that the attacker's own infrastructure genuinely
   authenticates.
3. **Authentication failed or was only asserted by untrusted infrastructure, plus
   corroboration** (malicious intelligence or a matched lookalike domain) →
   `Likely Phishing`.
4. **Multiple independent providers agree the indicator is malicious**, with no clean
   verified authentication to weigh against it → `Likely Phishing`.
5. **Trusted, verified-clean authentication plus one adverse intelligence hit** →
   `Suspicious`, **deliberately dampened rather than escalated**. This is
   overwhelmingly the shared-infrastructure false positive (a reputation provider
   flagging an address for a neighbouring tenant's behaviour on the same host) — but a
   compromised legitimate account produces exactly the same picture, so it is not
   waved through either.
6. **Verified-clean, aligned authentication and nothing else of note** →
   `Likely Legitimate based on available header evidence` — never simply "safe."
7. Otherwise, numeric thresholds apply: **≥50 → Likely Phishing, ≥25 → Suspicious,
   <25 → Likely Legitimate** (only reached once the above cases are exhausted).

Every `RiskAssessment` records which pattern actually decided the verdict
(`matched_pattern`), or `None` if it fell through to thresholds — so the reasoning is
inspectable, not just the outcome.

## Confidence

Confidence in the *verdict* (not any one finding) rises with independent verification
having actually run and with the number of distinct categories that agree — a high
score built from one category is less trustworthy than a moderate score corroborated
across three.

## What is deliberately never a verdict

- **`Safe` / `Clean`** — does not exist. A compromised but genuine mailbox passes
  every check this tool performs; the strongest available wording is "Likely
  Legitimate based on available header evidence."
- **`BEC Confirmed`** — does not exist, only "Possible BEC / Impersonation." Header
  evidence alone cannot establish business context or confirm account compromise.

Full rule-by-rule reference: [`app/core/rules/rules.yaml`](../app/core/rules/rules.yaml).
