# Demo Video Script

Target length: 7–9 minutes. Just read each quote naturally — don't memorize it word for word.
If you're running long, cut narration, not the parts where you click through the app.

**Before you hit record:** set `DEMO_MODE=true` in `.env` and restart the server. That makes
the scores you see match the numbers in this script exactly.

## 1. What problem this solves (0:00–0:45)

> "When a SOC analyst gets a reported phishing email, they read the header by hand — check
> SPF, DKIM and DMARC, the three standards that verify who actually sent an email and whether
> it's really from who it claims to be. They trace how the email traveled, and pull out any
> suspicious IPs or links. It's repetitive, and easy to mess up when you're moving fast. This
> tool automates that whole process, but it always shows its work — you never just get a score
> with no explanation."

Show: title screen / README.

## 2. How I did this by hand, first (0:45–1:45)

> "Before I automated this, I did it manually." [point to the manual-analysis doc]
> "Short version: if the From, Reply-To and Return-Path fields don't match, that's worth a
> second look — but it's not proof of anything by itself. The Received headers are stacked
> newest-on-top, so you read from the bottom up. And SPF, DKIM, DMARC each check a different
> thing — even if a message passes all three, that doesn't mean it's safe. A hacked mailbox
> passes every check too, because it really is the real account."

Show: `docs/MANUAL_EMAIL_ANALYSIS.md`, scroll through the headings.

## 3. The fields that matter (1:45–2:30)

> "From, Return-Path, Reply-To, Message-ID — each one is set by a different party along the
> way. That's exactly why it's worth noticing when they don't match, but it's not proof
> someone's lying."

Show: `docs/EMAIL_AUTHENTICATION.md` identity table, or the identity block on a results page.

## 4. SPF, DKIM, DMARC — and what makes this different (2:30–3:30)

> "Quick names, so these aren't just letters: SPF is Sender Policy Framework — it lists which
> servers are allowed to send mail for a domain. DKIM is DomainKeys Identified Mail — a
> cryptographic signature proving the message wasn't altered after it was sent. DMARC is
> Domain-based Message Authentication, Reporting and Conformance — the policy that says what to
> do if a message fails those checks, and whether the domain that passed actually matches what
> the inbox shows as the sender.
>
> Most header tools just read the Authentication-Results header the mail server already
> wrote — and trust it. But that header can be faked, and the spec for it says so outright.
> This tool doesn't trust it. It goes and re-checks the domain's real SPF record and DMARC
> policy from DNS itself, live, and shows you what was *claimed* right next to what it
> *actually verified* — and flags it clearly whenever the two disagree."

Show: the auth matrix on a results page, point at the "claimed vs. verified" columns.

## 5. The clean sample (3:30–4:15)

> "Loading the legitimate sample — SPF clean, DMARC clean, everything lines up and is
> verified for real. Score: zero. Verdict: Likely Legitimate. Notice the exact wording though
> — 'based on available header evidence,' never just 'safe.' A hacked-but-real mailbox would
> pass all of this too, so the tool never claims more than it can actually prove."

Show: click "Legitimate" sample → Analyze → scroll through the results top to bottom.

## 6. The phishing sample — the actual rules that fire (4:15–5:00)

> "This one uses a lookalike domain — one letter swapped for a digit. Score's 52, verdict
> Likely Phishing, and I want to name the specific rules behind that number instead of just
> waving at 'evidence' — this is the part that shows the tool isn't a black box.
>
> IDN-001 fires for +18 — Reply-To points to a different organisation than From. That's the
> single biggest contributor here: replies on this message don't go back to the sender's own
> domain, they go somewhere else entirely.
> RTE-002 fires for +10 — no trust boundary could be established, meaning nothing in the
> delivery path is corroborated infrastructure, it's all sender-supplied claims.
> IDN-002 and IDN-003 each fire for +8 — the Return-Path and the Message-ID both point to
> domains unrelated to the sender's own domain, on top of the Reply-To mismatch. Three
> different identity fields disagreeing with From, at once, is what pushes this from
> 'suspicious' into 'phishing.'
> AUTH-009 fires for +5 — the sender's own domain doesn't even publish a DMARC policy.
>
> None of these alone would be a verdict. It's that four separate, independent categories of
> evidence all point the same direction at the same time — that's what the score is actually
> measuring."

Show: phishing sample results, open two or three findings to show the full breakdown.

## 7. The tricky one — possible BEC, and the rule that exists specifically for it (5:00–5:45)

> "This is the interesting case. Score's 61, verdict Possible BEC — Business Email
> Compromise. Here, one rule matters more than the rest: BEC-001, worth +28, and it's the
> single biggest score in the whole rule set for a reason. It fires specifically when
> authentication passes cleanly — for real, independently verified — but the reply path or
> sending identity is internally inconsistent. That combination is exactly what a targeted
> business scam looks like on the wire: the attacker's own setup authenticates correctly,
> because there's nothing technically wrong with it, so SPF/DKIM/DMARC alone can never catch
> it. That's precisely why this rule exists as its own named pattern instead of just being
> folded into the generic identity-mismatch checks.
>
> IDN-001 also fires here for +18 — same Reply-To mismatch as the phishing case — plus
> RTE-002 and AUTH-009 for smaller amounts. But BEC-001 is what actually names the verdict:
> the results page shows it as the 'matched pattern' — authenticated-but-inconsistent-identity
> — right next to the score.
>
> The verdict says 'Possible' — never 'Confirmed.' A header alone can't prove someone's lying
> about business context — it can only tell you it's worth picking up the phone and
> checking."

Show: BEC sample results, open the BEC-001 finding, point at "matched pattern" on the verdict card.

## 8. How the email actually traveled (5:45–6:30)

> "This view reads oldest-first — flipped from how the raw header actually stores it — and
> draws a line showing which hops are trusted infrastructure versus which ones are just
> claims nobody's verified. This first hop has no 'from' info at all — that's what a gateway
> or internal mail system looks like, and it's exactly the kind of hop some other tools just
> drop, losing track of where the message actually came from."

Show: hop timeline, point at the trust-boundary line and the hop with no "from" info.

## 9. Pulling out the suspicious stuff — the IOCs (6:30–7:00)

> "Every IP, domain, link and email address gets pulled out automatically — these are called
> IOCs, Indicators of Compromise, meaning anything worth checking because it might be tied to
> an attack. They get deduplicated, and defanged by default — so nothing here is an
> accidentally-clickable live link. Only public IPs ever get checked against outside services —
> internal and test addresses never leave this machine."

Show: IOC table, flip the defang/refang switch once.

## 10. Checking against threat intel (7:00–7:30)

> "By default, nothing leaves this machine — outside lookups are off. Demo mode gives you
> sample results for these four bundled examples, clearly labeled as demo data. With real API
> keys turned on, it actually queries AbuseIPDB, EmailRep and VirusTotal — but it never makes
> up a result. If a lookup is off, or fails, it just says so honestly instead of pretending
> everything's clean."

Show: the config-status badges, one intel table with the "Demo Fixture" label visible.

## 11. How the score actually gets calculated — the rule catalog (7:30–8:15)

> "All 30-plus rules live in one plain YAML file, `app/core/rules/rules.yaml` — not buried
> inside Python. Every rule has four required parts: a stable ID like AUTH-001 or BEC-001, a
> point weight, why an analyst should care, and — mandatory, every single rule — the innocent
> explanation for it. A tool that only tells you what's suspicious and never what's normal
> trains people to over-escalate.
>
> A few worth knowing by name, since they're the ones that actually decide most verdicts:
> AUTH-001, DMARC failed independently — the single heaviest rule at +35, because it's the
> one control that ties authentication to the address you actually see. AUTH-010, all three
> controls pass and align — that one's negative, -18, because clean verified authentication
> should actually pull the score down, not just fail to add to it. IDN-001, Reply-To pointing
> to a different organisation than From — the biggest identity-mismatch rule at +18, and it's
> in three of our four bundled samples. And BEC-001, which we just saw — the highest single
> weight in the whole file at +28, specifically for the 'authenticates cleanly but identity is
> inconsistent' pattern.
>
> Categories also have a point cap — authentication can contribute at most 45 points total, no
> matter how many auth rules fire — so one noisy category can't alone pin the score at 100.
> And the verdict isn't just 'add up the score and check a threshold' — named patterns like
> BEC-001 get checked as a combination first. For example, clean verified authentication plus
> one bad threat-intel hit gets toned down toward Suspicious instead of escalated, because that
> specific combination is usually just shared hosting, not an actual attack."

Show: `app/core/rules/rules.yaml` briefly, then the "why this verdict" text on a results page.

## 12. What this tool won't claim (8:15–8:35)

> "There's no 'Safe' verdict anywhere in this tool, and no 'BEC Confirmed.' Both would be
> claiming more than a header alone can actually prove."

Show: `docs/LIMITATIONS.md` headings, quick scroll.

## 13. How to actually run it (8:35–9:00)

> "Everything you need is in the repo — no database, nothing external required. Install the
> requirements, copy the env file, run it — or just `docker compose up` if you don't want to
> touch Python at all. The tests all run fully offline too, no API keys needed."

Show: terminal — `docker compose up --build`, then open the app in a browser to prove it's
live. End on the running app.
