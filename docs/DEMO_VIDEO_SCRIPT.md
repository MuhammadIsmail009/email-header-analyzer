# Demo Video Script

Target length: 7–9 minutes. Just read each quote naturally — don't memorize it word for word.
If you're running long, cut narration, not the parts where you click through the app.

**Before you hit record:** set `DEMO_MODE=true` in `.env` and restart the server. That makes
the scores you see match the numbers in this script exactly.

## 1. What problem this solves (0:00–0:45)

> "When a SOC analyst gets a reported phishing email, they read the header by hand — check
> SPF, DKIM, DMARC, trace how the email traveled, pull out any suspicious IPs or links. It's
> repetitive, and easy to mess up when you're moving fast. This tool automates that whole
> process, but it always shows its work — you never just get a score with no explanation."

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

> "Most header tools just read the Authentication-Results header the mail server already
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

## 6. The phishing sample (4:15–5:00)

> "This one uses a lookalike domain — one letter swapped for a digit. DMARC fails, and the
> Reply-To address points somewhere completely different from the real sender's domain.
> Score's in the 70s, verdict Likely Phishing. And every single finding explains itself: what
> the evidence is, why it matters, and — this part matters — what the innocent explanation
> could be, so the tool doesn't train anyone to panic over something normal."

Show: phishing sample results, open two or three findings to show the full breakdown.

## 7. The tricky one — possible BEC (5:00–5:45)

> "This is the interesting case. Authentication passes cleanly — for real, independently
> verified. But the reply-to address quietly points somewhere else. This is what a Business
> Email Compromise attack actually looks like: the attacker's own setup passes every check,
> so SPF/DKIM/DMARC alone can't catch it. The verdict says 'Possible BEC' — never
> 'Confirmed.' A header alone can't prove someone's lying about business context — it can
> only tell you it's worth picking up the phone and checking."

Show: BEC sample results, open the BEC-001 finding.

## 8. How the email actually traveled (5:45–6:30)

> "This view reads oldest-first — flipped from how the raw header actually stores it — and
> draws a line showing which hops are trusted infrastructure versus which ones are just
> claims nobody's verified. This first hop has no 'from' info at all — that's what a gateway
> or internal mail system looks like, and it's exactly the kind of hop some other tools just
> drop, losing track of where the message actually came from."

Show: hop timeline, point at the trust-boundary line and the hop with no "from" info.

## 9. Pulling out the suspicious stuff (6:30–7:00)

> "Every IP, domain, link and email address gets pulled out automatically, deduplicated, and
> defanged by default — so nothing here is an accidentally-clickable live link. Only public
> IPs ever get checked against outside services — internal and test addresses never leave
> this machine."

Show: IOC table, flip the defang/refang switch once.

## 10. Checking against threat intel (7:00–7:30)

> "By default, nothing leaves this machine — outside lookups are off. Demo mode gives you
> sample results for these four bundled examples, clearly labeled as demo data. With real API
> keys turned on, it actually queries AbuseIPDB, EmailRep and VirusTotal — but it never makes
> up a result. If a lookup is off, or fails, it just says so honestly instead of pretending
> everything's clean."

Show: the config-status badges, one intel table with the "Demo Fixture" label visible.

## 11. How the score actually gets calculated (7:30–8:15)

> "The scoring rules live in a plain YAML file, not buried inside Python code — every rule
> has an ID, a weight, and a required explanation of what an innocent version of this would
> look like. And the verdict isn't just 'add up the score and check a threshold' — specific
> evidence patterns get checked first. For example: clean, verified authentication plus one
> bad threat-intel hit gets toned down to Suspicious instead of escalated, because that
> combination is usually just shared hosting, not an actual attack."

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
