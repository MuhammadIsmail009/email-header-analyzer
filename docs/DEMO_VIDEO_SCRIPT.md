# Demo Video Script

Target length: 7–9 minutes. Read each quote naturally, in your own words — don't memorize it.
If you're running long, cut narration, not the app walkthrough.

**Before you hit record:** set `DEMO_MODE=true` in `.env` and restart the server. That makes
the scores you see match the numbers in this script exactly.

**The idea behind this script:** explain everything the way you'd explain it to a smart friend
who's never worked in security — using a package/mail analogy throughout, so nobody watching
needs to already know what SPF or DMARC is to follow along.

## 1. What problem this solves (0:00–0:45)

> "Think of an email like a package that shows up at your door. It's got a return address on
> it, some stamps and stickers showing everywhere it passed through, and a note claiming who
> sent it. The problem is: anyone can write anything on a package. A scammer can put your
> bank's name on the return address and it still shows up at your door looking legit.
>
> So when a security analyst gets a suspicious email, they don't just trust what's written on
> it — they actually go check: is this really from who it claims? Did it really travel the
> path it says it did? That's slow, repetitive work to do by hand. This tool does that checking
> automatically — but it always shows you exactly why it concluded what it concluded. Never
> just a score with no explanation."

Show: title screen / README.

## 2. How I did this by hand, first (0:45–1:45)

> "Before I built this, I did the whole process by hand." [point to the manual-analysis doc]
> "Quick version: an email has a few different 'who sent this' fields, and each one is filled
> in by a different party — kind of like a package having a return address, a 'send complaints
> here' address, and a shipping label, and none of them being required to match. If they don't
> match, that's worth a second look, but it doesn't automatically mean something's wrong.
>
> Also, the 'path this email traveled' info gets stacked with the newest stop on top — like
> stickers piling up on a box — so you actually have to read it backwards, oldest stop first,
> to see where it really started.
>
> And passing all the security checks doesn't mean a message is safe. If someone's real account
> gets hacked and used to send a scam, it'll pass every single check, because it really is
> coming from that real account."

Show: `docs/MANUAL_EMAIL_ANALYSIS.md`, scroll through the headings.

## 3. The fields that matter (1:45–2:30)

> "So — From, Return-Path, Reply-To, Message-ID. Think of these like: the name on the package,
> the return address if it bounces, the address for complaints, and a tracking number. Each
> one's controlled by a different part of the system. That's exactly why it's worth noticing
> when they point in different directions — but by itself, it's not proof anyone's lying."

Show: `docs/EMAIL_AUTHENTICATION.md` identity table, or the identity block on a results page.

## 4. The three big checks — and what actually makes this tool different (2:30–3:30)

> "There are three standard checks every mail server does, and I'll explain each with a quick
> analogy instead of just throwing acronyms at you.
>
> First — SPF. Think of it as an approved-delivery-drivers list a company publishes: 'only
> these specific trucks are allowed to deliver mail on our behalf.' A mail server checks: did
> this actually come from an approved truck?
>
> Second — DKIM. Think of it like a wax seal on an envelope. It proves the message wasn't
> opened and tampered with after it was sealed — a cryptographic signature, not just a sticker
> that says 'sealed.'
>
> Third — DMARC. This is the instruction note taped next to the mailbox: 'if a package shows up
> without the right seal, or from a truck that's not on the list, here's what to do with it —
> ignore it, flag it, or refuse it outright.' It also checks something sneaky: even if the
> truck WAS approved, does the name on the package actually match the company that approved it?
>
> Here's the thing — almost every other header-checking tool just reads the note the receiving
> mail server already wrote saying 'yep, checks passed' and takes its word for it. But that
> note can be faked by whoever sent the email. This tool doesn't take anyone's word for it — it
> goes and checks the real approved-drivers list and the real instructions itself, live, right
> now, and shows you exactly what was *claimed* next to what it *actually verified*. If they
> don't match, it tells you."

Show: the auth matrix on a results page, point at the "claimed vs. verified" columns.

## 5. The clean sample (3:30–4:15)

> "Let's load the clean example. Everything checks out — the truck's approved, the seal's
> intact, the name matches. Score: zero. Verdict: Likely Legitimate.
>
> But look at the exact wording — 'based on available header evidence,' never just 'safe.'
> Remember the hacked-account problem from earlier? A real account that's been hijacked would
> pass every one of these checks too. So the tool never claims more certainty than it actually
> has."

Show: click "Legitimate" sample → Analyze → scroll through the results top to bottom.

## 6. The phishing sample (4:15–5:00)

> "This one's using a lookalike name — one letter quietly swapped for a number, the kind of
> thing you'd miss at a glance. The DMARC check fails, and the 'send replies here' address
> points somewhere completely different from where the message claims to be from. Score's in
> the 70s, verdict Likely Phishing.
>
> And every single finding explains itself in plain language: what the evidence actually is,
> why it matters, and — this part matters — what an innocent explanation could look like. So
> this doesn't train anyone to panic over something that turns out to be normal."

Show: phishing sample results, open two or three findings to show the full breakdown.

## 7. The tricky one (5:00–5:45)

> "This is the interesting case. All three checks pass — genuinely, for real. But the 'reply
> to' address quietly points somewhere else. This is what a targeted business scam actually
> looks like in practice: the attacker's own setup passes every technical check, because
> there's nothing technically wrong with it — the trick is entirely social, not technical. So
> checking the truck and the seal alone can't catch it.
>
> The verdict here says 'Possible' — never 'Confirmed.' A header can flag that something's
> worth a phone call to double-check. It can't prove someone's lying about business context —
> only a human conversation can do that."

Show: BEC sample results, open the BEC-001 finding.

## 8. How the email actually traveled (5:45–6:30)

> "This view shows the real path the email took, read oldest-stop-first — flipped from how the
> raw data actually stores it, remember the sticker analogy from earlier. There's a line drawn
> showing which stops are infrastructure we actually trust versus which ones are just
> unverified claims. This first stop has no origin info listed at all — that's completely
> normal for an internal mail system, but it's exactly the kind of stop some other tools just
> silently drop, and then they lose track of where the message really came from."

Show: hop timeline, point at the trust-boundary line and the hop with no "from" info.

## 9. Pulling out the suspicious stuff (6:30–7:00)

> "Every IP address, domain, link, and email address in the header gets automatically pulled
> out and listed — basically, everything worth double-checking because it might be tied to an
> attack. They get cleaned up and de-fanged by default, meaning a link gets rewritten so it's
> never an accidentally-clickable live link on screen. And only public, real-world addresses
> ever get checked against outside services — internal or fake test addresses never leave this
> machine at all."

Show: IOC table, flip the defang/refang switch once.

## 10. Checking against outside sources (7:00–7:30)

> "By default, nothing about your data leaves this machine — outside lookups are switched off.
> Demo mode gives you sample results for these four bundled examples so you can see what it
> looks like, clearly labeled as demo data, not real. With real API keys turned on, it actually
> asks real security databases — AbuseIPDB, EmailRep, VirusTotal — 'has anyone flagged this
> before?' But it never makes up an answer. If a check is turned off, or it fails, it says so
> honestly instead of quietly pretending everything's clean."

Show: the config-status badges, one intel table with the "Demo Fixture" label visible.

## 11. How the score actually gets calculated (7:30–8:15)

> "Every rule that can add to the score lives in one plain, readable settings file — not
> buried in code. Each rule has a name, a point value, and it's required to also explain what
> an innocent version of that same finding could look like.
>
> And it's not just 'add up the points and see if you cross a line.' Specific combinations get
> checked first. For example: a message that's genuinely verified clean, but has one bad hit
> from an outside security check, gets toned down to just 'Suspicious' instead of escalated —
> because that specific combination is usually just two unrelated things sharing the same
> server, not an actual attack."

Show: `app/core/rules/rules.yaml` briefly, then the "why this verdict" text on a results page.

## 12. What this tool deliberately won't say (8:15–8:35)

> "There's no 'Safe' verdict anywhere in this tool, and no 'Confirmed' for the tricky
> business-scam case. Both of those would be claiming more certainty than a header alone can
> actually give you."

Show: `docs/LIMITATIONS.md` headings, quick scroll.

## 13. How to actually run it (8:35–9:00)

> "Everything you need is in the repo — no database, nothing external required to set up.
> Install the requirements, copy the settings file, run it — or just one Docker command if you
> don't want to touch Python at all. All the automated tests run fully offline too, no
> internet, no API keys needed."

Show: terminal — `docker compose up --build`, then open the app in a browser to prove it's
live. End on the running app.
