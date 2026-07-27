"""``Received:`` chain parsing and mail-route reconstruction.

Written from scratch. The best available implementation (``eml_parser``, GOVCERT-LU)
is AGPL-3.0, and §13 of that licence triggers on serving the work over a network —
which is precisely what this application does. See docs/REFERENCE_REPOSITORIES.md §7.

The grammar is RFC 5321 §4.4::

    Received: from <sender> by <receiver> [with <protocol>] [id <queue-id>]
              [for <recipient>] ; <timestamp>

Real deployments deviate from it constantly, so this parser scans for clause keywords
at parenthesis depth zero rather than applying one large regular expression. Two
consequences of that choice are worth stating, because both are defects in the
best-known tools in this space:

1. **A line with no ``from`` clause is still a hop.** ``Received: by host (PGP
   Universal, from userid 997) id ...`` is what locally-injected mail looks like when
   it comes from a submission agent or an encryption gateway. A parser anchored on
   ``from\\s+(.*?)\\s+by`` discards the line entirely, which deletes the *origin* hop
   and makes the second hop look like the source.

2. **Nothing is dropped silently.** A hop that cannot be understood is still emitted,
   with warnings attached. In forensics an incomplete chain presented as complete is
   worse than an explicit gap.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime

from app.core.models import (
    Confidence,
    HopDelay,
    IPClass,
    MailRoute,
    ParsedHeader,
    ReceivedHop,
)
from app.core.netutils import classify_ip, extract_ips

_CLAUSE_KEYWORDS = ("from", "by", "with", "via", "id", "for")

_WS_RUN = re.compile(r"\s+")


def _depth_aware_tokens(text: str) -> list[tuple[int, str]]:
    """Yield ``(offset, word)`` for words appearing at parenthesis/bracket depth zero.

    Clause keywords inside a comment must not be treated as clauses. ``(PGP Universal,
    from userid 997)`` contains the word ``from``, but it is prose inside a comment,
    not the start of a ``from`` clause. Depth tracking is what tells the difference.
    """
    tokens: list[tuple[int, str]] = []
    depth = 0
    word_start: int | None = None

    for index, char in enumerate(text):
        if char in "([":
            depth += 1
            if word_start is not None:
                tokens.append((word_start, text[word_start:index]))
                word_start = None
            continue
        if char in ")]":
            depth = max(0, depth - 1)
            if word_start is not None:
                tokens.append((word_start, text[word_start:index]))
                word_start = None
            continue
        if depth != 0:
            continue
        if char.isspace() or char == ";":
            if word_start is not None:
                tokens.append((word_start, text[word_start:index]))
                word_start = None
            continue
        if word_start is None:
            word_start = index

    if word_start is not None:
        tokens.append((word_start, text[word_start:]))
    return tokens


def _split_timestamp(value: str) -> tuple[str, str | None]:
    """Split the trailing timestamp from the clause section.

    The separator is the last ``;`` at depth zero. Searching from the right matters:
    ``for <addr>; <date>`` is the common shape, but comments earlier in the line can
    contain semicolons.
    """
    depth = 0
    last_semicolon = -1
    for index, char in enumerate(value):
        if char in "([":
            depth += 1
        elif char in ")]":
            depth = max(0, depth - 1)
        elif char == ";" and depth == 0:
            last_semicolon = index
    if last_semicolon == -1:
        return value, None
    return value[:last_semicolon], value[last_semicolon + 1 :].strip()


def _parse_timestamp(raw: str) -> tuple[datetime | None, str | None, str | None]:
    """Parse an RFC 5322 date-time.

    Returns ``(utc_datetime, original_offset, warning)``.

    ``email.utils.parsedate_to_datetime`` is used first because it is RFC 5322-aware
    and correctly ignores the trailing CFWS comment. That comment is not always a
    legal timezone abbreviation — ``+0300 (+03)`` appears in real mail and defeats
    parsers that try to interpret it.
    """
    if not raw:
        return None, None, "hop has no timestamp"

    cleaned = _WS_RUN.sub(" ", raw).strip()
    offset_match = re.search(r"([+-]\d{4}|\b(?:UT|GMT|[ECMP][SD]T|Z)\b)", cleaned)
    original_offset = offset_match.group(1) if offset_match else None

    try:
        parsed = parsedate_to_datetime(cleaned)
    except (TypeError, ValueError, IndexError):
        parsed = None

    if parsed is None:
        try:
            from dateutil import parser as dateutil_parser

            parsed = dateutil_parser.parse(cleaned, fuzzy=True)
        except (ValueError, OverflowError, TypeError):
            return None, original_offset, f"unparsable timestamp: {cleaned!r}"

    if parsed.tzinfo is None:
        # RFC 5322 §3.3 says -0000 means the local time is known but the offset is
        # not. Treating it as UTC is the conventional fallback, but it is an
        # assumption and the analyst should know it was made.
        parsed = parsed.replace(tzinfo=UTC)
        return (
            parsed.astimezone(UTC),
            original_offset,
            "timestamp had no timezone offset; assumed UTC",
        )

    return parsed.astimezone(UTC), original_offset, None


def parse_received_line(raw: str, index: int) -> ReceivedHop:
    """Decompose one ``Received:`` field value."""
    warnings: list[str] = []
    normalized = _WS_RUN.sub(" ", raw).strip()

    clause_text, timestamp_raw = _split_timestamp(normalized)
    timestamp_utc, original_offset, ts_warning = _parse_timestamp(timestamp_raw or "")
    if ts_warning:
        warnings.append(ts_warning)

    tokens = _depth_aware_tokens(clause_text)
    clause_positions: list[tuple[int, str]] = [
        (offset, word.lower())
        for offset, word in tokens
        if word.lower() in _CLAUSE_KEYWORDS
    ]

    clauses: dict[str, str] = {}
    for position, (offset, keyword) in enumerate(clause_positions):
        start = offset + len(keyword)
        end = (
            clause_positions[position + 1][0]
            if position + 1 < len(clause_positions)
            else len(clause_text)
        )
        if keyword not in clauses:
            clauses[keyword] = clause_text[start:end].strip()

    if "from" not in clauses and "by" not in clauses:
        warnings.append(
            "hop has neither a 'from' nor a 'by' clause; retained as unparsable"
        )
    elif "from" not in clauses:
        # Not an error. This is what locally-injected mail looks like.
        warnings.append(
            "hop has no 'from' clause, consistent with local injection by a "
            "submission agent or gateway rather than an SMTP connection"
        )

    from_clause = clauses.get("from", "")
    from_host, from_rdns = _parse_from_clause(from_clause)
    by_host = _first_hostlike(clauses.get("by", ""))

    protocol = None
    tls_info = None
    if "with" in clauses:
        protocol, tls_info = _parse_with_clause(clauses["with"])

    ip_addresses = tuple(extract_ips(clause_text))
    primary_ip = _select_primary_ip(from_clause, ip_addresses)
    primary_ip_class = classify_ip(primary_ip) if primary_ip else None

    return ReceivedHop(
        index_in_header=index,
        raw=raw.strip(),
        from_host=from_host,
        from_rdns=from_rdns,
        by_host=by_host,
        protocol=protocol,
        tls_info=tls_info,
        queue_id=_first_token(clauses.get("id", "")) or None,
        for_recipient=_first_token(clauses.get("for", "")) or None,
        ip_addresses=ip_addresses,
        primary_ip=primary_ip,
        primary_ip_class=primary_ip_class,
        raw_timestamp=timestamp_raw,
        timestamp_utc=timestamp_utc,
        original_offset=original_offset,
        warnings=tuple(warnings),
    )


def _parse_from_clause(clause: str) -> tuple[str | None, str | None]:
    """Extract the claimed HELO name and the receiver-observed reverse-DNS name.

    ``from mail.example.com (relay.example.net. [203.0.113.15])`` gives a claimed name
    of ``mail.example.com`` and an observed name of ``relay.example.net``.

    The distinction is the whole point. The bare hostname is what the connecting
    server *said* it was, and it is free text. The parenthesised name is what the
    receiving server looked up for itself. Only the second is evidence.
    """
    if not clause:
        return None, None

    claimed = _first_hostlike(clause.split("(")[0])

    observed: str | None = None
    comment = re.search(r"\(([^)]*)\)", clause)
    if comment:
        inner = comment.group(1)
        inner = re.sub(r"\[[^\]]*\]", " ", inner)  # strip the IP literal
        inner = re.sub(r"(?i)\bhelo\s*=?\s*", " ", inner)
        observed = _first_hostlike(inner)

    return claimed, observed


def _parse_with_clause(clause: str) -> tuple[str | None, str | None]:
    """Split the protocol token from any TLS detail.

    ``ESMTPS (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128)``
    yields ``ESMTPS`` and the cipher detail. ESMTPS versus plain ESMTP tells the
    analyst whether that hop was encrypted, which is expected for legitimate
    enterprise mail flow and notable by its absence.
    """
    protocol = _first_token(clause.split("(")[0])
    detail = None
    comment = re.search(r"\(([^)]*)\)", clause)
    if comment and re.search(r"(?i)tls|cipher|version=", comment.group(1)):
        detail = comment.group(1).strip()
    elif re.search(r"(?i)tls|cipher", clause):
        detail = clause.strip()
    return protocol or None, detail


_HOSTLIKE_RE = re.compile(r"[A-Za-z0-9_](?:[A-Za-z0-9_.-]*[A-Za-z0-9_])?")


def _first_hostlike(text: str) -> str | None:
    """First hostname-shaped token, with any trailing root dot removed.

    The trailing dot matters: ``mail.example.com.`` is a fully-qualified name and is
    equal to ``mail.example.com``, but naive string comparison says otherwise, and
    that difference has produced false 'domain mismatch' findings in other tools.
    """
    for match in _HOSTLIKE_RE.finditer(text or ""):
        token = match.group(0).rstrip(".")
        if token and not token.isdigit():
            return token
    return None


def _first_token(text: str) -> str:
    stripped = (text or "").strip()
    return stripped.split(" ")[0].strip() if stripped else ""


def _select_primary_ip(from_clause: str, all_ips: tuple[str, ...]) -> str | None:
    """Prefer the address the receiving server observed on the connection.

    That address lives in the ``from`` clause's bracketed literal. It is the single
    trustworthy element of a Received line — everything else in it, including the
    hostname, is supplied by the sender.
    """
    if from_clause:
        in_from = extract_ips(from_clause)
        if in_from:
            return in_from[0]
    return all_ips[0] if all_ips else None


# ---------------------------------------------------------------------------
# Route reconstruction
# ---------------------------------------------------------------------------


def compute_delays(hops_chronological: list[ReceivedHop]) -> list[HopDelay]:
    """Elapsed time between consecutive hops.

    Uses ``timedelta.total_seconds()``. The most-starred tool in this space uses
    ``timedelta.seconds``, which is the within-day remainder rather than the total:
    one second of backwards clock skew becomes ``days=-1, seconds=86399`` and is
    reported as 86,399 seconds of delay, while a genuine 25-hour delay reports as one
    hour. Its ``if delay < 0`` guard is unreachable, because ``.seconds`` is never
    negative.

    Negative deltas are kept and labelled as clock skew rather than clamped to zero.
    Two MTAs disagreeing about the time is ordinary — NTP drift, a misconfigured
    timezone — and it is not by itself suspicious. But it is evidence, and hiding it
    would misrepresent the route.
    """
    delays: list[HopDelay] = []
    for previous, current in zip(hops_chronological, hops_chronological[1:], strict=False):
        if previous.timestamp_utc is None or current.timestamp_utc is None:
            continue
        seconds = (current.timestamp_utc - previous.timestamp_utc).total_seconds()
        is_skew = seconds < 0
        note = None
        if is_skew:
            note = (
                f"Timestamp moves backwards by {abs(seconds):.1f}s between these hops. "
                "Usually clock skew between mail servers, not evidence of tampering."
            )
        elif seconds > 3600:
            note = (
                f"Unusually long delay ({seconds / 3600:.1f}h). Often queueing, "
                "greylisting or a retry, but worth confirming."
            )
        delays.append(
            HopDelay(
                from_hop_index=previous.index_in_header,
                to_hop_index=current.index_in_header,
                seconds=seconds,
                is_clock_skew=is_skew,
                note=note,
            )
        )
    return delays


def build_route(
    parsed: ParsedHeader,
    trusted_domains: tuple[str, ...] = (),
    trusted_hosts: tuple[str, ...] = (),
) -> MailRoute:
    """Reconstruct the delivery path from all ``Received:`` fields."""
    fields = parsed.get_all("Received")
    hops_header_order = [
        parse_received_line(field.raw_value, index) for index, field in enumerate(fields)
    ]

    # MTAs prepend, so stored order is newest-first. Chronological order is the
    # reverse. The UI shows both and labels the reversal, because it is an
    # interpretation rather than a fact recorded in the message.
    hops_chronological = list(reversed(hops_header_order))
    delays = compute_delays(hops_chronological)

    positive = [d.seconds for d in delays if d.seconds >= 0]
    total_transit = sum(positive) if positive else None

    origin_index = hops_chronological[0].index_in_header if hops_chronological else None
    trusted_index, confidence, explanation, missing = _locate_trust_boundary(
        hops_chronological, trusted_domains, trusted_hosts
    )

    warnings: list[str] = []
    for hop in hops_header_order:
        for warning in hop.warnings:
            warnings.append(f"hop {hop.index_in_header}: {warning}")

    if any(d.is_clock_skew for d in delays):
        warnings.append(
            "One or more hops show negative transit time. Reported as clock skew, "
            "not counted toward total transit."
        )

    private_to_public = _detect_boundary_transitions(hops_chronological)
    warnings.extend(private_to_public)

    return MailRoute(
        hops_header_order=tuple(hops_header_order),
        hops_chronological=tuple(hops_chronological),
        delays=tuple(delays),
        total_transit_seconds=total_transit,
        estimated_origin_hop_index=origin_index,
        first_trusted_hop_index=trusted_index,
        trust_boundary_confidence=confidence,
        trust_boundary_explanation=explanation,
        missing_evidence=tuple(missing),
        warnings=tuple(warnings),
    )


def _locate_trust_boundary(
    hops_chronological: list[ReceivedHop],
    trusted_domains: tuple[str, ...],
    trusted_hosts: tuple[str, ...],
) -> tuple[int | None, Confidence, str, list[str]]:
    """Find the first hop handled by infrastructure we actually trust.

    Everything recorded *before* that point was written by systems outside our
    control, and an attacker can fabricate as many plausible ``Received:`` lines as
    they like. So the bottom-most hop is not "the sender" — it is the earliest
    *claim*. What can be relied on is the first hop added by a trusted receiver, and
    the connecting IP that receiver observed.

    With no trusted infrastructure configured this returns low confidence and says so,
    rather than guessing.
    """
    missing: list[str] = []

    if not trusted_domains and not trusted_hosts:
        missing.append(
            "No trusted receiver domains or hosts configured "
            "(TRUSTED_RECEIVER_DOMAINS / TRUSTED_RECEIVER_HOSTS), so no hop can be "
            "confirmed as trusted infrastructure."
        )
        return (
            None,
            Confidence.LOW,
            "Trust boundary not established: no trusted infrastructure is configured. "
            "Every hop below is a sender-supplied claim and none can be corroborated.",
            missing,
        )

    lowered_hosts = {h.lower().rstrip(".") for h in trusted_hosts if h}
    lowered_domains = [d.lower().strip().rstrip(".") for d in trusted_domains if d]

    def is_trusted(host: str | None) -> bool:
        if not host:
            return False
        candidate = host.lower().rstrip(".")
        if candidate in lowered_hosts:
            return True
        return any(
            candidate == domain or candidate.endswith("." + domain)
            for domain in lowered_domains
        )

    for hop in hops_chronological:
        if is_trusted(hop.by_host):
            confidence = Confidence.HIGH if hop.primary_ip else Confidence.MEDIUM
            if not hop.primary_ip:
                missing.append(
                    f"Hop {hop.index_in_header} is trusted infrastructure but records "
                    "no connecting IP, so the sender address cannot be corroborated."
                )
            return (
                hop.index_in_header,
                confidence,
                f"First hop handled by trusted infrastructure: {hop.by_host}. "
                "Hops recorded before this point are sender-supplied and may be "
                "fabricated; hops from here onward were written by systems we trust.",
                missing,
            )

    missing.append(
        "No hop was handled by any configured trusted receiver. Either the message "
        "did not traverse the configured infrastructure, or the configuration does "
        "not match this mail flow."
    )
    return (
        None,
        Confidence.LOW,
        "Trust boundary not found: none of the receiving hosts matched configured "
        "trusted infrastructure.",
        missing,
    )


def _detect_boundary_transitions(hops_chronological: list[ReceivedHop]) -> list[str]:
    """Note transitions between non-public and public address space.

    Private addresses inside a delivery path are entirely normal — internal relays,
    load balancers, appliances. What is worth a second look is the *shape* of the
    transition, so this reports it as an observation rather than a finding.
    """
    notes: list[str] = []
    for previous, current in zip(hops_chronological, hops_chronological[1:], strict=False):
        if previous.primary_ip_class is None or current.primary_ip_class is None:
            continue
        was_internal = previous.primary_ip_class in (
            IPClass.PRIVATE,
            IPClass.LOOPBACK,
            IPClass.LINK_LOCAL,
        )
        now_public = current.primary_ip_class is IPClass.PUBLIC
        if was_internal and now_public:
            notes.append(
                f"Route moves from internal address space ({previous.primary_ip}) to "
                f"public ({current.primary_ip}) between hops "
                f"{previous.index_in_header} and {current.index_in_header}. Normal for "
                "outbound mail leaving an organisation."
            )
    return notes
