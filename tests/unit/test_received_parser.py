"""Received-chain parsing regression tests.

Most of the cases below correspond to a defect actually observed in one of the
reference projects audited in docs/REFERENCE_REPOSITORIES.md. Each test names the
behaviour it protects so a future change that reintroduces the defect fails loudly.

All header material here is synthetic: RFC 2606 reserved domains and RFC 5737
documentation address ranges.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.core.header_parser import parse_headers
from app.core.models import Confidence, IPClass
from app.core.received_parser import (
    build_route,
    compute_delays,
    parse_received_line,
)

# ---------------------------------------------------------------------------
# Clause decomposition
# ---------------------------------------------------------------------------


def test_full_received_line_decomposes():
    raw = (
        "from mail.example.com (relay.example.net. [203.0.113.15]) "
        "by mx.example.org with ESMTPS "
        "(version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128) "
        "id 14643A91718 for <analyst@example.org>; "
        "Tue, 21 Oct 2025 23:28:50 -0700 (PDT)"
    )
    hop = parse_received_line(raw, 0)

    assert hop.from_host == "mail.example.com"
    assert hop.from_rdns == "relay.example.net"
    assert hop.by_host == "mx.example.org"
    assert hop.protocol == "ESMTPS"
    assert "TLS1_2" in (hop.tls_info or "")
    assert hop.queue_id == "14643A91718"
    assert hop.for_recipient == "<analyst@example.org>"
    assert hop.primary_ip == "203.0.113.15"
    assert hop.primary_ip_class is IPClass.DOCUMENTATION
    assert hop.used_tls is True


def test_by_only_received_line_is_not_dropped():
    """A hop with no 'from' clause must survive parsing.

    ``Received: by host (PGP Universal, from userid 997)`` is what locally-injected
    mail looks like coming from a submission agent or encryption gateway. Parsers
    anchored on ``from\\s+(.*?)\\s+by`` — which is what MHA uses and what
    MailHeaderDetective inherited — discard the line entirely. That deletes the origin
    hop and makes the *second* hop look like the source of the message.
    """
    raw = (
        "by keys1.example.com (PGP Universal, from userid 997) "
        "id 14643A91718; Wed, 22 Oct 2025 09:28:49 +0300 (+03)"
    )
    hop = parse_received_line(raw, 0)

    assert hop.by_host == "keys1.example.com"
    assert hop.queue_id == "14643A91718"
    assert hop.timestamp_utc is not None
    # The word 'from' inside the comment must not be read as a from clause.
    assert hop.from_host is None
    assert any("no 'from' clause" in w for w in hop.warnings)


def test_clause_keyword_inside_comment_is_not_a_clause():
    """Depth-zero scanning: 'for' and 'from' inside a comment are prose, not clauses."""
    raw = (
        "from a.example.com (scanned for viruses by appliance) "
        "by b.example.org; Wed, 22 Oct 2025 09:28:49 +0000"
    )
    hop = parse_received_line(raw, 0)

    assert hop.from_host == "a.example.com"
    assert hop.by_host == "b.example.org"
    assert hop.for_recipient is None


def test_nonstandard_tz_parenthetical():
    """``+0300 (+03)`` appears in real mail and is not a legal tz abbreviation."""
    hop = parse_received_line(
        "by mail.example.com; Wed, 22 Oct 2025 09:28:49 +0300 (+03)", 0
    )
    assert hop.timestamp_utc == datetime(2025, 10, 22, 6, 28, 49, tzinfo=UTC)
    assert hop.original_offset == "+0300"


def test_trailing_dot_fqdn_is_stripped():
    """``mail.example.com.`` and ``mail.example.com`` are the same host."""
    hop = parse_received_line(
        "from mail.example.com. by mx.example.org; Wed, 22 Oct 2025 09:28:49 +0000", 0
    )
    assert hop.from_host == "mail.example.com"


def test_plain_esmtp_is_reported_as_not_encrypted():
    hop = parse_received_line(
        "from a.example.com by b.example.org with ESMTP; "
        "Wed, 22 Oct 2025 09:28:49 +0000",
        0,
    )
    assert hop.protocol == "ESMTP"
    assert hop.used_tls is False


def test_ipv6_hop_is_extracted():
    """IPv4-only extraction silently loses every hop in a v6 path."""
    hop = parse_received_line(
        "from mail.example.com ([2001:db8::1]) by mx.example.org; "
        "Wed, 22 Oct 2025 09:28:49 +0000",
        0,
    )
    assert hop.primary_ip == "2001:db8::1"
    assert hop.primary_ip_class is IPClass.DOCUMENTATION


def test_timestamp_fragments_are_not_parsed_as_addresses():
    """``09:28:49`` matches a loose IPv6 pattern and must be rejected by validation."""
    hop = parse_received_line(
        "by mail.example.com; Wed, 22 Oct 2025 09:28:49 +0000", 0
    )
    assert hop.ip_addresses == ()
    assert hop.primary_ip is None


def test_helo_claim_and_observed_rdns_are_kept_apart():
    """The bare hostname is a sender claim; the parenthesised name was looked up."""
    hop = parse_received_line(
        "from totally-legit.example.com (suspicious.example.net [198.51.100.7]) "
        "by mx.example.org; Wed, 22 Oct 2025 09:28:49 +0000",
        0,
    )
    assert hop.from_host == "totally-legit.example.com"
    assert hop.from_rdns == "suspicious.example.net"


def test_malformed_hop_emits_warning_and_is_retained():
    hop = parse_received_line("complete garbage with no structure", 0)
    assert hop.warnings
    assert hop.raw == "complete garbage with no structure"


def test_missing_timestamp_warns_but_does_not_crash():
    hop = parse_received_line("from a.example.com by b.example.org", 0)
    assert hop.timestamp_utc is None
    assert any("timestamp" in w for w in hop.warnings)


# ---------------------------------------------------------------------------
# Delay arithmetic
# ---------------------------------------------------------------------------


def _hop_at(index: int, when: datetime):
    return parse_received_line(
        f"by hop{index}.example.com; {when.strftime('%a, %d %b %Y %H:%M:%S %z')}", index
    )


def test_negative_delay_reported_as_skew_not_86399():
    """The single most consequential bug in this tool category.

    ``timedelta.seconds`` is the within-day remainder, not the total. Python
    normalises a negative timedelta to ``days=-1, seconds=86399``, so one second of
    backwards clock skew is reported as 86,399 seconds — and the customary
    ``if delay < 0: delay = 0`` guard never fires, because ``.seconds`` is never
    negative. MHA has this bug and MailHeaderDetective copied it verbatim.
    """
    earlier = datetime(2025, 10, 22, 9, 0, 1, tzinfo=UTC)
    later = datetime(2025, 10, 22, 9, 0, 0, tzinfo=UTC)  # 1s backwards

    delays = compute_delays([_hop_at(0, earlier), _hop_at(1, later)])

    assert len(delays) == 1
    assert delays[0].seconds == pytest.approx(-1.0)
    assert delays[0].seconds != 86399
    assert delays[0].is_clock_skew is True
    assert "backwards" in (delays[0].note or "")


def test_multi_day_delay_is_not_truncated_to_within_day_remainder():
    """A 25-hour delay must report as 25 hours, not 1 hour."""
    start = datetime(2025, 10, 21, 8, 0, 0, tzinfo=UTC)
    end = datetime(2025, 10, 22, 9, 0, 0, tzinfo=UTC)

    delays = compute_delays([_hop_at(0, start), _hop_at(1, end)])

    assert delays[0].seconds == pytest.approx(25 * 3600)


def test_clock_skew_annotated_not_swallowed():
    earlier = datetime(2025, 10, 22, 9, 0, 30, tzinfo=UTC)
    later = datetime(2025, 10, 22, 9, 0, 0, tzinfo=UTC)

    delays = compute_delays([_hop_at(0, earlier), _hop_at(1, later)])

    assert delays[0].is_clock_skew is True
    assert delays[0].note is not None
    assert delays[0].seconds < 0  # kept, not clamped to zero


def test_total_transit_ignores_negative_hops():
    """One bad clock must not subtract from the rest of the route."""
    raw = "\n".join(
        [
            "Received: by c.example.com; Wed, 22 Oct 2025 09:00:10 +0000",
            "Received: by b.example.com; Wed, 22 Oct 2025 08:59:55 +0000",
            "Received: by a.example.com; Wed, 22 Oct 2025 09:00:00 +0000",
        ]
    )
    route = build_route(parse_headers(raw))

    # chronological: a (09:00:00) -> b (08:59:55) -> c (09:00:10)
    assert route.total_transit_seconds == pytest.approx(15.0)
    assert any(d.is_clock_skew for d in route.delays)


# ---------------------------------------------------------------------------
# Route reconstruction
# ---------------------------------------------------------------------------


def test_stored_order_is_newest_first_and_chronological_is_reversed():
    raw = "\n".join(
        [
            "Received: by third.example.com; Wed, 22 Oct 2025 09:00:02 +0000",
            "Received: by second.example.com; Wed, 22 Oct 2025 09:00:01 +0000",
            "Received: by first.example.com; Wed, 22 Oct 2025 09:00:00 +0000",
        ]
    )
    route = build_route(parse_headers(raw))

    assert [h.by_host for h in route.hops_header_order] == [
        "third.example.com",
        "second.example.com",
        "first.example.com",
    ]
    assert [h.by_host for h in route.hops_chronological] == [
        "first.example.com",
        "second.example.com",
        "third.example.com",
    ]


def test_no_trusted_config_yields_low_confidence_and_says_so():
    """Absence of configuration must produce an honest 'unknown', not a guess."""
    raw = "Received: from a.example.com by b.example.org; Wed, 22 Oct 2025 09:00:00 +0000"
    route = build_route(parse_headers(raw))

    assert route.first_trusted_hop_index is None
    assert route.trust_boundary_confidence is Confidence.LOW
    assert "no trusted infrastructure is configured" in route.trust_boundary_explanation
    assert route.missing_evidence


def test_trust_boundary_found_when_configured():
    raw = "\n".join(
        [
            "Received: by mx.corp.example; Wed, 22 Oct 2025 09:00:02 +0000",
            "Received: from evil.example.net ([198.51.100.9]) by mx.corp.example;"
            " Wed, 22 Oct 2025 09:00:01 +0000",
            "Received: from claimed.example.org by attacker-controlled.example.net;"
            " Wed, 22 Oct 2025 09:00:00 +0000",
        ]
    )
    route = build_route(parse_headers(raw), trusted_domains=("corp.example",))

    assert route.first_trusted_hop_index is not None
    assert route.trust_boundary_confidence in (Confidence.MEDIUM, Confidence.HIGH)
    assert "corp.example" in route.trust_boundary_explanation


def test_private_addresses_are_classified_not_treated_as_sources():
    hop = parse_received_line(
        "from internal.corp.example ([10.1.2.3]) by mx.corp.example; "
        "Wed, 22 Oct 2025 09:00:00 +0000",
        0,
    )
    assert hop.primary_ip_class is IPClass.PRIVATE


def test_empty_header_produces_empty_route_without_crashing():
    route = build_route(parse_headers("Subject: no received headers here"))
    assert route.hops_header_order == ()
    assert route.total_transit_seconds is None
