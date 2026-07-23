"""Identity extraction and comparison tests."""

from __future__ import annotations

from app.core.header_parser import parse_headers
from app.core.identity_analyzer import build_identities, compare_identities
from app.core.models import AlignmentResult


def test_from_identity_extracted():
    parsed = parse_headers("From: Alice <alice@bank.example>\n")
    identities = build_identities(parsed)
    from_id = next(i for i in identities if i.source_header == "From")
    assert from_id.display_name == "Alice"
    assert from_id.address == "alice@bank.example"
    assert from_id.domain == "bank.example"


def test_absent_field_produces_no_identity():
    parsed = parse_headers("From: alice@bank.example\n")
    identities = build_identities(parsed)
    assert not any(i.source_header == "Reply-To" for i in identities)


def test_return_path_null_bounce_is_handled():
    parsed = parse_headers("Return-Path: <>\nFrom: alice@bank.example\n")
    identities = build_identities(parsed)
    rp = next(i for i in identities if i.source_header == "Return-Path")
    assert rp.address is None
    assert "null return path" in rp.warnings[0]


def test_return_path_bare_address():
    parsed = parse_headers("Return-Path: <bounce@mailer.example.net>\nFrom: a@bank.example\n")
    identities = build_identities(parsed)
    rp = next(i for i in identities if i.source_header == "Return-Path")
    assert rp.domain == "mailer.example.net"


def test_message_id_domain_extracted():
    parsed = parse_headers("Message-ID: <20251022062849.ABC@keys1.bank.example>\nFrom: a@bank.example\n")
    identities = build_identities(parsed)
    mid = next(i for i in identities if i.source_header == "Message-ID")
    assert mid.domain == "keys1.bank.example"


def test_message_id_without_at_sign_warns():
    parsed = parse_headers("Message-ID: <not-a-valid-id>\nFrom: a@bank.example\n")
    identities = build_identities(parsed)
    mid = next(i for i in identities if i.source_header == "Message-ID")
    assert mid.domain is None
    assert mid.warnings


def test_multiple_addresses_in_from_warns_and_keeps_first():
    parsed = parse_headers("From: alice@bank.example, mallory@evil.example\n")
    identities = build_identities(parsed)
    from_id = next(i for i in identities if i.source_header == "From")
    assert from_id.address == "alice@bank.example"
    assert from_id.warnings


# ---------------------------------------------------------------------------
# Comparisons
# ---------------------------------------------------------------------------


def test_reply_to_mismatch_detected():
    parsed = parse_headers(
        "From: Billing <billing@bank.example>\n"
        "Reply-To: collections@payments-secure.example\n"
    )
    identities = build_identities(parsed)
    comparisons = compare_identities(identities)
    reply_to = next(c for c in comparisons if c.right == "Reply-To")
    assert reply_to.result is AlignmentResult.MISMATCH
    assert "different organisation" in reply_to.explanation


def test_return_path_subdomain_is_not_mismatch():
    parsed = parse_headers(
        "From: alice@bank.example\nReturn-Path: <bounce@mail.bank.example>\n"
    )
    identities = build_identities(parsed)
    comparisons = compare_identities(identities)
    rp = next(c for c in comparisons if c.right == "Return-Path")
    assert rp.result is AlignmentResult.SUBDOMAIN


def test_exact_match_reported():
    parsed = parse_headers(
        "From: alice@bank.example\nSender: alice@bank.example\n"
    )
    identities = build_identities(parsed)
    comparisons = compare_identities(identities)
    sender = next(c for c in comparisons if c.right == "Sender")
    assert sender.result is AlignmentResult.EXACT


def test_no_from_domain_produces_no_comparisons():
    parsed = parse_headers("Reply-To: bob@other.example\n")
    identities = build_identities(parsed)
    assert compare_identities(identities) == []


def test_comparisons_are_always_against_from_not_each_other():
    """Reply-To vs Return-Path is not a standard analyst check."""
    parsed = parse_headers(
        "From: alice@bank.example\n"
        "Reply-To: bob@other.example\n"
        "Return-Path: <bounce@another.example>\n"
    )
    comparisons = compare_identities(build_identities(parsed))
    assert all(c.left == "From" for c in comparisons)
