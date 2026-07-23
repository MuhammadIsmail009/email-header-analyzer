"""Authentication evidence parsing and trust-marking tests.

The central assertion in this file is that an ``Authentication-Results`` header is
never believed on sight. RFC 8601 §7.1 warns it is forgeable; several widely-used tools
render a green PASS from whatever string they find.
"""

from __future__ import annotations

import pytest

from app.core.authentication_parser import (
    arc_chain_status,
    build_authentication_summary,
    dkim_signing_domains,
    parse_authentication_results,
    parse_received_spf,
    parse_tag_value_header,
    trusted_result,
)
from app.core.header_parser import parse_headers
from app.core.models import AlignmentResult, AuthMethod, AuthResult, TrustStatus

TRUSTED = ("google.com",)


# ---------------------------------------------------------------------------
# Authentication-Results grammar
# ---------------------------------------------------------------------------


def test_basic_authentication_results():
    authserv, evidence = parse_authentication_results(
        "mx.google.com; spf=pass smtp.mailfrom=alice@example.com; dkim=fail "
        "header.d=example.com; dmarc=pass header.from=example.com",
        trusted_domains=TRUSTED,
    )
    assert authserv == "mx.google.com"
    assert {(e.method, e.result) for e in evidence} == {
        (AuthMethod.SPF, AuthResult.PASS),
        (AuthMethod.DKIM, AuthResult.FAIL),
        (AuthMethod.DMARC, AuthResult.PASS),
    }
    spf = next(e for e in evidence if e.method is AuthMethod.SPF)
    assert spf.properties["smtp.mailfrom"] == "alice@example.com"


def test_nested_parens_in_auth_results():
    """``dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=x`` must parse.

    A pattern that stops at the first ``)`` misreads this, and the ``header.from``
    property — the thing alignment depends on — is lost.
    """
    _, evidence = parse_authentication_results(
        "mx.google.com; spf=pass smtp.mailfrom=a@example.com; "
        "dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=example.com",
        trusted_domains=TRUSTED,
    )
    dmarc = next(e for e in evidence if e.method is AuthMethod.DMARC)
    assert dmarc.result is AuthResult.PASS
    assert dmarc.properties["header.from"] == "example.com"
    assert "QUARANTINE" in (dmarc.reason or "")


def test_semicolon_inside_comment_does_not_split_segments():
    _, evidence = parse_authentication_results(
        "mx.example.org; spf=pass (sender ok; verified locally) "
        "smtp.mailfrom=a@example.com",
        trusted_domains=("example.org",),
    )
    assert len(evidence) == 1
    assert evidence[0].properties["smtp.mailfrom"] == "a@example.com"


def test_quoted_reason_is_preserved():
    _, evidence = parse_authentication_results(
        'mx.example.org; dkim=fail reason="body hash did not verify" '
        "header.d=example.com",
        trusted_domains=("example.org",),
    )
    assert evidence[0].reason == "body hash did not verify"


@pytest.mark.parametrize(
    "token,expected",
    [
        ("pass", AuthResult.PASS),
        ("fail", AuthResult.FAIL),
        ("softfail", AuthResult.SOFTFAIL),
        ("neutral", AuthResult.NEUTRAL),
        ("none", AuthResult.NONE),
        ("temperror", AuthResult.TEMPERROR),
        ("permerror", AuthResult.PERMERROR),
        ("policy", AuthResult.POLICY),
        ("wat", AuthResult.UNKNOWN),
    ],
)
def test_all_rfc8601_result_values(token, expected):
    _, evidence = parse_authentication_results(f"mx.example.org; spf={token}")
    assert evidence[0].result is expected


def test_method_with_version_is_accepted():
    _, evidence = parse_authentication_results("mx.example.org; dkim/1=pass")
    assert evidence[0].method is AuthMethod.DKIM


def test_unknown_method_is_skipped_not_crashed():
    _, evidence = parse_authentication_results(
        "mx.example.org; spf=pass; somefuturemethod=pass"
    )
    assert [e.method for e in evidence] == [AuthMethod.SPF]


# ---------------------------------------------------------------------------
# Trust marking — the security-critical behaviour
# ---------------------------------------------------------------------------


def test_untrusted_authserv_is_marked_untrusted():
    """The forged-header attack. An attacker writes this into their own message."""
    _, evidence = parse_authentication_results(
        "yourcompany.com; spf=pass; dkim=pass; dmarc=pass",
        trusted_domains=("google.com",),
    )
    assert all(e.trust is TrustStatus.UNTRUSTED for e in evidence)
    assert all(e.result is AuthResult.PASS for e in evidence)  # claimed, but worthless


def test_trusted_authserv_is_marked_trusted():
    _, evidence = parse_authentication_results(
        "mx.google.com; spf=pass", trusted_domains=("google.com",)
    )
    assert evidence[0].trust is TrustStatus.TRUSTED


def test_no_configuration_means_unknown_not_trusted():
    """An unconfigured deployment must not believe arbitrary headers."""
    _, evidence = parse_authentication_results("anything.example; spf=pass")
    assert evidence[0].trust is TrustStatus.UNKNOWN


def test_trusted_result_ignores_untrusted_assertions():
    parsed = parse_headers(
        "Authentication-Results: attacker.example; spf=pass; dmarc=pass\n"
        "From: alice@example.com\n"
    )
    summary = build_authentication_summary(parsed, trusted_domains=("google.com",))
    assert trusted_result(summary, AuthMethod.SPF) is None
    assert trusted_result(summary, AuthMethod.DMARC) is None


# ---------------------------------------------------------------------------
# Received-SPF
# ---------------------------------------------------------------------------


def test_received_spf_parsing():
    evidence = parse_received_spf(
        "pass (google.com: domain of alice@example.com designates 203.0.113.15 "
        "as permitted sender) client-ip=203.0.113.15;",
        trusted_domains=TRUSTED,
    )
    assert evidence is not None
    assert evidence.result is AuthResult.PASS
    assert evidence.properties["client-ip"] == "203.0.113.15"
    assert evidence.asserted_by == "google.com"
    assert evidence.trust is TrustStatus.TRUSTED


# ---------------------------------------------------------------------------
# DKIM-Signature / ARC
# ---------------------------------------------------------------------------


def test_dkim_tag_value_parsing_strips_folding_from_base64():
    tags = parse_tag_value_header(
        "v=1; a=rsa-sha256; d=example.com; s=sel; h=from:to:subject; "
        "bh=abc def ghi; b=sig nature here"
    )
    assert tags["d"] == "example.com"
    assert tags["h"] == "from:to:subject"
    assert tags["bh"] == "abcdefghi"  # folding whitespace removed
    assert tags["b"] == "signaturehere"


def test_multiple_dkim_signatures_all_collected():
    parsed = parse_headers(
        "DKIM-Signature: v=1; d=example.com; s=a; b=xx\n"
        "DKIM-Signature: v=1; d=mailer.example.net; s=b; b=yy\n"
    )
    assert dkim_signing_domains(parsed) == ["example.com", "mailer.example.net"]


def test_arc_cv_none_is_first_hop_not_a_failure():
    parsed = parse_headers("ARC-Seal: i=1; a=rsa-sha256; cv=none; d=example.com; s=a; b=x\n")
    present, status = arc_chain_status(parsed)
    assert present is True
    assert "first ARC hop" in (status or "")


def test_arc_cv_fail_is_reported():
    parsed = parse_headers(
        "ARC-Seal: i=2; cv=fail; d=example.com; s=a; b=x\n"
        "ARC-Seal: i=1; cv=none; d=example.net; s=b; b=y\n"
    )
    _, status = arc_chain_status(parsed)
    assert "cv=fail" in (status or "")


def test_arc_absent_reports_absent():
    assert arc_chain_status(parse_headers("From: a@example.com\n")) == (False, None)


# ---------------------------------------------------------------------------
# Alignment — computed here, never read from a header
# ---------------------------------------------------------------------------


def test_spf_pass_without_alignment_is_flagged():
    """The ESP-relay spoofing case: SPF passes on the relay's own domain."""
    parsed = parse_headers(
        "Authentication-Results: mx.google.com; spf=pass "
        "smtp.mailfrom=bounce@mailer.example.net\n"
        "From: Billing <billing@bank.example>\n"
        "Return-Path: <bounce@mailer.example.net>\n"
    )
    summary = build_authentication_summary(parsed, trusted_domains=TRUSTED)

    assert summary.header_from_domain == "bank.example"
    assert summary.spf_alignment is AlignmentResult.MISMATCH
    assert any("does not align" in w for w in summary.warnings)


def test_relaxed_alignment_across_subdomain_counts_as_aligned():
    parsed = parse_headers(
        "Authentication-Results: mx.google.com; spf=pass "
        "smtp.mailfrom=alice@mail.example.com\n"
        "From: alice@example.com\n"
    )
    summary = build_authentication_summary(parsed, trusted_domains=TRUSTED)
    assert summary.spf_alignment in (
        AlignmentResult.SUBDOMAIN,
        AlignmentResult.ORGANIZATIONAL,
    )


def test_dkim_alignment_uses_best_of_multiple_signatures():
    """One aligned signature satisfies DMARC, so the best relationship wins."""
    parsed = parse_headers(
        "DKIM-Signature: v=1; d=mailer.example.net; s=a; b=x\n"
        "DKIM-Signature: v=1; d=example.com; s=b; b=y\n"
        "From: alice@example.com\n"
    )
    summary = build_authentication_summary(parsed)
    assert summary.dkim_alignment is AlignmentResult.EXACT


def test_missing_authentication_is_reported_as_absent_not_as_pass():
    parsed = parse_headers("From: alice@example.com\nSubject: hi\n")
    summary = build_authentication_summary(parsed)

    assert summary.evidence == ()
    assert any("not recorded by any receiving system" in w for w in summary.warnings)


def test_unconfigured_trust_produces_an_explicit_warning():
    parsed = parse_headers(
        "Authentication-Results: mx.google.com; spf=pass\nFrom: a@example.com\n"
    )
    summary = build_authentication_summary(parsed)
    assert any("marked UNKNOWN trust" in w for w in summary.warnings)
