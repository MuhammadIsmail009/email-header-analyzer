"""Independent verification tests — all fully offline.

Every DNS answer comes from :class:`StaticResolver`. The suite requires no network
access and no API keys, which is a hard requirement: a test suite that needs the
internet is a test suite that gets skipped.

The DKIM tests sign a real message with a real RSA key and verify the real signature.
They are not assertions against a mock.
"""

from __future__ import annotations

import dkim

from app.core.models import VerificationOutcome
from app.core.verification import (
    StaticResolver,
    check_dnsbl,
    check_forward_reverse,
    parse_dmarc_record,
    verify_dkim,
    verify_dmarc,
    verify_spf,
)
from tests.fixtures.dkim_test_key import (
    PRIVATE_KEY_PEM,
    PUBLIC_KEY_RECORD,
    TEST_DOMAIN,
    TEST_SELECTOR,
)

# ---------------------------------------------------------------------------
# SPF
# ---------------------------------------------------------------------------

SPF_RESOLVER = StaticResolver(
    txt={
        "bank.example": ["v=spf1 ip4:203.0.113.15 -all"],
        "soft.example": ["v=spf1 ip4:203.0.113.1 ~all"],
        "nospf.example": [],
        "broken.example": StaticResolver.UNAVAILABLE,
    }
)


def test_spf_authorized_ip_verifies_pass():
    result = verify_spf(
        "203.0.113.15", "alice@bank.example", "mail.bank.example", SPF_RESOLVER
    )
    assert result.outcome is VerificationOutcome.VERIFIED_PASS
    assert result.record == "v=spf1 ip4:203.0.113.15 -all"
    assert "Independently evaluated" in result.detail


def test_spf_unauthorized_ip_verifies_fail():
    result = verify_spf(
        "198.51.100.9", "alice@bank.example", "evil.example", SPF_RESOLVER
    )
    assert result.outcome is VerificationOutcome.VERIFIED_FAIL
    assert "hard fail" in result.detail


def test_spf_softfail_is_not_a_pass():
    result = verify_spf("198.51.100.9", "a@soft.example", "x.example", SPF_RESOLVER)
    assert result.outcome is VerificationOutcome.VERIFIED_FAIL
    assert "soft fail" in result.detail


def test_spf_no_record_is_not_possible_not_a_fail():
    """Absence of a record is neither authorisation nor rejection."""
    result = verify_spf("198.51.100.9", "a@nospf.example", "x.example", SPF_RESOLVER)
    assert result.outcome is VerificationOutcome.NOT_POSSIBLE
    assert "publishes no SPF record" in result.detail
    assert "is not a pass" in result.detail


def test_spf_dns_failure_is_error_not_fail():
    """An outage must not masquerade as evidence about the sender."""
    result = verify_spf("198.51.100.9", "a@broken.example", "x", SPF_RESOLVER)
    assert result.outcome is VerificationOutcome.ERROR
    assert result.error


def test_spf_without_connecting_ip_is_not_possible():
    result = verify_spf(None, "a@bank.example", "x", SPF_RESOLVER)
    assert result.outcome is VerificationOutcome.NOT_POSSIBLE


# ---------------------------------------------------------------------------
# DMARC
# ---------------------------------------------------------------------------

DMARC_RESOLVER = StaticResolver(
    txt={
        "_dmarc.bank.example": [
            "v=DMARC1; p=quarantine; pct=90; adkim=r; aspf=r; rua=mailto:d@bank.example"
        ],
        "_dmarc.strict.example": ["v=DMARC1; p=reject; adkim=s; aspf=s"],
        "_dmarc.sub.bank.example": [],
        "_dmarc.nodmarc.example": [],
    }
)


def test_dmarc_record_parsing():
    tags = parse_dmarc_record("v=DMARC1; p=quarantine; pct=90; adkim=r; aspf=r")
    assert tags["p"] == "quarantine"
    assert tags["pct"] == "90"
    assert tags["adkim"] == "r"


def test_dmarc_passes_via_aligned_spf():
    result, spf_align, _, policy = verify_dmarc(
        header_from_domain="bank.example",
        spf_domain="bank.example",
        spf_passed=True,
        dkim_domains=(),
        dkim_passed=False,
        resolver=DMARC_RESOLVER,
    )
    assert result.outcome is VerificationOutcome.VERIFIED_PASS
    assert policy == "quarantine"
    assert "via SPF" in result.detail


def test_dmarc_fails_when_spf_passes_but_does_not_align():
    """The ESP-relay spoofing case, evaluated from evidence rather than believed."""
    result, _, _, _ = verify_dmarc(
        header_from_domain="bank.example",
        spf_domain="mailer.example.net",
        spf_passed=True,
        dkim_domains=(),
        dkim_passed=False,
        resolver=DMARC_RESOLVER,
    )
    assert result.outcome is VerificationOutcome.VERIFIED_FAIL
    assert "does not align" in result.detail
    assert "quarantine" in result.detail


def test_dmarc_falls_back_to_organizational_domain():
    """RFC 7489 §6.6.3 — without this every subdomain looks unprotected."""
    result, _, _, policy = verify_dmarc(
        header_from_domain="sub.bank.example",
        spf_domain="sub.bank.example",
        spf_passed=True,
        dkim_domains=(),
        dkim_passed=False,
        resolver=DMARC_RESOLVER,
    )
    assert policy == "quarantine"
    assert result.outcome is VerificationOutcome.VERIFIED_PASS


def test_dmarc_strict_alignment_rejects_subdomain():
    result, _, _, _ = verify_dmarc(
        header_from_domain="strict.example",
        spf_domain="mail.strict.example",
        spf_passed=True,
        dkim_domains=(),
        dkim_passed=False,
        resolver=DMARC_RESOLVER,
    )
    assert result.outcome is VerificationOutcome.VERIFIED_FAIL


def test_dmarc_relaxed_alignment_accepts_subdomain():
    result, _, _, _ = verify_dmarc(
        header_from_domain="bank.example",
        spf_domain="mail.bank.example",
        spf_passed=True,
        dkim_domains=(),
        dkim_passed=False,
        resolver=DMARC_RESOLVER,
    )
    assert result.outcome is VerificationOutcome.VERIFIED_PASS


def test_no_dmarc_record_is_a_domain_weakness_not_message_evidence():
    result, _, _, policy = verify_dmarc(
        header_from_domain="nodmarc.example",
        spf_domain="nodmarc.example",
        spf_passed=True,
        dkim_domains=(),
        dkim_passed=False,
        resolver=DMARC_RESOLVER,
    )
    assert result.outcome is VerificationOutcome.NOT_POSSIBLE
    assert policy is None
    assert "weakness of the domain, not evidence about this message" in result.detail


def test_dmarc_passes_via_dkim_when_spf_fails():
    result, _, _, _ = verify_dmarc(
        header_from_domain="bank.example",
        spf_domain="mailer.example.net",
        spf_passed=False,
        dkim_domains=("bank.example",),
        dkim_passed=True,
        resolver=DMARC_RESOLVER,
    )
    assert result.outcome is VerificationOutcome.VERIFIED_PASS
    assert "via DKIM" in result.detail


# ---------------------------------------------------------------------------
# DKIM — real signature, real key, no network
# ---------------------------------------------------------------------------

DKIM_RESOLVER = StaticResolver(
    txt={f"{TEST_SELECTOR}._domainkey.{TEST_DOMAIN}": [PUBLIC_KEY_RECORD]}
)

_BASE_HEADERS = (
    f"From: Alice <alice@{TEST_DOMAIN}>\r\n"
    "To: bob@example.org\r\n"
    "Subject: Quarterly statement\r\n"
    "Date: Wed, 22 Oct 2025 09:28:49 +0000\r\n"
)
_BODY = "This is the message body.\r\n"


def _signed_message(body: str = _BODY) -> tuple[str, str]:
    """Sign a synthetic message and return ``(header_text, body)``."""
    message = (_BASE_HEADERS + "\r\n" + body).encode()
    signature = dkim.sign(
        message,
        TEST_SELECTOR.encode(),
        TEST_DOMAIN.encode(),
        PRIVATE_KEY_PEM.encode(),
    ).decode()
    return signature + _BASE_HEADERS, body


def test_dkim_full_message_verifies_including_body_hash():
    headers, body = _signed_message()
    result = verify_dkim(headers, body, DKIM_RESOLVER)

    assert result.outcome is VerificationOutcome.VERIFIED_PASS
    assert result.checked_domain == TEST_DOMAIN
    assert "body hash" in (result.scope or "")
    assert "Both the signed headers and the body hash verify" in result.detail


def test_dkim_headers_only_verifies_signature_and_says_body_was_not_checked():
    """The staged claim. Headers alone still prove the signed headers are authentic."""
    headers, _ = _signed_message()
    result = verify_dkim(headers, None, DKIM_RESOLVER)

    assert result.outcome is VerificationOutcome.VERIFIED_PASS
    assert "body hash not checked" in (result.scope or "")
    assert "does NOT confirm body integrity" in result.detail
    assert "Upload the full .eml" in result.detail


def test_dkim_detects_tampered_body():
    headers, _ = _signed_message()
    result = verify_dkim(headers, "This body has been altered.\r\n", DKIM_RESOLVER)
    assert result.outcome is VerificationOutcome.VERIFIED_FAIL


def test_dkim_detects_tampered_signed_header():
    """Modifying a signed header must invalidate the signature even without the body."""
    headers, _ = _signed_message()
    tampered = headers.replace("Subject: Quarterly statement", "Subject: Urgent payment")
    result = verify_dkim(tampered, None, DKIM_RESOLVER)
    assert result.outcome is VerificationOutcome.VERIFIED_FAIL


def test_dkim_absent_signature_is_not_a_failure():
    result = verify_dkim(_BASE_HEADERS, None, DKIM_RESOLVER)
    assert result.outcome is VerificationOutcome.NOT_POSSIBLE
    assert "not an authentication failure" in result.detail


def test_dkim_key_not_published_does_not_verify():
    headers, body = _signed_message()
    result = verify_dkim(headers, body, StaticResolver(txt={}))
    assert result.outcome in (
        VerificationOutcome.VERIFIED_FAIL,
        VerificationOutcome.ERROR,
    )
    assert result.outcome is not VerificationOutcome.VERIFIED_PASS


def test_dkim_result_mentions_forwarders_break_dkim_legitimately():
    headers, _ = _signed_message()
    tampered = headers.replace("Subject: Quarterly statement", "Subject: [LIST] hi")
    result = verify_dkim(tampered, None, DKIM_RESOLVER)
    assert "mailing lists and forwarders" in result.detail


# ---------------------------------------------------------------------------
# Forward/reverse DNS and DNSBL
# ---------------------------------------------------------------------------


def test_forward_confirmed_reverse_dns():
    resolver = StaticResolver(
        ptr={"93.184.216.34": ["mail.bank.example"]},
        a={"mail.bank.example": ["93.184.216.34"]},
    )
    result = check_forward_reverse("93.184.216.34", resolver)
    assert result.forward_confirmed is True
    assert "Forward-confirmed" in result.detail


def test_reverse_dns_without_forward_confirmation_is_flagged():
    resolver = StaticResolver(
        ptr={"93.184.216.34": ["claimed.example"]},
        a={"claimed.example": ["198.51.100.1"]},
    )
    result = check_forward_reverse("93.184.216.34", resolver)
    assert result.forward_confirmed is False
    assert "does not resolve back" in result.detail


def test_missing_reverse_dns_is_hygiene_not_indicator():
    result = check_forward_reverse("93.184.216.34", StaticResolver(ptr={}))
    assert result.forward_confirmed is False
    assert "hygiene observation rather than an indicator" in result.detail


def test_private_ip_skips_forward_reverse():
    result = check_forward_reverse("10.1.2.3", StaticResolver())
    assert "not meaningful outside the network" in result.detail


ZONES = ("zen.spamhaus.org", "bl.spamcop.net")


def test_dnsbl_listing_detected():
    resolver = StaticResolver(listed=frozenset({"34.216.184.93.zen.spamhaus.org"}))
    result = check_dnsbl("93.184.216.34", resolver, ZONES)
    assert result.is_listed is True
    assert "zen.spamhaus.org" in result.listed_on


def test_dnsbl_absence_is_never_reported_as_clean():
    """The wording matters: 'not listed' is close to meaningless on its own."""
    result = check_dnsbl("93.184.216.34", StaticResolver(listed=frozenset()), ZONES)
    assert result.is_listed is False
    assert "not evidence that the sender is safe" in result.detail
    # The IP itself must never be described as clean; only the *caveat* may use the
    # word, as in "phishing frequently originates from clean infrastructure".
    lowered = result.detail.lower()
    assert "is clean" not in lowered
    assert f"{result.ip} is clean" not in lowered


def test_dnsbl_skips_non_public_addresses():
    result = check_dnsbl("192.168.1.1", StaticResolver(), ZONES)
    assert result.checked == ()
    assert "not submitted to any blocklist" in result.detail


def test_dnsbl_skips_documentation_addresses():
    """RFC 5737 ranges appear only in synthetic samples.

    Querying one would tell a blocklist operator we are analysing a sample, and the
    answer would be meaningless anyway. The skip is deliberate.
    """
    result = check_dnsbl("203.0.113.15", StaticResolver(), ZONES)
    assert result.checked == ()
    assert "documentation address space" in result.detail


def test_spf_include_chain_resolves_through_injected_resolver_only():
    """Proves pyspf cannot escape to the real network.

    pyspf dispatches DNS through a module-level global and treats an empty cache entry
    as a miss, so seeding its cache is not enough — it will silently query the internet
    for anything it has not been given. verify_spf swaps that global for an adapter
    over our resolver. This test drives an ``include:`` chain, which is the path that
    escaped before, and asserts the nested lookup was answered by the fake.
    """
    resolver = StaticResolver(
        txt={
            "chain.example": ["v=spf1 include:_spf.provider.example -all"],
            "_spf.provider.example": ["v=spf1 ip4:198.51.100.20 -all"],
        }
    )
    authorized = verify_spf(
        "198.51.100.20", "a@chain.example", "mail.chain.example", resolver
    )
    assert authorized.outcome is VerificationOutcome.VERIFIED_PASS

    rejected = verify_spf(
        "203.0.113.99", "a@chain.example", "mail.chain.example", resolver
    )
    assert rejected.outcome is VerificationOutcome.VERIFIED_FAIL


def test_spf_dns_outage_midchain_is_error_not_fail():
    resolver = StaticResolver(
        txt={
            "chain.example": ["v=spf1 include:_spf.provider.example -all"],
            "_spf.provider.example": StaticResolver.UNAVAILABLE,
        }
    )
    result = verify_spf("198.51.100.20", "a@chain.example", "x", resolver)
    # pyspf catches the TempError internally and reports a 'temperror' result, which
    # maps to ERROR. The point is that a DNS outage partway through an include: chain
    # must never be reported as a definite SPF fail.
    assert result.outcome is VerificationOutcome.ERROR
    assert result.outcome is not VerificationOutcome.VERIFIED_FAIL
    assert "inconclusive" in result.detail or "temporary" in result.detail


def test_forward_reverse_skip_is_distinct_from_unconfirmed():
    """Regression: a documentation/private IP (checked=False, forward_confirmed=False
    by dataclass default) was indistinguishable from a public IP that was checked and
    genuinely failed to confirm (also forward_confirmed=False). Conflating the two
    made every RFC 5737 sample IP report 'no forward-confirmed reverse DNS' as a
    finding, even though the check never actually ran for it."""
    skipped = check_forward_reverse("203.0.113.15", StaticResolver())
    assert skipped.checked is False
    assert skipped.forward_confirmed is False

    genuinely_unconfirmed = check_forward_reverse(
        "93.184.216.34",
        StaticResolver(ptr={"93.184.216.34": []}),
    )
    assert genuinely_unconfirmed.checked is True
    assert genuinely_unconfirmed.forward_confirmed is False
