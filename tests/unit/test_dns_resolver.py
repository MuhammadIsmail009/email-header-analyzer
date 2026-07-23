"""Tests for the live, dnspython-backed :class:`DnsResolver`.

Every other test in this suite uses ``StaticResolver`` and never touches
``DnsResolver`` at all, which left it as the one class in the verification layer with
essentially no coverage — correct behaviour by construction (tests should not need
live DNS), but a real gap: nothing actually exercised ``DnsResolver``'s TXT
concatenation, its NXDOMAIN/NoAnswer/timeout handling, or its PTR/DNSBL name
construction.

These tests close that gap by mocking ``dns.resolver.Resolver.resolve`` directly —
the same technique ``respx`` provides for ``httpx``, applied by hand since dnspython
has no equivalent test double built in. Still fully offline.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import dns.exception
import dns.resolver
import pytest

from app.core.verification.resolver import DnsResolver, DnsUnavailable


def _resolver() -> DnsResolver:
    return DnsResolver(nameservers=("203.0.113.53",), timeout=1.0, lifetime=2.0)


def _txt_record(*chunks: bytes) -> MagicMock:
    """One fake TXT record whose ``.strings`` holds multiple <character-string>
    chunks — this is the shape dnspython returns for a TXT record long enough to be
    split across chunks (SPF and DKIM records routinely exceed the 255-byte limit for
    a single chunk), and those chunks must be concatenated, not treated as separate
    records."""
    record = MagicMock()
    record.strings = list(chunks)
    return record


def test_txt_record_concatenation():
    resolver = _resolver()
    answer = [_txt_record(b"v=spf1 ", b"ip4:203.0.113.15 ", b"-all")]
    with patch.object(dns.resolver.Resolver, "resolve", return_value=answer):
        result = resolver.txt("bank.example")
    assert result == ["v=spf1 ip4:203.0.113.15 -all"]


def test_txt_multiple_records_are_kept_separate():
    """Two distinct TXT records (e.g. SPF plus an unrelated verification record) must
    not be concatenated into one string — only chunks *within* a record are joined."""
    resolver = _resolver()
    answer = [_txt_record(b"v=spf1 -all"), _txt_record(b"google-site-verification=x")]
    with patch.object(dns.resolver.Resolver, "resolve", return_value=answer):
        result = resolver.txt("bank.example")
    assert result == ["v=spf1 -all", "google-site-verification=x"]


def test_txt_nxdomain_returns_empty_list_not_an_error():
    resolver = _resolver()
    with patch.object(
        dns.resolver.Resolver, "resolve", side_effect=dns.resolver.NXDOMAIN()
    ):
        assert resolver.txt("nosuchdomain.example") == []


def test_txt_no_answer_returns_empty_list():
    resolver = _resolver()
    with patch.object(
        dns.resolver.Resolver, "resolve", side_effect=dns.resolver.NoAnswer()
    ):
        assert resolver.txt("bank.example") == []


def test_txt_timeout_raises_dns_unavailable_not_swallowed():
    """A timeout must not be indistinguishable from 'no record' — see DnsUnavailable's
    docstring: a missing SPF record is a finding about the domain, a timeout is a
    finding about our own visibility."""
    resolver = _resolver()
    with patch.object(
        dns.resolver.Resolver, "resolve", side_effect=dns.exception.Timeout()
    ), pytest.raises(DnsUnavailable):
        resolver.txt("bank.example")


def test_txt_no_nameservers_raises_dns_unavailable():
    resolver = _resolver()
    with patch.object(
        dns.resolver.Resolver, "resolve", side_effect=dns.resolver.NoNameservers()
    ), pytest.raises(DnsUnavailable):
        resolver.txt("bank.example")


def test_a_record_lookup():
    """resolver.a() also probes AAAA and merges — here the AAAA probe finds nothing,
    so exactly one address should come back, not two copies of the A result."""
    resolver = _resolver()
    a_record = MagicMock()
    a_record.__str__ = lambda self: "203.0.113.15"

    def side_effect(name, rdtype, *a, **kw):
        if rdtype == "A":
            return [a_record]
        raise dns.resolver.NoAnswer()

    with patch.object(dns.resolver.Resolver, "resolve", side_effect=side_effect):
        assert resolver.a("mail.bank.example") == ["203.0.113.15"]


def test_a_record_lookup_tries_aaaa_and_merges_results():
    resolver = _resolver()
    a_record = MagicMock()
    a_record.__str__ = lambda self: "203.0.113.15"
    aaaa_record = MagicMock()
    aaaa_record.__str__ = lambda self: "2001:db8::1"

    calls = {"count": 0}

    def side_effect(name, rdtype, *a, **kw):
        calls["count"] += 1
        if rdtype == "A":
            return [a_record]
        return [aaaa_record]

    with patch.object(dns.resolver.Resolver, "resolve", side_effect=side_effect):
        result = resolver.a("mail.bank.example")
    assert "203.0.113.15" in result
    assert "2001:db8::1" in result


def test_a_record_lookup_aaaa_failure_does_not_break_a_lookup():
    """An AAAA timeout must not discard A records that already resolved."""
    resolver = _resolver()
    a_record = MagicMock()
    a_record.__str__ = lambda self: "203.0.113.15"

    def side_effect(name, rdtype, *a, **kw):
        if rdtype == "A":
            return [a_record]
        raise dns.exception.Timeout()

    with patch.object(dns.resolver.Resolver, "resolve", side_effect=side_effect):
        result = resolver.a("mail.bank.example")
    assert result == ["203.0.113.15"]


def test_ptr_lookup_builds_reverse_pointer_correctly():
    resolver = _resolver()
    record = MagicMock()
    record.__str__ = lambda self: "mail.bank.example."

    captured = {}

    def side_effect(name, rdtype, *a, **kw):
        captured["name"] = name
        captured["rdtype"] = rdtype
        return [record]

    with patch.object(dns.resolver.Resolver, "resolve", side_effect=side_effect):
        result = resolver.ptr("203.0.113.15")

    assert captured["name"] == "15.113.0.203.in-addr.arpa"
    assert captured["rdtype"] == "PTR"
    # Trailing root dot is stripped from the returned hostname.
    assert result == ["mail.bank.example"]


def test_ptr_lookup_invalid_ip_returns_empty_without_querying():
    resolver = _resolver()
    with patch.object(dns.resolver.Resolver, "resolve") as mock_resolve:
        result = resolver.ptr("not-an-ip")
    assert result == []
    mock_resolve.assert_not_called()


def test_exists_true_when_a_record_found():
    resolver = _resolver()
    with patch.object(dns.resolver.Resolver, "resolve", return_value=[MagicMock()]):
        assert resolver.exists("15.113.0.203.zen.spamhaus.org") is True


def test_exists_false_on_nxdomain():
    resolver = _resolver()
    with patch.object(
        dns.resolver.Resolver, "resolve", side_effect=dns.resolver.NXDOMAIN()
    ):
        assert resolver.exists("15.113.0.203.zen.spamhaus.org") is False


def test_exists_raises_dns_unavailable_on_timeout():
    resolver = _resolver()
    with patch.object(
        dns.resolver.Resolver, "resolve", side_effect=dns.exception.Timeout()
    ), pytest.raises(DnsUnavailable):
        resolver.exists("15.113.0.203.zen.spamhaus.org")


def test_resolver_is_constructed_with_configured_nameservers_and_timeouts():
    resolver = DnsResolver(nameservers=("8.8.8.8", "1.1.1.1"), timeout=3.0, lifetime=6.0)
    assert resolver._resolver.nameservers == ["8.8.8.8", "1.1.1.1"]
    assert resolver._resolver.timeout == 3.0
    assert resolver._resolver.lifetime == 6.0
