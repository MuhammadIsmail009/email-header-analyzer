"""IOC extraction tests. All material is synthetic (RFC 2606 / RFC 5737)."""

from __future__ import annotations

from app.core.header_parser import parse_headers
from app.core.ioc_extractor import defang, extract_iocs
from app.core.models import IOCType


def _by_type(iocs, ioc_type):
    return [i for i in iocs if i.ioc_type is ioc_type]


def test_ipv4_extraction_and_public_eligibility():
    parsed = parse_headers(
        "Received: from a.example.com ([93.184.216.34]) by b.example.org;"
        " Wed, 22 Oct 2025 09:00:00 +0000\n"
    )
    ips = _by_type(extract_iocs(parsed), IOCType.IPV4)
    assert any(i.normalized == "93.184.216.34" for i in ips)
    hit = next(i for i in ips if i.normalized == "93.184.216.34")
    assert hit.enrichment_eligible is True


def test_private_ip_extracted_but_not_eligible():
    parsed = parse_headers(
        "Received: from internal.corp ([10.1.2.3]) by mx.corp; Wed, 22 Oct 2025 09:00:00 +0000\n"
    )
    ips = _by_type(extract_iocs(parsed), IOCType.IPV4)
    hit = next(i for i in ips if i.normalized == "10.1.2.3")
    assert hit.enrichment_eligible is False
    assert hit.ineligibility_reason is not None


def test_documentation_ip_not_eligible():
    """RFC 5737 ranges appear only in synthetic samples and must never be enriched."""
    parsed = parse_headers(
        "Received: from x ([203.0.113.15]) by y; Wed, 22 Oct 2025 09:00:00 +0000\n"
    )
    ips = _by_type(extract_iocs(parsed), IOCType.IPV4)
    hit = next(i for i in ips if i.normalized == "203.0.113.15")
    assert hit.enrichment_eligible is False


def test_ipv6_extraction():
    parsed = parse_headers(
        "Received: from a ([2001:db8::1]) by b; Wed, 22 Oct 2025 09:00:00 +0000\n"
    )
    ips = _by_type(extract_iocs(parsed), IOCType.IPV6)
    assert any(i.normalized == "2001:db8::1" for i in ips)


def test_domain_extraction():
    parsed = parse_headers("From: alice@bank.example\nSubject: visit mail.bank.example\n")
    domains = _by_type(extract_iocs(parsed), IOCType.DOMAIN)
    assert any(d.normalized == "mail.bank.example" for d in domains)


def test_url_extraction_including_defanged_input():
    parsed = parse_headers(
        "Subject: click hxxps://bank-secure[.]example/login or "
        "https://other.example/x\n"
    )
    urls = _by_type(extract_iocs(parsed), IOCType.URL)
    normalized = {u.normalized for u in urls}
    assert any("bank-secure.example" in u for u in normalized)
    assert any("other.example" in u for u in normalized)


def test_email_extraction():
    parsed = parse_headers("From: Alice <alice@bank.example>\nReply-To: bob@other.example\n")
    emails = _by_type(extract_iocs(parsed), IOCType.EMAIL)
    normalized = {e.normalized for e in emails}
    assert "alice@bank.example" in normalized
    assert "bob@other.example" in normalized


def test_deduplication_preserves_multiple_sources():
    parsed = parse_headers(
        "Received: from a ([93.184.216.34]) by b; Wed, 22 Oct 2025 09:00:00 +0000\n"
        "Received: from c ([93.184.216.34]) by d; Wed, 22 Oct 2025 09:00:01 +0000\n"
    )
    ips = _by_type(extract_iocs(parsed), IOCType.IPV4)
    hit = next(i for i in ips if i.normalized == "93.184.216.34")
    assert hit.occurrences == 2


def test_header_from_artifact_is_not_extracted_as_a_domain():
    """'header.from=example.com' in Authentication-Results must not yield a bogus
    'header.from' domain indicator."""
    parsed = parse_headers(
        "Authentication-Results: mx.example.org; dmarc=pass header.from=bank.example\n"
    )
    domains = {d.normalized for d in _by_type(extract_iocs(parsed), IOCType.DOMAIN)}
    assert "header.from" not in domains
    assert "bank.example" in domains


def test_smtp_mailfrom_artifact_is_not_extracted_as_a_domain():
    parsed = parse_headers(
        "Authentication-Results: mx.example.org; spf=pass smtp.mailfrom=alice@bank.example\n"
    )
    domains = {d.normalized for d in _by_type(extract_iocs(parsed), IOCType.DOMAIN)}
    assert "smtp.mailfrom" not in domains


def test_timestamp_fragment_not_extracted_as_ip():
    parsed = parse_headers(
        "Received: by mail.example.com; Wed, 22 Oct 2025 09:28:49 +0000\n"
    )
    ips = _by_type(extract_iocs(parsed), IOCType.IPV4) + _by_type(
        extract_iocs(parsed), IOCType.IPV6
    )
    assert ips == []


def test_never_visits_or_follows_urls():
    """Structural guarantee: extraction is text analysis only. Confirmed by the
    absence of any network-capable import in this module."""
    import app.core.ioc_extractor as mod

    source = mod.__file__
    with open(source, encoding="utf-8") as f:
        content = f.read()
    for banned in ("httpx", "requests", "urllib.request", "socket"):
        assert banned not in content


# ---------------------------------------------------------------------------
# Defanging
# ---------------------------------------------------------------------------


def test_defang_domain():
    assert defang("bank-secure.example", IOCType.DOMAIN) == "bank-secure[.]example"


def test_defang_url_http():
    assert defang("http://x.example/a", IOCType.URL) == "hxxp://x[.]example/a"


def test_defang_url_https():
    assert defang("https://x.example/a", IOCType.URL) == "hxxps://x[.]example/a"


def test_defang_preserves_scheme_separator():
    """Regression: an earlier implementation mangled '://' into '/'."""
    result = defang("https://bank-secure.example/login", IOCType.URL)
    assert "://" in result
    assert result.startswith("hxxps://")


def test_defang_email():
    assert defang("user@bank-secure.example", IOCType.EMAIL) == "user[@]bank-secure[.]example"


def test_original_value_is_retained_alongside_defanged():
    parsed = parse_headers("Subject: see https://bank-secure.example/x\n")
    url = next(i for i in extract_iocs(parsed) if i.ioc_type is IOCType.URL)
    assert url.value == "https://bank-secure.example/x"
    assert url.defanged != url.value
    assert "[.]" in url.defanged
