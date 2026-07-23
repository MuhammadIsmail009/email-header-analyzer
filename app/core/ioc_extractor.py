"""Indicator extraction: IPs, domains, URLs and email addresses from a parsed header.

Pipeline is deliberately staged as extract → normalize → validate → defang, so each
step is independently testable and a later stage never has to re-parse what an
earlier one already understood.

Design commitments:

* **Only public IPs are enrichment-eligible.** Private, loopback, link-local, reserved,
  multicast, unspecified and documentation ranges are extracted (they matter for route
  analysis) but never marked eligible for a third-party lookup — sending them leaks
  internal topology and asks a provider about an address that means nothing outside our
  own network.
* **Every IOC keeps every source location.** The same IP can appear in a Received line
  and inside a DKIM `d=` domain's infrastructure; both occurrences are recorded rather
  than the first one winning.
* **Defanging is presentation, not mutation.** The original value is always retained
  ("Retain the original safely for internal analysis and exports"); `defanged` is a
  separate computed field so the UI can render safely without losing the real value
  needed for a copy-to-clipboard or an export.
* **Nothing here ever fetches a URL, follows a redirect, or performs a DNS lookup.**
  Extraction is text analysis only.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from app.core.domain_analyzer import normalize_domain
from app.core.models import IOC, IOCSource, IOCType, ParsedHeader
from app.core.netutils import classify_ip, extract_ips, is_enrichable, normalize_ip

# Fields worth scanning for IOCs. Restricting to these avoids pulling addresses out of
# e.g. a Content-Type boundary string or a base64 DKIM signature, which are not
# observables in any meaningful sense.
_SCANNABLE_HEADERS = (
    "from",
    "sender",
    "to",
    "cc",
    "reply-to",
    "return-path",
    "message-id",
    "received",
    "received-spf",
    "authentication-results",
    "arc-authentication-results",
    "subject",
    "x-originating-ip",
    "x-sender-ip",
)

_DOMAIN_RE = re.compile(
    r"(?<![\w.-])"
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}"
    r"(?![\w.-])"
)

_URL_RE = re.compile(r"(?:https?|hxxps?)://[^\s<>\"'\]\)]+", re.IGNORECASE)

_EMAIL_RE = re.compile(
    r"(?<![\w.+-])"
    r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+"
)

# Never treat these as observable domains: they are structural artefacts, not
# indicators. "header.from" and similar dotted-property names from
# Authentication-Results are the main source of false positives here.
_NON_DOMAIN_SUFFIXES = (".arpa",)
_PROPERTY_PREFIXES = (
    "header.",
    "smtp.",
    "body.",
    "policy.",
)


def _refang(value: str) -> str:
    """Reverse common defanging so an analyst-pasted IOC still extracts correctly."""
    result = value
    result = re.sub(r"hxxps?://", lambda m: m.group(0).replace("xx", "tt"), result, flags=re.IGNORECASE)
    result = result.replace("[.]", ".").replace("(.)", ".")
    result = result.replace("[@]", "@").replace("(@)", "@")
    return result


def defang(value: str, ioc_type: IOCType) -> str:
    """Render an indicator safely for on-screen display.

    ``example.com`` -> ``example[.]com``, ``https://example.com/x`` ->
    ``hxxps://example[.]com/x``. Never used for the retained/exported value.
    """
    result = value
    if ioc_type is IOCType.URL:
        # Replace only the two letters after the leading "h" ("tt" in http, "tt" in
        # https) so the "://" separator survives intact — "http://" -> "hxxp://",
        # "https://" -> "hxxps://".
        result = re.sub(
            r"(?i)^(h)(tt)(ps?://)",
            lambda m: m.group(1) + "xx" + m.group(3),
            result,
        )
    result = result.replace(".", "[.]")
    if ioc_type is IOCType.EMAIL:
        result = result.replace("@", "[@]")
    return result


def _extract_domains_from_text(text: str) -> list[str]:
    found: list[str] = []
    for match in _DOMAIN_RE.finditer(text):
        candidate = match.group(0)
        lowered = candidate.lower()
        if any(lowered.startswith(p) for p in _PROPERTY_PREFIXES):
            continue
        if any(lowered.endswith(s) for s in _NON_DOMAIN_SUFFIXES):
            continue
        if lowered.replace(".", "").isdigit():
            continue  # an IP literal matched the domain pattern
        normalized = normalize_domain(candidate)
        if normalized:
            found.append(normalized)
    return found


def _extract_urls_from_text(text: str) -> list[str]:
    refanged_text = _refang(text)
    return [m.group(0) for m in _URL_RE.finditer(refanged_text)]


def _extract_emails_from_text(text: str) -> list[str]:
    return [m.group(0) for m in _EMAIL_RE.finditer(_refang(text))]


def extract_iocs(parsed: ParsedHeader) -> list[IOC]:
    """Extract, normalize, deduplicate and classify every IOC in the header.

    Deduplication key is ``(normalized_value, ioc_type)`` — the same value appearing
    as both a domain match and inside a URL is intentionally kept as separate entries
    (the domain is a component of the URL, not a duplicate of it), but the same domain
    seen in two different headers collapses into one entry with both sources recorded.
    """
    collected: dict[tuple[str, IOCType], IOC] = {}
    position = 0

    def _add(
        ioc_type: IOCType,
        value: str,
        normalized: str,
        header_name: str,
        ip_class=None,
    ) -> None:
        nonlocal position
        key = (normalized, ioc_type)
        source = IOCSource(header_name=header_name, position=position)
        position += 1

        if key in collected:
            existing = collected[key]
            if source.header_name not in {s.header_name for s in existing.sources}:
                sources = existing.sources + (source,)
            else:
                sources = existing.sources
            collected[key] = existing.model_copy(
                update={
                    "sources": sources,
                    "occurrences": existing.occurrences + 1,
                }
            )
            return

        eligible = False
        reason = None
        if ioc_type in (IOCType.IPV4, IOCType.IPV6):
            eligible = is_enrichable(ip_class)
            if not eligible:
                reason = f"{ip_class.value} address space is not eligible for enrichment"
        elif ioc_type in (IOCType.DOMAIN, IOCType.URL, IOCType.EMAIL):
            eligible = True

        is_unicode = any(ord(c) > 127 for c in value)

        collected[key] = IOC(
            value=value,
            normalized=normalized,
            ioc_type=ioc_type,
            sources=(source,),
            occurrences=1,
            ip_class=ip_class,
            enrichment_eligible=eligible,
            ineligibility_reason=reason,
            defanged=defang(normalized, ioc_type),
            is_unicode=is_unicode,
        )

    for header_name in _SCANNABLE_HEADERS:
        for field in parsed.get_all(header_name):
            text = field.decoded_value or field.normalized_value

            for ip in extract_ips(text):
                ip_class = classify_ip(ip)
                ioc_type = IOCType.IPV6 if ":" in ip else IOCType.IPV4
                _add(ioc_type, ip, normalize_ip(ip), header_name, ip_class)

            for email in _extract_emails_from_text(text):
                _add(IOCType.EMAIL, email, email.lower(), header_name)

            for url in _extract_urls_from_text(text):
                try:
                    parsed_url = urlsplit(url)
                    normalized_url = url if parsed_url.scheme else url
                except ValueError:
                    normalized_url = url
                _add(IOCType.URL, url, normalized_url, header_name)

            # Domains: skip text already claimed by an email or URL match, so the
            # domain component of an email/URL isn't double-counted as a bare domain.
            email_spans = {e for e in _extract_emails_from_text(text)}
            url_spans = {u for u in _extract_urls_from_text(text)}
            residual = text
            for consumed in list(email_spans) + list(url_spans):
                residual = residual.replace(consumed, " ")

            for domain in _extract_domains_from_text(residual):
                _add(IOCType.DOMAIN, domain, domain, header_name)

    return sorted(
        collected.values(),
        key=lambda i: (i.ioc_type.value, i.sources[0].position if i.sources else 0),
    )
