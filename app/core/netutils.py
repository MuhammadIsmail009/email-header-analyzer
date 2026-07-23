"""IP address classification and extraction.

Shared by the Received-chain parser and the IOC extractor so both agree on what
counts as an address and which addresses may be sent to a third party.

Addresses are validated with :mod:`ipaddress` rather than trusted from a regex match.
A regex tells you a string *looks* like four dot-separated numbers; it will happily
match ``999.1.2.3``, and it will match the ``1.2.3.4`` hiding inside a queue ID or a
software version string. Validation is what makes the difference between an indicator
and a false positive.
"""

from __future__ import annotations

import ipaddress
import re

from app.core.models import IPClass

# Boundaries matter here. Without the lookarounds this matches the ``25.10.20`` inside
# a version string and the digits inside a timestamp.
_IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")

# Deliberately loose; every candidate is validated afterwards. Timestamps such as
# ``09:28:49`` match this pattern and are then correctly rejected by ipaddress,
# because three groups is not a valid IPv6 address without a ``::``.
_IPV6_RE = re.compile(r"(?<![0-9A-Fa-f:.])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f:.]{0,39}")

_DOCUMENTATION_V4 = (
    ipaddress.ip_network("192.0.2.0/24"),  # RFC 5737 TEST-NET-1
    ipaddress.ip_network("198.51.100.0/24"),  # RFC 5737 TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),  # RFC 5737 TEST-NET-3
)
_DOCUMENTATION_V6 = (
    ipaddress.ip_network("2001:db8::/32"),  # RFC 3849
)


def classify_ip(value: str) -> IPClass:
    """Classify an address for enrichment eligibility.

    Order matters: documentation ranges are checked before the generic reserved test,
    because ``203.0.113.0/24`` is globally routable as far as :mod:`ipaddress` is
    concerned but must never be sent to a reputation provider — it appears only in
    synthetic samples, and looking it up would leak that we are analysing one.
    """
    try:
        addr = ipaddress.ip_address(value.strip())
    except ValueError:
        return IPClass.INVALID

    if addr.is_unspecified:
        return IPClass.UNSPECIFIED
    if addr.is_loopback:
        return IPClass.LOOPBACK
    if addr.is_link_local:
        return IPClass.LINK_LOCAL
    if addr.is_multicast:
        return IPClass.MULTICAST

    networks = _DOCUMENTATION_V4 if addr.version == 4 else _DOCUMENTATION_V6
    if any(addr in net for net in networks):
        return IPClass.DOCUMENTATION

    if addr.is_private:
        return IPClass.PRIVATE
    if addr.is_reserved:
        return IPClass.RESERVED
    if addr.is_global:
        return IPClass.PUBLIC
    return IPClass.RESERVED


def is_enrichable(ip_class: IPClass) -> bool:
    """Only public addresses may be sent to a threat-intelligence provider.

    Everything else either leaks internal topology, or asks a provider about an
    address that is meaningless outside our own network.
    """
    return ip_class is IPClass.PUBLIC


def normalize_ip(value: str) -> str:
    """Canonical form, so ``2001:DB8::0:1`` and ``2001:db8::1`` deduplicate."""
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return value.strip()


def extract_ips(text: str) -> list[str]:
    """Every valid IP literal in ``text``, in order of appearance, deduplicated.

    IPv6 is extracted as well as IPv4. Tools that use an IPv4-only pattern silently
    lose every hop in a v6 delivery path, which is no longer an edge case.
    """
    found: list[str] = []
    seen: set[str] = set()

    for match in _IPV6_RE.finditer(text):
        candidate = match.group(0).rstrip(":.")
        if ":" not in candidate:
            continue
        try:
            addr = ipaddress.IPv6Address(candidate)
        except ValueError:
            continue
        canonical = str(addr)
        if canonical not in seen:
            seen.add(canonical)
            found.append(canonical)

    for match in _IPV4_RE.finditer(text):
        candidate = match.group(0)
        try:
            addr = ipaddress.IPv4Address(candidate)
        except ValueError:
            continue
        canonical = str(addr)
        if canonical not in seen:
            seen.add(canonical)
            found.append(canonical)

    return found


def reverse_pointer(value: str) -> str | None:
    """The reversed-octet form used for DNSBL and PTR queries.

    For ``203.0.113.15`` this is ``15.113.0.203`` — the form prepended to a blocklist
    zone, e.g. ``15.113.0.203.zen.spamhaus.org``.
    """
    try:
        addr = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    if addr.version == 4:
        return ".".join(reversed(str(addr).split(".")))
    return addr.reverse_pointer.removesuffix(".ip6.arpa")
