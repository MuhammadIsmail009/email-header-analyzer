"""Email address extraction from header values.

Shared by the authentication parser and the identity analyzer so both agree on what
the ``From:`` domain actually is — a disagreement there would make alignment results
inconsistent with the identity table shown next to them.
"""

from __future__ import annotations

from email.utils import getaddresses

from app.core.domain_analyzer import normalize_domain


def parse_addresses(value: str | None) -> list[tuple[str, str]]:
    """Return ``(display_name, address)`` pairs from a header value.

    ``getaddresses`` handles group syntax, quoting and comments. Malformed input
    yields whatever could be recovered rather than raising, because a deliberately
    malformed ``From:`` is itself worth showing.
    """
    if not value:
        return []
    try:
        pairs = getaddresses([value])
    except (ValueError, TypeError, IndexError):
        return []
    return [(name.strip(), addr.strip()) for name, addr in pairs if name or addr]


def first_address(value: str | None) -> str | None:
    for _, address in parse_addresses(value):
        if "@" in address:
            return address
    return None


def address_domain(address: str | None) -> str | None:
    """Domain part of an address, normalised.

    Takes the text after the *last* ``@`` — ``"a@b"@example.com`` is legal, and
    splitting on the first ``@`` yields the wrong domain.
    """
    if not address or "@" not in address:
        return None
    return normalize_domain(address.rsplit("@", 1)[1])


def domain_of_header(value: str | None) -> str | None:
    return address_domain(first_address(value))
