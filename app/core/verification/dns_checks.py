"""Forward/reverse DNS consistency and DNSBL membership.

Both checks automate steps performed manually in a standard header investigation.
Neither is a verdict on its own, and the wording throughout reflects that.

On DNSBL results specifically: a listing is meaningful, but an *absence* of listing is
close to meaningless. Blocklists cover bulk spam sources; targeted phishing routinely
originates from clean infrastructure, and a compromised legitimate mail server will
never be listed. "Not listed" must therefore never be rendered as "clean".
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.core.models import IPClass
from app.core.netutils import classify_ip, reverse_pointer
from app.core.verification.resolver import DnsUnavailable, Resolver


@dataclass(frozen=True)
class ForwardReverseResult:
    ip: str
    ptr_names: tuple[str, ...] = ()
    forward_confirmed: bool = False
    consistent: bool = False
    detail: str = ""
    error: str | None = None
    checked: bool = True
    """Whether the check actually ran.

    ``False`` for non-public address space, where the check is skipped as not
    meaningful (see below) — distinct from ``checked=True, forward_confirmed=False``,
    which means the check ran and did *not* confirm. Conflating the two would report
    "no forward-confirmed reverse DNS" for every RFC 5737 documentation-range address
    used in this project's own synthetic samples, which is a skip, not a finding.
    """


@dataclass(frozen=True)
class DnsblResult:
    ip: str
    listed_on: tuple[str, ...] = field(default_factory=tuple)
    checked: tuple[str, ...] = field(default_factory=tuple)
    unavailable: tuple[str, ...] = field(default_factory=tuple)
    detail: str = ""

    @property
    def is_listed(self) -> bool:
        return bool(self.listed_on)


def check_forward_reverse(ip: str, resolver: Resolver) -> ForwardReverseResult:
    """Forward-confirmed reverse DNS (FCrDNS).

    Reverse-resolve the IP, then forward-resolve each name returned and confirm it
    points back. Only the round trip is evidence: a PTR record alone is set by whoever
    controls the address block and proves nothing about the domain in the ``From:``
    header.
    """
    ip_class = classify_ip(ip)
    if ip_class is not IPClass.PUBLIC:
        return ForwardReverseResult(
            ip=ip,
            checked=False,
            detail=(
                f"{ip} is {ip_class.value} address space; forward/reverse consistency "
                "is not meaningful outside the network that owns it."
            ),
        )

    if reverse_pointer(ip) is None:
        return ForwardReverseResult(
            ip=ip, checked=False, detail=f"{ip} is not a valid address."
        )

    try:
        names = tuple(n.rstrip(".").lower() for n in resolver.ptr(ip))
    except DnsUnavailable as exc:
        return ForwardReverseResult(
            ip=ip,
            detail=f"Reverse DNS lookup for {ip} was unavailable.",
            error=str(exc),
        )

    if not names:
        return ForwardReverseResult(
            ip=ip,
            detail=(
                f"{ip} has no reverse DNS record. Many legitimate senders lack one, "
                "and many receivers penalise it, so this is a hygiene observation "
                "rather than an indicator."
            ),
        )

    confirmed = False
    for name in names:
        try:
            addresses = {a.lower() for a in resolver.a(name)}
        except DnsUnavailable as exc:
            return ForwardReverseResult(
                ip=ip,
                ptr_names=names,
                detail=(
                    f"{ip} resolves to {', '.join(names)}, but the forward lookup was "
                    "unavailable, so the round trip could not be confirmed."
                ),
                error=str(exc),
            )
        if ip.lower() in addresses:
            confirmed = True
            break

    if confirmed:
        detail = (
            f"Forward-confirmed reverse DNS: {ip} resolves to {', '.join(names)}, and "
            "that name resolves back to the same address. The sending infrastructure "
            "is internally consistent."
        )
    else:
        detail = (
            f"{ip} has reverse DNS ({', '.join(names)}), but that name does not resolve "
            "back to this address. Common with shared hosting and misconfigured relays; "
            "also what an unrelated host claiming someone else's identity looks like."
        )

    return ForwardReverseResult(
        ip=ip,
        ptr_names=names,
        forward_confirmed=confirmed,
        consistent=confirmed,
        detail=detail,
    )


def check_dnsbl(
    ip: str, resolver: Resolver, zones: tuple[str, ...]
) -> DnsblResult:
    """Query DNS blocklists for ``ip``.

    A listing is queried by reversing the octets and prepending them to the zone —
    ``203.0.113.15`` becomes ``15.113.0.203.zen.spamhaus.org``. An NXDOMAIN answer
    means not listed.
    """
    ip_class = classify_ip(ip)
    if ip_class is not IPClass.PUBLIC:
        return DnsblResult(
            ip=ip,
            detail=(
                f"{ip} is {ip_class.value} address space and was not submitted to any "
                "blocklist."
            ),
        )

    pointer = reverse_pointer(ip)
    if pointer is None:
        return DnsblResult(ip=ip, detail=f"{ip} is not a valid address.")

    listed: list[str] = []
    checked: list[str] = []
    unavailable: list[str] = []

    for zone in zones:
        try:
            if resolver.exists(f"{pointer}.{zone}"):
                listed.append(zone)
            checked.append(zone)
        except DnsUnavailable:
            unavailable.append(zone)

    if listed:
        detail = (
            f"{ip} is listed on {', '.join(listed)}. A listing means the address has a "
            "recorded history of spam or abuse."
        )
    elif checked:
        detail = (
            f"{ip} is not listed on {', '.join(checked)}. Note that blocklists mainly "
            "track bulk spam sources: targeted phishing frequently originates from "
            "clean infrastructure, and a compromised legitimate mail server will never "
            "appear. Absence of a listing is not evidence that the sender is safe."
        )
    else:
        detail = f"No blocklist could be queried for {ip}."

    return DnsblResult(
        ip=ip,
        listed_on=tuple(listed),
        checked=tuple(checked),
        unavailable=tuple(unavailable),
        detail=detail,
    )
