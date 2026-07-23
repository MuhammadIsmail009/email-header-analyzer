"""Independent SPF evaluation.

This does not read ``Received-SPF`` or ``Authentication-Results``. It retrieves the
sender domain's SPF record and evaluates it against the IP address that actually
connected, using ``pyspf`` — a full RFC 7208 implementation including ``include:``
recursion, macro expansion and the ten-lookup limit.

Reimplementing that was considered and rejected. The ten-lookup limit alone is a
frequent real-world finding (a domain whose record silently exceeds it fails for
everyone), and getting void-lookup and permerror semantics right is a multi-week
exercise with a high chance of being subtly wrong. Being subtly wrong here means
telling an analyst a message is authorised when it is not.

``pyspf`` performs blocking DNS. Call this from a worker thread.
"""

from __future__ import annotations

import threading

from app.core.models import AuthMethod, VerificationOutcome, VerificationResult
from app.core.verification.resolver import DnsUnavailable, Resolver

# Serialises the module-global DNSLookup swap in verify_spf().
_DNS_LOOKUP_LOCK = threading.Lock()

_RESULT_TO_OUTCOME = {
    "pass": VerificationOutcome.VERIFIED_PASS,
    "fail": VerificationOutcome.VERIFIED_FAIL,
    "softfail": VerificationOutcome.VERIFIED_FAIL,
    "neutral": VerificationOutcome.NOT_POSSIBLE,
    "none": VerificationOutcome.NOT_POSSIBLE,
    "permerror": VerificationOutcome.ERROR,
    "temperror": VerificationOutcome.ERROR,
}

_EXPLANATION = {
    "pass": "The connecting IP is authorised to send for this domain.",
    "fail": (
        "The connecting IP is NOT authorised by the domain's SPF record, and the "
        "record ends in '-all' (hard fail)."
    ),
    "softfail": (
        "The connecting IP is not authorised, but the record ends in '~all' "
        "(soft fail) — the domain owner discourages rather than forbids it."
    ),
    "neutral": (
        "The record explicitly takes no position on this IP ('?all' or '?' qualifier). "
        "This is not a pass."
    ),
    "none": (
        "The domain publishes no SPF record, so SPF cannot authorise or reject "
        "anything. Absence of a record is not a failure, and it is not a pass."
    ),
    "permerror": (
        "The SPF record is malformed or exceeds the RFC 7208 ten-DNS-lookup limit. "
        "Receivers are entitled to treat this as a failure, so it affects real "
        "deliverability."
    ),
    "temperror": "SPF evaluation hit a temporary DNS error and is inconclusive.",
}


def _make_dns_lookup(resolver: Resolver):
    """Adapt our :class:`Resolver` to pyspf's ``DNSLookup`` contract.

    Returns ``[((name, qtype), value), ...]`` in the shapes pyspf expects.

    Installing this is not optional. pyspf dispatches through a *module-level*
    ``DNSLookup``, and its cache treats an empty list as a miss — so pre-seeding the
    cache does not prevent it reaching the network. Two things follow:

    * Tests would silently perform real DNS queries, which makes the suite dependent
      on the internet and on whatever those domains happen to publish today.
    * In production, every ``include:``, ``a:``, ``mx:`` and ``redirect=`` in an SPF
      record would be resolved by the system resolver rather than the configured one,
      ignoring our nameservers and timeouts.

    Routing everything through the injected resolver fixes both.
    """
    import spf

    def lookup(name: str, qtype: str, tcpfallback: bool = True, timeout: int = 30):
        key = str(name).rstrip(".").lower()
        try:
            if qtype in ("TXT", "SPF"):
                return [
                    ((name, qtype), (value.encode("utf-8"),))
                    for value in resolver.txt(key)
                ]
            if qtype in ("A", "AAAA"):
                want_v6 = qtype == "AAAA"
                return [
                    ((name, qtype), address)
                    for address in resolver.a(key)
                    if (":" in address) == want_v6
                ]
            if qtype == "PTR":
                return [((name, qtype), value) for value in resolver.ptr(key)]
            # MX is not exposed by our resolver protocol; an SPF record relying on
            # 'mx' resolves to nothing rather than silently escaping to the network.
            return []
        except DnsUnavailable as exc:
            raise spf.TempError(f"DNS unavailable for {key}: {exc}") from exc

    return lookup


def verify_spf(
    connecting_ip: str | None,
    envelope_from: str | None,
    helo: str | None,
    resolver: Resolver,
    timeout: float = 6.0,
) -> VerificationResult:
    """Evaluate SPF for ``connecting_ip`` sending as ``envelope_from``.

    Per RFC 7208 §2.3, SPF checks the envelope sender (``MAIL FROM``) — not the
    visible ``From:`` header. When the envelope sender is empty (a bounce), the HELO
    identity is checked instead. This distinction is the reason SPF alone cannot stop
    display-name spoofing, and it is why alignment is evaluated separately.
    """
    import spf

    if not connecting_ip:
        return VerificationResult(
            method=AuthMethod.SPF,
            outcome=VerificationOutcome.NOT_POSSIBLE,
            detail=(
                "No connecting IP could be established from the Received chain, so "
                "SPF cannot be evaluated."
            ),
        )

    sender = envelope_from or ""
    identity = "envelope sender"
    if not sender:
        if not helo:
            return VerificationResult(
                method=AuthMethod.SPF,
                outcome=VerificationOutcome.NOT_POSSIBLE,
                detail=(
                    "Neither an envelope sender nor a HELO identity is available, so "
                    "there is no identity to check SPF against."
                ),
            )
        identity = "HELO identity"

    domain = sender.rsplit("@", 1)[-1] if "@" in sender else (helo or "")

    try:
        published = resolver.txt(domain) if domain else []
    except DnsUnavailable as exc:
        return VerificationResult(
            method=AuthMethod.SPF,
            outcome=VerificationOutcome.ERROR,
            detail=f"DNS was unavailable, so SPF could not be verified: {exc}",
            checked_domain=domain or None,
            error=str(exc),
        )

    query = spf.query(i=connecting_ip, s=sender, h=helo or domain, timeout=timeout)

    # pyspf dispatches DNS through a module-level global, so it has to be swapped for
    # the duration of the call. The lock serialises that swap: analyses run
    # concurrently in a threadpool, and two of them racing on this global would let one
    # analysis resolve names through another's resolver.
    with _DNS_LOOKUP_LOCK:
        original = spf.DNSLookup
        spf.DNSLookup = _make_dns_lookup(resolver)
        try:
            result, _code, explanation = query.check()
        except spf.TempError as exc:
            return VerificationResult(
                method=AuthMethod.SPF,
                outcome=VerificationOutcome.ERROR,
                detail=f"SPF evaluation hit a temporary DNS error: {exc}",
                checked_domain=domain or None,
                error=f"TempError: {exc}",
            )
        except Exception as exc:  # pyspf raises varied types on malformed records
            return VerificationResult(
                method=AuthMethod.SPF,
                outcome=VerificationOutcome.ERROR,
                detail=f"SPF evaluation failed: {exc}",
                checked_domain=domain or None,
                error=f"{type(exc).__name__}: {exc}",
            )
        finally:
            spf.DNSLookup = original

    result = (result or "").lower()
    record = next(
        (r for r in published if r.lower().startswith("v=spf1")), None
    )

    return VerificationResult(
        method=AuthMethod.SPF,
        outcome=_RESULT_TO_OUTCOME.get(result, VerificationOutcome.ERROR),
        detail=(
            f"Independently evaluated: SPF {result} for {connecting_ip} using the "
            f"{identity}. {_EXPLANATION.get(result, explanation or '')}"
        ).strip(),
        checked_domain=domain or None,
        record=record,
        scope=f"{identity} ({sender or helo}) against connecting IP {connecting_ip}",
    )
