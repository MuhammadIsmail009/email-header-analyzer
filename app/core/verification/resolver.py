"""DNS access for the verification layer.

Everything here is **synchronous**. ``dnspython``, ``pyspf`` and ``dkimpy`` are all
blocking libraries, and pretending otherwise is how a reference project ended up with
``time.sleep(15)`` inside a synchronous FastAPI route handler, occupying a threadpool
worker for the whole analysis. The service layer calls these through
``anyio.to_thread.run_sync``; the core stays honest about being blocking.

A :class:`Resolver` protocol is defined so tests inject a fake and never touch the
network. The entire test suite runs offline and without API keys.
"""

from __future__ import annotations

import contextlib
from typing import Protocol

_DEFAULT_TIMEOUT = 3.0
_DEFAULT_LIFETIME = 6.0


class DnsUnavailable(Exception):
    """DNS could not answer. Distinct from 'the record does not exist'.

    The difference matters: a missing SPF record is a finding about the domain, while
    a DNS timeout is a finding about our own visibility. Collapsing them would let an
    outage masquerade as evidence.
    """


class Resolver(Protocol):
    def txt(self, name: str) -> list[str]: ...
    def a(self, name: str) -> list[str]: ...
    def ptr(self, ip: str) -> list[str]: ...
    def exists(self, name: str) -> bool: ...


class DnsResolver:
    """dnspython-backed resolver."""

    def __init__(
        self,
        nameservers: tuple[str, ...] = ("8.8.8.8", "1.1.1.1"),
        timeout: float = _DEFAULT_TIMEOUT,
        lifetime: float = _DEFAULT_LIFETIME,
    ) -> None:
        import dns.resolver

        self._resolver = dns.resolver.Resolver(configure=False)
        self._resolver.nameservers = list(nameservers)
        self._resolver.timeout = timeout
        self._resolver.lifetime = lifetime

    def _query(self, name: str, rdtype: str) -> list[str]:
        import dns.exception
        import dns.resolver

        try:
            answer = self._resolver.resolve(name, rdtype)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except (dns.resolver.NoNameservers, dns.exception.Timeout) as exc:
            raise DnsUnavailable(f"{rdtype} lookup for {name!r} failed: {exc}") from exc
        except dns.exception.DNSException as exc:
            raise DnsUnavailable(f"{rdtype} lookup for {name!r} failed: {exc}") from exc

        results: list[str] = []
        for record in answer:
            if rdtype == "TXT":
                # TXT records arrive as one or more strings that must be concatenated;
                # SPF and DKIM records regularly exceed 255 bytes and are split.
                parts = getattr(record, "strings", None)
                if parts is not None:
                    results.append(
                        b"".join(parts).decode("utf-8", errors="replace")
                    )
                else:
                    results.append(str(record).strip('"'))
            else:
                results.append(str(record).rstrip("."))
        return results

    def txt(self, name: str) -> list[str]:
        return self._query(name, "TXT")

    def a(self, name: str) -> list[str]:
        records = self._query(name, "A")
        # A missing AAAA record is normal for an IPv4-only host, not a failure worth
        # surfacing on its own — the caller already has whatever A records exist.
        with contextlib.suppress(DnsUnavailable):
            records.extend(self._query(name, "AAAA"))
        return records

    def ptr(self, ip: str) -> list[str]:
        from app.core.netutils import reverse_pointer

        pointer = reverse_pointer(ip)
        if pointer is None:
            return []
        suffix = "in-addr.arpa" if ip.count(".") == 3 else "ip6.arpa"
        return self._query(f"{pointer}.{suffix}", "PTR")

    def exists(self, name: str) -> bool:
        """Whether a name resolves at all — used for DNSBL membership."""
        import dns.exception
        import dns.resolver

        try:
            self._resolver.resolve(name, "A")
            return True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return False
        except dns.exception.DNSException as exc:
            raise DnsUnavailable(f"lookup for {name!r} failed: {exc}") from exc


class StaticResolver:
    """In-memory resolver for tests and demo fixtures.

    Names absent from the mapping return an empty list (NXDOMAIN), and names mapped to
    the sentinel :data:`UNAVAILABLE` raise :class:`DnsUnavailable`, so both the
    'no record' and 'cannot tell' paths are reachable in tests.
    """

    UNAVAILABLE = object()

    def __init__(
        self,
        txt: dict[str, object] | None = None,
        a: dict[str, object] | None = None,
        ptr: dict[str, object] | None = None,
        listed: frozenset[str] = frozenset(),
    ) -> None:
        self._txt = txt or {}
        self._a = a or {}
        self._ptr = ptr or {}
        self._listed = listed

    def _get(self, table: dict[str, object], key: str) -> list[str]:
        value = table.get(key.rstrip(".").lower())
        if value is self.UNAVAILABLE:
            raise DnsUnavailable(f"simulated DNS failure for {key!r}")
        if value is None:
            return []
        return list(value)  # type: ignore[arg-type]

    def txt(self, name: str) -> list[str]:
        return self._get(self._txt, name)

    def a(self, name: str) -> list[str]:
        return self._get(self._a, name)

    def ptr(self, ip: str) -> list[str]:
        return self._get(self._ptr, ip)

    def exists(self, name: str) -> bool:
        return name.rstrip(".").lower() in self._listed
