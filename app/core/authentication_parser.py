"""Authentication evidence: what the receiving infrastructure *claimed*.

Everything this module produces is a **claim read out of a header**, never a fact this
tool established. Facts come from ``app/core/verification/``, and the interface shows
the two side by side.

That distinction is the whole point, and it rests on RFC 8601 §7.1:

    "...a malicious user or agent could forge a header field using the DNS domain of a
    receiving ADMD as the authserv-id token..."

Safe use of ``Authentication-Results`` requires the receiving ADMD to strip inbound
copies bearing its own authserv-id, and requires the reader to check *who* asserted the
result. An attacker can simply place

    Authentication-Results: yourcompany.com; spf=pass; dkim=pass; dmarc=pass

into a message they send. Every tool that renders a green PASS from that string without
checking the authserv-id is reporting the attacker's own assertion back to the analyst.

So every piece of evidence here carries a :class:`TrustStatus`, and with no trusted
infrastructure configured the honest answer is ``UNKNOWN`` — not ``TRUSTED``.

Parsing is depth- and quote-aware rather than regex-based. ``dmarc=pass (p=QUARANTINE
sp=QUARANTINE dis=NONE) header.from=example.com`` breaks any pattern that stops at the
first ``)``.
"""

from __future__ import annotations

import re

from app.core.addresses import address_domain, domain_of_header
from app.core.domain_analyzer import compare_domains, is_aligned, normalize_domain
from app.core.models import (
    AlignmentResult,
    AuthenticationEvidence,
    AuthenticationSummary,
    AuthMethod,
    AuthResult,
    ParsedHeader,
    TrustStatus,
)

_METHOD_BY_NAME = {m.value: m for m in AuthMethod}
_RESULT_BY_NAME = {r.value: r for r in AuthResult}

_WS = re.compile(r"\s+")


# ---------------------------------------------------------------------------
# Tokenising
# ---------------------------------------------------------------------------


def _split_top_level(text: str, separator: str = ";") -> list[str]:
    """Split on ``separator`` at parenthesis depth zero, outside quoted strings."""
    parts: list[str] = []
    depth = 0
    in_quotes = False
    escaped = False
    current: list[str] = []

    for char in text:
        if escaped:
            current.append(char)
            escaped = False
            continue
        if char == "\\":
            current.append(char)
            escaped = True
            continue
        if char == '"':
            in_quotes = not in_quotes
            current.append(char)
            continue
        if not in_quotes:
            if char == "(":
                depth += 1
            elif char == ")":
                depth = max(0, depth - 1)
            elif char == separator and depth == 0:
                parts.append("".join(current))
                current = []
                continue
        current.append(char)

    parts.append("".join(current))
    return [p.strip() for p in parts if p.strip()]


def _strip_comments(text: str) -> tuple[str, list[str]]:
    """Remove balanced ``(...)`` comments, returning the text and the comments.

    Comments carry the human-readable reason a receiver reached its verdict — e.g.
    ``(google.com: domain of x@y designates 203.0.113.15 as permitted sender)`` — so
    they are retained rather than discarded.
    """
    out: list[str] = []
    comments: list[str] = []
    depth = 0
    in_quotes = False
    escaped = False
    buffer: list[str] = []

    for char in text:
        if escaped:
            (buffer if depth else out).append(char)
            escaped = False
            continue
        if char == "\\":
            (buffer if depth else out).append(char)
            escaped = True
            continue
        if char == '"' and depth == 0:
            in_quotes = not in_quotes
            out.append(char)
            continue
        if not in_quotes:
            if char == "(":
                depth += 1
                if depth == 1:
                    buffer = []
                    continue
            elif char == ")":
                if depth:
                    depth -= 1
                    if depth == 0:
                        comments.append("".join(buffer).strip())
                        continue
        (buffer if depth else out).append(char)

    return _WS.sub(" ", "".join(out)).strip(), comments


def _split_tokens(text: str) -> list[str]:
    """Whitespace split that keeps quoted strings intact."""
    tokens: list[str] = []
    in_quotes = False
    escaped = False
    current: list[str] = []

    for char in text:
        if escaped:
            current.append(char)
            escaped = False
            continue
        if char == "\\":
            current.append(char)
            escaped = True
            continue
        if char == '"':
            in_quotes = not in_quotes
            current.append(char)
            continue
        if char.isspace() and not in_quotes:
            if current:
                tokens.append("".join(current))
                current = []
            continue
        current.append(char)

    if current:
        tokens.append("".join(current))
    return tokens


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1].replace('\\"', '"')
    return value


# ---------------------------------------------------------------------------
# Authentication-Results
# ---------------------------------------------------------------------------


def parse_authentication_results(
    value: str,
    trusted_domains: tuple[str, ...] = (),
    trusted_hosts: tuple[str, ...] = (),
    source_header: str = "Authentication-Results",
) -> tuple[str | None, list[AuthenticationEvidence]]:
    """Parse one ``Authentication-Results`` field (RFC 8601 §2.2).

    Returns ``(authserv_id, evidence)``.
    """
    segments = _split_top_level(value, ";")
    if not segments:
        return None, []

    authserv_raw, _ = _strip_comments(segments[0])
    authserv_tokens = _split_tokens(authserv_raw)
    authserv_id = normalize_domain(authserv_tokens[0]) if authserv_tokens else None

    trust = _trust_for(authserv_id, trusted_domains, trusted_hosts)

    evidence: list[AuthenticationEvidence] = []
    for segment in segments[1:]:
        parsed = _parse_methodspec(
            segment, authserv_id, trust, source_header
        )
        if parsed is not None:
            evidence.append(parsed)

    return authserv_id, evidence


def _trust_for(
    authserv_id: str | None,
    trusted_domains: tuple[str, ...],
    trusted_hosts: tuple[str, ...],
) -> TrustStatus:
    """Classify an authserv-id against configured infrastructure.

    With nothing configured the answer is ``UNKNOWN``, not ``TRUSTED``. An unconfigured
    deployment must not silently believe arbitrary headers — that is the exact failure
    this class exists to prevent.
    """
    if not authserv_id:
        return TrustStatus.UNKNOWN
    if not trusted_domains and not trusted_hosts:
        return TrustStatus.UNKNOWN

    candidate = authserv_id.lower().rstrip(".")
    if candidate in {h.lower().rstrip(".") for h in trusted_hosts if h}:
        return TrustStatus.TRUSTED
    for domain in trusted_domains:
        domain = domain.lower().strip().rstrip(".")
        if domain and (candidate == domain or candidate.endswith("." + domain)):
            return TrustStatus.TRUSTED
    return TrustStatus.UNTRUSTED


def _parse_methodspec(
    segment: str,
    authserv_id: str | None,
    trust: TrustStatus,
    source_header: str,
) -> AuthenticationEvidence | None:
    cleaned, comments = _strip_comments(segment)
    tokens = _split_tokens(cleaned)
    if not tokens or "=" not in tokens[0]:
        return None

    method_raw, _, result_raw = tokens[0].partition("=")
    method_name = method_raw.strip().lower().split("/")[0]  # method/version
    method = _METHOD_BY_NAME.get(method_name)
    if method is None:
        return None

    result = _RESULT_BY_NAME.get(result_raw.strip().lower(), AuthResult.UNKNOWN)

    properties: dict[str, str] = {}
    reason: str | None = None
    for token in tokens[1:]:
        if "=" not in token:
            continue
        key, _, val = token.partition("=")
        key = key.strip().lower()
        val = _unquote(val)
        if key == "reason":
            reason = val
        else:
            properties[key] = val

    if reason is None and comments:
        reason = comments[0]

    return AuthenticationEvidence(
        method=method,
        result=result,
        asserted_by=authserv_id,
        trust=trust,
        source_header=source_header,
        properties=properties,
        reason=reason,
        raw=segment.strip(),
    )


# ---------------------------------------------------------------------------
# Received-SPF
# ---------------------------------------------------------------------------


def parse_received_spf(
    value: str,
    trusted_domains: tuple[str, ...] = (),
    trusted_hosts: tuple[str, ...] = (),
) -> AuthenticationEvidence | None:
    """Parse a ``Received-SPF`` field (RFC 7208 §9.1).

    Shape: ``pass (comment) key=value; key=value``. The result is the first token; the
    comment usually names the evaluating host, which is the only clue to who asserted
    it — this header has no authserv-id of its own.
    """
    cleaned, comments = _strip_comments(value)
    tokens = _split_tokens(cleaned)
    if not tokens:
        return None

    result = _RESULT_BY_NAME.get(tokens[0].strip().lower(), AuthResult.UNKNOWN)

    properties: dict[str, str] = {}
    for token in tokens[1:]:
        if "=" in token:
            key, _, val = token.partition("=")
            properties[key.strip().lower().rstrip(";")] = _unquote(val.rstrip(";"))

    # "google.com: domain of x@y designates 203.0.113.15 as permitted sender"
    asserted_by = None
    if comments:
        leading = comments[0].split(":")[0].strip()
        if leading and " " not in leading:
            asserted_by = normalize_domain(leading)

    return AuthenticationEvidence(
        method=AuthMethod.SPF,
        result=result,
        asserted_by=asserted_by,
        trust=_trust_for(asserted_by, trusted_domains, trusted_hosts),
        source_header="Received-SPF",
        properties=properties,
        reason=comments[0] if comments else None,
        raw=value.strip(),
    )


# ---------------------------------------------------------------------------
# Tag-value headers: DKIM-Signature, ARC-Seal, ARC-Message-Signature
# ---------------------------------------------------------------------------


def parse_tag_value_header(value: str) -> dict[str, str]:
    """Parse a ``tag=value; tag=value`` header (RFC 6376 §3.2).

    Whitespace inside values is stripped, because DKIM base64 fields are folded across
    lines and the folding whitespace is not part of the value.
    """
    tags: dict[str, str] = {}
    for part in _split_top_level(value, ";"):
        if "=" not in part:
            continue
        key, _, val = part.partition("=")
        key = key.strip().lower()
        if key:
            tags[key] = _WS.sub("", val.strip()) if key in {"b", "bh"} else val.strip()
    return tags


def dkim_signing_domains(parsed: ParsedHeader) -> list[str]:
    """The ``d=`` domain of each ``DKIM-Signature``.

    A message may carry several signatures — one from the author domain and one from a
    relaying service is common and legitimate. All are returned; alignment is judged
    per signature, and one aligned signature is sufficient for DMARC.
    """
    domains: list[str] = []
    for field in parsed.get_all("DKIM-Signature"):
        tags = parse_tag_value_header(field.normalized_value)
        domain = normalize_domain(tags.get("d"))
        if domain and domain not in domains:
            domains.append(domain)
    return domains


def arc_chain_status(parsed: ParsedHeader) -> tuple[bool, str | None]:
    """Summarise the ARC chain (RFC 8617), without overinterpreting it.

    ARC preserves authentication results across a forwarder or mailing list, which is
    the single most common reason a legitimate message shows an SPF failure. Its
    presence is context, not a verdict: an ARC chain is only as trustworthy as the
    intermediaries that sealed it, and this tool does not validate those seals.
    """
    seals = parsed.get_all("ARC-Seal")
    if not seals:
        return False, None

    instances: list[tuple[int, str]] = []
    for field in seals:
        tags = parse_tag_value_header(field.normalized_value)
        try:
            instance = int(tags.get("i", "0"))
        except ValueError:
            instance = 0
        instances.append((instance, (tags.get("cv") or "unknown").strip().lower()))

    instances.sort()
    newest_cv = instances[-1][1] if instances else "unknown"

    if newest_cv == "fail":
        status = (
            f"{len(instances)} ARC seal(s); most recent chain validation cv=fail. "
            "The forwarding chain reports it could not validate earlier hops."
        )
    elif newest_cv == "none":
        status = (
            f"{len(instances)} ARC seal(s); cv=none, i.e. this is the first ARC hop. "
            "Expected for a message that has not yet been forwarded."
        )
    elif newest_cv == "pass":
        status = (
            f"{len(instances)} ARC seal(s); most recent chain validation cv=pass. "
            "Seals were not independently validated by this tool."
        )
    else:
        status = f"{len(instances)} ARC seal(s); chain validation value {newest_cv!r}."

    return True, status


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------


def build_authentication_summary(
    parsed: ParsedHeader,
    trusted_domains: tuple[str, ...] = (),
    trusted_hosts: tuple[str, ...] = (),
) -> AuthenticationSummary:
    """Collect all recorded authentication evidence and compute alignment ourselves.

    Alignment is *computed here*, never read from a header. A receiver's ``dmarc=pass``
    tells you it aligned against whatever it considered the From domain; recomputing it
    against the ``From:`` actually present is what catches the case where SPF passes
    legitimately on a relay's own domain while the visible sender says something else.
    """
    evidence: list[AuthenticationEvidence] = []
    warnings: list[str] = []

    for field in parsed.get_all("Authentication-Results"):
        _, found = parse_authentication_results(
            field.normalized_value, trusted_domains, trusted_hosts
        )
        evidence.extend(found)

    for field in parsed.get_all("ARC-Authentication-Results"):
        # Strip the leading "i=N;" instance tag before parsing as an AR header.
        value = re.sub(r"^\s*i\s*=\s*\d+\s*;\s*", "", field.normalized_value)
        _, found = parse_authentication_results(
            value, trusted_domains, trusted_hosts, source_header="ARC-Authentication-Results"
        )
        evidence.extend(found)

    for field in parsed.get_all("Received-SPF"):
        spf = parse_received_spf(field.normalized_value, trusted_domains, trusted_hosts)
        if spf is not None:
            evidence.append(spf)

    header_from_domain = domain_of_header(parsed.value_of("From"))

    envelope_from = None
    return_path = parsed.value_of("Return-Path")
    if return_path:
        envelope_from = return_path.strip().strip("<>") or None

    helo_identity = None
    for item in evidence:
        if item.method is AuthMethod.SPF:
            envelope_from = envelope_from or item.properties.get("smtp.mailfrom")
            helo_identity = helo_identity or item.properties.get("smtp.helo")

    # -- Alignment, computed rather than believed ------------------------
    spf_domain = address_domain(envelope_from) or normalize_domain(envelope_from)
    spf_alignment = (
        compare_domains(spf_domain, header_from_domain)
        if spf_domain and header_from_domain
        else AlignmentResult.UNKNOWN
    )

    signing_domains = dkim_signing_domains(parsed)
    for item in evidence:
        if item.method is AuthMethod.DKIM:
            candidate = normalize_domain(item.properties.get("header.d"))
            if candidate and candidate not in signing_domains:
                signing_domains.append(candidate)

    dkim_alignment = AlignmentResult.UNKNOWN
    if header_from_domain and signing_domains:
        comparisons = [compare_domains(d, header_from_domain) for d in signing_domains]
        # One aligned signature is enough for DMARC, so take the best relationship.
        for preferred in (
            AlignmentResult.EXACT,
            AlignmentResult.SUBDOMAIN,
            AlignmentResult.ORGANIZATIONAL,
            AlignmentResult.MISMATCH,
        ):
            if preferred in comparisons:
                dkim_alignment = preferred
                break

    arc_present, arc_status = arc_chain_status(parsed)

    if not evidence:
        warnings.append(
            "No Authentication-Results, ARC-Authentication-Results or Received-SPF "
            "header is present. Authentication was not recorded by any receiving "
            "system, so nothing can be read from the header alone."
        )

    untrusted = [e for e in evidence if e.trust is not TrustStatus.TRUSTED]
    if untrusted and (trusted_domains or trusted_hosts):
        warnings.append(
            f"{len(untrusted)} authentication result(s) were asserted by infrastructure "
            "that is not configured as trusted. Per RFC 8601 §7.1 these headers are "
            "forgeable and carry no weight on their own."
        )
    elif evidence and not trusted_domains and not trusted_hosts:
        warnings.append(
            "No trusted receiver infrastructure is configured, so every recorded "
            "authentication result is marked UNKNOWN trust. Set "
            "TRUSTED_RECEIVER_DOMAINS to your own mail infrastructure."
        )

    if _has_result(evidence, AuthMethod.SPF, AuthResult.PASS) and not is_aligned(
        spf_alignment
    ):
        warnings.append(
            "SPF passed but does not align with the visible From domain. Legitimate for "
            "mail relayed by an email service provider, and also what a spoofed sender "
            "using their own authenticated domain looks like."
        )

    if _has_result(evidence, AuthMethod.DKIM, AuthResult.PASS) and not is_aligned(
        dkim_alignment
    ):
        warnings.append(
            "DKIM passed but the signing domain does not align with the visible From "
            "domain. Common for third-party senders; also consistent with a message "
            "signed by infrastructure unrelated to the claimed sender."
        )

    return AuthenticationSummary(
        evidence=tuple(evidence),
        spf_alignment=spf_alignment,
        dkim_alignment=dkim_alignment,
        dkim_signing_domains=tuple(signing_domains),
        envelope_from=envelope_from,
        helo_identity=helo_identity,
        header_from_domain=header_from_domain,
        arc_present=arc_present,
        arc_chain_status=arc_status,
        warnings=tuple(warnings),
    )


def _has_result(
    evidence: list[AuthenticationEvidence], method: AuthMethod, result: AuthResult
) -> bool:
    return any(e.method is method and e.result is result for e in evidence)


def trusted_result(
    summary: AuthenticationSummary, method: AuthMethod
) -> AuthResult | None:
    """The result for ``method`` asserted by trusted infrastructure, if any.

    Returns ``None`` when the only assertions came from untrusted or unknown sources —
    which the risk engine must treat as "not established", never as a pass.
    """
    for item in summary.evidence:
        if item.method is method and item.trust is TrustStatus.TRUSTED:
            return item.result
    return None
