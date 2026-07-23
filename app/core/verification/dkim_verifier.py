"""Independent DKIM verification — staged honestly by the evidence available.

A DKIM signature (RFC 6376) covers two things: a hash of the listed headers, and a
hash of the body (the ``bh=`` tag). The ``b=`` signature is computed over the signed
headers *plus the DKIM-Signature header itself*, and ``bh=`` lives inside that header.

That structure has a consequence most tools never exploit:

* With **headers only**, the ``b=`` signature can still be verified. Doing so proves
  the signed headers are authentic and unmodified, and that the ``bh=`` claim really
  was made by the signing domain. What it cannot prove is that the body matches
  ``bh=`` — because there is no body to hash.
* With a **full ``.eml``**, both checks run and the verification is complete.

So this module reports three distinct outcomes rather than one vague "DKIM: pass", and
each is worded to say exactly what was and was not established. Overclaiming here would
be the single most misleading thing this tool could do — every reference project
audited either parses the recorded result and calls it verification, or says nothing.

``dkimpy`` performs blocking DNS. Call this from a worker thread.
"""

from __future__ import annotations

from app.core.models import AuthMethod, VerificationOutcome, VerificationResult
from app.core.verification.resolver import DnsUnavailable, Resolver


def _dns_func(resolver: Resolver):
    """Adapt our resolver to the callable ``dkimpy`` expects.

    ``dkimpy`` asks for a name and wants the TXT record as bytes.
    """

    def get_txt(name: bytes, timeout: int = 5) -> bytes:
        decoded = name.decode("ascii", errors="replace").rstrip(".")
        try:
            records = resolver.txt(decoded)
        except DnsUnavailable:
            return b""
        for record in records:
            if "p=" in record or record.startswith("v=DKIM1"):
                return record.encode("utf-8")
        return records[0].encode("utf-8") if records else b""

    return get_txt


def _message_bytes(header_text: str, body: str | None) -> bytes:
    """Assemble a message for dkimpy, using CRLF as RFC 6376 canonicalisation expects."""
    headers = header_text.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "\r\n")
    if not headers.endswith("\r\n"):
        headers += "\r\n"
    return (headers + "\r\n" + (body or "")).encode("utf-8", errors="replace")


def verify_dkim(
    header_text: str,
    body: str | None,
    resolver: Resolver,
    signature_index: int = 0,
) -> VerificationResult:
    """Verify one DKIM signature.

    ``body`` is ``None`` for pasted headers, in which case only the header signature is
    checked and the result says so explicitly.
    """
    import dkim

    if "dkim-signature" not in header_text.lower():
        return VerificationResult(
            method=AuthMethod.DKIM,
            outcome=VerificationOutcome.NOT_POSSIBLE,
            detail=(
                "The message carries no DKIM-Signature header, so there is nothing to "
                "verify. This is not an authentication failure — DMARC needs only one "
                "of SPF or DKIM to pass with alignment — but it does mean the message "
                "has no cryptographic integrity protection."
            ),
        )

    headers_only = body is None
    message = _message_bytes(header_text, body)

    try:
        verifier = dkim.DKIM(message)
        prep = verifier.verify_headerprep(signature_index)
    except Exception as exc:
        return VerificationResult(
            method=AuthMethod.DKIM,
            outcome=VerificationOutcome.ERROR,
            detail=f"The DKIM-Signature header could not be parsed: {exc}",
            error=f"{type(exc).__name__}: {exc}",
        )

    if not prep:
        return VerificationResult(
            method=AuthMethod.DKIM,
            outcome=VerificationOutcome.NOT_POSSIBLE,
            detail="No DKIM signature at the requested index.",
        )

    sig, include_headers, sig_headers = prep
    signing_domain = sig.get(b"d", b"").decode("ascii", errors="replace")
    selector = sig.get(b"s", b"").decode("ascii", errors="replace")
    algorithm = sig.get(b"a", b"").decode("ascii", errors="replace")

    if headers_only:
        # Removing bh= makes dkimpy skip the body-hash comparison and verify only the
        # header signature. The bh= value is still covered by b=, because b= is
        # computed over the raw DKIM-Signature header text, not over this dict.
        sig = dict(sig)
        sig.pop(b"bh", None)

    scope = (
        "signed headers only — body hash not checked, because only headers were "
        "supplied"
        if headers_only
        else "signed headers and body hash"
    )

    try:
        valid = verifier.verify_sig(
            sig, include_headers, sig_headers[signature_index], _dns_func(resolver)
        )
    except Exception as exc:
        return VerificationResult(
            method=AuthMethod.DKIM,
            outcome=VerificationOutcome.VERIFIED_FAIL
            if "body hash mismatch" in str(exc).lower()
            else VerificationOutcome.ERROR,
            detail=(
                f"DKIM verification failed for d={signing_domain} s={selector}: {exc}"
            ),
            checked_domain=signing_domain or None,
            scope=scope,
            error=f"{type(exc).__name__}: {exc}",
        )

    if valid:
        detail = (
            f"Independently verified: DKIM signature is cryptographically valid for "
            f"signing domain {signing_domain} (selector {selector}, {algorithm}). "
        )
        detail += (
            "This proves the signed headers are authentic and unmodified. It does NOT "
            "confirm body integrity — that requires the message body, which was not "
            "supplied. Upload the full .eml to verify the body hash."
            if headers_only
            else "Both the signed headers and the body hash verify."
        )
        return VerificationResult(
            method=AuthMethod.DKIM,
            outcome=VerificationOutcome.VERIFIED_PASS,
            detail=detail,
            checked_domain=signing_domain or None,
            scope=scope,
        )

    return VerificationResult(
        method=AuthMethod.DKIM,
        outcome=VerificationOutcome.VERIFIED_FAIL,
        detail=(
            f"Independently verified: the DKIM signature for d={signing_domain} "
            f"(selector {selector}) does NOT validate. Either the signed headers were "
            "modified after signing, or the public key at "
            f"{selector}._domainkey.{signing_domain} could not be retrieved or does "
            "not match. Note that ordinary mailing lists and forwarders modify headers "
            "and break DKIM legitimately — check for ARC headers before concluding "
            "tampering."
        ),
        checked_domain=signing_domain or None,
        scope=scope,
    )


def fetch_dkim_key(
    selector: str, domain: str, resolver: Resolver
) -> tuple[str | None, str | None]:
    """Retrieve a DKIM public key record. Returns ``(record, error)``.

    Used to distinguish "the signature is invalid" from "the key is not published",
    which are different findings: the second usually means a rotated selector or a
    misconfiguration, not tampering.
    """
    try:
        records = resolver.txt(f"{selector}._domainkey.{domain}")
    except DnsUnavailable as exc:
        return None, str(exc)
    for record in records:
        if "p=" in record:
            return record, None
    return None, None
