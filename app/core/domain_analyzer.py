"""Domain normalisation, organisational-domain comparison and impersonation checks.

Two decisions in here carry most of the false-positive risk in the whole tool, so
both are stated explicitly.

**Organisational domain comes from the Public Suffix List, not from "last two
labels".** Naive two-label comparison says ``example.co.uk`` and ``other.co.uk`` share
the organisational domain ``co.uk``, which is wrong and would make every UK domain
appear aligned with every other. It also mishandles the many multi-label suffixes
(``com.au``, ``s3.amazonaws.com``, ``github.io``).

**There is no allowlist that suppresses indicators.** A list of "known good" providers
used to drop findings is how a tool misses the compromised-Microsoft-tenant case, which
is one of the most common real phishing origins. Well-known infrastructure is *labelled*
here, never silenced — labelling gives the analyst context; suppression removes evidence.

The PSL is loaded from the bundled snapshot with network fetch disabled. ``tldextract``
otherwise retrieves the list over HTTP on first use, and a security tool making an
unannounced outbound request during analysis is not acceptable in a SOC.
"""

from __future__ import annotations

import functools
import re
import unicodedata

import tldextract

from app.core.models import AlignmentResult


@functools.lru_cache(maxsize=1)
def _extractor() -> tldextract.TLDExtract:
    """Offline PSL extractor. See ADR-08 in STATUS.md.

    ``cache_dir=None`` in addition to ``suffix_list_urls=()``: without it,
    ``tldextract`` still tries to *write* its (never-fetched) cache file to
    ``$HOME/.cache`` on first use. Under the container's non-root user that directory
    doesn't exist and isn't writable, so every startup logged a permission-denied
    warning. The failure was harmless (caught, falls back to the bundled snapshot
    regardless), but a security tool logging a spurious permission error on every boot
    is exactly the kind of noise that trains an operator to ignore real ones.
    """
    return tldextract.TLDExtract(
        suffix_list_urls=(), fallback_to_snapshot=True, cache_dir=None
    )


def normalize_domain(value: str | None) -> str | None:
    """Lowercase, strip the root dot, strip any port, drop enclosing brackets.

    The trailing root dot matters: ``mail.example.com.`` is fully qualified and equal to
    ``mail.example.com``, but string comparison disagrees, and that difference has
    produced spurious 'domain mismatch' findings in other tools.
    """
    if not value:
        return None
    candidate = value.strip().strip("<>[]").rstrip(".").lower()
    candidate = candidate.split("/")[0]
    if candidate.count(":") == 1:  # host:port, but not IPv6
        candidate = candidate.split(":")[0]
    return candidate or None


def to_unicode(domain: str | None) -> str | None:
    """Punycode to Unicode, for display only.

    Never use the result for comparison — that is what the attacker wants. Display the
    Unicode form so the analyst can see what the *victim* saw, and compare on the ASCII
    form.
    """
    if not domain:
        return None
    try:
        return domain.encode("ascii").decode("idna")
    except (UnicodeError, UnicodeDecodeError, ValueError):
        return domain


def to_ascii(domain: str | None) -> str | None:
    """Unicode to punycode, for comparison."""
    if not domain:
        return None
    try:
        return domain.encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError):
        return domain.lower()


def has_punycode(domain: str | None) -> bool:
    return bool(domain) and any(
        label.startswith("xn--") for label in domain.lower().split(".")
    )


def _split_registrable(normalized: str) -> tuple[str, str]:
    """Return ``(subdomain_part, organizational_domain)`` for a normalised domain.

    The Public Suffix List is authoritative when it recognises the suffix. When it does
    **not**, this falls back to the last two labels rather than treating the whole name
    as unsplittable.

    That fallback is load-bearing, not a nicety. The PSL snapshot bundled with
    ``tldextract`` is a point-in-time copy and network refresh is deliberately disabled
    (ADR-08), so any TLD delegated after the snapshot — and every RFC 2606 reserved TLD
    such as ``.example``, ``.test`` and ``.invalid`` — is unknown to it. Without this
    branch, ``mail.bank.example`` and ``bank.example`` would be reported as *unrelated
    organisations*, which would turn every aligned message on an unrecognised TLD into
    a false 'domain mismatch' finding.
    """
    result = _extractor()(normalized)
    if result.domain and result.suffix:
        return result.subdomain, f"{result.domain}.{result.suffix}"

    labels = normalized.split(".")
    if len(labels) < 2:
        return "", normalized
    return ".".join(labels[:-2]), ".".join(labels[-2:])


def organizational_domain(value: str | None) -> str | None:
    """Registrable domain, per the Public Suffix List where it is known.

    ``news.mail.example.co.uk`` → ``example.co.uk``.
    """
    normalized = normalize_domain(value)
    if not normalized:
        return None
    return _split_registrable(normalized)[1]


def suffix_is_known(value: str | None) -> bool:
    """Whether the PSL recognised this domain's suffix.

    Exposed so the UI can mark an organisational-domain comparison as heuristic rather
    than authoritative when the suffix is unrecognised.
    """
    normalized = normalize_domain(value)
    if not normalized:
        return False
    return bool(_extractor()(normalized).suffix)


def subdomain_depth(value: str | None) -> int:
    normalized = normalize_domain(value)
    if not normalized:
        return 0
    subdomain = _split_registrable(normalized)[0]
    return len(subdomain.split(".")) if subdomain else 0


def compare_domains(left: str | None, right: str | None) -> AlignmentResult:
    """Relationship between two domains, in DMARC alignment terms (RFC 7489 §3.1).

    ``EXACT`` is strict alignment. ``ORGANIZATIONAL`` and ``SUBDOMAIN`` both satisfy
    relaxed alignment. The distinction is preserved because ``mail.example.com`` being a
    subdomain of ``example.com`` is a different observation from two unrelated
    subdomains of a shared organisational parent.
    """
    left_norm = normalize_domain(left)
    right_norm = normalize_domain(right)
    if not left_norm or not right_norm:
        return AlignmentResult.UNKNOWN
    if left_norm == right_norm:
        return AlignmentResult.EXACT

    left_org = organizational_domain(left_norm)
    right_org = organizational_domain(right_norm)
    if not left_org or not right_org:
        return AlignmentResult.UNKNOWN

    if left_org == right_org:
        if left_norm.endswith("." + right_norm) or right_norm.endswith("." + left_norm):
            return AlignmentResult.SUBDOMAIN
        return AlignmentResult.ORGANIZATIONAL
    return AlignmentResult.MISMATCH


def is_aligned(result: AlignmentResult, strict: bool = False) -> bool:
    """Whether a comparison satisfies DMARC alignment.

    Under ``adkim=s`` / ``aspf=s`` only exact alignment counts; under the default
    relaxed mode an organisational match is sufficient.
    """
    if strict:
        return result is AlignmentResult.EXACT
    return result in (
        AlignmentResult.EXACT,
        AlignmentResult.ORGANIZATIONAL,
        AlignmentResult.SUBDOMAIN,
    )


# ---------------------------------------------------------------------------
# Script and homoglyph analysis
# ---------------------------------------------------------------------------

# Confusables that appear in real registered lookalike domains. Not exhaustive —
# the full Unicode confusables table is large — but these cover the Cyrillic and
# Greek characters overwhelmingly used against Latin-script brands.
_CONFUSABLES: dict[str, str] = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "ѕ": "s", "і": "i", "ј": "j", "ԁ": "d", "һ": "h", "ӏ": "l", "ν": "v",
    "α": "a", "ο": "o", "ρ": "p", "τ": "t", "υ": "u", "ѐ": "e", "ё": "e",
    "0": "o", "1": "l", "5": "s",
}


def _script_of(char: str) -> str | None:
    """Coarse Unicode script name, from the character's Unicode name."""
    if not char.isalpha():
        return None
    try:
        name = unicodedata.name(char)
    except ValueError:
        return None
    for script in ("LATIN", "CYRILLIC", "GREEK", "ARABIC", "HEBREW", "HAN", "CHEROKEE"):
        if name.startswith(script):
            return script
    return "OTHER"


def scripts_in(value: str) -> set[str]:
    return {s for s in (_script_of(c) for c in value) if s}


def is_mixed_script(value: str | None) -> bool:
    """Whether a label mixes writing systems.

    Mixing scripts *within a single label* is the classic homograph technique —
    ``аpple.com`` with a Cyrillic а. Mixing across different labels is common and
    legitimate in internationalised domains, so only within-label mixing is flagged.
    """
    if not value:
        return False
    display = to_unicode(normalize_domain(value)) or ""
    return any(len(scripts_in(label)) > 1 for label in display.split("."))


def skeleton(value: str) -> str:
    """Map confusable characters to a canonical form for comparison.

    ``pаypal`` (Cyrillic а) and ``paypal`` produce the same skeleton, which is what
    makes homograph detection possible without an edit-distance false-positive storm.
    """
    display = (to_unicode(normalize_domain(value)) or "").lower()
    normalized = unicodedata.normalize("NFKD", display)
    return "".join(_CONFUSABLES.get(c, c) for c in normalized if not unicodedata.combining(c))


def levenshtein(left: str, right: str) -> int:
    if left == right:
        return 0
    if not left:
        return len(right)
    if not right:
        return len(left)

    previous = list(range(len(right) + 1))
    for i, lc in enumerate(left, start=1):
        current = [i]
        for j, rc in enumerate(right, start=1):
            current.append(
                min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (lc != rc))
            )
        previous = current
    return previous[-1]


def lookalike_of(
    candidate: str | None, protected: tuple[str, ...]
) -> tuple[str, str] | None:
    """Whether ``candidate`` impersonates one of ``protected``.

    Returns ``(matched_protected_domain, technique)`` or ``None``.

    ``protected`` is a watchlist of domains worth impersonating — *not* an allowlist.
    Nothing here suppresses an indicator; a match adds context, and a non-match removes
    nothing. A compromised genuine Microsoft tenant must still surface all its
    indicators, which is exactly what a suppression list would break.
    """
    candidate_org = organizational_domain(candidate)
    if not candidate_org:
        return None

    candidate_skeleton = skeleton(candidate_org)

    for target in protected:
        target_org = organizational_domain(target)
        if not target_org or candidate_org == target_org:
            continue  # identical is not impersonation

        target_skeleton = skeleton(target_org)

        if candidate_skeleton == target_skeleton:
            return target_org, "homoglyph substitution — visually identical"

        # Compare registrable labels only, so example.com vs example.net is not
        # reported as a one-character typosquat of the brand.
        #
        # Length thresholds here are a false-positive/false-negative trade-off, and
        # they are set low deliberately: 'protected' is a watchlist an operator
        # populated on purpose (their own org, a bank, a partner), so a 4-letter brand
        # like "bank" or "visa" must still be catchable — that is the entire point of
        # adding it to the watchlist. A higher threshold silently makes short,
        # real-world brand names impossible to protect. The cost is accepted because a
        # match here is only ever a MODERATE-strength finding with a legitimate
        # explanation attached (see IMP-001 in rules.yaml), never an automatic verdict.
        candidate_label = candidate_org.split(".")[0]
        target_label = target_org.split(".")[0]
        if len(target_label) >= 4:
            distance = levenshtein(
                skeleton(candidate_label), skeleton(target_label)
            )
            if distance == 1:
                return target_org, f"one-character difference from {target_label}"
            if distance == 2 and len(target_label) >= 7:
                return target_org, f"two-character difference from {target_label}"

        # brand embedded in an unrelated registrable domain, e.g. paypal-secure.example
        if (
            target_label in candidate_label
            and candidate_label != target_label
            and len(target_label) >= 4
        ):
            return target_org, f"contains the string {target_label!r} in another domain"

    return None


_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$")


def structural_warnings(domain: str | None, max_subdomain_depth: int = 4) -> list[str]:
    """Structural oddities worth noting. None is a verdict on its own."""
    warnings: list[str] = []
    normalized = normalize_domain(domain)
    if not normalized:
        return warnings

    if has_punycode(normalized):
        display = to_unicode(normalized)
        warnings.append(
            f"Domain uses punycode: {normalized} displays as {display!r}. Legitimate "
            "for internationalised domains, and also the standard homograph technique."
        )

    if is_mixed_script(normalized):
        warnings.append(
            "Domain mixes writing systems within a single label, which is the classic "
            "homograph technique. Rare in legitimate domains."
        )

    depth = subdomain_depth(normalized)
    if depth > max_subdomain_depth:
        warnings.append(
            f"Domain has {depth} subdomain levels. Common in tracking and bulk-mail "
            "infrastructure, and also used to push a lookalike brand name into the "
            "part of the hostname a phone client truncates."
        )

    for label in normalized.split("."):
        ascii_label = to_ascii(label) or label
        if not _LABEL_RE.match(ascii_label):
            warnings.append(f"Domain label {label!r} is not a valid hostname label.")
            break

    return warnings
