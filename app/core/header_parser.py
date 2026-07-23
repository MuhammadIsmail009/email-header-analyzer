"""Raw header parsing.

Deliberately *not* built on ``email.parser`` alone. That module is excellent at giving
you a decoded, normalised view, but it discards things this tool needs as evidence:
the exact bytes of each field as they arrived, the original field order, and the
distinction between "this header was absent" and "this header was present but
unparsable". A forensic tool has to be able to show the analyst what was actually
there.

So field boundaries are found here, and stdlib is used for the parts where it is
authoritative — RFC 2047 encoded-word decoding in particular.

Design commitments:

* Duplicates are preserved. Two ``From:`` headers is a real attack technique, and RFC
  5322 §3.6 permits exactly one; a parser that takes the first and moves on hides it.
* Order is preserved, so the raw view can be reconstructed faithfully.
* Malformed input produces warnings, never exceptions and never silent discards.
* The header/body boundary is the *first* empty line only. Blank lines are not
  stripped globally — doing that to an ``.eml`` corrupts the message.
"""

from __future__ import annotations

import re
from email.errors import HeaderParseError
from email.header import decode_header

from app.core.models import HeaderField, ParsedHeader

# RFC 5322 §3.6: fields that may appear at most once. More than one occurrence is
# malformed, and is worth surfacing rather than resolving silently.
_SINGLETON_FIELDS = frozenset(
    {
        "date",
        "from",
        "sender",
        "reply-to",
        "to",
        "cc",
        "bcc",
        "message-id",
        "subject",
        "in-reply-to",
        "references",
    }
)

# A field name is printable US-ASCII excluding colon and space (RFC 5322 §3.6.8).
_FIELD_NAME_RE = re.compile(r"^([\x21-\x39\x3b-\x7e]+)[ \t]*:(.*)$", re.DOTALL)

_WS_RUN = re.compile(r"[ \t]+")


def split_header_body(raw: str) -> tuple[str, str | None]:
    """Split at the *first* empty line, per RFC 5322 §2.1.

    Returns ``(header_text, body_text)``. ``body_text`` is ``None`` when no boundary
    was found, which is the normal case for a pasted header block.

    Blank lines after the boundary are left completely untouched — they are part of
    the body and, for DKIM body-hash purposes, significant.
    """
    normalized = raw.replace("\r\n", "\n").replace("\r", "\n")
    match = re.search(r"\n[ \t]*\n", normalized)
    if match is None:
        return normalized, None
    return normalized[: match.start()], normalized[match.end() :]


def _unfold(lines: list[str]) -> str:
    """Join a folded field into one logical line.

    RFC 5322 §2.2.3: folding inserts CRLF before existing whitespace, so unfolding is
    removal of the CRLF only. The leading whitespace on continuation lines is retained
    in the raw value because it was genuinely there.
    """
    return "".join(lines)


def _decode_encoded_words(value: str) -> tuple[str, list[str]]:
    """Decode RFC 2047 encoded-words, e.g. ``=?utf-8?B?...?=``.

    Returns ``(decoded, warnings)``. Decoding is best-effort: a malformed encoded-word
    yields the original text plus a warning rather than an exception, because a
    deliberately broken encoded-word is itself something an analyst wants to see.
    """
    if "=?" not in value:
        return value, []

    warnings: list[str] = []
    out: list[str] = []
    try:
        for chunk, charset in decode_header(value):
            if isinstance(chunk, bytes):
                try:
                    out.append(chunk.decode(charset or "utf-8", errors="replace"))
                except (LookupError, UnicodeDecodeError):
                    out.append(chunk.decode("utf-8", errors="replace"))
                    warnings.append(
                        f"unknown or invalid charset {charset!r} in encoded-word; "
                        "decoded as UTF-8 with replacement"
                    )
            else:
                out.append(chunk)
    except (ValueError, TypeError, HeaderParseError) as exc:
        # HeaderParseError is raised for e.g. undecodable base64 and is *not* a
        # ValueError subclass, so it has to be named explicitly. A deliberately
        # corrupted encoded-word is itself worth showing the analyst, so this
        # degrades to the original text plus a warning rather than failing the parse.
        return value, [f"malformed RFC 2047 encoded-word: {exc}"]

    decoded = "".join(out)
    if "�" in decoded and not warnings:
        warnings.append("encoded-word contained undecodable bytes")
    return decoded, warnings


def _normalize(value: str) -> str:
    """Collapse folding whitespace to single spaces for comparison and display."""
    return _WS_RUN.sub(" ", value.replace("\n", " ")).strip()


def parse_headers(raw: str) -> ParsedHeader:
    """Parse a raw header block into ordered, duplicate-preserving fields."""
    if not raw or not raw.strip():
        return ParsedHeader(fields=(), warnings=("input was empty",))

    header_text, body = split_header_body(raw)
    warnings: list[str] = []

    lines = header_text.split("\n")

    fields: list[HeaderField] = []
    current_name: str | None = None
    current_lines: list[str] = []
    order = 0

    def flush() -> None:
        nonlocal current_name, current_lines, order
        if current_name is None:
            return
        raw_value = _unfold(current_lines)
        decoded, decode_warnings = _decode_encoded_words(raw_value)
        normalized = _normalize(raw_value)
        fields.append(
            HeaderField(
                name=current_name,
                raw_value=raw_value,
                normalized_value=normalized,
                decoded_value=_normalize(decoded) if decoded != raw_value else None,
                order=order,
                warnings=tuple(decode_warnings),
            )
        )
        order += 1
        current_name = None
        current_lines = []

    for lineno, line in enumerate(lines):
        if not line:
            # An empty line inside the header block. split_header_body already
            # separated the body, so this is malformed rather than a boundary.
            continue

        if line[0] in " \t":
            if current_name is None:
                warnings.append(
                    f"line {lineno + 1}: continuation line with no preceding field; "
                    "kept as an unparsable fragment"
                )
                fields.append(
                    HeaderField(
                        name="(unparsable)",
                        raw_value=line,
                        normalized_value=_normalize(line),
                        order=order,
                        warnings=("orphaned continuation line",),
                    )
                )
                order += 1
                continue
            current_lines.append("\n" + line)
            continue

        match = _FIELD_NAME_RE.match(line)
        if match is None:
            flush()
            # The mbox "From " separator is common and benign; anything else is not.
            if line.startswith("From "):
                warnings.append(
                    f"line {lineno + 1}: mbox 'From ' separator line ignored"
                )
            else:
                warnings.append(
                    f"line {lineno + 1}: line is not a valid header field and was "
                    "retained as unparsable"
                )
                fields.append(
                    HeaderField(
                        name="(unparsable)",
                        raw_value=line,
                        normalized_value=_normalize(line),
                        order=order,
                        warnings=("no field name / colon separator",),
                    )
                )
                order += 1
            continue

        flush()
        current_name = match.group(1)
        current_lines = [match.group(2)]

    flush()

    warnings.extend(_singleton_warnings(fields))

    return ParsedHeader(
        fields=tuple(fields),
        warnings=tuple(warnings),
        had_body=body is not None,
    )


def _singleton_warnings(fields: list[HeaderField]) -> list[str]:
    """Flag fields that RFC 5322 §3.6 permits at most once but which appear repeatedly.

    Duplicate ``From:`` in particular is worth an analyst's attention: mail clients
    differ in which one they display, and that divergence has been used to show the
    recipient one sender while authentication evaluates another.
    """
    counts: dict[str, int] = {}
    for field in fields:
        lowered = field.name.lower()
        if lowered in _SINGLETON_FIELDS:
            counts[lowered] = counts.get(lowered, 0) + 1

    return [
        f"header {name!r} appears {count} times; RFC 5322 §3.6 permits at most one. "
        "Mail clients may disagree about which is displayed."
        for name, count in sorted(counts.items())
        if count > 1
    ]
