"""Decoder for mail-filter vendor verdict headers.

Currently: Microsoft's ``X-Forefront-Antispam-Report`` and ``X-Microsoft-Antispam``.
Both are semicolon-delimited ``Tag:value`` pairs carrying the receiving filter's own
spam/bulk confidence and category classification. Microsoft documents the field
meanings publicly at
https://learn.microsoft.com/en-us/defender-office-365/message-headers-eop-mdo — this
module is a lookup table against that documentation.

Almost no open-source header analyzer decodes these, despite them being present on
essentially every message that transited Exchange Online / Microsoft 365, which is a
large share of real-world corporate phishing samples. Decoding SCL/BCL/CAT into English
is cheap, high-value analyst context.

This is presented as *corroborating context from the vendor's own filter*, never as an
independent finding this tool established — the values are exactly as forgeable as any
other header unless the message actually transited that vendor's infrastructure, which
is why trust marking (via authserv-id / receiving host) still applies to any risk
conclusion drawn from it.
"""

from __future__ import annotations

import re

from app.core.models import ParsedHeader, VendorFilterReport

_SCL_MEANINGS = {
    "-1": "Message skipped spam filtering (e.g. from a trusted/safe sender or internal)",
    "0": "Spam filtering determined the message is not spam",
    "1": "Spam filtering determined the message is not spam",
    "5": "Spam filtering determined the message is spam",
    "6": "Spam filtering determined the message is spam",
    "9": "Spam filtering determined the message is high-confidence spam",
}

_BCL_MEANINGS = {
    "0": "Not classified as bulk mail",
    "1": "Low bulk-mail confidence",
    "2": "Low bulk-mail confidence",
    "3": "Low bulk-mail confidence",
    "4": "Low bulk-mail confidence",
    "5": "Low bulk-mail confidence",
    "6": "Low bulk-mail confidence",
    "7": "High bulk-mail confidence",
    "8": "High bulk-mail confidence",
    "9": "High bulk-mail confidence",
}

_CAT_MEANINGS = {
    "SPM": "Spam",
    "HSPM": "High-confidence spam",
    "PHSH": "Phishing",
    "MALW": "Malware",
    "BULK": "Bulk mail",
    "SPOOF": "Spoofing detected by the filter",
    "IMT": "Impersonation — protected user",
    "IMTD": "Impersonation — protected domain",
    "GIMP": "Impersonation — mailbox intelligence",
    "UIMP": "Impersonation — unauthenticated sender",
    "AMP": "Anti-malware protection",
    "SAP": "Suspicious mailbox activity",
    "OSPM": "Outbound spam",
    "NONE": "No category assigned",
}

_SFV_MEANINGS = {
    "SPM": "Message was marked as spam by spam filtering",
    "SKS": "Message was marked as spam prior to being processed by spam filtering",
    "BLK": "Filtering skipped; recipient blocked the sender",
    "SKA": "Filtering skipped due to an allow entry",
    "SKB": "Filtering skipped due to sender block entry",
    "SKI": "Filtering skipped for intra-org mail under Standard/Strict preset policies",
    "SKN": "Filtering skipped: message marked as not spam prior to arrival",
    "SKQ": "Message released from quarantine",
    "SKS ": "Message skipped filtering, marked as spam",
    "NSPM": "Message determined to be clean (not spam)",
}

_FIELD_MEANINGS = {
    "SCL": ("Spam Confidence Level", _SCL_MEANINGS),
    "BCL": ("Bulk Complaint Level", _BCL_MEANINGS),
    "CAT": ("Filter category", _CAT_MEANINGS),
    "SFV": ("Spam filtering verdict", _SFV_MEANINGS),
}


def _decode_field(code: str, raw_value: str) -> tuple[str, str, str]:
    label, meanings = _FIELD_MEANINGS.get(code, (code, {}))
    meaning = meanings.get(raw_value.strip().upper(), f"Unrecognised {label} value")
    return code, raw_value, meaning


def _parse_semicolon_tags(value: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    for part in value.split(";"):
        if ":" not in part:
            continue
        key, _, val = part.partition(":")
        key = key.strip()
        if key:
            tags[key] = val.strip()
    return tags


_IP_TOKEN_RE = re.compile(r"IP:\[?([0-9A-Fa-f:.]+)\]?")


def decode_forefront_antispam_report(raw: str) -> VendorFilterReport:
    """Decode ``X-Forefront-Antispam-Report``.

    Format: ``CIP:1.2.3.4;CTRY:XX;LANG:en;SCL:5;SRV:...;IPV:CAL;SFV:SPM;...``
    """
    tags = _parse_semicolon_tags(raw)
    decoded: list[tuple[str, str, str]] = []
    notes: list[str] = []

    for code in ("SCL", "SFV", "CAT", "BCL"):
        if code in tags:
            decoded.append(_decode_field(code, tags[code]))

    for key in ("CIP", "H", "PTR"):
        if key in tags:
            decoded.append((key, tags[key], _RAW_FIELD_LABEL.get(key, key)))

    if "CTRY" in tags:
        notes.append(
            "CTRY (connecting country) is present but deliberately not decoded into "
            "a risk signal — geographic origin is not used as evidence in this tool."
        )

    return VendorFilterReport(
        vendor="Microsoft",
        source_header="X-Forefront-Antispam-Report",
        raw=raw,
        decoded=tuple(decoded),
        notes=tuple(notes),
    )


_RAW_FIELD_LABEL = {
    "CIP": "Connecting IP address",
    "H": "HELO/EHLO string presented by the connecting host",
    "PTR": "Reverse DNS (PTR) of the connecting IP, as seen by the filter",
}


def decode_microsoft_antispam(raw: str) -> VendorFilterReport:
    """Decode ``X-Microsoft-Antispam``.

    Format includes ``BCL:0;`` among other internal routing tags. Most of this header
    is Microsoft-internal routing metadata with no public field reference; only BCL is
    reliably documented and decoded here.
    """
    tags = _parse_semicolon_tags(raw)
    decoded: list[tuple[str, str, str]] = []
    if "BCL" in tags:
        decoded.append(_decode_field("BCL", tags["BCL"]))

    return VendorFilterReport(
        vendor="Microsoft",
        source_header="X-Microsoft-Antispam",
        raw=raw,
        decoded=tuple(decoded),
        notes=(
            "Most fields in this header are undocumented Microsoft-internal routing "
            "metadata and are shown only in the raw header view.",
        ),
    )


def decode_vendor_headers(parsed: ParsedHeader) -> list[VendorFilterReport]:
    """Decode every recognised vendor filter header present in the message."""
    reports: list[VendorFilterReport] = []

    for field in parsed.get_all("X-Forefront-Antispam-Report"):
        reports.append(decode_forefront_antispam_report(field.normalized_value))

    for field in parsed.get_all("X-Microsoft-Antispam"):
        reports.append(decode_microsoft_antispam(field.normalized_value))

    return reports
