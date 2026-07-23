"""Microsoft anti-spam header decoder tests."""

from __future__ import annotations

from app.core.header_parser import parse_headers
from app.core.vendor_headers import decode_vendor_headers


def test_forefront_report_decodes_scl_and_sfv():
    parsed = parse_headers(
        "X-Forefront-Antispam-Report: CIP:203.0.113.15;CTRY:XX;SCL:5;SFV:SPM;"
        "CAT:PHSH;H:mail.example.com;PTR:mail.bank.example\n"
    )
    reports = decode_vendor_headers(parsed)
    report = next(r for r in reports if r.source_header == "X-Forefront-Antispam-Report")

    decoded = {code: (raw, meaning) for code, raw, meaning in report.decoded}
    assert "spam" in decoded["SCL"][1].lower()
    assert "phishing" in decoded["CAT"][1].lower()
    assert decoded["CIP"][0] == "203.0.113.15"


def test_forefront_report_never_uses_country_as_a_signal():
    parsed = parse_headers(
        "X-Forefront-Antispam-Report: CIP:203.0.113.15;CTRY:RU;SCL:1\n"
    )
    reports = decode_vendor_headers(parsed)
    report = reports[0]
    codes = {code for code, _, _ in report.decoded}
    assert "CTRY" not in codes  # present in raw, but not decoded as a field
    assert any("not used as evidence" in n for n in report.notes)


def test_microsoft_antispam_decodes_bcl():
    parsed = parse_headers("X-Microsoft-Antispam: BCL:0;ARA:...\n")
    reports = decode_vendor_headers(parsed)
    report = next(r for r in reports if r.source_header == "X-Microsoft-Antispam")
    decoded = {code: meaning for code, _, meaning in report.decoded}
    assert "bulk" in decoded["BCL"].lower()


def test_absent_vendor_headers_produce_empty_list():
    parsed = parse_headers("From: alice@bank.example\n")
    assert decode_vendor_headers(parsed) == []


def test_unrecognised_scl_value_does_not_crash():
    parsed = parse_headers("X-Forefront-Antispam-Report: SCL:999\n")
    reports = decode_vendor_headers(parsed)
    decoded = {code: meaning for code, _, meaning in reports[0].decoded}
    assert "Unrecognised" in decoded["SCL"]


def test_raw_header_is_preserved_for_the_escape_hatch():
    raw_value = "CIP:203.0.113.15;CTRY:XX;SCL:5;X-Unknown-Tag:something"
    parsed = parse_headers(f"X-Forefront-Antispam-Report: {raw_value}\n")
    report = decode_vendor_headers(parsed)[0]
    assert report.raw == raw_value
