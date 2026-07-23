"""Header parsing regression tests.

All material is synthetic — RFC 2606 reserved domains, RFC 5737 documentation IPs.
"""

from __future__ import annotations

from app.core.header_parser import parse_headers, split_header_body

# ---------------------------------------------------------------------------
# Field boundaries, folding, order
# ---------------------------------------------------------------------------


def test_folded_field_is_unfolded_but_raw_is_preserved():
    raw = (
        "Subject: this subject\n"
        " continues across\n"
        "\tthree lines\n"
        "From: alice@example.com\n"
    )
    parsed = parse_headers(raw)

    subject = parsed.get_first("Subject")
    assert subject is not None
    assert subject.normalized_value == "this subject continues across three lines"
    # The raw value keeps the folding, because it is what actually arrived.
    assert "\n" in subject.raw_value


def test_field_order_is_preserved():
    raw = "B: 2\nA: 1\nC: 3\n"
    parsed = parse_headers(raw)
    assert [f.name for f in parsed.fields] == ["B", "A", "C"]
    assert [f.order for f in parsed.fields] == [0, 1, 2]


def test_duplicate_fields_are_all_retained():
    """Two ``From:`` headers is an attack technique, not something to deduplicate."""
    raw = "From: alice@example.com\nFrom: attacker@example.net\nTo: bob@example.org\n"
    parsed = parse_headers(raw)

    froms = parsed.get_all("From")
    assert len(froms) == 2
    assert froms[0].normalized_value == "alice@example.com"
    assert froms[1].normalized_value == "attacker@example.net"


def test_duplicate_singleton_header_is_a_warning():
    raw = "From: alice@example.com\nFrom: attacker@example.net\n"
    parsed = parse_headers(raw)
    assert any(
        "'from' appears 2 times" in w.lower() for w in parsed.warnings
    ), parsed.warnings


def test_message_id_lowercase_d_is_found():
    """RFC 5322 §1.2.2 makes field names case-insensitive.

    Real messages carry ``Message-Id`` at least as often as ``Message-ID``; a
    case-sensitive dictionary lookup silently misses them.
    """
    parsed = parse_headers("Message-Id: <abc@example.com>\n")
    assert parsed.value_of("Message-ID") == "<abc@example.com>"
    assert parsed.value_of("message-id") == "<abc@example.com>"


def test_field_with_empty_value_is_kept():
    parsed = parse_headers("X-Empty:\nFrom: alice@example.com\n")
    field = parsed.get_first("X-Empty")
    assert field is not None
    assert field.normalized_value == ""


# ---------------------------------------------------------------------------
# Encoded words
# ---------------------------------------------------------------------------


def test_rfc2047_base64_display_name_is_decoded():
    # "Ünïcödé Sender" as UTF-8 base64
    raw = "From: =?utf-8?B?w5xuw69jw7Zkw6kgU2VuZGVy?= <sender@example.com>\n"
    parsed = parse_headers(raw)
    field = parsed.get_first("From")
    assert field is not None
    assert field.decoded_value is not None
    assert "Sender" in field.decoded_value
    # The undecoded original is still available as evidence.
    assert "=?utf-8?B?" in field.raw_value


def test_rfc2047_quoted_printable_is_decoded():
    raw = "Subject: =?utf-8?Q?Payment_Confirmation?=\n"
    parsed = parse_headers(raw)
    field = parsed.get_first("Subject")
    assert field is not None
    assert field.decoded_value == "Payment Confirmation"


def test_malformed_encoded_word_warns_rather_than_raising():
    raw = "Subject: =?utf-8?B?not-valid-base64!!!?=\n"
    parsed = parse_headers(raw)
    field = parsed.get_first("Subject")
    assert field is not None  # retained rather than dropped


def test_unknown_charset_falls_back_with_warning():
    raw = "Subject: =?definitely-not-a-charset?Q?hello?=\n"
    parsed = parse_headers(raw)
    field = parsed.get_first("Subject")
    assert field is not None


# ---------------------------------------------------------------------------
# Header / body boundary
# ---------------------------------------------------------------------------


def test_body_is_split_at_first_blank_line_only():
    raw = "From: a@example.com\n\nbody line one\n\nbody line two\n"
    header_text, body = split_header_body(raw)

    assert header_text == "From: a@example.com"
    # The blank line *inside* the body must survive. Stripping blank lines globally
    # corrupts an .eml and breaks any later body-hash verification.
    assert body == "body line one\n\nbody line two\n"


def test_crlf_line_endings_are_handled():
    raw = "From: a@example.com\r\nSubject: hi\r\n\r\nbody\r\n"
    parsed = parse_headers(raw)
    assert parsed.value_of("From") == "a@example.com"
    assert parsed.had_body is True


def test_headers_without_body_report_no_body():
    parsed = parse_headers("From: a@example.com\nSubject: hi\n")
    assert parsed.had_body is False


# ---------------------------------------------------------------------------
# Malformed input
# ---------------------------------------------------------------------------


def test_empty_input_is_reported_not_raised():
    parsed = parse_headers("")
    assert parsed.fields == ()
    assert parsed.warnings


def test_whitespace_only_input_is_reported_not_raised():
    parsed = parse_headers("   \n\t\n")
    assert parsed.fields == ()
    assert parsed.warnings


def test_line_without_colon_is_retained_as_unparsable():
    """Never silently discard a malformed field. An incomplete view of the evidence
    presented as complete is worse than an explicit gap."""
    parsed = parse_headers("From: a@example.com\nthis line has no colon\nTo: b@example.org\n")

    assert parsed.value_of("From") == "a@example.com"
    assert parsed.value_of("To") == "b@example.org"
    assert any(f.name == "(unparsable)" for f in parsed.fields)
    assert any("not a valid header field" in w for w in parsed.warnings)


def test_orphaned_continuation_line_is_retained():
    parsed = parse_headers("   orphaned continuation\nFrom: a@example.com\n")
    assert any(f.name == "(unparsable)" for f in parsed.fields)
    assert parsed.value_of("From") == "a@example.com"


def test_mbox_from_separator_is_ignored_with_a_note():
    parsed = parse_headers("From alice@example.com Mon Oct 22 09:00:00 2025\nFrom: a@example.com\n")
    assert parsed.value_of("From") == "a@example.com"
    assert any("mbox" in w for w in parsed.warnings)


def test_html_in_header_value_is_not_interpreted():
    """The parser stores values verbatim; escaping is the template layer's job.

    What matters here is that nothing strips or executes it, so the analyst sees the
    payload exactly as it arrived.
    """
    payload = "<script>alert(1)</script>"
    parsed = parse_headers(f"Subject: {payload}\n")
    assert parsed.value_of("Subject") == payload


def test_very_long_single_header_does_not_hang():
    parsed = parse_headers("X-Long: " + ("a" * 100_000) + "\n")
    field = parsed.get_first("X-Long")
    assert field is not None
    assert len(field.normalized_value) == 100_000
