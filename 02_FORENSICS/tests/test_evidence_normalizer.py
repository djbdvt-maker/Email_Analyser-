"""
Evidence Normalizer regression tests.

Covers: zero-width character insertion, unusual Unicode whitespace,
full-width characters, benign multilingual text, mixed-script text,
obfuscated security/phishing-style text, text that should remain
unchanged, and preservation/traceability of the original text.
"""

import copy

from hopzero_forensics.config.normalization_policy_v1 import NORMALIZATION_POLICY_VERSION
from hopzero_forensics.evidence_normalizer import normalize_email, normalize_text
from hopzero_forensics.parser import parse_eml


# ---------------------------------------------------------------------------
# Zero-width character insertion
# ---------------------------------------------------------------------------

def test_zero_width_space_between_letters_is_removed_and_logged():
    original = "P\u200ba\u200by\u200bP\u200ba\u200bl"  # "PayPal" with ZWSP between every letter
    field = normalize_text(original, "subject")
    assert field.normalized_text == "PayPal"
    assert field.unchanged is False
    assert field.original_text == original  # original preserved verbatim
    zero_width_events = [e for e in field.events if e.transformation == "zero_width_removed"]
    assert len(zero_width_events) == 5  # 5 ZWSP characters removed
    for e in zero_width_events:
        assert e.replacement_span is None
        assert e.codepoints == "U+200B"


def test_zero_width_joiner_and_non_joiner_removed():
    original = "Ver\u200dify\u200cAccount"
    field = normalize_text(original, "subject")
    assert field.normalized_text == "VerifyAccount"
    assert any(e.transformation == "zero_width_removed" for e in field.events)


def test_bom_zero_width_no_break_space_removed():
    original = "\ufeffUrgent Notice"
    field = normalize_text(original, "subject")
    assert field.normalized_text == "Urgent Notice"


# ---------------------------------------------------------------------------
# Unusual Unicode whitespace
# ---------------------------------------------------------------------------

def test_no_break_space_normalized_to_ascii_space():
    original = "Account\u00a0Verification\u00a0Required"
    field = normalize_text(original, "subject")
    assert field.normalized_text == "Account Verification Required"
    whitespace_events = [e for e in field.events if e.transformation == "unicode_whitespace_normalized"]
    assert len(whitespace_events) == 2


def test_ideographic_space_normalized():
    original = "\u3000\u3000Please respond"
    field = normalize_text(original, "body.text_plain")
    assert field.normalized_text == "  Please respond"


def test_line_and_paragraph_separators_normalized_to_newline():
    original = "Line one\u2028Line two\u2029Line three"
    field = normalize_text(original, "body.text_plain")
    assert field.normalized_text == "Line one\nLine two\nLine three"


def test_various_unicode_spaces_all_normalized():
    original = "a\u2000b\u2001c\u2002d\u2003e\u2007f\u200af"
    field = normalize_text(original, "body.text_plain")
    assert "\u2000" not in field.normalized_text
    assert "\u200a" not in field.normalized_text
    assert field.normalized_text == "a b c d e f f"


# ---------------------------------------------------------------------------
# Full-width characters
# ---------------------------------------------------------------------------

def test_fullwidth_latin_letters_folded_to_ascii():
    original = "\uff30\uff41\uff59\uff30\uff41\uff4c"  # fullwidth "PayPal"
    field = normalize_text(original, "subject")
    assert field.normalized_text == "PayPal"
    assert any(e.transformation == "nfkc_compatibility_normalization" for e in field.events)


def test_fullwidth_domain_like_string_folded():
    original = "\uff50\uff41\uff59\uff50\uff41\uff4c\uff0e\uff43\uff4f\uff4d"  # fullwidth "paypal.com"
    field = normalize_text(original, "body.text_plain")
    assert field.normalized_text == "paypal.com"


def test_fullwidth_digits_folded_to_ascii_digits():
    original = "\uff11\uff12\uff13"  # fullwidth "123"
    field = normalize_text(original, "subject")
    assert field.normalized_text == "123"


# ---------------------------------------------------------------------------
# Benign multilingual text - must survive normalization intact/meaningfully
# ---------------------------------------------------------------------------

def test_benign_spanish_text_with_accents_is_unchanged():
    original = "Hola, ¿cómo estás? Espero que tengas un buen día."
    field = normalize_text(original, "body.text_plain")
    assert field.normalized_text == original
    assert field.unchanged is True


def test_benign_japanese_text_with_only_native_punctuation_is_unchanged():
    # Uses only native ideographic punctuation (、 。) - no ASCII-range
    # fullwidth punctuation - so nothing here is an NFKC compatibility
    # variant of anything, and the text must be fully unchanged.
    original = "こんにちは、元気ですか。明日会いましょう。"
    field = normalize_text(original, "body.text_plain")
    assert field.normalized_text == original
    assert field.unchanged is True


def test_benign_japanese_text_with_fullwidth_ascii_punctuation_folds_punctuation_only():
    """
    IMPORTANT DOCUMENTED BEHAVIOR: NFKC folds fullwidth ASCII-range
    punctuation (e.g. FULLWIDTH QUESTION MARK U+FF1F) to its ASCII
    compatibility form, even in otherwise ordinary Japanese text, because
    that punctuation IS an NFKC compatibility variant of ASCII '?'. This
    is expected, required NFKC behavior (per the normalization
    requirement), not a bug and not confusable/homoglyph folding - it
    does NOT touch native kana/kanji, which are not compatibility
    variants of anything and pass through completely unchanged. This
    test exists specifically to document that "benign multilingual text
    is preserved" does not mean "byte-identical in all cases" - it means
    native script content is preserved; ASCII-derived compatibility
    punctuation is normalized like anywhere else.
    """
    original = "こんにちは、元気ですか\uff1f明日会いましょう。"  # fullwidth '？'
    field = normalize_text(original, "body.text_plain")
    assert field.normalized_text == "こんにちは、元気ですか?明日会いましょう。"
    # Every kana/kanji character survives untouched; only the fullwidth
    # ASCII-derived question mark changed.
    assert "こんにちは" in field.normalized_text
    assert "元気ですか" in field.normalized_text
    assert "明日会いましょう" in field.normalized_text
    events = [e for e in field.events if e.transformation == "nfkc_compatibility_normalization"]
    assert len(events) == 1
    assert events[0].original_span == "\uff1f"


def test_benign_japanese_text_is_unchanged():
    # Alias kept for the originally-requested test name; delegates to the
    # precise native-punctuation-only case above.
    test_benign_japanese_text_with_only_native_punctuation_is_unchanged()


def test_benign_russian_text_is_unchanged():
    original = "Здравствуйте, как ваши дела сегодня?"
    field = normalize_text(original, "body.text_plain")
    assert field.normalized_text == original
    assert field.unchanged is True


def test_benign_arabic_text_is_unchanged():
    original = "مرحبا، كيف حالك اليوم؟"
    field = normalize_text(original, "body.text_plain")
    assert field.normalized_text == original
    assert field.unchanged is True


# ---------------------------------------------------------------------------
# Mixed-script text - must be preserved AS-IS (no confusable folding here;
# that signal belongs to the Domain analyzer, not to this normalizer).
# ---------------------------------------------------------------------------

def test_mixed_cyrillic_latin_homoglyph_is_not_folded():
    # "Apple" but the 'A' is Cyrillic А (U+0410), not Latin A (U+0041).
    original = "\u0410pple support team"
    field = normalize_text(original, "body.text_plain")
    # Must remain byte-for-byte unchanged - confusable folding is
    # deliberately NOT performed by this normalizer.
    assert field.normalized_text == original
    assert field.unchanged is True
    assert field.normalized_text[0] == "\u0410"  # still Cyrillic, not folded to Latin 'A'


def test_mixed_greek_latin_text_is_not_folded():
    # Greek 'Ο' (Omicron, U+039F) substituted for Latin 'O' in "Official"
    original = "\u039ffficial Notice"
    field = normalize_text(original, "subject")
    assert field.normalized_text == original
    assert field.unchanged is True


# ---------------------------------------------------------------------------
# Obfuscated security/phishing-style text
# ---------------------------------------------------------------------------

def test_phishing_keyword_obfuscated_with_zero_width_joiners_is_deobfuscated():
    # Classic keyword-filter-evasion pattern: invisible characters
    # inserted between every letter of a sensitive phrase.
    original = "V\u200be\u200br\u200bi\u200bf\u200by\u200b \u200by\u200bo\u200bu\u200br\u200b \u200ba\u200bc\u200bc\u200bo\u200bu\u200bn\u200bt"
    field = normalize_text(original, "body.text_plain")
    assert field.normalized_text == "Verify your account"
    assert field.original_text == original  # original preserved for evidence
    assert len(field.events) > 0


def test_phishing_text_with_mixed_fullwidth_and_zero_width_obfuscation():
    # Fullwidth characters combined with zero-width insertions - both
    # passes must apply correctly together.
    original = "\uff35\u200b\uff32\u200bG\u200bE\u200bN\u200bT"  # fullwidth "URGENT"-ish mix
    field = normalize_text(original, "subject")
    assert "\u200b" not in field.normalized_text
    assert field.normalized_text == "URGENT"


def test_bidi_override_obfuscation_is_stripped():
    # RTL override can be used to visually disguise a filename/extension
    # (e.g. making "gnp.exe" display as "exe.png"). The characters
    # themselves must be removed deterministically; this normalizer does
    # not interpret the security meaning, only strips the invisible
    # control character mechanically.
    original = "invoice\u202eexe.png"
    field = normalize_text(original, "attachments[0].filename")
    assert "\u202e" not in field.normalized_text
    assert field.normalized_text == "invoiceexe.png"


# ---------------------------------------------------------------------------
# Text that should remain unchanged
# ---------------------------------------------------------------------------

def test_plain_ascii_text_is_completely_unchanged():
    original = "Please review the attached invoice at your earliest convenience."
    field = normalize_text(original, "body.text_plain")
    assert field.normalized_text == original
    assert field.unchanged is True
    assert field.events == []


def test_empty_string_is_unchanged():
    field = normalize_text("", "subject")
    assert field.normalized_text == ""
    assert field.unchanged is True
    assert field.events == []


# ---------------------------------------------------------------------------
# Preservation / traceability of original text
# ---------------------------------------------------------------------------

def test_original_text_is_preserved_verbatim_on_the_field():
    original = "Inv\u200boice \u00a0 #12345"
    field = normalize_text(original, "body.text_plain")
    assert field.original_text == original
    assert field.original_text is not field.normalized_text  # distinct values, not aliased


def test_events_are_positioned_relative_to_original_text():
    original = "AB\u200bCD"
    field = normalize_text(original, "subject")
    zw_events = [e for e in field.events if e.transformation == "zero_width_removed"]
    assert len(zw_events) == 1
    event = zw_events[0]
    # position must index correctly into the ORIGINAL text
    assert original[event.position] == "\u200b"


def test_policy_version_is_recorded_on_every_field():
    field = normalize_text("hello", "subject")
    assert field.policy_version == NORMALIZATION_POLICY_VERSION


def test_normalize_email_does_not_mutate_canonical_email():
    raw = (
        b"From: a@example.com\r\n"
        b"To: b@example.com\r\n"
        b"Subject: Ver\xe2\x80\x8bify your account\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"\r\n"
        b"Please\xc2\xa0respond soon.\r\n"
    )
    email = parse_eml(raw, artifact_id="norm-test-1")
    original_subject = email.subject
    original_body = email.body.text_plain
    snapshot = copy.deepcopy(email)

    evidence = normalize_email(email)

    # CanonicalEmail must be completely untouched by normalization.
    assert email.subject == original_subject
    assert email.body.text_plain == original_body
    assert email == snapshot

    # The normalized evidence must show the obfuscation was resolved.
    subject_field = next(f for f in evidence.fields if f.field_path == "subject")
    assert "\u200b" not in subject_field.normalized_text
    assert "Verify" in subject_field.normalized_text
    body_field = next(f for f in evidence.fields if f.field_path == "body.text_plain")
    assert "\u00a0" not in body_field.normalized_text


def test_normalized_evidence_traces_back_to_source_artifact_and_email_id():
    raw = b"From: a@example.com\r\nTo: b@example.com\r\nSubject: hi\r\n\r\nbody\r\n"
    email = parse_eml(raw, artifact_id="artifact-xyz-789")
    evidence = normalize_email(email)
    assert evidence.source_artifact_id == "artifact-xyz-789"
    assert evidence.source_canonical_email_id == email.id
    assert evidence.policy_version == NORMALIZATION_POLICY_VERSION


def test_normalize_email_skips_absent_fields_without_fabricating_them():
    # A multipart message with only an attachment part - no text/plain
    # and no text/html part at all, so body.text_plain is genuinely
    # None (absent), not merely an empty string (which would still be
    # "present" and would legitimately produce a NormalizedField).
    raw = (
        b"From: a@example.com\r\n"
        b"To: b@example.com\r\n"
        b"MIME-Version: 1.0\r\n"
        b'Content-Type: multipart/mixed; boundary="B"\r\n'
        b"\r\n"
        b"--B\r\n"
        b"Content-Type: application/octet-stream\r\n"
        b'Content-Disposition: attachment; filename="data.bin"\r\n'
        b"Content-Transfer-Encoding: base64\r\n\r\n"
        b"aGVsbG8=\r\n"
        b"--B--\r\n"
    )
    email = parse_eml(raw, artifact_id="artifact-empty")
    assert email.subject is None
    assert email.body.text_plain is None
    evidence = normalize_email(email)
    field_paths = {f.field_path for f in evidence.fields}
    assert "subject" not in field_paths
    assert "body.text_plain" not in field_paths


def test_normalize_email_covers_display_names_and_attachment_filenames():
    raw = (
        b"From: =?UTF-8?B?VmVyxLtmeQ==?= <a@example.com>\r\n"
        b"To: \"Bob\xe2\x80\x8b Smith\" <b@example.com>\r\n"
        b"Subject: files\r\n"
        b"MIME-Version: 1.0\r\n"
        b'Content-Type: multipart/mixed; boundary="B"\r\n'
        b"\r\n"
        b"--B\r\n"
        b"Content-Type: text/plain\r\n\r\n"
        b"body\r\n"
        b"--B\r\n"
        b"Content-Type: application/pdf\r\n"
        b"Content-Disposition: attachment; filename=\"Inv\xe2\x80\x8boice.pdf\"\r\n"
        b"Content-Transfer-Encoding: base64\r\n\r\n"
        b"aGVsbG8=\r\n"
        b"--B--\r\n"
    )
    email = parse_eml(raw, artifact_id="artifact-names")
    evidence = normalize_email(email)
    field_paths = {f.field_path for f in evidence.fields}
    assert any(p.startswith("to_addresses[") and p.endswith("].display_name") for p in field_paths)
    assert any(p.startswith("attachments[") and p.endswith("].filename") for p in field_paths)

    to_field = next(f for f in evidence.fields if f.field_path.startswith("to_addresses["))
    assert "\u200b" not in to_field.normalized_text
