"""Unit tests for EmailParserService."""

from __future__ import annotations

from app.infrastructure.db.models.enums import AuthResultStatus, ReputationVerdict
from app.services.email_parser_service import EmailParserService


def test_parse_structured_email() -> None:
    artifacts = EmailParserService.parse_structured(
        from_address="security@alerts-bank.top",
        to_addresses=["employee@target.com"],
        subject="Urgent Security Alert: Verify Credentials",
        body_plain="Click here immediately: http://192.168.1.55/login or visit https://safe-domain.com",
        cc_addresses=["audit@alerts-bank.top"],
        reply_to="phisher@external-domain.com",
        raw_headers_str="Received-SPF: fail\nAuthentication-Results: spf=fail dkim=fail dmarc=fail",
    )

    assert artifacts.from_address == "security@alerts-bank.top"
    assert artifacts.from_domain == "alerts-bank.top"
    assert artifacts.to_addresses == ["employee@target.com"]
    assert artifacts.subject == "Urgent Security Alert: Verify Credentials"
    assert artifacts.reply_to == "phisher@external-domain.com"
    assert artifacts.headers.spf_status == AuthResultStatus.FAIL
    assert artifacts.headers.dkim_status == AuthResultStatus.FAIL
    assert artifacts.headers.dmarc_status == AuthResultStatus.FAIL

    # URL checks
    assert len(artifacts.urls) >= 2
    ip_url = next((u for u in artifacts.urls if u.is_ip_address), None)
    assert ip_url is not None
    assert ip_url.domain == "192.168.1.55"
    assert ip_url.defanged_url.startswith("hxxp://")
    assert "[.]" in ip_url.defanged_url
    assert ip_url.reputation == ReputationVerdict.SUSPICIOUS


def test_parse_raw_rfc822_email() -> None:
    raw_email = (
        'From: "Alerts" <support@service-paypa1.top>\n'
        "To: victim@company.com\n"
        "Subject: Account Locked\n"
        "Date: Mon, 29 Sep 2026 12:00:00 +0000\n"
        "Message-ID: <12345@service-paypa1.top>\n"
        "Authentication-Results: spf=pass dkim=pass dmarc=pass\n"
        "Content-Type: text/plain; charset=utf-8\n"
        "\n"
        "Please visit http://login.service-paypa1.top/auth to restore access.\n"
    )

    artifacts = EmailParserService.parse_raw_eml(raw_email)
    assert artifacts.from_address == "support@service-paypa1.top"
    assert artifacts.from_domain == "service-paypa1.top"
    assert artifacts.to_addresses == ["victim@company.com"]
    assert artifacts.subject == "Account Locked"
    assert artifacts.message_id == "<12345@service-paypa1.top>"
    assert artifacts.headers.spf_status == AuthResultStatus.PASS
    assert artifacts.headers.dkim_status == AuthResultStatus.PASS
    assert artifacts.headers.dmarc_status == AuthResultStatus.PASS

    assert len(artifacts.urls) == 1
    assert artifacts.urls[0].domain == "login.service-paypa1.top"
    assert artifacts.urls[0].is_suspicious_tld is True
    assert artifacts.urls[0].defanged_url == "hxxp://login[.]service-paypa1[.]top/auth"


def test_attachment_extraction_and_classification() -> None:
    att = EmailParserService._process_attachment(
        "malware_payload.exe", "application/x-msdownload", b"MZ\x90\x00testbytes"
    )
    assert att.filename == "malware_payload.exe"
    assert att.is_executable is True
    assert att.is_archive is False
    assert len(att.sha256) == 64

    zip_att = EmailParserService._process_attachment(
        "archive.zip", "application/zip", b"PK\x03\x04testbytes"
    )
    assert zip_att.filename == "archive.zip"
    assert zip_att.is_executable is False
    assert zip_att.is_archive is True
