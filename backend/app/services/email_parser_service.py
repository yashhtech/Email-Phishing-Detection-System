"""Email forensic parsing and artifact extraction service.

Extracts structured metadata, headers, authentication results (SPF, DKIM, DMARC),
body content (plain/HTML), URLs, and attachments from either:
- Raw RFC 822 / 5322 .eml bytes or string
- Form-submitted structured email fields
"""

from __future__ import annotations

import email
import hashlib
import re
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email import policy
from email.message import EmailMessage
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urlparse

from app.infrastructure.db.models.enums import AuthResultStatus, ReputationVerdict


@dataclass
class ExtractedURL:
    url: str
    domain: str
    scheme: str
    path: str
    is_ip_address: bool
    defanged_url: str
    reputation: ReputationVerdict = ReputationVerdict.UNKNOWN
    is_suspicious_tld: bool = False


@dataclass
class ExtractedAttachment:
    filename: str
    content_type: str
    size_bytes: int
    sha256: str
    is_executable: bool
    is_archive: bool
    raw_data: bytes | None = None


@dataclass
class ExtractedHeaders:
    message_id: str
    from_raw: str
    to_raw: list[str]
    cc_raw: list[str]
    reply_to: str | None
    subject: str | None
    date: datetime
    spf_status: AuthResultStatus = AuthResultStatus.NONE
    spf_details: str | None = None
    dkim_status: AuthResultStatus = AuthResultStatus.NONE
    dkim_details: str | None = None
    dmarc_status: AuthResultStatus = AuthResultStatus.NONE
    dmarc_details: str | None = None
    hop_count: int = 0
    route_hops: list[dict[str, Any]] = field(default_factory=list)
    raw_headers: dict[str, str] = field(default_factory=dict)


@dataclass
class ParsedEmailArtifacts:
    message_id: str
    subject: str | None
    from_address: str
    from_domain: str
    to_addresses: list[str]
    cc_addresses: list[str]
    reply_to: str | None
    received_at: datetime
    body_plain: str | None
    body_html: str | None
    body_preview: str | None
    headers: ExtractedHeaders
    urls: list[ExtractedURL] = field(default_factory=list)
    attachments: list[ExtractedAttachment] = field(default_factory=list)


class _HTMLHrefExtractor(HTMLParser):
    """Minimal HTML parser to extract links and text."""

    def __init__(self) -> None:
        super().__init__()
        self.urls: list[str] = []
        self.text_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() == "a":
            for attr, val in attrs:
                if attr.lower() == "href" and val:
                    self.urls.append(val.strip())

    def handle_data(self, data: str) -> None:
        self.text_parts.append(data)


# Common regex patterns for email analysis
_URL_REGEX = re.compile(
    r"(?i)\b((?:https?://|ftp://|www\d{0,3}\.)[^\s()<>]+(?:\([\w\d]+\)|(?:[^\s`!()\[\]{};:'\".,<>?])))",
    re.IGNORECASE,
)
_IPV4_REGEX = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
_SUSPICIOUS_TLDS = {
    "xyz",
    "top",
    "work",
    "loan",
    "click",
    "country",
    "link",
    "gq",
    "ml",
    "cf",
    "ga",
    "buzz",
    "fit",
    "surf",
}
_EXECUTABLE_EXTENSIONS = {
    ".exe",
    ".bat",
    ".cmd",
    ".scr",
    ".pif",
    ".vbs",
    ".js",
    ".jse",
    ".wsf",
    ".msi",
    ".dll",
    ".ps1",
    ".com",
    ".hta",
}
_ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".tar", ".gz", ".iso", ".img", ".cab"}


class EmailParserService:
    """Service that parses raw emails or structured inputs and extracts forensic telemetry."""

    @classmethod
    def parse_raw_eml(cls, raw_content: str | bytes) -> ParsedEmailArtifacts:
        """Parse raw RFC 822/5322 email string or bytes."""
        if isinstance(raw_content, str):
            raw_bytes = raw_content.encode("utf-8", errors="replace")
        else:
            raw_bytes = raw_content

        msg: EmailMessage = email.message_from_bytes(raw_bytes, policy=policy.default)

        # Extract basic headers
        from_str = str(msg.get("From", "")).strip()
        from_addr, from_domain = cls._extract_email_and_domain(from_str)
        if not from_addr:
            from_addr = "unknown@unknown.local"
            from_domain = "unknown.local"

        to_addrs = cls._extract_address_list(msg.get("To"))
        cc_addrs = cls._extract_address_list(msg.get("Cc"))
        reply_to_raw = msg.get("Reply-To")
        reply_to_addr, _ = (
            cls._extract_email_and_domain(str(reply_to_raw)) if reply_to_raw else (None, None)
        )
        subject = msg.get("Subject")
        message_id = msg.get("Message-ID") or f"<{uuid.uuid4()}@{from_domain}>"

        # Date parsing
        date_header = msg.get("Date")
        received_at = cls._parse_date_header(date_header)

        # Extract body components
        body_plain: str | None = None
        body_html: str | None = None
        attachments: list[ExtractedAttachment] = []

        if msg.is_multipart():
            for part in msg.walk():
                content_disposition = str(part.get("Content-Disposition", ""))
                content_type = part.get_content_type()
                filename = part.get_filename()

                is_attachment = "attachment" in content_disposition.lower() or filename is not None
                if is_attachment and filename:
                    payload = part.get_payload(decode=True)
                    if isinstance(payload, bytes):
                        attachments.append(cls._process_attachment(filename, content_type, payload))
                elif content_type == "text/plain" and body_plain is None:
                    payload = part.get_payload(decode=True)
                    if isinstance(payload, bytes):
                        body_plain = payload.decode(
                            part.get_content_charset() or "utf-8", errors="replace"
                        )
                elif content_type == "text/html" and body_html is None:
                    payload = part.get_payload(decode=True)
                    if isinstance(payload, bytes):
                        body_html = payload.decode(
                            part.get_content_charset() or "utf-8", errors="replace"
                        )
        else:
            payload = msg.get_payload(decode=True)
            if isinstance(payload, bytes):
                decoded = payload.decode(msg.get_content_charset() or "utf-8", errors="replace")
                if msg.get_content_type() == "text/html":
                    body_html = decoded
                else:
                    body_plain = decoded

        # Headers analysis
        headers = cls._extract_headers_metadata(
            msg, message_id, from_str, to_addrs, cc_addrs, reply_to_addr, subject, received_at
        )

        # URLs extraction
        urls = cls._extract_urls(body_plain, body_html)

        body_preview = cls._make_body_preview(body_plain, body_html)

        return ParsedEmailArtifacts(
            message_id=message_id,
            subject=subject,
            from_address=from_addr,
            from_domain=from_domain,
            to_addresses=to_addrs,
            cc_addresses=cc_addrs,
            reply_to=reply_to_addr,
            received_at=received_at,
            body_plain=body_plain,
            body_html=body_html,
            body_preview=body_preview,
            headers=headers,
            urls=urls,
            attachments=attachments,
        )

    @classmethod
    def parse_structured(
        cls,
        *,
        from_address: str,
        to_addresses: list[str],
        subject: str,
        body_plain: str | None = None,
        body_html: str | None = None,
        cc_addresses: list[str] | None = None,
        reply_to: str | None = None,
        raw_headers_str: str | None = None,
        attachments: list[ExtractedAttachment] | None = None,
    ) -> ParsedEmailArtifacts:
        """Parse structured fields entered manually via web form."""
        from_addr, from_domain = cls._extract_email_and_domain(from_address)
        if not from_addr:
            from_addr = from_address
            from_domain = from_address.split("@")[-1] if "@" in from_address else "local"

        message_id = f"<{uuid.uuid4()}@{from_domain}>"
        received_at = datetime.now(UTC)

        raw_headers_dict: dict[str, str] = {}
        if raw_headers_str:
            for line in raw_headers_str.splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    raw_headers_dict[k.strip()] = v.strip()

        # Check SPF/DKIM/DMARC from raw headers if supplied
        spf_status, spf_desc = cls._eval_auth_header(
            raw_headers_dict.get("Received-SPF") or raw_headers_dict.get("Authentication-Results"),
            "spf",
        )
        dkim_status, dkim_desc = cls._eval_auth_header(
            raw_headers_dict.get("Authentication-Results")
            or raw_headers_dict.get("DKIM-Signature"),
            "dkim",
        )
        dmarc_status, dmarc_desc = cls._eval_auth_header(
            raw_headers_dict.get("Authentication-Results"), "dmarc"
        )

        headers = ExtractedHeaders(
            message_id=message_id,
            from_raw=from_address,
            to_raw=to_addresses,
            cc_raw=cc_addresses or [],
            reply_to=reply_to,
            subject=subject,
            date=received_at,
            spf_status=spf_status,
            spf_details=spf_desc,
            dkim_status=dkim_status,
            dkim_details=dkim_desc,
            dmarc_status=dmarc_status,
            dmarc_details=dmarc_desc,
            hop_count=len([k for k in raw_headers_dict if k.lower() == "received"]),
            raw_headers=raw_headers_dict,
        )

        urls = cls._extract_urls(body_plain, body_html)
        body_preview = cls._make_body_preview(body_plain, body_html)

        return ParsedEmailArtifacts(
            message_id=message_id,
            subject=subject,
            from_address=from_addr,
            from_domain=from_domain,
            to_addresses=to_addresses,
            cc_addresses=cc_addresses or [],
            reply_to=reply_to,
            received_at=received_at,
            body_plain=body_plain,
            body_html=body_html,
            body_preview=body_preview,
            headers=headers,
            urls=urls,
            attachments=attachments or [],
        )

    # -----------------------------------------------------------------------
    # Helper methods
    # -----------------------------------------------------------------------

    @staticmethod
    def _extract_email_and_domain(raw: str) -> tuple[str, str]:
        """Extract clean email address and domain from 'Name <user@domain.com>' string."""
        match = re.search(r"[\w\.-]+@[\w\.-]+\.\w+", raw)
        if match:
            clean_email = match.group(0).lower()
            domain = clean_email.split("@")[-1]
            return clean_email, domain
        return raw.strip().lower(), ""

    @staticmethod
    def _extract_address_list(header_val: Any) -> list[str]:
        if not header_val:
            return []
        raw_str = str(header_val)
        found = re.findall(r"[\w\.-]+@[\w\.-]+\.\w+", raw_str)
        return [f.lower() for f in found] if found else [raw_str.strip()]

    @staticmethod
    def _parse_date_header(date_str: Any) -> datetime:
        if not date_str:
            return datetime.now(UTC)
        try:
            from email.utils import parsedate_to_datetime

            dt = parsedate_to_datetime(str(date_str))
            if dt.tzinfo is None:
                return dt.replace(tzinfo=UTC)
            return dt
        except Exception:
            return datetime.now(UTC)

    @classmethod
    def _extract_headers_metadata(
        cls,
        msg: EmailMessage,
        message_id: str,
        from_str: str,
        to_addrs: list[str],
        cc_addrs: list[str],
        reply_to: str | None,
        subject: str | None,
        received_at: datetime,
    ) -> ExtractedHeaders:
        raw_dict: dict[str, str] = {}
        route_hops: list[dict[str, Any]] = []

        for k, v in msg.items():
            str_val = str(v)
            raw_dict[k] = str_val
            if k.lower() == "received":
                route_hops.append({"raw": str_val})

        auth_results = msg.get("Authentication-Results", "")
        received_spf = msg.get("Received-SPF", "")

        spf_status, spf_desc = cls._eval_auth_header(received_spf or auth_results, "spf")
        dkim_status, dkim_desc = cls._eval_auth_header(
            auth_results or msg.get("DKIM-Signature", ""), "dkim"
        )
        dmarc_status, dmarc_desc = cls._eval_auth_header(auth_results, "dmarc")

        return ExtractedHeaders(
            message_id=message_id,
            from_raw=from_str,
            to_raw=to_addrs,
            cc_raw=cc_addrs,
            reply_to=reply_to,
            subject=subject,
            date=received_at,
            spf_status=spf_status,
            spf_details=spf_desc,
            dkim_status=dkim_status,
            dkim_details=dkim_desc,
            dmarc_status=dmarc_status,
            dmarc_details=dmarc_desc,
            hop_count=len(route_hops),
            route_hops=route_hops,
            raw_headers=raw_dict,
        )

    @staticmethod
    def _eval_auth_header(
        header_content: Any, protocol: str
    ) -> tuple[AuthResultStatus, str | None]:
        if not header_content:
            return AuthResultStatus.NONE, None
        content = str(header_content).lower()
        if f"{protocol}=pass" in content or (protocol == "spf" and content.startswith("pass")):
            return AuthResultStatus.PASS, f"{protocol.upper()} verification passed"
        if f"{protocol}=fail" in content or (protocol == "spf" and content.startswith("fail")):
            return AuthResultStatus.FAIL, f"{protocol.upper()} verification failed"
        if f"{protocol}=softfail" in content:
            return AuthResultStatus.SOFTFAIL, f"{protocol.upper()} softfail"
        if f"{protocol}=neutral" in content:
            return AuthResultStatus.NEUTRAL, f"{protocol.upper()} neutral"
        return AuthResultStatus.NONE, None

    @classmethod
    def _extract_urls(cls, body_plain: str | None, body_html: str | None) -> list[ExtractedURL]:
        raw_urls: set[str] = set()

        if body_plain:
            for match in _URL_REGEX.finditer(body_plain):
                raw_urls.add(match.group(0))

        if body_html:
            parser = _HTMLHrefExtractor()
            try:
                parser.feed(body_html)
                for u in parser.urls:
                    raw_urls.add(u)
            except Exception:
                pass
            for match in _URL_REGEX.finditer(body_html):
                raw_urls.add(match.group(0))

        results: list[ExtractedURL] = []
        for raw in raw_urls:
            cleaned = raw.strip().rstrip(".,;:)>]")
            if not cleaned or cleaned.startswith("mailto:") or cleaned.startswith("javascript:"):
                continue

            try:
                parsed = urlparse(cleaned)
                domain = (parsed.hostname or "").lower()
                scheme = parsed.scheme or "http"
                path = parsed.path or "/"

                is_ip = bool(_IPV4_REGEX.match(domain))
                tld = domain.split(".")[-1] if "." in domain else ""
                is_suspicious_tld = tld in _SUSPICIOUS_TLDS

                # Defang URL (e.g. hxxps://domain[.]com/path)
                defanged = (
                    cleaned.replace("http://", "hxxp://")
                    .replace("https://", "hxxps://")
                    .replace(".", "[.]")
                )

                reputation = ReputationVerdict.UNKNOWN
                if is_ip or is_suspicious_tld:
                    reputation = ReputationVerdict.SUSPICIOUS

                results.append(
                    ExtractedURL(
                        url=cleaned,
                        domain=domain,
                        scheme=scheme,
                        path=path,
                        is_ip_address=is_ip,
                        defanged_url=defanged,
                        reputation=reputation,
                        is_suspicious_tld=is_suspicious_tld,
                    )
                )
            except Exception:
                continue

        return results

    @classmethod
    def _process_attachment(
        cls, filename: str, content_type: str, data: bytes
    ) -> ExtractedAttachment:
        ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        sha256 = hashlib.sha256(data).hexdigest()
        is_executable = ext in _EXECUTABLE_EXTENSIONS
        is_archive = ext in _ARCHIVE_EXTENSIONS

        return ExtractedAttachment(
            filename=filename,
            content_type=content_type or "application/octet-stream",
            size_bytes=len(data),
            sha256=sha256,
            is_executable=is_executable,
            is_archive=is_archive,
            raw_data=data,
        )

    @staticmethod
    def _make_body_preview(body_plain: str | None, body_html: str | None) -> str | None:
        if body_plain:
            text = " ".join(body_plain.split())
            return text[:450] + ("..." if len(text) > 450 else "")
        if body_html:
            clean = re.sub(r"<[^>]+>", " ", body_html)
            text = " ".join(clean.split())
            return text[:450] + ("..." if len(text) > 450 else "")
        return None
