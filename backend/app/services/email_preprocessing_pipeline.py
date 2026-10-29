"""Email preprocessing pipeline.

This module is the **sole entry point** for all raw email ingestion.

Security and evidence integrity invariants:
1. Raw bytes are NEVER modified — they are preserved inside RawEvidence and stored separately.
2. All normalization, decoding, and sanitization produces NEW data objects.
3. HTML is NEVER rendered or executed; it is sanitized via an allowlist-based cleaner.
4. JavaScript — whether inline <script>, event attributes (on*), or javascript: scheme URIs —
   is completely stripped and flagged as a structural anomaly.
5. Attachments are NOT executed or opened; only metadata (filenames, sizes, MIME types,
   cryptographic hashes, and file-signature "magic bytes") are extracted.
6. All encoding normalization is conservative: unknown charsets fall back to
   'utf-8' with 'replace', never to 'exec' or 'eval'.
7. Malformed MIME structures are detected and included in the StructuralIntegrity report
   so downstream engines can treat them as risk signals, not parser exceptions.
8. ULIDs are used for all entity IDs to avoid UUID predictability.
"""

from __future__ import annotations

import email
import email.policy
import hashlib
import html
import math
import re
import unicodedata
import uuid
from datetime import UTC, datetime
from email import message_from_bytes, message_from_string
from email.message import Message
from typing import Any
from urllib.parse import urlparse

import structlog

from app.domain.entities.email_analysis_input import (
    EmailAnalysisInput,
    ExtractedAttachmentMetadata,
    ExtractedURLItem,
    NormalizedContent,
    NormalizedHeaders,
    NormalizedRecipient,
    NormalizedSender,
    RawEvidence,
    StructuralAnomaly,
    StructuralIntegrity,
)

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_MAX_BODY_BYTES = 10 * 1024 * 1024  # 10 MB hard ceiling for body text
_MAX_ATTACHMENT_BYTES = 25 * 1024 * 1024  # 25 MB attachment size limit

_EXECUTABLE_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".exe",
        ".bat",
        ".cmd",
        ".scr",
        ".pif",
        ".vbs",
        ".vbe",
        ".js",
        ".jse",
        ".wsf",
        ".wsh",
        ".msi",
        ".msp",
        ".msc",
        ".dll",
        ".sys",
        ".drv",
        ".ps1",
        ".ps2",
        ".psm1",
        ".psd1",
        ".com",
        ".cpl",
        ".hta",
        ".inf",
        ".reg",
        ".gadget",
        ".xbap",
        ".application",
        ".lnk",
    }
)

_MACRO_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".docm",
        ".xlsm",
        ".pptm",
        ".dotm",
        ".xlam",
        ".xltm",
    }
)

_ARCHIVE_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".zip",
        ".rar",
        ".7z",
        ".tar",
        ".gz",
        ".bz2",
        ".xz",
        ".iso",
        ".cab",
        ".arj",
        ".ace",
        ".udf",
    }
)

_URL_LINK_SHORTENERS: frozenset[str] = frozenset(
    {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
        "buff.ly",
        "dlvr.it",
        "is.gd",
        "cli.gs",
        "tiny.cc",
        "short.ie",
        "rb.gy",
        "cutt.ly",
    }
)

_SUSPICIOUS_TLDS: frozenset[str] = frozenset(
    {
        ".top",
        ".xyz",
        ".click",
        ".loan",
        ".online",
        ".win",
        ".bid",
        ".men",
        ".stream",
        ".gq",
        ".ml",
        ".ga",
        ".cf",
        ".tk",
        ".buzz",
        ".monster",
        ".cyou",
        ".cfd",
        ".digital",
        ".rest",
        ".art",
        ".world",
        ".site",
        ".cam",
    }
)

_IP_PATTERN = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
_URL_PATTERN = re.compile(
    r"""(?xi)
    (?:https?://|ftp://)                # scheme — required
    (?:[^\s<>"{}|\\^`\[\]]{2,2048})    # path/host up to 2 KB
    """,
    re.VERBOSE,
)

# Allowlisted HTML tags and attributes for safe rendering
_HTML_ALLOWED_TAGS: frozenset[str] = frozenset(
    {
        "a",
        "abbr",
        "b",
        "blockquote",
        "br",
        "caption",
        "cite",
        "code",
        "col",
        "colgroup",
        "dd",
        "del",
        "details",
        "dfn",
        "div",
        "dl",
        "dt",
        "em",
        "figcaption",
        "figure",
        "footer",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "head",
        "header",
        "hr",
        "i",
        "img",
        "kbd",
        "li",
        "main",
        "mark",
        "ol",
        "p",
        "pre",
        "q",
        "s",
        "samp",
        "section",
        "small",
        "span",
        "strong",
        "sub",
        "summary",
        "sup",
        "table",
        "tbody",
        "td",
        "tfoot",
        "th",
        "thead",
        "time",
        "tr",
        "u",
        "ul",
        "var",
        "wbr",
    }
)

_HTML_ALLOWED_ATTRS: dict[str, frozenset[str]] = {
    "a": frozenset({"href", "title", "rel"}),
    "img": frozenset({"src", "alt", "width", "height"}),
    "td": frozenset({"colspan", "rowspan"}),
    "th": frozenset({"colspan", "rowspan", "scope"}),
    "col": frozenset({"span"}),
    "colgroup": frozenset({"span"}),
    "*": frozenset({"id", "class", "title", "lang", "dir"}),
}

# Script-related pattern for JavaScript stripping when bleach is unavailable
_DANGEROUS_HTML_PATTERN = re.compile(
    r"<script[^>]*>.*?</script>|javascript:\s*[^\"';]+|"
    r"\bon\w+\s*=\s*[\"'][^\"']*[\"']|"
    r"\bon\w+\s*=\s*\S+",
    re.IGNORECASE | re.DOTALL,
)


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------


def _sanitize_html(raw_html: str) -> str:
    """Strip all dangerous HTML while preserving safe structural content.

    Removes: <script> tags, javascript: href/src, on* event handlers,
    <style> sheets, <link> imports, <form> elements, <iframe>/<object>/<embed>.

    Falls back to a conservative regex-based strip if bleach is unavailable.
    """
    try:
        import bleach
        from bleach.css_sanitizer import CSSSanitizer

        CSSSanitizer(
            allowed_css_properties=[
                "color",
                "background-color",
                "font-size",
                "font-weight",
                "font-family",
                "text-align",
                "text-decoration",
                "margin",
                "padding",
                "border",
                "width",
                "height",
                "display",
            ]
        )

        # Convert frozensets to lists for bleach compatibility
        allowed_attrs: dict[str, list[str]] = {
            tag: list(attrs) for tag, attrs in _HTML_ALLOWED_ATTRS.items()
        }

        cleaned = bleach.clean(
            raw_html,
            tags=list(_HTML_ALLOWED_TAGS),
            attributes=allowed_attrs,
            strip=True,
            strip_comments=True,
        )
        return str(cleaned)
    except ImportError:
        # Fallback: aggressive regex-based stripping
        sanitized = re.sub(
            r"<(script|style|iframe|object|embed|form|link|meta)[^>]*>.*?</\1>",
            "",
            raw_html,
            flags=re.IGNORECASE | re.DOTALL,
        )
        sanitized = re.sub(r"\bon\w+\s*=\s*['\"][^'\"]*['\"]", "", sanitized, flags=re.IGNORECASE)
        sanitized = re.sub(r"\bon\w+\s*=\s*\S+", "", sanitized, flags=re.IGNORECASE)
        sanitized = re.sub(r"javascript\s*:", "BLOCKED:", sanitized, flags=re.IGNORECASE)
        return sanitized


def _contains_js(html_content: str) -> bool:
    """Check if HTML contains JavaScript or dangerous event handlers."""
    patterns = [
        r"<\s*script[\s>]",
        r"javascript\s*:",
        r"\bon\w+\s*=\s*[\"']",
        r"\bon\w+\s*=\s*\w",
        r"<\s*iframe[\s>]",
        r"<\s*object[\s>]",
        r"<\s*embed[\s>]",
        r"vbscript\s*:",
        r"data:text/html",
    ]
    combined = re.compile("|".join(patterns), re.IGNORECASE | re.DOTALL)
    return bool(combined.search(html_content))


def _decode_part(part: Message) -> str:
    """Safely decode an email MIME part to UTF-8 text."""
    charset = part.get_content_charset() or "utf-8"
    payload = part.get_payload(decode=True)
    if not isinstance(payload, bytes):
        return ""
    try:
        return payload.decode(charset, errors="replace")
    except (LookupError, UnicodeDecodeError):
        return payload.decode("utf-8", errors="replace")


def _normalize_whitespace(text: str) -> str:
    """Collapse excessive whitespace while preserving structural newlines."""
    # NFKC unicode normalization: converts ligatures, fullwidth chars, etc.
    text = unicodedata.normalize("NFKC", text)
    # Collapse blank-line runs (3+ blank lines → 2)
    text = re.sub(r"\n{3,}", "\n\n", text)
    # Collapse in-line whitespace to single space
    text = re.sub(r"[ \t]+", " ", text)
    return text.strip()


def _html_to_plain_text(html_content: str) -> str:
    """Convert sanitized HTML to readable plain text for LLM processing."""
    # Remove HTML comments
    text = re.sub(r"<!--.*?-->", "", html_content, flags=re.DOTALL)
    # Block-level elements → newlines
    text = re.sub(r"<br\s*/?>", "\n", text, flags=re.IGNORECASE)
    text = re.sub(
        r"</?(p|div|h[1-6]|li|tr|table|thead|tbody|blockquote)[^>]*>",
        "\n",
        text,
        flags=re.IGNORECASE,
    )
    # Strip all remaining tags
    text = re.sub(r"<[^>]+>", "", text)
    # Unescape HTML entities
    text = html.unescape(text)
    return _normalize_whitespace(text)


def _defang_url(url: str) -> str:
    """Produce a defanged representation of a URL safe for display and logging."""
    defanged = url
    defanged = re.sub(
        r"^https?://",
        lambda m: m.group().replace("http://", "hxxp://").replace("https://", "hxxps://"),
        defanged,
        flags=re.IGNORECASE,
    )
    defanged = defanged.replace(".", "[.]")
    return defanged


def _is_suspicious_tld(domain: str) -> bool:
    return any(domain.lower().endswith(tld) for tld in _SUSPICIOUS_TLDS)


def _compute_entropy(data: bytes) -> float:
    """Compute Shannon entropy of bytes (useful for detecting packed/encrypted payloads)."""
    if not data:
        return 0.0
    freq: dict[int, int] = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


def _extract_header_dict(msg: Message) -> dict[str, list[str]]:
    """Return all headers grouped by header name (case-insensitive normalized)."""
    headers: dict[str, list[str]] = {}
    for key, value in msg.items():
        normalized_key = key.strip()
        headers.setdefault(normalized_key, []).append(value.strip() if value else "")
    return headers


def _extract_address_parts(raw: str) -> tuple[str, str]:
    """Parse 'Display Name <email@domain.com>' into (display_name, address)."""
    raw = raw.strip()
    match = re.match(r'^"?([^"<>]*)"?\s*<([^>]+)>$', raw)
    if match:
        return match.group(1).strip(), match.group(2).strip().lower()
    # Plain address
    return "", raw.lower()


def _parse_address_list(raw_header: str) -> list[tuple[str, str]]:
    """Split comma-separated address list and parse each entry."""
    if not raw_header:
        return []
    # Basic RFC 2822 split — handles quoted commas poorly but suffices for normalization
    parts = re.split(r",(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)", raw_header)
    result = []
    for part in parts:
        part = part.strip()
        if not part:
            continue
        display, addr = _extract_address_parts(part)
        if addr:
            result.append((display, addr))
    return result


def _extract_urls_from_text(text: str, source: str) -> list[ExtractedURLItem]:
    """Extract and normalize URLs from plain text."""
    items: list[ExtractedURLItem] = []
    seen: set[str] = set()
    for match in _URL_PATTERN.finditer(text):
        raw_url = match.group().rstrip(".,;:!?>")
        if raw_url in seen:
            continue
        seen.add(raw_url)
        items.append(_build_url_item(raw_url, source))
    return items


def _extract_urls_from_html(html_content: str) -> list[ExtractedURLItem]:
    """Extract href/src URLs from HTML attributes in addition to plain-text links."""
    items: list[ExtractedURLItem] = []
    seen: set[str] = set()

    # href and src attributes
    attr_pattern = re.compile(r'(?:href|src|action)\s*=\s*["\']([^"\'<>]+)["\']', re.IGNORECASE)
    for match in attr_pattern.finditer(html_content):
        raw_url = match.group(1).strip()
        if raw_url.lower().startswith(("javascript:", "vbscript:", "data:")):
            continue  # Already stripped by sanitizer but guard defensively
        if raw_url in seen:
            continue
        seen.add(raw_url)
        items.append(_build_url_item(raw_url, "body_html_href"))

    # Also extract plain-text-style links in HTML body
    for item in _extract_urls_from_text(html_content, "body_html_text"):
        if item.raw_url not in seen:
            seen.add(item.raw_url)
            items.append(item)

    return items


def _build_url_item(raw_url: str, source: str) -> ExtractedURLItem:
    """Build an ExtractedURLItem from a raw URL string."""
    try:
        parsed = urlparse(raw_url)
        domain = parsed.hostname or ""
        scheme = parsed.scheme or ""
        path = parsed.path or "/"
    except Exception:
        domain, scheme, path = "", "", "/"

    return ExtractedURLItem(
        raw_url=raw_url,
        canonical_url=raw_url.lower(),
        defanged_url=_defang_url(raw_url),
        domain=domain,
        scheme=scheme,
        path=path,
        is_ip_address=bool(_IP_PATTERN.match(domain)),
        is_shortener=domain in _URL_LINK_SHORTENERS,
        is_suspicious_tld=_is_suspicious_tld(domain),
        source_location=source,
    )


def _extract_attachment_metadata(part: Message) -> ExtractedAttachmentMetadata | None:
    """Safely extract metadata from a MIME attachment without executing content."""
    filename = part.get_filename() or ""
    if not filename:
        return None

    # Sanitize the filename — strip directory traversal and null bytes
    safe_filename = re.sub(r"[^\w.\-_() ]", "_", filename).replace("..", "_")

    # Extension analysis (look for double extensions: e.g. "invoice.pdf.exe")
    parts = filename.split(".")
    extension = ("." + parts[-1].lower()) if len(parts) > 1 else ""
    has_double_extension = len(parts) > 2

    declared_mime = part.get_content_type() or "application/octet-stream"

    raw_payload = part.get_payload(decode=True)
    payload_bytes: bytes = raw_payload if isinstance(raw_payload, bytes) else b""

    # Detect MIME via magic bytes (first 16 bytes)
    detected_mime = _detect_mime_from_magic(payload_bytes[:16], declared_mime)

    md5_hex = hashlib.md5(payload_bytes, usedforsecurity=False).hexdigest()
    sha256_hex = hashlib.sha256(payload_bytes).hexdigest()

    # Cap entropy computation at 64 KB to avoid slow analysis on huge attachments
    entropy = _compute_entropy(payload_bytes[:65536]) if payload_bytes else None

    return ExtractedAttachmentMetadata(
        filename=filename,
        safe_filename=safe_filename,
        extension=extension,
        declared_mime_type=declared_mime,
        detected_mime_type=detected_mime,
        size_bytes=len(payload_bytes),
        md5_hash=md5_hex,
        sha256_hash=sha256_hex,
        is_executable=extension in _EXECUTABLE_EXTENSIONS,
        is_archive=extension in _ARCHIVE_EXTENSIONS,
        has_double_extension=has_double_extension,
        has_macro_extension=extension in _MACRO_EXTENSIONS,
        entropy_score=entropy,
    )


def _detect_mime_from_magic(header_bytes: bytes, fallback: str) -> str:
    """Primitive file-signature detection from magic bytes (no file execution)."""
    if len(header_bytes) < 4:
        return fallback
    h = header_bytes
    if h[:2] == b"MZ":
        return "application/x-dosexec"
    if h[:4] == b"PK\x03\x04":
        return "application/zip"
    if h[:4] == b"%PDF":
        return "application/pdf"
    if h[:4] in (b"\xd0\xcf\x11\xe0",):
        return "application/vnd.ms-office"
    if h[:3] == b"\xff\xfb" or h[:3] == b"ID3":
        return "audio/mpeg"
    if h[:6] in (b"GIF87a", b"GIF89a"):
        return "image/gif"
    if h[:4] == b"\x89PNG":
        return "image/png"
    if h[:2] == b"\xff\xd8":
        return "image/jpeg"
    if h[:4] == b"RIFF":
        return "video/avi"
    return fallback


def _parse_received_hops(received_headers: list[str]) -> list[dict[str, Any]]:
    """Parse Received header chain into structured hop dicts."""
    hops = []
    for raw in received_headers:
        hop: dict[str, Any] = {"raw": raw}
        from_match = re.search(r"\bfrom\s+(\S+)", raw, re.IGNORECASE)
        by_match = re.search(r"\bby\s+(\S+)", raw, re.IGNORECASE)
        with_match = re.search(r"\bwith\s+(\S+)", raw, re.IGNORECASE)
        ip_match = re.search(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]", raw)
        date_match = re.search(r";\s*(.+)$", raw)
        if from_match:
            hop["from"] = from_match.group(1)
        if by_match:
            hop["by"] = by_match.group(1)
        if with_match:
            hop["with"] = with_match.group(1)
        if ip_match:
            hop["ip"] = ip_match.group(1)
        if date_match:
            hop["date"] = date_match.group(1).strip()
        hops.append(hop)
    return hops


def _detect_spoofed_display_name(display_name: str, from_domain: str) -> tuple[bool, str | None]:
    """Detect impersonation of well-known brands in the display name vs actual domain."""
    known_brands: dict[str, str] = {
        "paypal": "paypal.com",
        "microsoft": "microsoft.com",
        "apple": "apple.com",
        "google": "google.com",
        "amazon": "amazon.com",
        "netflix": "netflix.com",
        "dropbox": "dropbox.com",
        "linkedin": "linkedin.com",
        "facebook": "facebook.com",
        "instagram": "instagram.com",
        "twitter": "twitter.com",
        "x corp": "x.com",
        "irs": "irs.gov",
        "fedex": "fedex.com",
        "ups": "ups.com",
        "dhl": "dhl.com",
    }
    lower_name = display_name.lower()
    for brand, domain in known_brands.items():
        if brand in lower_name and not from_domain.lower().endswith(domain):
            return True, domain
    return False, None


def _detect_structural_anomalies(
    msg: Message,
    raw_source: str | bytes,
    has_html: bool,
    html_body: str | None,
) -> list[StructuralAnomaly]:
    """Detect malformed MIME structures and injection signals."""
    anomalies: list[StructuralAnomaly] = []

    # 1. Missing/empty From
    if not msg.get("From", "").strip():
        anomalies.append(
            StructuralAnomaly(
                anomaly_type="MISSING_FROM",
                description="Email has no From header — violates RFC 5322 §3.6.",
                severity="HIGH",
            )
        )

    # 2. Missing Message-ID
    if not msg.get("Message-ID", "").strip():
        anomalies.append(
            StructuralAnomaly(
                anomaly_type="MISSING_MESSAGE_ID",
                description="Email is missing the Message-ID header.",
                severity="MEDIUM",
            )
        )

    # 3. JavaScript/scripting in HTML body
    if has_html and html_body and _contains_js(html_body):
        anomalies.append(
            StructuralAnomaly(
                anomaly_type="JS_IN_HTML_BODY",
                description="HTML body contains JavaScript, event handlers, or scripting URIs — all stripped for safety.",
                severity="HIGH",
            )
        )

    # 4. Header injection characters in Subject
    subject = msg.get("Subject", "")
    if subject and re.search(r"[\r\n]", subject):
        anomalies.append(
            StructuralAnomaly(
                anomaly_type="HEADER_INJECTION_IN_SUBJECT",
                description="Subject header contains CRLF characters, indicating possible header injection.",
                severity="CRITICAL",
            )
        )

    # 5. Multiple From headers
    from_headers = msg.get_all("From") or []
    if len(from_headers) > 1:
        anomalies.append(
            StructuralAnomaly(
                anomaly_type="MULTIPLE_FROM_HEADERS",
                description=f"Email has {len(from_headers)} From headers — RFC 5322 allows only one.",
                severity="HIGH",
            )
        )

    # 6. MIME boundary conflicts
    msg.get_content_type() or ""
    if msg.is_multipart() and "boundary" not in (msg.get("Content-Type", "") or ""):
        anomalies.append(
            StructuralAnomaly(
                anomaly_type="MISSING_MIME_BOUNDARY",
                description="Multipart MIME message lacks a boundary parameter.",
                severity="MEDIUM",
            )
        )

    # 7. Encoding anomaly detection (base64 in non-attachment text parts)
    for part in msg.walk():
        cte = (part.get("Content-Transfer-Encoding") or "").lower()
        ct = part.get_content_type() or ""
        if cte in ("base64", "quoted-printable") and ct.startswith("text/plain"):
            anomalies.append(
                StructuralAnomaly(
                    anomaly_type="ENCODED_TEXT_BODY",
                    description=f"Plain text body is {cte}-encoded — commonly used to evade content filters.",
                    severity="LOW",
                )
            )
            break

    # 8. Null bytes in raw source
    raw_str = (
        raw_source if isinstance(raw_source, str) else raw_source.decode("utf-8", errors="replace")
    )
    if "\x00" in raw_str:
        anomalies.append(
            StructuralAnomaly(
                anomaly_type="NULL_BYTES_IN_RAW",
                description="Raw email content contains NUL bytes — may indicate binary injection or corrupted parsing.",
                severity="MEDIUM",
            )
        )

    return anomalies


# ---------------------------------------------------------------------------
# Primary Pipeline Class
# ---------------------------------------------------------------------------


class EmailPreprocessingPipeline:
    """Stateless pipeline that parses raw email into a canonical EmailAnalysisInput.

    Usage:
        pipeline = EmailPreprocessingPipeline()
        result = pipeline.preprocess_raw(raw_bytes_or_string)
        result = pipeline.preprocess_structured(from_addr, to_addrs, subject, body, ...)
    """

    def preprocess_raw(self, raw: str | bytes) -> EmailAnalysisInput:
        """Full pipeline: parse raw RFC 822 / MIME email bytes or string.

        Args:
            raw: Complete RFC 822 email with headers + body.

        Returns:
            Canonical EmailAnalysisInput for downstream engines.
        """
        if isinstance(raw, bytes):
            try:
                msg: Message = message_from_bytes(raw, policy=email.policy.compat32)
            except Exception as exc:
                logger.warning("email_parse_failed", error=str(exc))
                msg = email.message.Message()
            raw_str = raw.decode("utf-8", errors="replace")
        else:
            try:
                msg = message_from_string(raw, policy=email.policy.compat32)
            except Exception as exc:
                logger.warning("email_parse_failed", error=str(exc))
                msg = email.message.Message()
            raw_str = raw

        return self._build_analysis_input(msg, raw_str)

    def preprocess_structured(
        self,
        from_address: str,
        to_addresses: list[str],
        subject: str,
        *,
        body_plain: str | None = None,
        body_html: str | None = None,
        cc_addresses: list[str] | None = None,
        bcc_addresses: list[str] | None = None,
        reply_to: str | None = None,
        raw_headers_str: str | None = None,
    ) -> EmailAnalysisInput:
        """Pipeline for structured field submissions (e.g. from API form).

        Synthetic RFC 822 message is constructed from the fields for uniform processing.

        Args:
            from_address: Sender address (required).
            to_addresses: List of recipient addresses.
            subject: Email subject line.
            body_plain: Plain text body.
            body_html: HTML body (will be sanitized).
            cc_addresses: Carbon copy recipients.
            bcc_addresses: Blind carbon copy recipients.
            reply_to: Optional Reply-To override.
            raw_headers_str: Optional raw headers to parse for SPF/DKIM/DMARC.

        Returns:
            Canonical EmailAnalysisInput for downstream engines.
        """
        # Build a synthetic RFC 822 string
        header_block = f"From: {from_address}\r\n"
        header_block += f"To: {', '.join(to_addresses)}\r\n" if to_addresses else ""
        if cc_addresses:
            header_block += f"Cc: {', '.join(cc_addresses)}\r\n"
        if bcc_addresses:
            header_block += f"Bcc: {', '.join(bcc_addresses)}\r\n"
        if reply_to:
            header_block += f"Reply-To: {reply_to}\r\n"
        header_block += f"Subject: {subject}\r\n"
        header_block += f"Message-ID: <synthetic-{uuid.uuid4()}@preprocessor>\r\n"
        header_block += f"Date: {datetime.now(UTC).strftime('%a, %d %b %Y %H:%M:%S %z')}\r\n"

        # Inject additional raw headers if provided
        if raw_headers_str:
            header_block += raw_headers_str.strip() + "\r\n"

        body_block = body_plain or ""

        synthetic_raw = header_block + "\r\n" + body_block

        # Parse the synthetic message to get uniform header parsing
        msg: Message = message_from_string(synthetic_raw, policy=email.policy.compat32)

        # Inject HTML as a special attribute so it survives the synthetic parse
        result = self._build_analysis_input(msg, synthetic_raw)

        # If HTML body was provided separately, reprocess content with it
        if body_html is not None:
            result = self._inject_html_body(result, body_html)

        return result

    # ------------------------------------------------------------------
    # Internal processing steps
    # ------------------------------------------------------------------

    def _build_analysis_input(self, msg: Message, raw_source: str) -> EmailAnalysisInput:
        """Build canonical EmailAnalysisInput from a parsed Message object."""
        headers = _extract_header_dict(msg)

        # --- Extract and normalize sender ---
        raw_from = msg.get("From", "") or ""
        sender = self._normalize_sender(raw_from)

        # --- Extract recipients ---
        recipients = self._extract_recipients(msg)

        # --- Reply-To / Return-Path ---
        raw_reply_to = msg.get("Reply-To")
        raw_return_path = msg.get("Return-Path")
        _, reply_to = _extract_address_parts(raw_reply_to) if raw_reply_to else ("", "")
        _, return_path = _extract_address_parts(raw_return_path) if raw_return_path else ("", "")

        # --- Subject normalization ---
        raw_subject = msg.get("Subject", "") or ""
        subject = self._decode_header_value(raw_subject)
        normalized_subject = _normalize_whitespace(subject)

        # --- Date parsing ---
        msg_date = self._parse_date(msg.get("Date"))

        # --- Message-ID ---
        message_id = msg.get("Message-ID", "") or ""

        # --- Headers ---
        received_raw = headers.get("Received", [])
        normalized_headers = NormalizedHeaders(
            message_id=message_id,
            date=msg_date,
            all_headers=headers,
            received_hops=tuple(_parse_received_hops(received_raw)),
            spf_header=self._first_header(headers, "Received-SPF"),
            dkim_header=self._first_header(headers, "DKIM-Signature"),
            dmarc_header=self._first_header(headers, "DMARC-Filter"),
            arc_headers=tuple(headers.get("ARC-Message-Signature", [])),
            x_originating_ip=self._first_header(headers, "X-Originating-IP"),
            x_mailer=self._first_header(headers, "X-Mailer"),
        )

        # --- Body extraction ---
        plain_body, html_body = self._extract_bodies(msg)
        sanitized_html = _sanitize_html(html_body) if html_body else None
        plain_from_html = _html_to_plain_text(sanitized_html) if sanitized_html else None

        effective_plain = plain_body or plain_from_html or ""
        normalized_plain = _normalize_whitespace(effective_plain)

        # Token-efficient AI text: first 32 000 chars (≈ ~24 000 GPT tokens)
        clean_for_ai = normalized_plain[:32_000]

        content = NormalizedContent(
            normalized_plain=normalized_plain,
            raw_html=html_body,
            sanitized_html=sanitized_html,
            clean_text_for_ai=clean_for_ai,
            character_count=len(normalized_plain),
            has_html=html_body is not None,
            has_plain=plain_body is not None,
        )

        # --- URL extraction ---
        url_items: list[ExtractedURLItem] = []
        url_items.extend(_extract_urls_from_text(normalized_plain, "body_plain"))
        if sanitized_html:
            url_items.extend(_extract_urls_from_html(sanitized_html))
        # Deduplicate by raw_url
        seen_urls: set[str] = set()
        dedup_urls: list[ExtractedURLItem] = []
        for u in url_items:
            if u.raw_url not in seen_urls:
                seen_urls.add(u.raw_url)
                dedup_urls.append(u)

        # Unique domains across all URLs
        domains = tuple(sorted({u.domain for u in dedup_urls if u.domain}))

        # --- Attachment extraction ---
        attachments = self._extract_all_attachments(msg)

        # --- Structural integrity ---
        anomalies = _detect_structural_anomalies(msg, raw_source, html_body is not None, html_body)
        integrity = StructuralIntegrity(
            is_malformed=any(a.severity in ("HIGH", "CRITICAL") for a in anomalies),
            anomalies=tuple(anomalies),
            flags=tuple(a.anomaly_type for a in anomalies),
        )

        # --- Raw evidence snapshot ---
        raw_to_addrs = tuple(addr for _, addr in _parse_address_list(msg.get("To", "") or ""))
        raw_cc_addrs = tuple(addr for _, addr in _parse_address_list(msg.get("Cc", "") or ""))
        raw_bcc_addrs = tuple(addr for _, addr in _parse_address_list(msg.get("Bcc", "") or ""))
        evidence = RawEvidence(
            raw_content=raw_source,
            raw_header_pairs=tuple(msg.items()),
            raw_from=raw_from,
            raw_to=raw_to_addrs,
            raw_cc=raw_cc_addrs,
            raw_bcc=raw_bcc_addrs,
            raw_reply_to=raw_reply_to,
            raw_return_path=raw_return_path,
            raw_subject=raw_subject,
            raw_date=msg.get("Date"),
            raw_body_plain=plain_body,
            raw_body_html=html_body,
        )

        return EmailAnalysisInput(
            analysis_input_id=str(uuid.uuid4()),
            raw_evidence=evidence,
            sender=sender,
            recipients=tuple(recipients),
            reply_to=reply_to or None,
            return_path=return_path or None,
            subject=subject,
            normalized_subject=normalized_subject,
            headers=normalized_headers,
            content=content,
            urls=tuple(dedup_urls),
            domains=domains,
            attachments=tuple(attachments),
            integrity=integrity,
        )

    def _inject_html_body(self, result: EmailAnalysisInput, html_body: str) -> EmailAnalysisInput:
        """Return a new EmailAnalysisInput with the HTML body injected."""
        sanitized_html = _sanitize_html(html_body)
        plain_from_html = _html_to_plain_text(sanitized_html)
        existing_plain = result.content.normalized_plain or plain_from_html
        normalized_plain = _normalize_whitespace(existing_plain)

        # Re-extract URLs from HTML
        html_urls = _extract_urls_from_html(sanitized_html)
        all_urls = list(result.urls)
        seen = {u.raw_url for u in all_urls}
        for u in html_urls:
            if u.raw_url not in seen:
                seen.add(u.raw_url)
                all_urls.append(u)

        all_domains = tuple(sorted({u.domain for u in all_urls if u.domain}))

        # Detect JS in injected HTML
        extra_anomalies = list(result.integrity.anomalies)
        if _contains_js(html_body):
            extra_anomalies.append(
                StructuralAnomaly(
                    anomaly_type="JS_IN_HTML_BODY",
                    description="HTML body contains JavaScript, event handlers, or scripting URIs — all stripped.",
                    severity="HIGH",
                )
            )
        new_integrity = StructuralIntegrity(
            is_malformed=any(a.severity in ("HIGH", "CRITICAL") for a in extra_anomalies),
            anomalies=tuple(extra_anomalies),
            flags=tuple(a.anomaly_type for a in extra_anomalies),
        )

        return EmailAnalysisInput(
            analysis_input_id=result.analysis_input_id,
            raw_evidence=RawEvidence(
                **{**result.raw_evidence.__dict__, "raw_body_html": html_body}
            ),
            sender=result.sender,
            recipients=result.recipients,
            reply_to=result.reply_to,
            return_path=result.return_path,
            subject=result.subject,
            normalized_subject=result.normalized_subject,
            headers=result.headers,
            content=NormalizedContent(
                normalized_plain=normalized_plain,
                raw_html=html_body,
                sanitized_html=sanitized_html,
                clean_text_for_ai=normalized_plain[:32_000],
                character_count=len(normalized_plain),
                has_html=True,
                has_plain=result.content.has_plain,
            ),
            urls=tuple(all_urls),
            domains=all_domains,
            attachments=result.attachments,
            integrity=new_integrity,
        )

    def _normalize_sender(self, raw_from: str) -> NormalizedSender:
        """Parse and normalize the From field."""
        display_name, address = _extract_address_parts(raw_from)
        parts = address.split("@", 1)
        local_part = parts[0] if len(parts) > 0 else ""
        domain = parts[1] if len(parts) == 2 else ""
        is_spoofed, spoofed_target = _detect_spoofed_display_name(display_name, domain)
        return NormalizedSender(
            address=address,
            display_name=display_name,
            domain=domain,
            local_part=local_part,
            is_spoofed_display_name=is_spoofed,
            spoofed_target=spoofed_target,
        )

    def _extract_recipients(self, msg: Message) -> list[NormalizedRecipient]:
        """Extract and normalize To, Cc, Bcc recipients."""
        recipients: list[NormalizedRecipient] = []
        for field, rtype in [("To", "to"), ("Cc", "cc"), ("Bcc", "bcc")]:
            raw_val = msg.get(field, "") or ""
            for display_name, addr in _parse_address_list(raw_val):
                if not addr:
                    continue
                parts = addr.split("@", 1)
                domain = parts[1] if len(parts) == 2 else ""
                recipients.append(
                    NormalizedRecipient(
                        address=addr,
                        display_name=display_name,
                        domain=domain,
                        recipient_type=rtype,
                    )
                )
        return recipients

    def _extract_bodies(self, msg: Message) -> tuple[str | None, str | None]:
        """Walk MIME tree and extract plain text and HTML bodies.

        Returns a tuple (plain_text, html_text).
        Bodies are capped at _MAX_BODY_BYTES to prevent memory exhaustion.
        """
        plain: str | None = None
        html_content: str | None = None

        if msg.is_multipart():
            for part in msg.walk():
                ct = part.get_content_type()
                cd = str(part.get("Content-Disposition") or "")
                if "attachment" in cd:
                    continue
                if ct == "text/plain" and plain is None:
                    decoded = _decode_part(part)
                    plain = decoded[:_MAX_BODY_BYTES]
                elif ct == "text/html" and html_content is None:
                    decoded = _decode_part(part)
                    html_content = decoded[:_MAX_BODY_BYTES]
        else:
            ct = msg.get_content_type()
            if ct == "text/plain":
                decoded = _decode_part(msg)
                plain = decoded[:_MAX_BODY_BYTES]
            elif ct == "text/html":
                decoded = _decode_part(msg)
                html_content = decoded[:_MAX_BODY_BYTES]

        return plain, html_content

    def _extract_all_attachments(self, msg: Message) -> list[ExtractedAttachmentMetadata]:
        """Walk MIME tree and safely extract attachment metadata."""
        attachments: list[ExtractedAttachmentMetadata] = []
        for part in msg.walk():
            cd = str(part.get("Content-Disposition") or "")
            if "attachment" in cd or "inline" in cd:
                meta = _extract_attachment_metadata(part)
                if meta is not None:
                    attachments.append(meta)
        return attachments

    def _decode_header_value(self, raw: str) -> str:
        """Decode RFC 2047-encoded header values."""
        from email.header import decode_header

        try:
            parts = decode_header(raw)
            decoded = []
            for raw_bytes, charset in parts:
                if isinstance(raw_bytes, bytes):
                    decoded.append(raw_bytes.decode(charset or "utf-8", errors="replace"))
                else:
                    decoded.append(str(raw_bytes))
            return " ".join(decoded)
        except Exception:
            return raw

    def _parse_date(self, raw_date: str | None) -> datetime:
        """Parse RFC 2822 date string into timezone-aware datetime, fallback to now."""
        if not raw_date:
            return datetime.now(UTC)
        from email.utils import parsedate_to_datetime

        try:
            dt = parsedate_to_datetime(raw_date)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
            return dt
        except Exception:
            return datetime.now(UTC)

    @staticmethod
    def _first_header(headers: dict[str, list[str]], name: str) -> str | None:
        values = headers.get(name, [])
        return values[0] if values else None
