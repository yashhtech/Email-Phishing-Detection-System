"""Feature extractor for email machine learning classification.

Extracts a calibrated, fixed-length feature vector from an EmailAnalysisInput object.
All features are normalized into numeric values suitable for linear, ensemble,
or neural classifiers.

Feature vector structure (total 30 features):
- Lexical / Structural features (subject length, body length, HTML ratio, uppercase ratio)
- URL features (URL count, IP URL count, shortener count, suspicious TLD count, credential keyword count)
- Domain features (domain length, entropy, digit ratio, subdomain count, typosquatting flag)
- Authentication features (SPF status code, DKIM status code, DMARC status code)
- Attachment features (attachment count, executable flag, archive flag, macro flag, max entropy)
- Behavioral / NLP cues (urgency keyword count, financial keyword count, suspicious word count)
- Header anomalies (hop count, missing message-id flag, multiple from flag)
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

from app.domain.entities.email_analysis_input import EmailAnalysisInput

# Feature names in deterministic canonical order
FEATURE_NAMES: tuple[str, ...] = (
    "subject_length",
    "subject_uppercase_ratio",
    "body_length",
    "body_html_ratio",
    "url_count",
    "url_has_ip",
    "url_has_shortener",
    "url_suspicious_tld_count",
    "url_credential_keyword_count",
    "url_max_subdomain_depth",
    "domain_length",
    "domain_entropy",
    "domain_digit_ratio",
    "domain_is_spoofed_brand",
    "reply_to_mismatch",
    "spf_status_score",  # 1.0 = pass, 0.5 = softfail/none, 0.0 = fail
    "dkim_status_score",  # 1.0 = pass, 0.0 = fail/none
    "dmarc_status_score",  # 1.0 = pass, 0.0 = fail/none
    "attachment_count",
    "attachment_has_executable",
    "attachment_has_archive",
    "attachment_has_macro",
    "attachment_max_entropy",
    "urgency_keyword_count",
    "financial_keyword_count",
    "security_lure_keyword_count",
    "routing_hop_count",
    "missing_message_id",
    "has_hidden_text_html",
    "structural_anomaly_count",
)


@dataclass(frozen=True)
class FeatureExtractionResult:
    """Extracted feature vector and explainability mapping."""

    features: dict[str, float]
    feature_vector: list[float]
    feature_names: tuple[str, ...] = FEATURE_NAMES


class FeatureExtractor:
    """Extracts numerical features from EmailAnalysisInput."""

    # Lexical patterns for heuristic NLP feature counting
    _URGENCY_PATTERNS = re.compile(
        r"\b(?:urgent|immediately|action required|suspended|locked|within 24 hours|deadline|act now|expires)\b",
        re.IGNORECASE,
    )
    _FINANCIAL_PATTERNS = re.compile(
        r"\b(?:wire transfer|invoice|payment|bank|bitcoin|crypto|gift card|payroll|salary|reimbursement)\b",
        re.IGNORECASE,
    )
    _SECURITY_PATTERNS = re.compile(
        r"\b(?:security alert|unauthorized|password reset|verify account|confirm identity|suspicious activity)\b",
        re.IGNORECASE,
    )

    def extract(self, email_input: EmailAnalysisInput) -> FeatureExtractionResult:
        """Transform an EmailAnalysisInput into a normalized feature map and vector."""
        subject = email_input.subject or ""
        body_plain = email_input.content.normalized_plain or ""
        body_html = email_input.content.raw_html or ""
        sender = email_input.sender
        sender_domain = sender.domain.lower()
        combined_text = f"{subject} {body_plain}"

        features: dict[str, float] = {}

        # 1. Subject features
        features["subject_length"] = float(min(len(subject), 200)) / 200.0
        features["subject_uppercase_ratio"] = sum(1 for c in subject if c.isupper()) / max(
            len(subject), 1
        )

        # 2. Body features
        features["body_length"] = min(float(len(body_plain)), 10000.0) / 10000.0
        total_content_len = len(body_plain) + len(body_html)
        features["body_html_ratio"] = (
            float(len(body_html)) / float(total_content_len) if total_content_len > 0 else 0.0
        )

        # 3. URL features
        urls = email_input.urls
        features["url_count"] = min(float(len(urls)), 20.0) / 20.0
        features["url_has_ip"] = 1.0 if any(u.is_ip_address for u in urls) else 0.0
        features["url_has_shortener"] = 1.0 if any(u.is_shortener for u in urls) else 0.0
        features["url_suspicious_tld_count"] = (
            min(float(sum(1 for u in urls if u.is_suspicious_tld)), 5.0) / 5.0
        )
        features["url_credential_keyword_count"] = (
            min(
                float(
                    sum(
                        1
                        for u in urls
                        if any(
                            kw in u.path.lower()
                            for kw in ("login", "signin", "verify", "account", "password", "wallet")
                        )
                    )
                ),
                5.0,
            )
            / 5.0
        )
        max_subdomains = max((len(u.domain.split(".")) for u in urls), default=2) if urls else 2
        features["url_max_subdomain_depth"] = min(float(max_subdomains), 8.0) / 8.0

        # 4. Domain features
        features["domain_length"] = min(float(len(sender_domain)), 50.0) / 50.0
        features["domain_entropy"] = min(self._shannon_entropy(sender_domain), 5.0) / 5.0
        features["domain_digit_ratio"] = sum(1 for c in sender_domain if c.isdigit()) / max(
            len(sender_domain), 1
        )
        features["domain_is_spoofed_brand"] = 1.0 if sender.is_spoofed_display_name else 0.0

        # Reply-To mismatch
        reply_to_domain = (
            email_input.reply_to.split("@")[-1].lower()
            if email_input.reply_to and "@" in email_input.reply_to
            else ""
        )
        features["reply_to_mismatch"] = (
            1.0 if reply_to_domain and sender_domain and reply_to_domain != sender_domain else 0.0
        )

        # 5. Authentication features
        headers = email_input.headers
        auth_raw = " ".join(headers.all_headers.get("Authentication-Results", [])).lower()
        spf_raw = (headers.spf_header or "").lower()

        # SPF score
        if "pass" in spf_raw or "spf=pass" in auth_raw:
            features["spf_status_score"] = 1.0
        elif "softfail" in spf_raw or "spf=softfail" in auth_raw:
            features["spf_status_score"] = 0.5
        elif "fail" in spf_raw or "spf=fail" in auth_raw:
            features["spf_status_score"] = 0.0
        else:
            features["spf_status_score"] = 0.5  # neutral/none

        # DKIM score
        if "dkim=pass" in auth_raw or headers.dkim_header:
            features["dkim_status_score"] = 1.0
        elif "dkim=fail" in auth_raw:
            features["dkim_status_score"] = 0.0
        else:
            features["dkim_status_score"] = 0.5

        # DMARC score
        if "dmarc=pass" in auth_raw:
            features["dmarc_status_score"] = 1.0
        elif "dmarc=fail" in auth_raw:
            features["dmarc_status_score"] = 0.0
        else:
            features["dmarc_status_score"] = 0.5

        # 6. Attachment features
        attachments = email_input.attachments
        features["attachment_count"] = min(float(len(attachments)), 5.0) / 5.0
        features["attachment_has_executable"] = (
            1.0 if any(a.is_executable for a in attachments) else 0.0
        )
        features["attachment_has_archive"] = 1.0 if any(a.is_archive for a in attachments) else 0.0
        features["attachment_has_macro"] = (
            1.0 if any(a.has_macro_extension for a in attachments) else 0.0
        )
        entropies = [a.entropy_score for a in attachments if a.entropy_score is not None]
        features["attachment_max_entropy"] = min(max(entropies), 8.0) / 8.0 if entropies else 0.0

        # 7. Behavioral / NLP cue counts
        features["urgency_keyword_count"] = (
            min(float(len(self._URGENCY_PATTERNS.findall(combined_text))), 10.0) / 10.0
        )
        features["financial_keyword_count"] = (
            min(float(len(self._FINANCIAL_PATTERNS.findall(combined_text))), 10.0) / 10.0
        )
        features["security_lure_keyword_count"] = (
            min(float(len(self._SECURITY_PATTERNS.findall(combined_text))), 10.0) / 10.0
        )

        # 8. Structural and header anomalies
        features["routing_hop_count"] = min(float(len(headers.received_hops)), 15.0) / 15.0
        features["missing_message_id"] = (
            1.0 if not headers.message_id or headers.message_id.strip() in ("", "<>") else 0.0
        )
        features["has_hidden_text_html"] = (
            1.0
            if "font-size:0" in body_html.lower() or "display:none" in body_html.lower()
            else 0.0
        )
        features["structural_anomaly_count"] = (
            min(float(len(email_input.integrity.anomalies)), 10.0) / 10.0
        )

        # Generate ordered vector matching FEATURE_NAMES
        vector = [features[name] for name in FEATURE_NAMES]

        return FeatureExtractionResult(
            features=features,
            feature_vector=vector,
            feature_names=FEATURE_NAMES,
        )

    @staticmethod
    def _shannon_entropy(s: str) -> float:
        if not s:
            return 0.0
        freq: dict[str, int] = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        total = len(s)
        return -sum((cnt / total) * math.log2(cnt / total) for cnt in freq.values())
