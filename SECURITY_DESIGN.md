# Security Design
## Email Threat Detection & Security Intelligence Platform

> **Version:** 1.0.0 | **Standard:** OWASP ASVS Level 2 | **Date:** 2026-09-29

---

## Table of Contents

1. [Security Architecture Overview](#1-security-architecture-overview)
2. [Authentication & Authorization](#2-authentication--authorization)
3. [Email Security Analysis Engines](#3-email-security-analysis-engines)
4. [LLM Safety Gateway](#4-llm-safety-gateway)
5. [Risk Scoring Engine](#5-risk-scoring-engine)
6. [API Security Controls](#6-api-security-controls)
7. [Data Security](#7-data-security)
8. [Secret Management](#8-secret-management)
9. [Audit Logging](#9-audit-logging)
10. [Threat Intelligence Integration](#10-threat-intelligence-integration)
11. [Infrastructure Security](#11-infrastructure-security)
12. [Security Headers](#12-security-headers)

---

## 1. Security Architecture Overview

### Defense-in-Depth Layers

```
Layer 0:  Network perimeter (WAF, TLS 1.3 enforcement, IP allowlists)
Layer 1:  API Gateway (rate limiting, auth enforcement, CORS, security headers)
Layer 2:  Application (input validation, RBAC, audit logging, sanitization)
Layer 3:  LLM Safety Gateway (prompt injection defense, output validation)
Layer 4:  Data (encryption at rest, column-level sensitivity, no PII in logs)
Layer 5:  Infrastructure (non-root containers, read-only filesystems, secrets via env)
```

### Threat Model (STRIDE)

| Threat | Mitigation |
|---|---|
| **S**poofing | JWT RS256 with key rotation; Argon2id password hashing |
| **T**ampering | Audit log (append-only); DB-level CHECK constraints; Pydantic validation |
| **R**epudiation | Immutable audit_log with actor, IP, timestamp, correlation ID for all state changes |
| **I**nformation Disclosure | PII redacted from logs; TLS everywhere; column-level encryption for sensitive fields |
| **D**enial of Service | Redis rate limiting; request size limits; Celery queue depth alerting |
| **E**levation of Privilege | RBAC enforced at middleware layer; role checks on every protected endpoint |

---

## 2. Authentication & Authorization

### 2.1 JWT Configuration

| Property | Value |
|---|---|
| Algorithm | RS256 (asymmetric — private key signs, public key verifies) |
| Access token TTL | 15 minutes |
| Refresh token TTL | 7 days |
| Key rotation period | 90 days |
| Claims | `sub` (user ID), `role`, `iat`, `exp`, `jti` (for revocation) |

**Private key:** stored as environment variable `JWT_PRIVATE_KEY` (PEM format, base64-encoded).  
**Public key:** stored as `JWT_PUBLIC_KEY` — can be distributed to services that need to verify tokens.

### 2.2 Token Lifecycle

```
[Login] → issue access_token (15min) + refresh_token (7 days)
                │
        refresh_token stored as opaque reference in Redis:
        key: "rt:{user_id}:{jti}" → value: "valid"  TTL: 7 days

[Refresh] → verify refresh_token signature + Redis presence
          → issue new access_token + rotate refresh_token
          → revoke old refresh_token in Redis

[Logout] → add jti to Redis blocklist (TTL = remaining access_token lifetime)
         → delete refresh_token from Redis
```

### 2.3 Password Security

- Algorithm: **Argon2id** (OWASP recommended)
- Parameters: `time_cost=3`, `memory_cost=65536` (64 MB), `parallelism=4`, `hash_len=32`, `salt_len=16`
- No password is ever logged, cached, or transmitted after initial receipt
- Plaintext password is cleared from memory immediately after hashing

### 2.4 RBAC Implementation

```python
# Permission matrix — defined in domain/entities/user.py
ROLE_PERMISSIONS = {
    "viewer": {
        "emails": ["read"],
        "analyses": ["read"],
        "threats": ["read"],
        "dashboard": ["read"],
        "alerts": ["read"],
    },
    "analyst": {
        **ROLE_PERMISSIONS["viewer"],
        "emails": ["read", "create"],
        "threats": ["read", "annotate"],
        "analyses": ["read", "retry"],
    },
    "admin": {
        **ROLE_PERMISSIONS["analyst"],
        "users": ["read", "create", "update", "delete"],
        "emails": ["read", "create", "delete"],
        "settings": ["read", "update"],
    }
}
```

RBAC checks run in FastAPI dependency injection — **before** any business logic executes:

```python
# api/dependencies.py
def require_permission(resource: str, action: str):
    def dependency(current_user: User = Depends(get_current_user)):
        if action not in ROLE_PERMISSIONS.get(current_user.role, {}).get(resource, []):
            raise ForbiddenError(f"Role '{current_user.role}' cannot {action} {resource}")
        return current_user
    return dependency
```

---

## 3. Email Security Analysis Engines

### 3.1 SPF (Sender Policy Framework)

**Library:** `pyspf` or `checkdmarc`

**Analysis steps:**
1. Extract `Return-Path` / `MAIL FROM` domain from email headers
2. DNS TXT record lookup: `_spf.<domain>`
3. Evaluate against sender IP from `Received:` headers
4. Return: `pass` | `fail` | `softfail` | `neutral` | `none` | `temperror` | `permerror`

**Risk contribution:** SPF `fail` → +25 risk points; `softfail` → +10; `none` → +5

**Edge cases handled:**
- SPF record syntax errors → treated as `permerror`, risk score increased
- DNS lookup limit exceeded (>10 DNS lookups) → flagged as policy error
- Include loops → detected and broken

---

### 3.2 DKIM (DomainKeys Identified Mail)

**Library:** `dkimpy`

**Analysis steps:**
1. Extract `DKIM-Signature:` header
2. Parse `d=` (signing domain), `s=` (selector), `a=` (algorithm), `b=` (signature)
3. DNS TXT lookup: `<selector>._domainkey.<d=domain>`
4. Verify signature against email body hash
5. Check `i=` identity alignment with `From:` domain (strict vs. relaxed)

**Return:** `pass` | `fail` | `none` | `policy_error` | `temperror`

**Risk contribution:** DKIM `fail` → +20; `none` → +10

---

### 3.3 DMARC (Domain-based Message Authentication)

**Library:** `checkdmarc`

**Analysis steps:**
1. DNS TXT lookup: `_dmarc.<from_domain>`
2. Parse policy (`p=none|quarantine|reject`), `rua=` (aggregate report URI), `adkim=`, `aspf=` (alignment modes)
3. Evaluate SPF alignment: `From:` domain vs. `Return-Path` domain
4. Evaluate DKIM alignment: `From:` domain vs. `d=` in DKIM-Signature
5. Apply policy: both SPF and DKIM alignment must pass for DMARC pass

**Return:**
```python
class DMARCResult:
    result: Literal["pass", "fail", "none"]
    policy: Literal["none", "quarantine", "reject"]
    spf_aligned: bool
    dkim_aligned: bool
    policy_disposition: str  # what action the policy dictates
```

**Risk contribution:** DMARC `fail` with `reject` policy → +30; with `quarantine` → +20; `none` → +15

---

### 3.4 Header Analysis Engine

**Analyzes:**

| Check | Description |
|---|---|
| Received chain | Validate each hop's IP/hostname pair; detect route anomalies |
| X-Originating-IP | Compare with SPF result |
| From vs. Reply-To mismatch | Different domains = high suspicion |
| Display name spoofing | Display name matches org name but email domain doesn't |
| Time zone anomalies | `Date:` header timezone vs. sending server location |
| X-Mailer / User-Agent | Known bulk/phishing mailer signatures |
| MIME structure | Multipart bombs, unusual nesting |
| Encoding anomalies | Base64 encoding of plain text (often used to evade scanners) |

**Output:**
```python
class HeaderAnalysisResult:
    routing_anomalies: list[str]
    display_name_spoof: bool
    reply_to_mismatch: bool
    timezone_mismatch: bool
    suspicious_xmailer: bool
    encoding_anomalies: list[str]
    risk_contribution: int  # 0-100
```

---

### 3.5 URL Analysis Engine

**Pipeline per extracted URL:**

1. **Extraction:** `BeautifulSoup` + regex from HTML body, plain text, and headers
2. **Deobfuscation:** Decode HTML entities, URL encoding, unicode normalization
3. **Expansion:** Follow redirects (max 10 hops) with `httpx` (timeout 5s, no JS)
4. **Homoglyph detection:** Levenshtein distance against top-1000 brand domains using confusable characters
5. **VirusTotal lookup:** URL reputation check via VT API v3 (cached by URL SHA256 in Redis, TTL 24h)
6. **Suspicious patterns:** IP-as-host, non-standard ports, excessive subdomains, known phishing TLDs

**Homoglyph detection algorithm:**
```python
# Confusable character mapping
CONFUSABLES = {
    '0': 'o', '1': 'l', '3': 'e', '4': 'a',
    'rn': 'm', 'vv': 'w', 'c1': 'd', ...
}

def homoglyph_score(candidate: str, brand_domains: list[str]) -> tuple[float, str]:
    normalized = normalize_confusables(candidate)
    for brand in brand_domains:
        similarity = 1 - (edit_distance(normalized, brand) / max(len(normalized), len(brand)))
        if similarity > 0.85:
            return similarity, brand
    return 0.0, ""
```

---

### 3.6 Attachment Scanner

**Checks per attachment:**

| Check | Method |
|---|---|
| MIME type validation | Compare declared MIME vs. magic bytes |
| Extension mismatch | `invoice.pdf` with Office XML magic bytes |
| Hash lookup | MD5 + SHA256 against VirusTotal (cached 24h) |
| Archive inspection | List contents of ZIP/RAR without extraction |
| Executable detection | Flag `.exe`, `.bat`, `.ps1`, `.vbs`, `.js` in attachments or archives |
| Macro detection | Flag Office files with macros (`python-docx` + `oletools`) |

---

### 3.7 Sender & Domain Reputation

| Check | Data Source | Weight |
|---|---|---|
| Domain age | WHOIS | High |
| MX record validity | DNS | Medium |
| Typosquat detection | Levenshtein vs. brand list | High |
| Domain reputation | VirusTotal domain report | High |
| IP geolocation | MaxMind GeoLite2 | Low |
| ASN reputation | BGP ASN abuse score | Medium |
| Historical occurrences | Internal `threat_indicators` DB | High |

---

## 4. LLM Safety Gateway

### 4.1 Purpose

All LLM input (prompts) and output (responses) pass through the LLM Safety Gateway. This prevents:
- **Prompt injection** via malicious email content
- **Data exfiltration** through LLM responses
- **Hallucinated IOCs** being persisted as threat intelligence
- **PII leakage** from email body into LLM logs

### 4.2 Input Sanitization (Pre-LLM)

```python
class LLMInputSanitizer:
    MAX_BODY_LENGTH = 3000  # characters
    MAX_SUBJECT_LENGTH = 200

    def sanitize(self, email_context: EmailAnalysisContext) -> SafeEmailContext:
        # 1. Truncate to token budget
        body = self._truncate(email_context.body_preview, self.MAX_BODY_LENGTH)

        # 2. Strip HTML (plaintext only to LLM)
        body = self._strip_html(body)

        # 3. Detect and neutralize prompt injection patterns
        body = self._neutralize_injection(body)

        # 4. Redact PII (phone numbers, SSNs, CC numbers)
        body = self._redact_pii(body)

        return SafeEmailContext(subject=subject, body=body, urls=urls, ...)

    def _neutralize_injection(self, text: str) -> str:
        # Detect injection patterns like:
        # "Ignore previous instructions", "You are now", "System prompt:"
        INJECTION_PATTERNS = [
            r"ignore\s+(all\s+)?previous\s+instructions",
            r"you\s+are\s+now\s+a",
            r"system\s*prompt\s*:",
            r"<\s*system\s*>",
            # ... comprehensive list
        ]
        for pattern in INJECTION_PATTERNS:
            text = re.sub(pattern, "[REDACTED]", text, flags=re.IGNORECASE)
        return text
```

### 4.3 Structured Output Schema

LLM is prompted to return structured JSON conforming to:

```python
class ThreatNarrative(BaseModel):
    threat_narrative: str = Field(max_length=2000)
    threat_categories: list[ThreatCategory]
    iocs: list[IOCExtract]
    recommended_action: Literal["allow", "flag", "quarantine", "block"]
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str = Field(max_length=1000)

class IOCExtract(BaseModel):
    type: IOCType
    value: str = Field(max_length=500)
    confidence: float = Field(ge=0.0, le=1.0)
```

### 4.4 Output Validation (Post-LLM)

```python
class LLMOutputValidator:
    MIN_CONFIDENCE = 0.3  # reject hallucinated low-confidence outputs

    def validate(self, raw_output: str) -> ThreatNarrative:
        # 1. JSON parse — reject if not valid JSON
        parsed = self._parse_json(raw_output)

        # 2. Pydantic schema validation — reject if schema mismatch
        narrative = ThreatNarrative.model_validate(parsed)

        # 3. Confidence gate — reject if overall confidence too low
        if narrative.confidence < self.MIN_CONFIDENCE:
            raise LowConfidenceError(narrative.confidence)

        # 4. IOC plausibility check — validate IOC formats
        for ioc in narrative.iocs:
            self._validate_ioc_format(ioc)

        # 5. Narrative length sanity check
        if len(narrative.threat_narrative) < 50:
            raise HallucinationSuspected("Narrative too short")

        return narrative
```

---

## 5. Risk Scoring Engine

### 5.1 Scoring Model

The `RiskEngine` is the **single source of truth** for risk scores. It aggregates weighted sub-scores from all analysis layers into a composite 0–100 integer.

### 5.2 Factor Weights

| Factor | Weight | Max Contribution |
|---|---|---|
| ML phishing probability | 30% | 30 points |
| SPF result | 15% | 15 points |
| DKIM result | 12% | 12 points |
| DMARC result | 13% | 13 points |
| URL reputation | 15% | 15 points |
| Sender/domain reputation | 10% | 10 points |
| Attachment scan | 5% | 5 points |
| **Total** | **100%** | **100 points** |

LLM output does **not** contribute directly to the risk score. It provides narrative explanation. This prevents hallucinated IOCs from inflating risk scores.

### 5.3 Scoring Algorithm

```python
class RiskEngine:
    WEIGHTS = {
        "ml_phishing_probability": 0.30,
        "spf":                     0.15,
        "dkim":                    0.12,
        "dmarc":                   0.13,
        "url_reputation":          0.15,
        "sender_reputation":       0.10,
        "attachment":              0.05,
    }

    SPF_SCORES  = {"fail": 100, "softfail": 60, "none": 30, "neutral": 10, "pass": 0}
    DKIM_SCORES = {"fail": 100, "none": 60, "pass": 0}
    DMARC_SCORES = {"fail": 100, "none": 40, "pass": 0}

    def compute(self, sub_results: SubAnalysisResults) -> RiskScore:
        raw_scores = {
            "ml_phishing_probability": sub_results.ml.phishing_probability * 100,
            "spf":  self.SPF_SCORES.get(sub_results.header.spf, 50),
            "dkim": self.DKIM_SCORES.get(sub_results.header.dkim, 50),
            "dmarc": self.DMARC_SCORES.get(sub_results.header.dmarc, 50),
            "url_reputation": self._url_score(sub_results.urls),
            "sender_reputation": self._sender_score(sub_results.sender),
            "attachment": self._attachment_score(sub_results.attachments),
        }

        # Failed analysis layers raise risk, not lower it
        for key, result in sub_results.failed_layers.items():
            raw_scores[key] = 75  # penalize failed analysis

        composite = sum(
            score * self.WEIGHTS[factor]
            for factor, score in raw_scores.items()
        )

        return RiskScore(
            score=round(composite),
            level=self._to_level(composite),
            factors=[RiskFactor(factor=k, score=v, weight=self.WEIGHTS[k])
                     for k, v in raw_scores.items()]
        )

    @staticmethod
    def _to_level(score: float) -> RiskLevel:
        if score >= 80: return RiskLevel.CRITICAL
        if score >= 60: return RiskLevel.HIGH
        if score >= 40: return RiskLevel.MEDIUM
        if score >= 20: return RiskLevel.LOW
        return RiskLevel.SAFE
```

---

## 6. API Security Controls

### 6.1 Rate Limiting

Redis sliding window counter per (user_id, endpoint_group):

```python
class SlidingWindowRateLimiter:
    async def check(self, key: str, limit: int, window_seconds: int) -> RateLimitResult:
        now = time.time()
        window_start = now - window_seconds
        async with self.redis.pipeline() as pipe:
            pipe.zremrangebyscore(key, 0, window_start)
            pipe.zadd(key, {str(now): now})
            pipe.zcard(key)
            pipe.expire(key, window_seconds + 1)
            _, _, count, _ = await pipe.execute()
        allowed = count <= limit
        return RateLimitResult(allowed=allowed, current=count, limit=limit, reset_at=now + window_seconds)
```

### 6.2 Input Validation

- All request bodies validated by Pydantic v2 models with strict mode
- File uploads limited to 25 MB
- EML files scanned for zip bombs (compressed size limit: 100 MB)
- SQL injection: impossible via SQLAlchemy parameterized queries (never raw SQL with user input)
- Path traversal: all file paths resolved and jail-checked against allowed directories

### 6.3 CORS Configuration

```python
CORS_SETTINGS = {
    "allow_origins": settings.ALLOWED_ORIGINS,  # explicit whitelist from env
    "allow_credentials": True,
    "allow_methods": ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    "allow_headers": ["Authorization", "Content-Type", "X-Request-ID"],
}
```

In production, `ALLOWED_ORIGINS` is a specific list — no wildcards.

---

## 7. Data Security

### 7.1 Encryption

| Data | Encryption | Key Management |
|---|---|---|
| Data at rest (PostgreSQL) | Transparent Data Encryption (managed DB) or pgcrypto | Cloud KMS / Vault |
| Data in transit | TLS 1.3 (ECDHE + AES-256-GCM) | Auto-managed (Let's Encrypt) |
| Raw EML files (object storage) | SSE-S3 or SSE-GCS | Cloud KMS |
| Sensitive JSONB fields | Not encrypted at column level in v1 (deferred) | — |

### 7.2 PII Policy

- Email body content is stored in object storage (raw EML), not in PostgreSQL
- `body_preview` in DB is truncated to 500 chars and sanitized (no CC numbers, SSNs)
- Logs contain only: sender domain (not full address), analysis ID, risk score
- LLM input is PII-redacted before dispatch

### 7.3 Secrets Policy

- **No secrets in source control** — `.env.example` lists required variable names only
- All secrets injected via environment variables at runtime
- In production: secrets sourced from HashiCorp Vault or cloud secrets manager
- Secrets rotated: JWT keys every 90 days, external API keys every 180 days

---

## 8. Secret Management

### Required Environment Variables

```bash
# Database
DATABASE_URL=postgresql+asyncpg://user:password@host:5432/dbname

# Redis
REDIS_URL=redis://host:6379/0

# JWT
JWT_PRIVATE_KEY=<base64-encoded PEM>
JWT_PUBLIC_KEY=<base64-encoded PEM>
JWT_ALGORITHM=RS256
ACCESS_TOKEN_EXPIRE_MINUTES=15
REFRESH_TOKEN_EXPIRE_DAYS=7

# Groq
GROQ_API_KEY=gsk_...
GROQ_MODEL=llama-3.3-70b-versatile
GROQ_MAX_TOKENS=2048
GROQ_TIMEOUT_SECONDS=30

# VirusTotal
VIRUSTOTAL_API_KEY=...

# App
APP_ENV=production  # development|staging|production
SECRET_KEY=<random 64-byte hex>  # used for signing non-JWT tokens
ALLOWED_ORIGINS=https://app.example.com
LOG_LEVEL=WARNING
```

### Vault Integration (Production)

```python
# infrastructure/config/vault_loader.py
# At startup, if VAULT_ADDR is set, load secrets from Vault KV:
# - mount: secret/
# - path: email-platform/{APP_ENV}/
# Merge with environment variables (env vars take precedence)
```

---

## 9. Audit Logging

### 9.1 Events Logged

| Event Type | Trigger | Data Captured |
|---|---|---|
| `USER_LOGIN` | Successful login | user_id, ip, user_agent |
| `USER_LOGIN_FAILED` | Failed login attempt | email (hash only), ip |
| `USER_LOGOUT` | Logout | user_id |
| `TOKEN_REFRESHED` | Token refresh | user_id |
| `EMAIL_SUBMITTED` | Email submission | email_id, source, user_id |
| `ANALYSIS_STARTED` | Worker picks up task | email_id, analysis_id |
| `ANALYSIS_COMPLETED` | Analysis done | analysis_id, risk_score, risk_level |
| `ANALYSIS_FAILED` | Worker error | analysis_id, error |
| `THREAT_ANNOTATED` | Analyst adds annotation | threat_id, user_id |
| `ALERT_TRIGGERED` | Alert rule fires | alert_id, severity |
| `ALERT_ACKNOWLEDGED` | Analyst acknowledges | alert_id, user_id |
| `USER_CREATED` | Admin creates user | new_user_id, role |
| `USER_ROLE_CHANGED` | Role change | user_id, old_role, new_role |
| `USER_DELETED` | Soft delete | user_id |
| `EMAIL_DELETED` | Soft delete | email_id, user_id |
| `SETTINGS_CHANGED` | Config update | key, old_value (masked), new_value (masked) |

### 9.2 Audit Log Protection

- Application DB user has `INSERT` only on `audit_log` (no UPDATE/DELETE)
- PostgreSQL row-level trigger prevents UPDATE/DELETE as additional defense
- Audit log partitions are archived to immutable object storage after 90 days

---

## 10. Threat Intelligence Integration

### External Provider Priority

```
1. Internal threat_indicators DB  (fastest, proprietary intel)
2. Redis cache                    (TTL: 24h for VT results, 6h for WHOIS)
3. VirusTotal API                 (URL + file hash + domain + IP reputation)
4. DNS-over-HTTPS (Cloudflare)    (MX/TXT/A record lookups)
5. WHOIS                          (domain age, registrar, country)
```

### VirusTotal Integration

- **URL scan:** `POST /urls` (scan new URL) + `GET /urls/{url_id}` (results)
- **File hash:** `GET /files/{hash}` (MD5, SHA256, SHA1)
- **Domain:** `GET /domains/{domain}`
- **IP:** `GET /ip_addresses/{ip}`
- Rate limit: 4 requests/minute (free tier); 1000/day → circuit breaker at 950

### Caching Strategy

```python
# Redis key patterns:
"vt:url:{sha256_of_url}"     → VT URL result    TTL: 24h
"vt:hash:{sha256}"           → VT file result   TTL: 7 days
"vt:domain:{domain}"         → VT domain report TTL: 6h
"whois:{domain}"             → WHOIS result     TTL: 24h
"dns:mx:{domain}"            → MX records       TTL: 1h
"dns:spf:{domain}"           → SPF record       TTL: 1h
```

---

## 11. Infrastructure Security

### Container Security

- All containers run as **non-root** user (UID 1000)
- Read-only root filesystem where possible
- No `--privileged` flag
- Drop all Linux capabilities, add back only required ones
- Docker images scanned by Trivy in CI pipeline

### Network Security (Docker Compose)

```yaml
networks:
  frontend_net:    # API + Frontend only
  backend_net:     # API + Workers + DB + Redis (not exposed externally)
  db_net:          # DB + Workers only (no API direct access)
```

### Production Hardening Checklist

- [ ] WAF with OWASP rule set enabled
- [ ] TLS 1.3 only (1.0/1.1/1.2 disabled)
- [ ] HSTS with `max-age=31536000; includeSubDomains; preload`
- [ ] PostgreSQL `ssl=require` enforced
- [ ] Redis authentication enabled (`requirepass`)
- [ ] Redis TLS transport
- [ ] DB backups encrypted with separate key
- [ ] Container images rebuilt from scratch weekly (patch cadence)

---

## 12. Security Headers

All HTTP responses include:

```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{random}'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' wss://api.example.com; frame-ancestors 'none'
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), microphone=(), camera=()
X-Request-ID: {uuid-v4}
```

**CSP Notes:**
- Inline scripts forbidden (nonce-based where needed)
- No CDN/external script sources (all assets self-hosted)
- `unsafe-eval` is never set
