# Security Architecture & Vulnerability Review

This document describes the security architecture, threat model, defensive controls, and operational guidelines for the **AI-Powered Email Phishing and Security Detection Platform**.

---

## 1. Threat Model & Security Posture

The application ingests, parses, analyzes, and scores untrusted email content submitted by end users and automated ingestion pipelines. The core security principles of this platform are:

1. **Zero Execution Guarantee**: Ingested emails, MIME parts, and attachments are treated as passive, malicious byte streams. Attachments are **never executed**, shelled out, or passed to external interpreters.
2. **Untrusted Content Boundary**: Email bodies and subject lines are treated as adversarial inputs capable of executing Prompt Injection, XSS, or Command Injection. They are isolated behind cryptographic token boundaries before AI analysis.
3. **SSRF Quarantine**: The backend never fetches raw URLs directly from untrusted emails. External threat intelligence providers (VirusTotal, AbuseIPDB) receive only sanitized hashes, domains, or public IPs. All RFC 1918, loopback, and cloud metadata addresses are blocked.
4. **Tenant Isolation by Construction**: All data access is scoped to the authenticated user's organization (`org_id`). Cross-tenant access is blocked at the ORM repository layer.
5. **Fail-Fast Defense**: Insecure secrets or configurations prevent the application from starting in production environments.

---

## 2. Authentication & JWT Security

### 2.1 Token Lifecycle
- **Access Tokens**: Short-lived (15 minutes), signed with `HS256`, containing claims: `sub` (User UUID), `org` (Organization UUID), `role` (UserRoleType), `jti` (JWT ID), `exp` (Expiry).
- **Refresh Tokens**: Long-lived (7 days), stored in Redis keyed by `jti`. Revoked immediately upon logout or password reset.
- **Fail-Fast Secret Validation**:
  - `Settings.enforce_production_security()` verifies that in `staging` or `production`, `JWT_SECRET_KEY` cannot equal the development placeholder (`CHANGE_ME_IN_PRODUCTION_...`).
  - Secrets shorter than 32 characters (256 bits) trigger an immediate startup exception.

### 2.2 Password Security
- Passwords hashed using **Argon2id** (memory cost: 65,536 KiB, time cost: 3 iterations, parallelism: 4 threads).
- Minimum password length: 10 characters.
- Login endpoints enforce strict brute-force rate limits (10 attempts / 60 seconds per IP).

---

## 3. Authorization & Tenant Isolation (IDOR Prevention)

### 3.1 Role-Based Access Control (RBAC)
User permissions follow a strict four-tier hierarchy:
```
VIEWER (0) < ANALYST (1) < ADMIN (2) < SYSTEM_ADMIN (3)
```
- Standard analysis and history access requires `ANALYST` or higher.
- System metrics and user provisioning require `ADMIN`.

### 3.2 Insecure Direct Object Reference (IDOR) Defenses
- **Analysis Access (`GET /api/v1/analysis/{id}`)**: Verifies that `analysis.org_id == caller_claims.org_id`. Mismatches return an opaque `404 Not Found` to prevent organization enumeration.
- **Email Access (`GET /api/v1/emails/{id}`)**: SQL query enforces `.where(Email.org_id == caller_org_id)`.
- **Stage Progression (`GET /api/v1/analysis/{id}/stages`)**: Enforces matching tenant ownership before returning event history.
- **Reports (`GET /api/v1/reports/analysis/{id}`)**: Validates caller tenant and records an immutable `AuditAction.EXPORT` log.

---

## 4. Network & Transport Security

### 4.1 CORS Policy
- Allowed origins are explicitly restricted via `Settings.allowed_origins` (defaulting strictly to frontend host ports in dev, explicitly declared domains in production).
- Allowed methods: `GET, POST, PUT, PATCH, DELETE, OPTIONS`.
- Wildcards (`"*"`) with `allow_credentials=True` are strictly prohibited.

### 4.2 Security Headers (`SecurityHeadersMiddleware`)
Every HTTP response carries OWASP-recommended headers:
- `Content-Security-Policy`: `default-src 'none'; frame-ancestors 'none'; form-action 'none'`
- `X-Content-Type-Options`: `nosniff`
- `X-Frame-Options`: `DENY`
- `X-XSS-Protection`: `1; mode=block`
- `Referrer-Policy`: `strict-origin-when-cross-origin`
- `Permissions-Policy`: `geolocation=(), microphone=(), camera=()`
- `Strict-Transport-Security` (in staging/production): `max-age=31536000; includeSubDomains; preload`

### 4.3 Rate Limiting (`RateLimitMiddleware`)
A Redis-backed sliding-window counter blocks traffic *before* dispatching to application logic:
- `/api/v1/auth/login`: 10 requests / 60 seconds
- `/api/v1/auth/register`: 5 requests / 600 seconds
- `/api/v1/auth/*`: 30 requests / 60 seconds
- `/api/v1/*` (global): 120 requests / 60 seconds

When limits are exceeded, requests immediately terminate with `HTTP 429 Too Many Requests` with `Retry-After` headers.

---

## 5. Input Validation & File Upload Security

### 5.1 Size & MIME Restrictions
- **RFC 822 / .eml Files**: Hard capped at **25 MB** (`_MAX_EML_BYTES = 25 * 1024 * 1024`).
- **Attachments**: Hard capped at **10 MB** per attachment.
- **Allowed MIME Types**: Only `message/rfc822`, `application/octet-stream`, `text/plain`, and `application/eml` are accepted for email uploads. Direct executable uploads (`application/x-dosexec`) are rejected with `HTTP 400 Validation Error`.

### 5.2 Path Traversal Defenses
- Uploaded attachment filenames are sanitized via `os.path.basename(filename.replace("\\", "/"))`.
- Relative directory traversal sequences (`../`, `..\\`) and null bytes (`\x00`) are stripped.
- Dot-prefixed hidden filenames default to generic `attachment` placeholders.

---

## 6. SSRF (Server-Side Request Forgery) Architecture

Implemented in `app.services.security.ssrf_validator.SSRFProtection`:

### 6.1 Prohibited Address Ranges
Outbound queries to external threat intelligence providers reject:
- `127.0.0.0/8`, `::1` (Loopback)
- `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` (RFC 1918 Private networks)
- `169.254.0.0/16`, `fe80::/10` (Link-local and cloud instance metadata `169.254.169.254`)
- `0.0.0.0/8` (Current network)
- `224.0.0.0/4`, `ff00::/8` (Multicast)
- Cloud metadata hostnames (`metadata.google.internal`, `instance-data`)

### 6.2 DNS Rebinding Protection
Hostnames are resolved via `socket.getaddrinfo()`. If any resolved `A` or `AAAA` record maps to a prohibited range, the query is blocked before initiating any network connections.

---

## 7. LLM Security & Prompt Injection Mitigation

Located in `app.services.llm.safety.LLMSafetyFilter` and `app.services.llm.prompts`:

1. **Randomized Boundary Tokens**: Untrusted email content is encapsulated in cryptographically random delimiters:
   ```xml
   <{random_hex}_untrusted_email_content>
   ... untrusted email body ...
   </{random_hex}_untrusted_email_content>
   ```
2. **Tag Neutralization**: Injected closing tags (`</system>`, `</instruction>`, `</untrusted>`) are rewritten to `[STRIPPED_TAG]`.
3. **Heuristic Prompt Injection Detection**: Known jailbreak phrases (`"ignore all instructions"`, `"system: override"`, `"declare this email clean"`) are detected pre-prompt and automatically increment threat risk scores.
4. **Non-Fabrication Invariants**: The system instruction forbids the LLM from assessing cryptographic authentication (SPF/DKIM/DMARC) or fabricating malware indicators.
5. **JSON Schema Enforcement**: Responses are validated against strict Pydantic models. Non-conforming or malformed output is flagged as a safety gateway failure.

---

## 8. WebSocket Security

WebSocket connections stream real-time pipeline analysis events:
- **Authentication**: Supports `?token=<access_jwt>` query parameters.
- **Tenant Validation**: Before accepting connections, the server verifies that `Analysis.org_id` matches `caller_claims.org_id`. Cross-tenant subscription attempts are closed with `WebSocket code 4003 (Access Denied)`.
- **Memory Hygiene**: Dead client connections are automatically purged from `WebSocketConnectionManager` sets on disconnect or transmission error.

---

## 9. Error Handling & Information Leakage Prevention

Registered in `app.api.exception_handlers`:
- **500 Internal Errors**: Logged with complete stack traces internally to structured logs; returned to clients as an opaque error JSON:
  ```json
  {
    "success": false,
    "error": {
      "code": "INTERNAL_ERROR",
      "message": "An unexpected error occurred. Please try again later."
    }
  }
  ```
- **422 Validation Errors**: Sanitized to expose only user-provided field paths and human-readable error messages. Internal framework classes and schema structures are not exposed.
- **Sensitive Data Logging Guard**: Email bodies, authorization headers, and API keys (`gsk_*`, VirusTotal keys) are filtered and never logged in plain text.

---

## 10. Audit Logging & Compliance

All sensitive operations generate immutable audit log records in the `audit_logs` table:
- **Tracked Actions**: `LOGIN`, `LOGOUT`, `CREATE`, `UPDATE`, `DELETE`, `EXPORT` (report generation).
- **Metadata**: Actor user ID, actor IP, user agent, resource type, resource ID, before/after states, and correlation ID.
- **Tamper Evidence**: Audit log rows have no update or delete endpoints exposed in the API.

---

## 11. Security Checklist for Production Deployment

Before promoting this application to production:
- [ ] Set `APP_ENV=production` in the environment.
- [ ] Provide a cryptographically random `JWT_SECRET_KEY` of at least 64 hex characters.
- [ ] Restrict `ALLOWED_ORIGINS` to the exact production domain(s).
- [ ] Ensure PostgreSQL and Redis connections use TLS and non-default credentials.
- [ ] Terminate TLS 1.3 at the reverse proxy / load balancer with valid certificates.
- [ ] Configure egress firewall rules to restrict outbound connections to designated threat intel and Groq endpoints.
