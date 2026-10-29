# API Specification
## Email Threat Detection & Security Intelligence Platform

> **Version:** v1 | **Base URL:** `https://api.example.com/api/v1` | **Date:** 2026-09-29

---

## Table of Contents

1. [General Conventions](#1-general-conventions)
2. [Authentication](#2-authentication)
3. [Rate Limiting](#3-rate-limiting)
4. [Error Responses](#4-error-responses)
5. [Endpoints — Auth](#5-endpoints--auth)
6. [Endpoints — Emails](#6-endpoints--emails)
7. [Endpoints — Analysis](#7-endpoints--analysis)
8. [Endpoints — Threats](#8-endpoints--threats)
9. [Endpoints — Dashboard](#9-endpoints--dashboard)
10. [Endpoints — Users](#10-endpoints--users)
11. [Endpoints — Health](#11-endpoints--health)
12. [WebSocket API](#12-websocket-api)
13. [Shared Schema Reference](#13-shared-schema-reference)

---

## 1. General Conventions

### Request Format
- Content-Type: `application/json` for all request bodies
- Multipart: `multipart/form-data` for email file uploads
- Dates: ISO 8601 UTC (`2026-09-29T09:12:44Z`)

### Response Format
All responses share a common envelope:

```json
{
  "success": true,
  "data": { ... },
  "meta": {
    "request_id": "uuid-v4",
    "timestamp": "2026-09-29T09:12:44Z",
    "version": "v1"
  }
}
```

Error responses:
```json
{
  "success": false,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Human-readable description",
    "details": [ ... ]
  },
  "meta": { ... }
}
```

### Pagination
All list endpoints support cursor-based pagination:

**Query Parameters:**
| Param | Type | Default | Description |
|---|---|---|---|
| `cursor` | string | null | Opaque cursor from previous response |
| `limit` | integer | 20 | Items per page (max: 100) |
| `sort` | string | `created_at` | Sort field |
| `order` | `asc`\|`desc` | `desc` | Sort direction |

**Response Meta for Lists:**
```json
{
  "pagination": {
    "cursor_next": "base64-encoded-cursor",
    "cursor_prev": "base64-encoded-cursor",
    "has_next": true,
    "has_prev": false,
    "total_count": 1432
  }
}
```

### Versioning
All endpoints are prefixed with `/api/v1`. Breaking changes introduce a new version prefix.

---

## 2. Authentication

### Scheme
JWT Bearer tokens (RS256). Access tokens expire in 15 minutes. Refresh tokens expire in 7 days.

### Headers
```
Authorization: Bearer <access_token>
```

### Permissions (RBAC)

| Role | Permissions |
|---|---|
| `viewer` | Read emails, analyses, threats, dashboard |
| `analyst` | `viewer` + submit emails, annotate threats |
| `admin` | `analyst` + manage users, configure system settings |
| `system` | Internal worker-to-API communications only |

---

## 3. Rate Limiting

Redis sliding-window rate limits, per authenticated user and per IP (unauthenticated).

| Endpoint Group | Authenticated | Unauthenticated |
|---|---|---|
| Auth endpoints | 10 req/min | 5 req/min |
| Email submission | 100 req/hour | N/A |
| Read endpoints | 1000 req/min | N/A |
| Dashboard WebSocket | 1 connection | N/A |

Rate limit headers returned on all responses:
```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 987
X-RateLimit-Reset: 1727597564
```

---

## 4. Error Responses

### Standard Error Codes

| HTTP Status | Code | When |
|---|---|---|
| 400 | `VALIDATION_ERROR` | Request body fails schema validation |
| 401 | `UNAUTHORIZED` | Missing or invalid access token |
| 403 | `FORBIDDEN` | Authenticated but insufficient permissions |
| 404 | `NOT_FOUND` | Resource does not exist |
| 409 | `CONFLICT` | Duplicate resource (e.g., duplicate email hash) |
| 422 | `UNPROCESSABLE` | Semantically invalid input |
| 429 | `RATE_LIMITED` | Rate limit exceeded |
| 500 | `INTERNAL_ERROR` | Unexpected server error |
| 503 | `SERVICE_UNAVAILABLE` | Dependency (DB/Redis) unhealthy |

---

## 5. Endpoints — Auth

### POST /auth/login

Authenticate a user, receive access + refresh tokens.

**Request:**
```json
{
  "email": "analyst@company.com",
  "password": "s3cur3P@ssw0rd"
}
```

**Response 200:**
```json
{
  "success": true,
  "data": {
    "access_token": "eyJ...",
    "refresh_token": "eyJ...",
    "token_type": "Bearer",
    "expires_in": 900,
    "user": {
      "id": "usr_01J...",
      "email": "analyst@company.com",
      "full_name": "Jane Analyst",
      "role": "analyst"
    }
  }
}
```

**Errors:** 401 (invalid credentials), 429 (rate limited)

---

### POST /auth/refresh

Exchange a refresh token for a new access token.

**Request:**
```json
{
  "refresh_token": "eyJ..."
}
```

**Response 200:** Same structure as `/auth/login` (new access + refresh tokens).

**Errors:** 401 (invalid/expired refresh token)

---

### POST /auth/logout

Invalidate the current refresh token (adds to Redis blocklist).

**Request:** No body (uses Authorization header)

**Response 204:** No content.

---

### GET /auth/me

Return the current authenticated user's profile.

**Response 200:**
```json
{
  "success": true,
  "data": {
    "id": "usr_01J...",
    "email": "analyst@company.com",
    "full_name": "Jane Analyst",
    "role": "analyst",
    "created_at": "2026-01-15T10:00:00Z",
    "last_login_at": "2026-09-29T09:00:00Z"
  }
}
```

---

## 6. Endpoints — Emails

### POST /emails

Submit a raw email for analysis. Accepts EML file or structured JSON.

**Permission:** `analyst`

**Request (multipart/form-data):**
| Field | Type | Required | Description |
|---|---|---|---|
| `file` | File (.eml) | One of | Raw EML file |
| `raw_content` | string | One of | Raw email string (MIME format) |
| `source` | string | No | Origin tag: `api`, `imap`, `forward`, etc. |
| `priority` | `low`\|`normal`\|`high` | No | Analysis priority (default: `normal`) |

**Response 202:**
```json
{
  "success": true,
  "data": {
    "email_id": "eml_01J...",
    "status": "queued",
    "message_id": "<abc123@mail.example.com>",
    "subject": "[SUSPECTED PHISH] Urgent account action required",
    "from_address": "security@paypa1.com",
    "received_at": "2026-09-29T09:12:44Z",
    "analysis_id": "anl_01J...",
    "estimated_completion_seconds": 15
  }
}
```

**Errors:** 400 (invalid EML), 409 (duplicate: same `message_id` already processed), 413 (file too large — max 25MB)

---

### GET /emails

List all submitted emails with filtering.

**Permission:** `viewer`

**Query Parameters:**
| Param | Type | Description |
|---|---|---|
| `status` | `queued`\|`analyzing`\|`complete`\|`failed` | Filter by status |
| `risk_level` | `critical`\|`high`\|`medium`\|`low`\|`safe` | Filter by risk level |
| `from_date` | ISO 8601 | Filter submitted after |
| `to_date` | ISO 8601 | Filter submitted before |
| `search` | string | Full-text search on subject/sender |
| `source` | string | Filter by source tag |

**Response 200:**
```json
{
  "success": true,
  "data": [
    {
      "id": "eml_01J...",
      "message_id": "<abc123@mail.example.com>",
      "subject": "[SUSPECTED PHISH] Urgent account action required",
      "from_address": "security@paypa1.com",
      "from_domain": "paypa1.com",
      "received_at": "2026-09-29T09:12:44Z",
      "status": "complete",
      "risk_score": 92,
      "risk_level": "critical",
      "threat_categories": ["phishing", "credential_theft"],
      "analysis_id": "anl_01J..."
    }
  ],
  "meta": {
    "pagination": { ... }
  }
}
```

---

### GET /emails/{email_id}

Retrieve a single email with full details.

**Permission:** `viewer`

**Response 200:**
```json
{
  "success": true,
  "data": {
    "id": "eml_01J...",
    "message_id": "<abc123@mail.example.com>",
    "subject": "[SUSPECTED PHISH] Urgent account action required",
    "from_address": "security@paypa1.com",
    "from_domain": "paypa1.com",
    "to_addresses": ["victim@company.com"],
    "reply_to": null,
    "received_at": "2026-09-29T09:12:44Z",
    "body_preview": "Dear valued customer, your account...",
    "has_attachments": true,
    "attachment_count": 2,
    "source": "api",
    "status": "complete",
    "analysis_id": "anl_01J...",
    "created_at": "2026-09-29T09:12:44Z"
  }
}
```

---

### DELETE /emails/{email_id}

Soft-delete an email record (audit-logged).

**Permission:** `admin`

**Response 204:** No content.

---

## 7. Endpoints — Analysis

### GET /analyses/{analysis_id}

Retrieve the complete analysis result for an email.

**Permission:** `viewer`

**Response 200:**
```json
{
  "success": true,
  "data": {
    "id": "anl_01J...",
    "email_id": "eml_01J...",
    "status": "complete",
    "started_at": "2026-09-29T09:12:45Z",
    "completed_at": "2026-09-29T09:12:58Z",
    "duration_ms": 13200,
    "risk_score": 92,
    "risk_level": "critical",
    "risk_factors": [
      {
        "factor": "spf_fail",
        "weight": 0.25,
        "score": 100,
        "description": "SPF record check failed (no record for sending domain)"
      },
      {
        "factor": "dkim_fail",
        "weight": 0.20,
        "score": 100,
        "description": "DKIM signature absent"
      },
      {
        "factor": "ml_phishing_probability",
        "weight": 0.30,
        "score": 89,
        "description": "ML classifier: 89.3% phishing probability"
      },
      {
        "factor": "url_reputation",
        "weight": 0.15,
        "score": 95,
        "description": "2/3 URLs flagged malicious by VirusTotal"
      },
      {
        "factor": "domain_age",
        "weight": 0.10,
        "score": 100,
        "description": "Sending domain registered 3 days ago"
      }
    ],
    "layers": {
      "header": {
        "status": "complete",
        "spf": "fail",
        "dkim": "none",
        "dmarc": "fail",
        "routing_anomalies": ["unexpected_relay", "timezone_mismatch"],
        "x_mailer": "PHPMailer 6.5.0",
        "auth_results": "spf=fail smtp.mailfrom=paypa1.com"
      },
      "content": {
        "status": "complete",
        "urgency_signals": true,
        "credential_request": true,
        "suspicious_keywords": ["verify account", "limited time", "click here"],
        "language": "en",
        "readability_score": 62
      },
      "urls": {
        "status": "complete",
        "extracted_urls": [
          {
            "url": "https://paypa1.com/secure/verify",
            "expanded_url": "https://185.220.101.12/phish/paypal/login",
            "is_shortened": true,
            "virustotal_positives": 41,
            "virustotal_total": 72,
            "reputation": "malicious",
            "homoglyph_score": 0.87
          }
        ]
      },
      "attachments": {
        "status": "complete",
        "files": [
          {
            "filename": "invoice.pdf",
            "mime_type": "application/pdf",
            "size_bytes": 245760,
            "md5": "abc123...",
            "sha256": "def456...",
            "virustotal_positives": 0,
            "virustotal_total": 72,
            "reputation": "clean"
          }
        ]
      },
      "sender": {
        "status": "complete",
        "domain": "paypa1.com",
        "domain_age_days": 3,
        "mx_valid": false,
        "typosquat_target": "paypal.com",
        "typosquat_confidence": 0.95,
        "whois_registrar": "Namecheap Inc.",
        "whois_country": "RU"
      },
      "ml": {
        "status": "complete",
        "model_version": "v2.3.1",
        "phishing_probability": 0.893,
        "label": "phishing",
        "confidence": 0.893,
        "feature_importance": {
          "url_count": 0.18,
          "urgency_words": 0.15,
          "spf_result": 0.22
        }
      },
      "llm": {
        "status": "complete",
        "model": "llama-3.3-70b-versatile",
        "threat_narrative": "This email exhibits hallmarks of a PayPal credential phishing campaign. The sender domain 'paypa1.com' uses a classic homoglyph substitution (l→1) targeting PayPal customers. The embedded URL redirects to an IP-hosted phishing page with no valid TLS certificate. SPF and DKIM both fail, indicating the email was not sent through legitimate PayPal infrastructure.",
        "threat_categories": ["phishing", "credential_theft", "brand_impersonation"],
        "iocs": [
          { "type": "domain", "value": "paypa1.com", "confidence": 0.97 },
          { "type": "ip", "value": "185.220.101.12", "confidence": 0.91 },
          { "type": "url", "value": "https://185.220.101.12/phish/paypal/login", "confidence": 0.95 }
        ],
        "recommended_action": "quarantine",
        "safety_gateway_passed": true
      }
    }
  }
}
```

---

### GET /analyses

List analyses with filtering.

**Permission:** `viewer`

**Query Parameters:**
| Param | Type | Description |
|---|---|---|
| `status` | string | Filter by analysis status |
| `risk_level` | string | Filter by risk level |
| `from_date` | ISO 8601 | Analyses started after |
| `to_date` | ISO 8601 | Analyses started before |

---

### POST /analyses/{analysis_id}/retry

Retry a failed analysis.

**Permission:** `analyst`

**Response 202:**
```json
{
  "success": true,
  "data": {
    "analysis_id": "anl_01J...",
    "status": "queued"
  }
}
```

---

## 8. Endpoints — Threats

### GET /threats

List all extracted threat indicators (IOCs).

**Permission:** `viewer`

**Query Parameters:**
| Param | Type | Description |
|---|---|---|
| `type` | `domain`\|`ip`\|`url`\|`hash`\|`email` | IOC type filter |
| `min_confidence` | float (0-1) | Minimum confidence threshold |
| `category` | string | Threat category filter |
| `from_date` | ISO 8601 | Seen after date |

**Response 200:**
```json
{
  "success": true,
  "data": [
    {
      "id": "thr_01J...",
      "type": "domain",
      "value": "paypa1.com",
      "confidence": 0.97,
      "categories": ["phishing", "brand_impersonation"],
      "first_seen": "2026-09-29T09:12:58Z",
      "last_seen": "2026-09-29T09:12:58Z",
      "occurrence_count": 1,
      "related_email_ids": ["eml_01J..."],
      "enrichment": {
        "whois_registrar": "Namecheap Inc.",
        "country": "RU",
        "domain_age_days": 3
      }
    }
  ]
}
```

---

### GET /threats/{threat_id}

Retrieve a specific threat indicator with full enrichment.

**Permission:** `viewer`

---

### POST /threats/{threat_id}/annotate

Add analyst annotation to a threat indicator.

**Permission:** `analyst`

**Request:**
```json
{
  "annotation": "Confirmed IOC — part of PayPal phishing campaign Q4-2026",
  "false_positive": false,
  "tags": ["paypal-campaign", "q4-2026"]
}
```

---

## 9. Endpoints — Dashboard

> **Important:** All metrics returned by these endpoints are computed from real persisted data in PostgreSQL. No in-memory counters or cached totals are used except for short-lived (≤60s) Redis caches of expensive aggregation queries.

### GET /dashboard/summary

High-level platform statistics.

**Permission:** `viewer`

**Response 200:**
```json
{
  "success": true,
  "data": {
    "period": "last_7_days",
    "emails_processed": 1432,
    "threats_detected": 87,
    "critical_threats": 12,
    "average_risk_score": 34.2,
    "average_analysis_duration_ms": 11800,
    "false_positive_rate": 0.023,
    "detection_rate": 0.943,
    "top_threat_categories": [
      { "category": "phishing", "count": 54 },
      { "category": "spam", "count": 21 },
      { "category": "malware", "count": 12 }
    ],
    "risk_distribution": {
      "critical": 12,
      "high": 28,
      "medium": 47,
      "low": 156,
      "safe": 1189
    }
  }
}
```

**Query Parameters:**
| Param | Default | Options |
|---|---|---|
| `period` | `last_7_days` | `last_24h`, `last_7_days`, `last_30_days`, `custom` |
| `from_date` | — | ISO 8601 (required if `period=custom`) |
| `to_date` | — | ISO 8601 (required if `period=custom`) |

---

### GET /dashboard/timeline

Time-series threat detection data for charts.

**Permission:** `viewer`

**Response 200:**
```json
{
  "success": true,
  "data": {
    "interval": "1h",
    "series": [
      {
        "timestamp": "2026-09-29T00:00:00Z",
        "emails_submitted": 23,
        "threats_detected": 4,
        "critical_count": 0,
        "average_risk_score": 28.1
      }
    ]
  }
}
```

**Query Parameters:**
| Param | Default | Description |
|---|---|---|
| `period` | `last_24h` | As above |
| `interval` | `1h` | `15m`, `1h`, `6h`, `1d` |

---

### GET /dashboard/top-threats

Top threat domains, IPs, and campaign clusters.

**Permission:** `viewer`

**Response 200:**
```json
{
  "success": true,
  "data": {
    "top_domains": [
      { "domain": "paypa1.com", "count": 14, "max_risk": 94 }
    ],
    "top_ips": [
      { "ip": "185.220.101.12", "count": 8, "max_risk": 92 }
    ],
    "top_categories": [
      { "category": "phishing", "count": 54, "trend": "+12%" }
    ]
  }
}
```

---

## 10. Endpoints — Users

### GET /users

List all users.

**Permission:** `admin`

**Response 200:** List of user objects.

---

### POST /users

Create a new user.

**Permission:** `admin`

**Request:**
```json
{
  "email": "newanalyst@company.com",
  "full_name": "Bob Analyst",
  "role": "analyst",
  "password": "T3mpP@ssw0rd!"
}
```

**Response 201:** Created user object.

---

### GET /users/{user_id}

Get a specific user.

**Permission:** `admin` (or self)

---

### PATCH /users/{user_id}

Update user details or role.

**Permission:** `admin`

**Request:**
```json
{
  "role": "analyst",
  "full_name": "Bob P. Analyst"
}
```

---

### DELETE /users/{user_id}

Deactivate a user account (soft delete; audit logged).

**Permission:** `admin`

**Response 204:** No content.

---

## 11. Endpoints — Health

### GET /health

Liveness + readiness probe.

**Response 200 (healthy):**
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "timestamp": "2026-09-29T09:12:44Z",
  "checks": {
    "database": { "status": "ok", "latency_ms": 3 },
    "redis": { "status": "ok", "latency_ms": 1 },
    "worker": { "status": "ok", "active_tasks": 4 }
  }
}
```

**Response 503 (unhealthy):** Same structure, `status: "degraded"` or `"unhealthy"`, failing check has `"status": "error"`.

---

### GET /metrics

Prometheus-compatible metrics endpoint.

**Response:** `text/plain` in Prometheus exposition format.

---

## 12. WebSocket API

### Connection

```
WSS /ws/live
Authorization: Bearer <access_token>  (query param: ?token=<access_token>)
```

### Client → Server Messages

**Subscribe to channels:**
```json
{
  "type": "subscribe",
  "channels": ["threat_feed", "metrics_update", "alert_stream"]
}
```

**Unsubscribe:**
```json
{
  "type": "unsubscribe",
  "channels": ["metrics_update"]
}
```

**Ping:**
```json
{ "type": "ping" }
```

### Server → Client Messages

**Analysis completed:**
```json
{
  "type": "analysis_completed",
  "channel": "threat_feed",
  "data": {
    "email_id": "eml_01J...",
    "analysis_id": "anl_01J...",
    "risk_level": "critical",
    "risk_score": 92,
    "threat_categories": ["phishing"]
  },
  "timestamp": "2026-09-29T09:12:58Z"
}
```

**Metrics update (every 30s):**
```json
{
  "type": "metrics_update",
  "channel": "metrics_update",
  "data": {
    "emails_last_hour": 47,
    "threats_last_hour": 8,
    "queue_depth": 12,
    "active_workers": 4
  },
  "timestamp": "2026-09-29T09:13:00Z"
}
```

**Alert triggered:**
```json
{
  "type": "alert",
  "channel": "alert_stream",
  "data": {
    "alert_id": "alt_01J...",
    "severity": "critical",
    "message": "Critical phishing campaign detected: 5 emails from paypa1.com in last 60 minutes",
    "related_email_ids": ["eml_01J..."]
  },
  "timestamp": "2026-09-29T09:12:59Z"
}
```

**Error:**
```json
{
  "type": "error",
  "code": "CHANNEL_NOT_FOUND",
  "message": "Channel 'unknown_channel' does not exist"
}
```

---

## 13. Shared Schema Reference

### RiskLevel Enum
`critical` | `high` | `medium` | `low` | `safe`

### RiskScore
Integer 0–100 (0 = clean, 100 = confirmed threat)

### AnalysisStatus Enum
`queued` | `analyzing` | `complete` | `failed` | `skipped`

### ThreatCategory Enum
`phishing` | `malware` | `spam` | `credential_theft` | `brand_impersonation` | `business_email_compromise` | `ransomware` | `social_engineering` | `unknown`

### IOCType Enum
`domain` | `ip` | `url` | `hash_md5` | `hash_sha256` | `email_address`

### UserRole Enum
`viewer` | `analyst` | `admin`
