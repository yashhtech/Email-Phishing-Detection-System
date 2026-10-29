# Email Threat Detection & Security Intelligence Platform
## System Architecture

> **Version:** 1.0.0 | **Status:** Design Phase | **Date:** 2026-09-29

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Architectural Principles](#2-architectural-principles)
3. [High-Level Architecture](#3-high-level-architecture)
4. [Layer Definitions](#4-layer-definitions)
5. [Module Boundaries & Responsibilities](#5-module-boundaries--responsibilities)
6. [Dependency Graph](#6-dependency-graph)
7. [Data Flow](#7-data-flow)
8. [Infrastructure Topology](#8-infrastructure-topology)
9. [Technology Decisions](#9-technology-decisions)
10. [Cross-Cutting Concerns](#10-cross-cutting-concerns)

---

## 1. System Overview

The **Email Threat Detection & Security Intelligence Platform** is a production-grade, AI-augmented security system that ingests, analyzes, and classifies email messages for phishing, malware, spoofing, and social-engineering threats. It combines rule-based security analysis (SPF/DKIM/DMARC, header forensics, URL reputation) with ML classification and Groq LLM-powered narrative threat intelligence, surfaced through a real-time React dashboard.

### Core Capabilities

| Capability | Description |
|---|---|
| Email Ingestion | REST API + IMAP polling + webhook receivers |
| Multi-layer Analysis | Header, body, attachment, URL, sender reputation |
| ML Classification | Trained classifier for phishing probability score |
| LLM Threat Intelligence | Groq-powered structured threat narrative and IOC extraction |
| Risk Scoring Engine | Composite risk score aggregated from all analysis layers |
| Real-time Dashboard | WebSocket-pushed metrics from persisted data only |
| Audit Trail | Immutable audit log for all analysis events |
| Threat Intelligence Feed | Integration with external TI providers |

---

## 2. Architectural Principles

### 2.1 Clean Architecture

All modules follow a strict **dependency inversion** policy:

```
Domain (innermost) → Application → Infrastructure (outermost)
```

- Domain layer has **zero** external dependencies.
- Application layer depends only on Domain.
- Infrastructure (DB, Redis, Groq, external APIs) depends on Application abstractions.

### 2.2 Single Responsibility

Each module owns **one** cohesive slice of behavior. Business logic is never duplicated across modules—shared logic lives in the Domain layer only.

### 2.3 Ports & Adapters (Hexagonal)

All external I/O (database, cache, email providers, AI providers, threat intel feeds) is accessed only through **interfaces (ports)** defined in the Application layer. Concrete implementations (adapters) live in the Infrastructure layer and are injected at runtime.

### 2.4 No Fake Metrics

Dashboard metrics are derived exclusively from persisted records in PostgreSQL. No in-memory counters, hardcoded values, or mock data are exposed in production builds.

### 2.5 Fail-Safe Security

Security analysis failures are logged and surfaced but **never silently swallowed**. A failed analysis raises the risk score, not lowers it.

---

## 3. High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         CLIENT TIER                             │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │           React + TypeScript + Vite (SPA)                │  │
│  │   Dashboard │ Email Viewer │ Threat Intel │ Settings      │  │
│  │   WebSocket Client │ REST API Client │ Auth (JWT)        │  │
│  └─────────────────────────┬────────────────────────────────┘  │
└────────────────────────────│────────────────────────────────────┘
                             │ HTTPS / WSS
┌────────────────────────────▼────────────────────────────────────┐
│                         API GATEWAY TIER                        │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │         FastAPI Application (Python 3.12)                │  │
│  │  Auth Middleware │ Rate Limiter │ Audit Logger            │  │
│  │  REST Routers    │ WebSocket Hub │ LLM Safety Gateway    │  │
│  └──────┬─────────────────────┬──────────────────────────────┘  │
└─────────│─────────────────────│───────────────────────────────── ┘
          │ Sync RPC             │ Async Task Dispatch
┌─────────▼─────────┐   ┌───────▼──────────────────────────────┐
│  BUSINESS LOGIC   │   │       WORKER TIER                    │
│  (Application     │   │                                      │
│   Services)       │   │  ┌─────────────────────────────────┐ │
│                   │   │  │ Analysis Orchestrator (Celery)   │ │
│  - EmailService   │   │  │  - HeaderAnalysisWorker          │ │
│  - AnalysisService│   │  │  - URLAnalysisWorker             │ │
│  - RiskEngine     │   │  │  - AttachmentWorker              │ │
│  - ThreatIntel    │   │  │  - MLClassifierWorker            │ │
│  - AlertService   │   │  │  - LLMAnalysisWorker             │ │
└─────────┬─────────┘   │  │  - RiskAggregatorWorker          │ │
          │             │  └─────────────────────────────────┘ │
          │             └──────────────────────────────────────┘
┌─────────▼──────────────────────────────────────────────────────┐
│                      DATA TIER                                 │
│                                                                │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────────┐  │
│  │  PostgreSQL  │  │    Redis     │  │  Object Storage    │  │
│  │  (primary)   │  │  (cache +    │  │  (attachments,     │  │
│  │              │  │   queues +   │  │   raw email EML)   │  │
│  │  - emails    │  │   sessions + │  │                    │  │
│  │  - analyses  │  │   rate limit)│  └────────────────────┘  │
│  │  - threats   │  └──────────────┘                          │
│  │  - audit_log │                                            │
│  │  - users     │                                            │
│  └──────────────┘                                            │
└────────────────────────────────────────────────────────────────┘
┌────────────────────────────────────────────────────────────────┐
│                    EXTERNAL PROVIDERS                          │
│                                                                │
│  Groq LLM API │ VirusTotal │ WHOIS │ DNS-over-HTTPS │ IMAP   │
└────────────────────────────────────────────────────────────────┘
```

---

## 4. Layer Definitions

### 4.1 Domain Layer (`backend/app/domain/`)

**What lives here:** Pure Python entities, value objects, domain events, domain exceptions. Zero imports from any framework or library beyond the Python standard library.

| Module | Contents |
|---|---|
| `entities/email.py` | `Email`, `EmailAddress`, `EmailHeader` entities |
| `entities/analysis.py` | `AnalysisResult`, `AnalysisLayer`, `AnalysisStatus` |
| `entities/threat.py` | `ThreatIndicator`, `IOC`, `ThreatCategory` |
| `entities/risk.py` | `RiskScore`, `RiskLevel`, `RiskFactor` |
| `entities/user.py` | `User`, `Role`, `Permission` |
| `entities/audit.py` | `AuditEvent`, `AuditAction` |
| `value_objects/` | `URL`, `IPAddress`, `HashDigest`, `SenderIdentity` |
| `events/` | `EmailSubmitted`, `AnalysisCompleted`, `ThreatDetected` |
| `exceptions/` | `DomainException`, `InvalidEmailError`, `AnalysisError` |
| `interfaces/` | Abstract repository interfaces (ports) |

### 4.2 Application Layer (`backend/app/application/`)

**What lives here:** Use cases, application services, DTOs, command/query objects. Depends only on Domain.

| Module | Contents |
|---|---|
| `services/email_service.py` | Submit, retrieve, list emails |
| `services/analysis_service.py` | Orchestrate full analysis pipeline |
| `services/risk_engine.py` | Aggregate sub-scores into composite risk score |
| `services/threat_intel_service.py` | Query and cache threat intel |
| `services/alert_service.py` | Emit alerts based on thresholds |
| `services/user_service.py` | User management, role assignment |
| `services/audit_service.py` | Write immutable audit events |
| `use_cases/` | Single-responsibility use case handlers |
| `dtos/` | Pydantic DTOs for cross-layer communication |
| `ports/` | Abstract interfaces for infra adapters |

### 4.3 Infrastructure Layer (`backend/app/infrastructure/`)

**What lives here:** All I/O adapters. Implements ports defined in Application. Framework-coupled code lives only here.

| Module | Contents |
|---|---|
| `db/models/` | SQLAlchemy ORM models |
| `db/repositories/` | Concrete repository implementations |
| `db/migrations/` | Alembic migration scripts |
| `cache/redis_client.py` | Redis adapter |
| `cache/session_store.py` | JWT session management |
| `workers/celery_app.py` | Celery worker bootstrap |
| `workers/tasks/` | Individual Celery task definitions |
| `ai/ml_classifier.py` | Scikit-learn model adapter |
| `ai/groq_client.py` | Groq API adapter |
| `ai/llm_safety_gateway.py` | LLM output validation/sanitization |
| `security/spf_checker.py` | SPF verification adapter |
| `security/dkim_verifier.py` | DKIM verification adapter |
| `security/dmarc_checker.py` | DMARC policy adapter |
| `security/url_analyzer.py` | URL reputation + expansion |
| `security/header_analyzer.py` | Email header forensics |
| `security/attachment_scanner.py` | Attachment hash + type analysis |
| `threat_intel/virustotal.py` | VirusTotal API adapter |
| `threat_intel/whois_client.py` | WHOIS domain lookup |
| `threat_intel/dns_client.py` | DNS resolution (DoH) |
| `email_providers/imap_poller.py` | IMAP inbox polling |
| `email_providers/smtp_parser.py` | Raw EML parser |
| `notifications/websocket_hub.py` | WebSocket broadcast |

### 4.4 API Layer (`backend/app/api/`)

**What lives here:** FastAPI routers, request/response schemas, middleware, dependency injection setup. No business logic—delegates to Application services.

| Module | Contents |
|---|---|
| `routers/emails.py` | Email CRUD + submission endpoints |
| `routers/analysis.py` | Analysis trigger + results |
| `routers/threats.py` | Threat indicator management |
| `routers/dashboard.py` | Aggregated dashboard metrics |
| `routers/users.py` | User management |
| `routers/auth.py` | Login, logout, token refresh |
| `routers/websocket.py` | WebSocket connection manager |
| `routers/health.py` | Health check + readiness |
| `middleware/auth.py` | JWT validation middleware |
| `middleware/rate_limit.py` | Redis-backed rate limiter |
| `middleware/audit.py` | Request audit logging |
| `middleware/cors.py` | CORS configuration |
| `schemas/` | Pydantic request/response models |
| `dependencies.py` | FastAPI `Depends()` factory functions |

---

## 5. Module Boundaries & Responsibilities

### 5.1 Strict Dependency Rules

```
API → Application → Domain
Infrastructure → Application → Domain
Workers → Application → Domain
API ✗→ Infrastructure (never direct)
Workers ✗→ API (never direct)
Domain ✗→ anything external
```

### 5.2 Module Ownership Matrix

| Module | Owner Layer | Can Import From | Cannot Import From |
|---|---|---|---|
| `domain/` | Domain | stdlib only | Everything else |
| `application/services/` | Application | `domain/`, stdlib | `api/`, `infrastructure/` |
| `application/ports/` | Application | `domain/` | `infrastructure/` |
| `infrastructure/db/` | Infrastructure | `application/ports/`, `domain/` | `api/` |
| `infrastructure/ai/` | Infrastructure | `application/ports/`, `domain/` | `api/` |
| `infrastructure/security/` | Infrastructure | `application/ports/`, `domain/` | `api/` |
| `api/routers/` | API | `application/services/`, `api/schemas/` | `infrastructure/` |
| `api/middleware/` | API | `application/ports/`, `domain/` | `infrastructure/` (via DI) |
| `workers/tasks/` | Infrastructure | `application/services/` | `api/` |

### 5.3 Risk Engine — Single Source of Truth

The `RiskEngine` in `application/services/risk_engine.py` is the **only** place where sub-scores are aggregated into a composite `RiskScore`. No other module computes or modifies the final score.

### 5.4 LLM Safety Gateway

All output from Groq LLM passes through `infrastructure/ai/llm_safety_gateway.py` before being persisted or returned. This gateway validates:
- Output schema conformance (Pydantic)
- Hallucination guard (confidence thresholds)
- PII / sensitive data scrubbing
- Token budget enforcement

---

## 6. Dependency Graph

```
                    ┌─────────────────────────────────────┐
                    │           DOMAIN LAYER               │
                    │  entities/ value_objects/ events/    │
                    │  interfaces/ (abstract ports)        │
                    └──────────┬──────────────────────────┘
                               │ (all arrows point inward)
            ┌──────────────────┼──────────────────────┐
            │                  │                      │
  ┌─────────▼──────┐  ┌────────▼────────┐  ┌─────────▼──────┐
  │  APPLICATION   │  │ APPLICATION     │  │ APPLICATION    │
  │  services/     │  │ use_cases/      │  │ dtos/          │
  │  risk_engine   │  │                 │  │ ports/         │
  └─────────┬──────┘  └────────┬────────┘  └─────────┬──────┘
            │                  │                      │
  ┌─────────▼──────────────────▼──────────────────────▼──────┐
  │                    INFRASTRUCTURE LAYER                   │
  │  db/ cache/ workers/ ai/ security/ threat_intel/          │
  │  email_providers/ notifications/                          │
  └───────────────────────────┬───────────────────────────────┘
                              │
                    ┌─────────▼──────────┐
                    │     API LAYER      │
                    │  routers/ schemas/ │
                    │  middleware/       │
                    └────────────────────┘
```

---

## 7. Data Flow

### 7.1 Email Submission & Analysis Pipeline

```
[Client] ──POST /api/v1/emails──► [API Router]
                                        │
                              [Auth Middleware]
                                        │
                              [Rate Limit Middleware]
                                        │
                              [EmailService.submit()]
                                        │
                           ┌────────────▼────────────┐
                           │  Persist Email (DB)      │
                           │  Store raw EML (object   │
                           │  storage)                │
                           │  Emit EmailSubmitted evt │
                           └────────────┬────────────┘
                                        │ Enqueue
                           ┌────────────▼────────────┐
                           │  Analysis Orchestrator   │
                           │  (Celery chord)          │
                           │                          │
                           │  ┌──────────────────┐   │
                           │  │HeaderAnalysis     │   │
                           │  │URLAnalysis        │◄──┤ Parallel
                           │  │AttachmentAnalysis │   │ Workers
                           │  │SenderReputation   │   │
                           │  │MLClassification   │   │
                           │  └──────────────────┘   │
                           │          │               │
                           │  ┌───────▼──────────┐   │
                           │  │LLM Analysis       │   │
                           │  │(Groq + Safety GW) │   │
                           │  └───────┬──────────┘   │
                           │          │               │
                           │  ┌───────▼──────────┐   │
                           │  │Risk Aggregation   │   │
                           │  │(RiskEngine)       │   │
                           │  └───────┬──────────┘   │
                           └──────────│───────────────┘
                                      │
                           ┌──────────▼──────────────┐
                           │  Persist AnalysisResult  │
                           │  Write AuditEvent        │
                           │  WebSocket push          │
                           │  Alert evaluation        │
                           └─────────────────────────┘
```

### 7.2 Dashboard Data Flow

```
[Client WebSocket] ──connect──► [WebSocket Hub]
                                      │
                              Subscribe to channels:
                              - threat_feed
                              - metrics_update
                              - alert_stream

[Background Scheduler] ──every 30s──► [Dashboard Metrics Query]
                                             │
                                    SELECT aggregated data
                                    FROM analyses, emails,
                                         threats, audit_log
                                    (PostgreSQL views)
                                             │
                                    Push to WebSocket Hub ──► [All connected clients]
```

---

## 8. Infrastructure Topology

### 8.1 Local Development (Docker Compose)

```
docker-compose.yml
├── api          (FastAPI, port 8000)
├── worker       (Celery workers, concurrency 4)
├── beat         (Celery beat scheduler)
├── flower       (Celery monitoring, port 5555)
├── postgres     (PostgreSQL 16, port 5432)
├── redis        (Redis 7, port 6379)
├── frontend     (Vite dev server, port 5173)
└── mailhog      (SMTP/IMAP test server, port 8025)
```

### 8.2 Production Topology

```
Internet ──► CDN/WAF ──► Load Balancer
                              │
                    ┌─────────┴─────────┐
                    │                   │
               [API Pod 1]         [API Pod 2]
                    │                   │
                    └─────────┬─────────┘
                              │
          ┌───────────────────┼───────────────────┐
          │                   │                   │
    [Worker Pod 1]     [Worker Pod 2]      [Beat Pod]
          │                   │
          └─────────┬─────────┘
                    │
       ┌────────────┼────────────┐
       │            │            │
  [PostgreSQL]  [Redis]    [Object Store]
  (managed)    (managed)   (S3/GCS/Minio)
```

---

## 9. Technology Decisions

### 9.1 Backend

| Decision | Choice | Rationale |
|---|---|---|
| Framework | FastAPI | Async-native, OpenAPI auto-gen, Pydantic v2 integration |
| ORM | SQLAlchemy 2.x | Async support, migration ecosystem |
| Migrations | Alembic | Industry standard, SQLAlchemy native |
| Task Queue | Celery + Redis | Mature, reliable, excellent monitoring (Flower) |
| Cache/Sessions | Redis | Atomic operations, TTL, pub/sub for WebSocket fanout |
| LLM Provider | Groq | Low-latency inference, structured output support |
| ML Runtime | scikit-learn + joblib | Lightweight, serializable, production-ready |

### 9.2 Frontend

| Decision | Choice | Rationale |
|---|---|---|
| Framework | React 18 | Concurrent features, ecosystem maturity |
| Language | TypeScript | Type safety, IDE support |
| Build Tool | Vite | Fast HMR, ESM-native |
| State | Zustand | Lightweight, no boilerplate |
| Charts | Recharts | React-native, composable |
| HTTP Client | Axios + React Query | Caching, retry, background refetch |
| WebSocket | native + custom hook | Avoid over-engineering |
| Styling | Tailwind CSS | Utility-first, design system friendly |
| Components | shadcn/ui | Accessible, headless, composable |

### 9.3 Security

| Decision | Choice | Rationale |
|---|---|---|
| Auth | JWT (RS256) + refresh tokens | Stateless, asymmetric keys |
| Password hashing | Argon2id | OWASP recommended |
| Secrets | Environment variables + Vault-ready | 12-factor, production portable |
| Rate limiting | Redis sliding window | Accurate, distributed |
| HTTPS | TLS 1.3 enforced | Modern cipher suites only |

---

## 10. Cross-Cutting Concerns

### 10.1 Logging

- Structured JSON logs via `structlog`
- Correlation ID propagated across all layers and workers
- Log levels: DEBUG (dev), INFO (staging), WARNING+ (prod)
- No PII in logs (emails redacted to domain only)

### 10.2 Observability

- Health endpoint: `GET /health` (liveness + readiness)
- Metrics endpoint: `GET /metrics` (Prometheus-compatible)
- Distributed tracing: OpenTelemetry-ready (trace IDs in logs)

### 10.3 Error Handling

- Domain exceptions map to HTTP status codes via exception handlers
- All 5xx errors trigger audit log entries
- Worker failures trigger dead-letter queue processing

### 10.4 Configuration

- `pydantic-settings` for typed config with validation
- Environment-specific config: `.env.local`, `.env.staging`, `.env.production`
- No secrets in source control — `.env.example` documents required variables
