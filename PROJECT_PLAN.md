# Project Implementation Plan
## Email Threat Detection & Security Intelligence Platform

> **Version:** 1.0.0 | **Status:** Planning | **Date:** 2026-09-29

---

## Table of Contents

1. [Implementation Philosophy](#1-implementation-philosophy)
2. [Module Dependency Map](#2-module-dependency-map)
3. [Phase Breakdown](#3-phase-breakdown)
4. [Milestone Definitions](#4-milestone-definitions)
5. [Task Registry](#5-task-registry)
6. [Risk Register](#6-risk-register)
7. [Testing Strategy](#7-testing-strategy)
8. [CI/CD Pipeline Design](#8-cicd-pipeline-design)

---

## 1. Implementation Philosophy

### Build Order Constraints

The following hard dependencies dictate build order. A task **cannot start** until all its listed prerequisites are complete.

```
Domain Entities
    └─► Application Ports (interfaces)
            └─► Infrastructure Adapters
                    └─► Application Services
                            └─► API Layer
                                    └─► Frontend
```

Worker tasks can be developed in parallel with the API layer once Application Services exist.

### No Fake Data Rule

- All dashboard widgets reference real DB aggregates from day one
- Seed scripts (`scripts/seed_dev.py`) populate the DB with **realistic synthetic data** for development
- No hardcoded metric returns anywhere in application code

### Incremental Security

Security controls are implemented from Phase 1. They are not retrofitted at the end.

---

## 2. Module Dependency Map

```
ID   Module                              Depends On
---  ----------------------------------  -----------------------------------------------
M01  Domain Entities & Value Objects     (none — foundation)
M02  Application Ports (Interfaces)      M01
M03  Database Models (SQLAlchemy)        M01
M04  Alembic Migration Setup             M03
M05  Repository Implementations         M02, M03, M04
M06  Redis Cache Adapter                 M02
M07  Celery Worker Bootstrap             M06
M08  Email Parser (SMTP/EML)             M01
M09  Header Analysis Engine              M01, M08
M10  SPF/DKIM/DMARC Checker             M01, M08
M11  URL Analyzer                        M01, M02
M12  Attachment Scanner                  M01, M02
M13  Sender/Domain Reputation            M01, M02, M11
M14  Threat Intel Adapters (VT/WHOIS)    M02, M11, M13
M15  ML Classifier Adapter               M02
M16  Groq LLM Client                     M02
M17  LLM Safety Gateway                  M16
M18  Application Services (core)         M02, M05, M06
M19  Risk Engine                         M18, M09-M15
M20  Analysis Orchestrator (Celery)      M07, M09-M17, M18
M21  Alert Service                       M18, M19
M22  Audit Service                       M02, M05
M23  WebSocket Hub                       M06
M24  Auth Middleware                     M02, M05, M06
M25  Rate Limit Middleware               M06
M26  API Routers                         M18, M19, M21, M22, M23, M24, M25
M27  Frontend Scaffold                   (none — parallel)
M28  Frontend Auth & State               M27
M29  Frontend API Client                 M27, M26
M30  Dashboard Components                M28, M29, M23
M31  Email Detail View                   M28, M29
M32  Threat Feed View                    M28, M29
M33  Settings & User Management          M28, M29
M34  Docker Compose Stack                M03-M07, M26
M35  CI/CD Pipeline                      M34
M36  Integration Tests                   M26, M20
M37  E2E Tests                           M30-M33
```

---

## 3. Phase Breakdown

### Phase 0 — Foundation (Week 1)
**Goal:** Repository structure, tooling, local environment up and running.

| Task | Module | Output |
|---|---|---|
| Initialize monorepo structure | — | `/backend`, `/frontend`, `/infrastructure` dirs |
| Python project setup (uv/pip) | — | `pyproject.toml`, virtual env |
| Frontend scaffold (Vite+React+TS) | M27 | Working `npm run dev` |
| Docker Compose skeleton | M34 | All services start (empty APIs) |
| Pre-commit hooks (ruff, mypy, prettier, eslint) | — | Code quality gate |
| Environment config system | — | `pydantic-settings`, `.env.example` |
| Domain entities (Email, Analysis, Threat, Risk, User, Audit) | M01 | All domain models with unit tests |
| Application ports (repository + service interfaces) | M02 | ABCs and protocols |

**Milestone 0:** `docker compose up` starts all containers; domain tests pass.

---

### Phase 1 — Data Layer (Week 2)
**Goal:** PostgreSQL schema live, migrations running, repositories tested.

| Task | Module | Output |
|---|---|---|
| SQLAlchemy models (all tables) | M03 | ORM models matching domain entities |
| Alembic baseline migration | M04 | Initial schema in DB |
| Repository implementations | M05 | CRUD for Email, Analysis, Threat, User, Audit |
| Repository unit tests (pytest + test DB) | M05 | ≥90% coverage |
| Redis adapter | M06 | Set/get/expire/pub-sub wrapper |
| Session store (JWT + Redis) | M24 | Token issue, verify, revoke |
| Seed script | — | 500 synthetic emails + analyses in dev DB |

**Milestone 1:** Database populated with seed data; all repository tests pass.

---

### Phase 2 — Security Engines (Week 3)
**Goal:** All security analysis engines implemented and unit-tested in isolation.

| Task | Module | Output |
|---|---|---|
| EML/SMTP parser | M08 | Structured `EmailMessage` from raw bytes |
| Header analysis engine | M09 | Route hops, header forgery detection, encoding anomalies |
| SPF verifier | M10 | Pass/Fail/SoftFail/Neutral/None |
| DKIM verifier | M10 | Signature validity, key alignment |
| DMARC checker | M10 | Policy evaluation (none/quarantine/reject) |
| URL extractor & expander | M11 | Unshorten, decode encoded URLs |
| URL reputation lookup | M11 | VirusTotal URL check, homoglyph detection |
| Attachment scanner | M12 | MIME type, hash (MD5/SHA256), VT lookup |
| Sender/domain reputation | M13 | Domain age, MX record validation, typosquat detection |
| Threat Intel adapters | M14 | VirusTotal, WHOIS, DNS-over-HTTPS |

**Milestone 2:** All security engines tested against RFC-compliant and adversarial email fixtures.

---

### Phase 3 — AI Layer (Week 4)
**Goal:** ML classifier and Groq LLM pipeline operational.

| Task | Module | Output |
|---|---|---|
| ML training pipeline (offline, scripts/) | M15 | Trained model artifact (`.joblib`) |
| ML classifier adapter | M15 | `predict(email) → (label, confidence)` |
| Groq client adapter | M16 | Structured API wrapper with retry + timeout |
| LLM prompt templates | M16 | Versioned prompts in `prompts/` directory |
| LLM Safety Gateway | M17 | Schema validation, PII scrub, confidence gate |
| Groq structured output schema | M17 | `ThreatNarrative` Pydantic model |
| AI adapter tests (mocked Groq API) | M15-M17 | Contract tests |

**Milestone 3:** Full AI pipeline runs end-to-end on sample emails with mocked LLM.

---

### Phase 4 — Application Services & Workers (Week 5)
**Goal:** Full analysis pipeline orchestrated through Celery workers.

| Task | Module | Output |
|---|---|---|
| EmailService | M18 | Submit, retrieve, list, update status |
| AnalysisService | M18 | Trigger, poll, retrieve analyses |
| Risk Engine | M19 | Composite score from all layer sub-scores |
| Alert Service | M21 | Threshold-based alert creation |
| Audit Service | M22 | Immutable audit event writes |
| Celery worker bootstrap | M07 | Worker process with all queues |
| Analysis Orchestrator | M20 | Celery chord: parallel engines → risk aggregation |
| WebSocket Hub | M23 | Broadcast analysis completion events |

**Milestone 4:** Submit email via CLI script → workers process → results in DB → WebSocket fires.

---

### Phase 5 — API Layer (Week 6)
**Goal:** Full REST + WebSocket API live, authenticated, rate-limited.

| Task | Module | Output |
|---|---|---|
| Auth router (login/logout/refresh) | M26 | JWT-based auth |
| User management router | M26 | CRUD with RBAC |
| Email submission router | M26 | POST /emails, GET /emails, GET /emails/{id} |
| Analysis router | M26 | GET /analyses, GET /analyses/{id} |
| Threats router | M26 | GET /threats, GET /threats/{id} |
| Dashboard metrics router | M26 | GET /dashboard (real DB aggregates) |
| WebSocket endpoint | M26 | ws://host/ws/live |
| Auth middleware | M24 | JWT validation on all protected routes |
| Rate limit middleware | M25 | Per-user + per-IP Redis sliding window |
| Audit middleware | M22 | Log every state-changing request |
| Health check endpoint | M26 | GET /health (DB + Redis ping) |
| OpenAPI spec validation | — | All endpoints documented |

**Milestone 5:** All endpoints tested via pytest + httpx; OpenAPI spec complete.

---

### Phase 6 — Frontend (Week 7-8)
**Goal:** Fully functional React dashboard consuming live API.

| Task | Module | Output |
|---|---|---|
| Frontend auth flow | M28 | Login page, JWT storage, route guards |
| API client (Axios + React Query) | M29 | Typed API client matching OpenAPI spec |
| WebSocket hook | M29 | `useWebSocket()` custom hook |
| Dashboard layout | M30 | Sidebar, header, main content area |
| Dashboard metrics widgets | M30 | Real data: threat counts, risk distribution, timeline |
| Threat timeline chart | M30 | Recharts line chart from real data |
| Risk distribution chart | M30 | Recharts pie/donut from real data |
| Email list view | M31 | Sortable, filterable, paginated |
| Email detail view | M31 | Full analysis report per email |
| Threat indicators panel | M32 | IOC list with threat intel enrichment |
| Live threat feed | M32 | WebSocket-driven real-time stream |
| User management UI | M33 | Admin CRUD + role assignment |
| Settings panel | M33 | API keys, thresholds, notifications |
| Responsive design (mobile/tablet) | M27-M33 | Tailwind breakpoints |
| Accessibility audit | M27-M33 | WCAG 2.1 AA compliance |

**Milestone 6:** Frontend communicates with live API; all dashboard widgets show real data.

---

### Phase 7 — Hardening & Production Readiness (Week 9)
**Goal:** Production-ready deployment with CI/CD, monitoring, and full test coverage.

| Task | Module | Output |
|---|---|---|
| Integration test suite | M36 | Full pipeline tests against test DB |
| E2E tests (Playwright) | M37 | Critical user flows automated |
| Docker production images (multi-stage) | M34 | Minimal, hardened images |
| CI/CD pipeline | M35 | GitHub Actions: lint→test→build→push |
| Secret management review | — | All secrets via env vars, no hardcoded values |
| HTTPS/TLS configuration | — | Nginx/Traefik config |
| Security headers | — | HSTS, CSP, X-Frame-Options |
| Log aggregation config | — | JSON logs to stdout (12-factor) |
| Prometheus metrics | — | `/metrics` endpoint |
| Load test | — | k6 script, API stable at 100 concurrent users |

**Milestone 7:** All tests green in CI; production deployment documented.

---

## 4. Milestone Definitions

| # | Milestone | Acceptance Criteria |
|---|---|---|
| M0 | Foundation | Docker Compose starts all services; domain entity tests pass; pre-commit hooks active |
| M1 | Data Layer | All DB migrations run; repository tests ≥90% coverage; seed data loaded |
| M2 | Security Engines | All security engines tested against adversarial email fixtures; all return structured domain objects |
| M3 | AI Layer | End-to-end: raw email → ML score → LLM narrative (mocked provider) returns validated `ThreatNarrative` |
| M4 | Worker Pipeline | Submit email → Celery processes → DB contains complete `AnalysisResult`; WebSocket event fires |
| M5 | API Layer | All endpoints return correct responses; auth/rate limit enforce; OpenAPI spec complete |
| M6 | Frontend | All dashboard widgets display real data from API; no mock/placeholder values |
| M7 | Production | CI pipeline green; load test passes; security headers scored A on securityheaders.com |

---

## 5. Task Registry

See individual phase tables above. All tasks should be tracked in the project issue tracker with:
- Phase label
- Module reference (M01–M37)
- Definition of Done linked to Milestone acceptance criteria

---

## 6. Risk Register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Groq API rate limits under load | Medium | High | Implement exponential backoff + caching of LLM results per email hash |
| ML model accuracy on novel phishing | High | High | Regular retraining pipeline; LLM as fallback for low-confidence predictions |
| PostgreSQL performance on large email corpus | Medium | Medium | Index strategy defined in DB design; query plans reviewed before production |
| Redis memory exhaustion from large attachments | Low | High | Attachments go to object storage, never Redis; enforce Redis maxmemory policy |
| WebSocket scaling beyond single API instance | Medium | Medium | Redis pub/sub fanout design supports horizontal API scaling |
| False positives causing legitimate email blocks | Medium | High | Configurable thresholds; human review queue for high-confidence FPs |
| DKIM key rotation by senders breaking verification | Low | Low | Log as advisory; don't fail hard on DKIM mismatches alone |
| LLM prompt injection via malicious email content | Medium | High | LLM Safety Gateway sanitizes email content before LLM prompt construction |

---

## 7. Testing Strategy

### Unit Tests
- Location: `backend/tests/unit/`
- Coverage target: ≥90% for domain and application layers; ≥80% for infrastructure
- Tools: `pytest`, `pytest-asyncio`, `pytest-cov`
- Mocking strategy: `unittest.mock` + `respx` for HTTP, custom fixtures for DB

### Integration Tests
- Location: `backend/tests/integration/`
- Use: Real PostgreSQL + Redis (via Docker Compose `test` profile)
- Coverage: Full pipeline from API call → DB state → WebSocket event
- Tools: `pytest`, `httpx`, `pytest-asyncio`

### Frontend Tests
- Location: `frontend/src/__tests__/`
- Unit: `vitest` + `@testing-library/react`
- E2E: `Playwright` against running dev stack

### Security Tests
- OWASP ZAP scan against staging API
- `bandit` static analysis on Python codebase
- `npm audit` for frontend dependencies
- Dependency vulnerability scanning in CI (Dependabot / Trivy)

### Performance Tests
- Tool: `k6`
- Target: 100 concurrent users, p99 < 500ms for all read endpoints
- Target: Email submission pipeline complete within 30s end-to-end

---

## 8. CI/CD Pipeline Design

```
┌──────────────────────────────────────────────────────┐
│                  GitHub Actions                       │
│                                                      │
│  Trigger: PR / push to main                          │
│                                                      │
│  ┌─────────┐  ┌─────────┐  ┌──────────┐             │
│  │  Lint   │  │  Type   │  │ Security │  (parallel)  │
│  │ (ruff,  │  │  Check  │  │  Scan    │             │
│  │ eslint) │  │ (mypy,  │  │ (bandit, │             │
│  │         │  │  tsc)   │  │  trivy)  │             │
│  └────┬────┘  └────┬────┘  └────┬─────┘             │
│       └────────────┼────────────┘                    │
│                    ▼                                  │
│  ┌─────────────────────────────────────────────┐    │
│  │          Unit Tests (pytest + vitest)        │    │
│  └─────────────────────┬───────────────────────┘    │
│                        ▼                             │
│  ┌─────────────────────────────────────────────┐    │
│  │   Integration Tests (docker compose test)    │    │
│  └─────────────────────┬───────────────────────┘    │
│                        ▼                             │
│  ┌─────────────────────────────────────────────┐    │
│  │       Build Docker Images (multi-stage)      │    │
│  └─────────────────────┬───────────────────────┘    │
│                        ▼                             │
│  ┌─────────────────────────────────────────────┐    │
│  │  E2E Tests (Playwright against built stack)  │    │
│  └─────────────────────┬───────────────────────┘    │
│                        ▼                             │
│  ┌─────────────────────────────────────────────┐    │
│  │     Push to Container Registry (main only)   │    │
│  └─────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────┘
```

### Branch Strategy
- `main` — production-ready, protected, requires PR + all checks passing
- `develop` — integration branch
- `feature/*` — individual feature branches
- `hotfix/*` — emergency fixes branched from main
