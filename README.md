# AI-Powered Email Threat Detection & Security Intelligence Platform

Production-ready, multi-layered email security platform leveraging Clean Architecture, rule-based verification (SPF/DKIM/DMARC), ML classification, and Groq LLM-powered narrative threat intelligence.

---

## Architecture & Technology Stack

- **Frontend:** React 18, TypeScript, Vite, Tailwind CSS, TanStack Query, Zustand, Recharts
- **Backend:** Python 3.12+, FastAPI, Pydantic v2, SQLAlchemy 2 (async), Alembic, Redis, Structlog
- **Data & Cache:** PostgreSQL 16, Redis 7
- **AI & Security:** Groq LLM (LLaMA 3.3 70B), ML classifier, SPF/DKIM/DMARC verifiers, URL/Attachment analysis, LLM Safety Gateway
- **Infrastructure:** Docker, Docker Compose, Multi-stage builds

---

## Directory Structure

```
├── ARCHITECTURE.md            # System architecture, clean architecture layers, dependency graph
├── PROJECT_PLAN.md            # 9-week phased implementation plan (M01-M37)
├── API_SPECIFICATION.md       # REST + WebSocket API contracts
├── DATABASE_DESIGN.md         # Full relational schema, DDLs, index strategy, views
├── SECURITY_DESIGN.md         # Defense-in-depth, LLM Safety Gateway, risk scoring formula
├── FRONTEND_ARCHITECTURE.md   # Feature-Sliced Design, state management, charts, accessibility
├── DEVELOPMENT_STANDARDS.md   # Code quality, git workflow, testing, and CI/CD rules
├── docker-compose.yml         # Local development stack (PostgreSQL, Redis, API, Frontend)
├── .env.example               # Root environment template (no secrets)
├── backend/                   # FastAPI backend application
│   ├── app/
│   │   ├── domain/            # Pure domain entities, value objects, exceptions, interfaces
│   │   ├── application/       # Use cases, DTOs, port protocols
│   │   ├── infrastructure/    # Database, cache, logging, config
│   │   └── api/               # FastAPI routers, middleware, schemas, dependencies
│   ├── alembic/               # Database migrations
│   └── tests/                 # Unit & integration test suites
├── frontend/                  # React + TypeScript + Vite SPA
│   └── src/
│       ├── entities/          # Domain models and zod schemas
│       ├── shared/            # Reusable UI, API client, stores, hooks
│       └── pages/             # Route-level pages
├── infra/                     # Infrastructure configurations
└── docs/                      # Architectural Decision Records (ADRs)
```

---

## Getting Started

### Prerequisites

- **Python** 3.12 or higher
- **Node.js** 20 or higher (v22 recommended) with `npm`
- **Docker** and **Docker Compose** (for containerized stack)

### Option 1: Quickstart with Docker Compose

1. Clone repository and create local environment configuration:
   ```bash
   cp .env.example .env
   ```

2. Start the full development stack:
   ```bash
   docker compose up --build
   ```

3. Access services:
   - **Frontend Dashboard:** http://localhost:5173
   - **Backend API Docs:** http://localhost:8000/docs
   - **API Health Check:** http://localhost:8000/api/v1/health

---

### Option 2: Local Development Setup

#### 1. Backend Setup

```bash
cd backend

# Create virtual environment
python -m venv .venv

# Activate virtual environment
# Windows (PowerShell):
.\.venv\Scripts\Activate.ps1
# Linux / macOS:
# source .venv/bin/activate

# Install package in editable mode with development dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/unit/ -v

# Run linter
ruff check app/ tests/

# Run type checker
mypy app/

# Start local API server
uvicorn app.main:app --reload --port 8000
```

#### 2. Frontend Setup

```bash
cd frontend

# Install dependencies
npm install

# Run type check
npm run typecheck

# Run linter
npm run lint

# Run unit tests
npm run test

# Build production bundle
npm run build

# Start development server
npm run dev
```

---

## Health Check Endpoint

`GET /api/v1/health`

Returns liveness and readiness status for the application and its critical dependencies:

```json
{
  "status": "healthy",
  "version": "1.0.0",
  "environment": "development",
  "timestamp": "2026-09-29T09:12:44Z",
  "checks": {
    "database": { "status": "ok" },
    "redis": { "status": "ok" }
  }
}
```

---

## Development Principles & Standards

- **Clean Architecture:** Strict boundary rules — domain entities have zero external dependencies.
- **No Fake Metrics:** All dashboard widgets and telemetry derive from persisted database records.
- **Fail-Safe Risk Scoring:** The `RiskEngine` is the single source of truth for composite risk calculation.
- **LLM Safety Gateway:** Prompts are scrubbed of PII and malicious injection patterns; outputs are schema-validated.
- **Secret Management:** Secrets are never committed; all configuration flows through typed environment variables.
