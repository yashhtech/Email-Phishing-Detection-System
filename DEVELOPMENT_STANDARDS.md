# Development Standards
## Email Threat Detection & Security Intelligence Platform

> **Version:** 1.0.0 | **Applies to:** All contributors | **Date:** 2026-09-29

---

## Table of Contents

1. [Code Organization Standards](#1-code-organization-standards)
2. [Python Backend Standards](#2-python-backend-standards)
3. [TypeScript Frontend Standards](#3-typescript-frontend-standards)
4. [Git Workflow](#4-git-workflow)
5. [Testing Standards](#5-testing-standards)
6. [Documentation Standards](#6-documentation-standards)
7. [API Design Standards](#7-api-design-standards)
8. [Security Development Standards](#8-security-development-standards)
9. [Environment & Configuration Standards](#9-environment--configuration-standards)
10. [PR & Review Standards](#10-pr--review-standards)
11. [Toolchain Enforcement](#11-toolchain-enforcement)

---

## 1. Code Organization Standards

### 1.1 Module Boundary Enforcement

**Rule: Never cross module boundaries in the wrong direction.**

The dependency rule is absolute:

```
✅ ALLOWED:
  API → Application Services
  Application Services → Domain
  Infrastructure Adapters → Application Ports
  Workers → Application Services

❌ NEVER:
  Domain → anything with external dependencies
  Application → Infrastructure (always via injected port)
  API → Infrastructure directly
  Workers → API
  Feature A → Feature B (frontend)
```

Violations are caught by import linting rules (see §11).

### 1.2 Single Responsibility

Each module, class, and function has exactly one reason to change.

- A module that does both "analyze SPF" and "analyze DKIM" is two modules.
- A service that both persists data and sends notifications is violating SRP.
- Exception: Use cases may orchestrate multiple domain operations — that is their single responsibility.

### 1.3 No Duplicate Business Logic

Before adding logic to a new location, search the codebase. If logic exists:
- **In domain:** Use it as-is.
- **In another service:** Extract to domain or a shared utility — never copy.
- **In infra:** If it belongs in domain, move it. Never duplicate.

---

## 2. Python Backend Standards

### 2.1 Language & Runtime

- Python **3.12+** minimum.
- Use `uv` for dependency management (`pyproject.toml`).
- All production dependencies pinned to exact versions in `uv.lock`.
- Type annotations **required** on all public functions and class attributes.

### 2.2 Type Safety

```python
# ✅ Correct — all arguments and return type annotated
async def get_email_by_id(email_id: str) -> Email | None:
    ...

# ❌ Wrong — no return type, no argument types
async def get_email(id):
    ...
```

- `mypy` runs in strict mode on all `domain/` and `application/` modules.
- `mypy` runs in standard mode on `infrastructure/` and `api/`.
- `pyright` is the secondary type checker (IDE integration).

### 2.3 Pydantic Models

- Use **Pydantic v2** with `model_config = ConfigDict(strict=True)` on all schemas.
- API request/response models are separate from domain entities and from ORM models.
- Never use `dict` for structured data crossing module boundaries — always a typed Pydantic model or dataclass.

```python
# ✅ Separate models for each concern:
class EmailSubmitRequest(BaseModel):      # API input schema
    ...
class Email(BaseModel):                   # Domain entity
    ...
class EmailORM(Base):                     # SQLAlchemy ORM model
    ...
class EmailSummaryResponse(BaseModel):    # API output schema
    ...
```

### 2.4 Async Patterns

- All FastAPI route handlers are `async def`.
- All SQLAlchemy queries use the async session (`AsyncSession`).
- Celery tasks are **synchronous** (Celery doesn't support async natively in production without workarounds — use `asyncio.run()` only if needed).
- Never `await` inside a Celery task — offload async operations to synchronous equivalents.
- Never block the event loop: use `asyncio.get_event_loop().run_in_executor()` for CPU-bound operations inside async code.

### 2.5 Error Handling

```python
# Domain exceptions — informative, no traceback exposure to client
class EmailNotFoundError(DomainException):
    def __init__(self, email_id: str):
        super().__init__(f"Email {email_id} not found", code="EMAIL_NOT_FOUND")

# FastAPI exception handler maps domain exceptions to HTTP responses
@app.exception_handler(DomainException)
async def domain_exception_handler(request: Request, exc: DomainException) -> JSONResponse:
    return JSONResponse(
        status_code=exc.http_status,
        content={"success": False, "error": {"code": exc.code, "message": exc.message}}
    )
```

**Rules:**
- Never `raise Exception(...)` — always a typed domain or application exception.
- Never expose internal stack traces to API responses.
- Log all 5xx-level errors with `logger.exception(...)` (includes traceback in log, not response).
- Catch specific exceptions — never bare `except:` or `except Exception:`.

### 2.6 Logging

```python
import structlog

logger = structlog.get_logger(__name__)

# ✅ Correct — structured key-value context
logger.info("email_submitted", email_id=email.id, source=email.source, from_domain=email.from_domain)

# ❌ Wrong — string interpolation, no structure
logger.info(f"Email {email.id} submitted from {email.from_address}")
```

- Log level **DEBUG:** internal state useful for development.
- Log level **INFO:** significant domain events (email submitted, analysis completed).
- Log level **WARNING:** expected error conditions (rate limited, external API failure with fallback).
- Log level **ERROR:** unexpected failures requiring investigation.
- **Never log:** passwords, tokens, full email bodies, PII (redact to domain level).

### 2.7 Database Access

- Never write raw SQL with user input. Always use SQLAlchemy ORM or `text()` with bound parameters.
- All DB access goes through repository classes — never `session.execute()` directly in services.
- Transactions are managed at the application service layer (not repository layer).
- Use `selectinload` / `joinedload` for eager loading — never N+1 queries.

```python
# ✅ Repository pattern
class EmailRepository:
    async def find_by_id(self, email_id: str) -> Email | None:
        result = await self.session.execute(
            select(EmailORM).where(EmailORM.id == email_id)
        )
        return result.scalar_one_or_none()

# ❌ Never in application service
async def get_email(self, email_id: str):
    result = await self.session.execute(...)  # direct DB access in service
```

### 2.8 Code Style

Tool: `ruff` (replaces black + isort + flake8)

```toml
# pyproject.toml
[tool.ruff]
line-length = 100
target-version = "py312"

[tool.ruff.lint]
select = ["E", "F", "W", "I", "N", "UP", "B", "A", "C4", "DTZ", "T20", "RUF"]
ignore = ["E501"]  # line length handled by formatter
```

- Max line length: 100 characters.
- Imports: stdlib → third-party → local (enforced by `ruff I` rules).
- No unused imports.
- No `print()` statements in application code (use `logger`).
- Docstrings on all public classes and functions (Google format).

---

## 3. TypeScript Frontend Standards

### 3.1 TypeScript Configuration

```json
// tsconfig.json
{
  "compilerOptions": {
    "strict": true,
    "noUncheckedIndexedAccess": true,
    "noImplicitReturns": true,
    "exactOptionalPropertyTypes": true,
    "noFallthroughCasesInSwitch": true
  }
}
```

- **No `any`** — use `unknown` and narrow types explicitly.
- **No non-null assertions (`!`)** unless accompanied by a comment explaining why it's safe.
- **No type assertions (`as T`)** on API response data — use Zod validation instead.

### 3.2 Component Standards

```typescript
// ✅ Correct: named export, typed props, no implicit any
interface EmailListItemProps {
  email: EmailSummary;
  onSelect: (id: string) => void;
}

export function EmailListItem({ email, onSelect }: EmailListItemProps) {
  // ...
}

// ❌ Wrong: default export, untyped props, implicit any
export default function EmailListItem(props: any) { ... }
```

- Use **named exports** for all components (no default exports) — enables better tree-shaking and refactoring.
- Component props interfaces defined directly above the component.
- No prop types via `React.FC<Props>` — use plain function signature.

### 3.3 API Data Validation

All data from the API is validated with Zod schemas at the boundary:

```typescript
// entities/email.ts
import { z } from 'zod';

export const EmailSummarySchema = z.object({
  id: z.string(),
  subject: z.string().nullable(),
  fromAddress: z.string(),
  riskLevel: z.enum(['critical', 'high', 'medium', 'low', 'safe']),
  riskScore: z.number().min(0).max(100),
  status: z.enum(['queued', 'analyzing', 'complete', 'failed']),
  receivedAt: z.string().datetime(),
});

export type EmailSummary = z.infer<typeof EmailSummarySchema>;

// shared/api/emails.api.ts — parse at API boundary
const response = await apiClient.get('/emails');
return PaginatedResponseSchema(EmailSummarySchema).parse(response.data);
```

### 3.4 Hooks Standards

- Custom hooks prefixed with `use`.
- Hooks encapsulate a single concern — no "god hooks".
- Return objects (not tuples) from hooks with more than 2 values.
- Hooks in `features/*/hooks/` may call React Query; hooks in `shared/hooks/` may not call feature-specific APIs.

### 3.5 Code Style

Tool: ESLint + Prettier

```json
// .eslintrc
{
  "rules": {
    "no-console": "error",
    "no-debugger": "error",
    "@typescript-eslint/no-explicit-any": "error",
    "@typescript-eslint/consistent-type-imports": "error",
    "import/no-cycle": "error"  // enforces FSD dependency direction
  }
}
```

- Max line length: 100 characters (Prettier).
- Single quotes for strings.
- Trailing commas in multi-line structures.
- No `console.log` in application code (use a proper logger utility).

---

## 4. Git Workflow

### 4.1 Branch Naming

| Type | Pattern | Example |
|---|---|---|
| Feature | `feature/<ticket>-<short-desc>` | `feature/EP-42-spf-verifier` |
| Bug fix | `fix/<ticket>-<short-desc>` | `fix/EP-87-analysis-timeout` |
| Hotfix | `hotfix/<ticket>-<short-desc>` | `hotfix/EP-91-auth-bypass` |
| Refactor | `refactor/<short-desc>` | `refactor/risk-engine-extract` |
| Chore | `chore/<short-desc>` | `chore/update-dependencies` |

### 4.2 Commit Messages (Conventional Commits)

Format: `<type>(<scope>): <short description>`

```
feat(analysis): add DKIM signature verification engine
fix(api): return 409 on duplicate message-id submission
refactor(risk-engine): extract URL scoring to separate method
test(email-service): add tests for EML parser edge cases
docs(api): update analysis endpoint response schema
chore(deps): bump groq-sdk to 0.11.0
```

**Types:** `feat`, `fix`, `refactor`, `test`, `docs`, `chore`, `perf`, `ci`

**Rules:**
- Subject line ≤ 72 characters
- Imperative mood ("add", not "added" or "adds")
- Reference ticket number in body: `Refs: EP-42`
- Breaking changes: `BREAKING CHANGE:` in commit footer

### 4.3 Commit Scope

| Scope | Area |
|---|---|
| `domain` | Domain entities and value objects |
| `analysis` | Analysis engines |
| `risk-engine` | Risk scoring |
| `api` | FastAPI routes/middleware |
| `worker` | Celery tasks |
| `db` | Database models/migrations |
| `ai` | ML/LLM components |
| `dashboard` | Frontend dashboard |
| `emails` | Frontend email feature |
| `auth` | Authentication |
| `infra` | Docker/CI/CD |

---

## 5. Testing Standards

### 5.1 Test File Location

```
# Backend: tests mirror source structure
backend/tests/
├── unit/
│   ├── domain/
│   │   └── test_risk_score.py          # tests for domain/entities/risk.py
│   ├── application/
│   │   └── test_risk_engine.py
│   └── infrastructure/
│       └── test_spf_checker.py
├── integration/
│   ├── test_email_submission_pipeline.py
│   └── test_websocket_events.py
└── fixtures/
    ├── emails/
    │   ├── phishing_simple.eml
    │   ├── spf_fail.eml
    │   └── clean_legitimate.eml
    └── conftest.py

# Frontend: co-located with source
frontend/src/features/emails/__tests__/EmailList.test.tsx
frontend/src/shared/hooks/__tests__/useWebSocket.test.ts
frontend/e2e/dashboard.spec.ts
```

### 5.2 Test Naming

```python
# Pattern: test_<what>_<condition>_<expected_result>
def test_risk_engine_spf_fail_returns_high_score():
    ...

def test_email_service_duplicate_message_id_raises_conflict():
    ...
```

### 5.3 Test Quality Rules

- **No test-specific code in production.** No `if settings.TESTING:` branches.
- **Tests are independent.** No shared mutable state between tests. Use fixtures.
- **Tests are deterministic.** No `time.sleep()`, no random data without seeded random.
- **Mock at the right boundary.** Mock infrastructure adapters, not domain logic.
- **Test happy path AND error paths.** Each exception in domain/application must have a test.

### 5.4 Coverage Requirements

| Layer | Minimum Coverage |
|---|---|
| `domain/` | 95% |
| `application/services/` | 90% |
| `application/use_cases/` | 90% |
| `infrastructure/security/` | 85% |
| `infrastructure/ai/` | 80% |
| `api/routers/` | 80% |
| `frontend/features/` | 80% |
| `frontend/shared/ui/` | 100% |

---

## 6. Documentation Standards

### 6.1 Code Documentation

```python
class RiskEngine:
    """Aggregates analysis layer sub-scores into a composite risk score.

    This is the single source of truth for risk computation. No other module
    should compute or modify the final RiskScore.

    The scoring model is documented in SECURITY_DESIGN.md §5.
    """

    def compute(self, sub_results: SubAnalysisResults) -> RiskScore:
        """Compute composite risk score from all analysis layer results.

        Args:
            sub_results: Aggregated results from all analysis workers.
                         Failed layers receive a penalty score (75) rather
                         than being excluded, ensuring security posture
                         errs on the side of caution.

        Returns:
            RiskScore with composite score (0-100), level, and per-factor breakdown.

        Raises:
            InsufficientDataError: If fewer than 3 analysis layers have results.
        """
```

### 6.2 Architecture Decision Records (ADRs)

Significant technical decisions are documented in `docs/adr/`:

```
docs/adr/
├── 0001-use-celery-for-async-analysis.md
├── 0002-jsonb-for-analysis-layer-results.md
├── 0003-jwt-rs256-over-hs256.md
└── template.md
```

ADR template:
```markdown
# ADR-NNNN: Title

## Status
Accepted | Superseded by ADR-XXXX

## Context
Why is this decision needed?

## Decision
What did we decide?

## Consequences
What are the trade-offs?
```

### 6.3 OpenAPI Documentation

- All FastAPI endpoints have `summary`, `description`, and `response_model`.
- All Pydantic models used in the API have `model_config = ConfigDict(json_schema_extra={"example": {...}})`.
- OpenAPI spec is auto-generated and validated in CI.

---

## 7. API Design Standards

### 7.1 RESTful Resource Naming

- Resources are plural nouns: `/emails`, `/analyses`, `/threats`, `/users`
- Sub-resources: `/emails/{id}/analysis`, `/threats/{id}/annotations`
- Actions on resources (non-CRUD): POST to action sub-resource: `POST /analyses/{id}/retry`
- No verbs in URL paths: ❌ `/getEmails`, ❌ `/submitEmail`

### 7.2 HTTP Methods

| Method | Use | Response |
|---|---|---|
| GET | Read resource(s) | 200 OK |
| POST | Create resource or trigger action | 201 Created or 202 Accepted |
| PUT | Full replace | 200 OK |
| PATCH | Partial update | 200 OK |
| DELETE | Delete | 204 No Content |

### 7.3 Status Codes

Use precise status codes — not just 200 and 500:

| Situation | Code |
|---|---|
| Created synchronously | 201 |
| Accepted for async processing | 202 |
| No content on delete | 204 |
| Bad input format | 400 |
| Missing/invalid auth | 401 |
| Insufficient permissions | 403 |
| Resource not found | 404 |
| Duplicate resource | 409 |
| Unprocessable entity | 422 |
| Rate limited | 429 |

### 7.4 Pagination

Always paginate lists. Never return unbounded arrays. Use cursor-based pagination (not offset) to handle concurrent inserts correctly.

---

## 8. Security Development Standards

### 8.1 Input Handling

- **Validate first, use second.** Never use input before it has been validated by Pydantic.
- **Parameterized queries always.** Never build SQL strings with user data.
- **Allowlist > Blocklist.** When filtering inputs, define what is allowed (not what is blocked).

### 8.2 Secrets in Code

- **Zero tolerance for secrets in source code.** `.env`, config files, hardcoded strings — all forbidden.
- Pre-commit hook runs `detect-secrets` scan on every commit.
- If a secret is accidentally committed: rotate it immediately, then remove from git history.

### 8.3 Dependencies

- All new dependencies require security review before merging:
  - Check CVE history
  - Check maintenance status (last commit date, open issues)
  - Prefer well-established packages over convenience packages
- `pip audit` and `npm audit` run in CI.
- Dependabot / Renovate configured for automated patch-level updates.

### 8.4 LLM-Specific Security

- Email content is **always sanitized** before being included in LLM prompts (see SECURITY_DESIGN.md §4).
- LLM outputs are **never directly persisted** without passing through the Safety Gateway.
- Prompt templates are version-controlled, not dynamically generated from user input.

---

## 9. Environment & Configuration Standards

### 9.1 12-Factor App Compliance

All configuration comes from environment variables. No environment-specific config files in the codebase (only `.env.example`).

### 9.2 Configuration Validation

All environment variables are typed and validated at application startup using `pydantic-settings`:

```python
class Settings(BaseSettings):
    # Database
    database_url: PostgresDsn
    # Redis
    redis_url: RedisDsn
    # JWT
    jwt_private_key: str  # base64 PEM
    jwt_algorithm: Literal["RS256"] = "RS256"
    access_token_expire_minutes: int = Field(default=15, ge=5, le=60)
    # Groq
    groq_api_key: SecretStr
    groq_model: str = "llama-3.3-70b-versatile"
    # App
    app_env: Literal["development", "staging", "production"]
    allowed_origins: list[str]
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    debug: bool = False

    model_config = ConfigDict(env_file=".env", case_sensitive=False)
```

If any required variable is missing or invalid, the application **fails to start** with a clear error message. No partial startup with missing configuration.

### 9.3 No `DEBUG=True` in Production

`app_env=production` automatically sets:
- `debug=False`
- `log_level=WARNING`
- Stricter CORS
- No OpenAPI docs endpoint (`/docs`, `/redoc` disabled)

---

## 10. PR & Review Standards

### 10.1 PR Requirements

Before requesting review, the author must:
- [ ] All CI checks pass (lint, type check, tests)
- [ ] PR description explains **why**, not just **what**
- [ ] Breaking changes documented in PR description
- [ ] New public APIs have documentation and tests
- [ ] No `TODO: fix later` without a linked issue
- [ ] Self-reviewed diff before requesting review

### 10.2 PR Size Guideline

| PR Scope | Max Diff Lines |
|---|---|
| Focused feature or fix | ~400 |
| Medium feature | ~800 |
| Large feature (needs justification) | ~1500 |
| Refactor | Unlimited (but no behavior change) |

Large PRs should be split into stacked PRs.

### 10.3 Review Standards

Reviewers must check:
- **Correctness:** Does this solve the stated problem correctly?
- **Module boundaries:** Does this respect the dependency rules?
- **Security:** Any new attack surface? Secrets? Input validation?
- **Test coverage:** Are edge cases and error paths tested?
- **Performance:** N+1 queries? Blocking calls in async code?
- **Documentation:** Are public APIs documented?

Review approval required from at least **1 other engineer** for all PRs to `main`.

---

## 11. Toolchain Enforcement

### 11.1 Pre-commit Hooks (`.pre-commit-config.yaml`)

```yaml
repos:
  - repo: https://github.com/astral-sh/ruff-pre-commit
    hooks:
      - id: ruff           # lint
      - id: ruff-format    # format

  - repo: https://github.com/pre-commit/mirrors-mypy
    hooks:
      - id: mypy

  - repo: https://github.com/Yelp/detect-secrets
    hooks:
      - id: detect-secrets # catch accidental secret commits

  - repo: https://github.com/pre-commit/pre-commit-hooks
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml
      - id: check-merge-conflict
      - id: no-commit-to-branch
        args: ['--branch', 'main']

  # Frontend
  - repo: local
    hooks:
      - id: eslint
        name: ESLint
        entry: npm run lint
        language: system
        types: [typescript]
      - id: prettier
        name: Prettier
        entry: npm run format:check
        language: system
```

### 11.2 CI Enforcement Matrix

| Check | Tool | Blocks Merge? |
|---|---|---|
| Python linting | `ruff` | Yes |
| Python type check | `mypy` | Yes |
| Python security | `bandit` | Yes (on HIGH severity) |
| Python tests | `pytest --cov` | Yes |
| Frontend linting | `eslint` | Yes |
| Frontend type check | `tsc --noEmit` | Yes |
| Frontend tests | `vitest` | Yes |
| Dependency audit | `pip audit` + `npm audit` | Yes (on CRITICAL) |
| Secret scan | `detect-secrets` | Yes |
| Docker image scan | `trivy` | Yes (on CRITICAL) |
| Integration tests | `pytest (integration)` | Yes |
| E2E tests | `playwright` | Yes (on main branch) |

### 11.3 `Makefile` Targets

```makefile
# Convenience targets — run locally before pushing

make lint          # ruff + eslint
make typecheck     # mypy + tsc
make test          # pytest unit + vitest
make test-int      # pytest integration (requires Docker)
make test-e2e      # Playwright (requires running stack)
make format        # ruff-format + prettier
make audit         # pip audit + npm audit
make check         # lint + typecheck + test (run all checks)
```
