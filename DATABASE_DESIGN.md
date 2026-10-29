# Database Design
## Email Threat Detection & Security Intelligence Platform

> **Version:** 1.0.0 | **Engine:** PostgreSQL 16 | **ORM:** SQLAlchemy 2.x | **Migrations:** Alembic

---

## Table of Contents

1. [Design Principles](#1-design-principles)
2. [Entity-Relationship Diagram](#2-entity-relationship-diagram)
3. [Table Definitions](#3-table-definitions)
4. [Index Strategy](#4-index-strategy)
5. [Query Patterns & Optimization](#5-query-patterns--optimization)
6. [PostgreSQL Views](#6-postgresql-views)
7. [Partitioning Strategy](#7-partitioning-strategy)
8. [Migration Policy](#8-migration-policy)
9. [Data Retention Policy](#9-data-retention-policy)

---

## 1. Design Principles

- **Immutability:** Audit events are append-only — no UPDATE or DELETE ever runs on `audit_log`.
- **Soft Deletes:** User-facing records use `deleted_at TIMESTAMPTZ` rather than hard deletes, preserving referential integrity.
- **ID Strategy:** All primary keys use `ULID` (lexicographically sortable, globally unique, URL-safe). Stored as `CHAR(26)`.
- **Timestamps:** All tables have `created_at` and `updated_at` (`TIMESTAMPTZ NOT NULL DEFAULT NOW()`).
- **No Business Logic in DB:** Stored procedures are not used. All business logic lives in the application layer. The DB provides storage, indexing, and aggregation only.
- **Schema Prefix:** All tables live in the `threat_platform` schema (non-default, prevents collisions).
- **Normalization:** Third Normal Form (3NF) with deliberate denormalization only where proven necessary for read performance (e.g., `risk_score` cached on `emails`).

---

## 2. Entity-Relationship Diagram

```
┌────────────────────┐         ┌──────────────────────────┐
│       users        │         │          emails           │
│────────────────────│         │──────────────────────────│
│ id (PK)            │         │ id (PK)                  │
│ email (UNIQUE)     │         │ message_id (UNIQUE)      │
│ full_name          │         │ subject                  │
│ hashed_password    │         │ from_address             │
│ role               │    ┌───►│ from_domain              │
│ is_active          │    │    │ to_addresses (JSONB)     │
│ created_at         │    │    │ reply_to                 │
│ updated_at         │    │    │ received_at              │
│ last_login_at      │    │    │ raw_eml_path             │
│ deleted_at         │    │    │ body_preview             │
└─────────┬──────────┘    │    │ has_attachments          │
          │               │    │ attachment_count         │
          │               │    │ source                   │
          │               │    │ priority                 │
          │               │    │ status                   │
          │               │    │ risk_score (denorm)      │
          │               │    │ risk_level (denorm)      │
          │               │    │ submitted_by_user_id (FK)│
          │               │    │ created_at               │
          │               │    │ updated_at               │
          │               │    │ deleted_at               │
          │               │    └──────────┬───────────────┘
          │               │               │ 1:1
          │               │    ┌──────────▼───────────────┐
          │               │    │        analyses           │
          │               │    │──────────────────────────│
          │               │    │ id (PK)                  │
          │               │    │ email_id (FK, UNIQUE)    │
          │               │    │ status                   │
          │               │    │ started_at               │
          │               │    │ completed_at             │
          │               │    │ duration_ms              │
          │               │    │ risk_score               │
          │               │    │ risk_level               │
          │               │    │ risk_factors (JSONB)     │
          │               │    │ header_result (JSONB)    │
          │               │    │ content_result (JSONB)   │
          │               │    │ sender_result (JSONB)    │
          │               │    │ ml_result (JSONB)        │
          │               │    │ llm_result (JSONB)       │
          │               │    │ error_message            │
          │               │    │ retry_count              │
          │               │    │ created_at               │
          │               │    │ updated_at               │
          │               │    └──────────┬───────────────┘
          │               │               │ 1:N
          │    ┌──────────┘    ┌──────────▼───────────────┐
          │    │               │      url_analyses         │
          │    │               │──────────────────────────│
          │    │               │ id (PK)                  │
          │    │               │ analysis_id (FK)         │
          │    │               │ raw_url                  │
          │    │               │ expanded_url             │
          │    │               │ is_shortened             │
          │    │               │ reputation               │
          │    │               │ homoglyph_score          │
          │    │               │ virustotal_positives     │
          │    │               │ virustotal_total         │
          │    │               │ checked_at               │
          │    │               │ created_at               │
          │    │               └──────────────────────────┘
          │    │
          │    │               ┌──────────────────────────┐
          │    │               │   attachment_analyses    │
          │    │               │──────────────────────────│
          │    │               │ id (PK)                  │
          │    │               │ analysis_id (FK)         │
          │    │               │ filename                 │
          │    │               │ mime_type                │
          │    │               │ size_bytes               │
          │    │               │ md5_hash                 │
          │    │               │ sha256_hash              │
          │    │               │ reputation               │
          │    │               │ virustotal_positives     │
          │    │               │ virustotal_total         │
          │    │               │ storage_path             │
          │    │               │ created_at               │
          │    │               └──────────────────────────┘
          │    │
          │    │               ┌──────────────────────────┐
          │    │          ┌───►│   threat_indicators      │
          │    │          │    │──────────────────────────│
          │    │          │    │ id (PK)                  │
          │    │          │    │ type (ENUM)              │
          │    │          │    │ value (UNIQUE per type)  │
          │    │          │    │ confidence               │
          │    │          │    │ categories (TEXT[])      │
          │    │          │    │ first_seen               │
          │    │          │    │ last_seen                │
          │    │          │    │ occurrence_count         │
          │    │          │    │ enrichment (JSONB)       │
          │    │          │    │ analyst_annotation       │
          │    │          │    │ is_false_positive        │
          │    │          │    │ tags (TEXT[])            │
          │    │          │    │ created_at               │
          │    │          │    │ updated_at               │
          │    │          │    └──────────────────────────┘
          │    │          │
          │    │          │    ┌──────────────────────────┐
          │    │          │    │  email_threat_indicators │
          │    │          │    │  (junction table)        │
          │    │          │    │──────────────────────────│
          │    │          └────│ threat_indicator_id (FK) │
          │    └───────────────│ email_id (FK)            │
          │                   │ analysis_id (FK)         │
          │                   │ created_at               │
          │                   └──────────────────────────┘
          │
          │                   ┌──────────────────────────┐
          │                   │        alerts            │
          │                   │──────────────────────────│
          │                   │ id (PK)                  │
          │                   │ severity (ENUM)          │
          │                   │ title                    │
          │                   │ message                  │
          │                   │ trigger_rule             │
          │                   │ related_email_ids (TEXT[])│
          │                   │ acknowledged_by (FK)     │
          │                   │ acknowledged_at          │
          │                   │ created_at               │
          │                   └──────────────────────────┘
          │
          │                   ┌──────────────────────────┐
          └──────────────────►│        audit_log         │
                              │  (append-only)           │
                              │──────────────────────────│
                              │ id (PK)                  │
                              │ event_type               │
                              │ actor_user_id (FK)       │
                              │ actor_ip                 │
                              │ resource_type            │
                              │ resource_id              │
                              │ action                   │
                              │ before_state (JSONB)     │
                              │ after_state (JSONB)      │
                              │ metadata (JSONB)         │
                              │ correlation_id           │
                              │ created_at               │
                              └──────────────────────────┘
```

---

## 3. Table Definitions

### 3.1 `users`

```sql
CREATE TABLE threat_platform.users (
    id              CHAR(26)        PRIMARY KEY,           -- ULID
    email           VARCHAR(255)    NOT NULL UNIQUE,
    full_name       VARCHAR(255)    NOT NULL,
    hashed_password VARCHAR(255)    NOT NULL,              -- Argon2id hash
    role            VARCHAR(20)     NOT NULL               -- viewer|analyst|admin
                    CHECK (role IN ('viewer', 'analyst', 'admin')),
    is_active       BOOLEAN         NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    last_login_at   TIMESTAMPTZ,
    deleted_at      TIMESTAMPTZ                            -- soft delete
);
```

---

### 3.2 `emails`

```sql
CREATE TABLE threat_platform.emails (
    id              CHAR(26)        PRIMARY KEY,
    message_id      VARCHAR(998)    NOT NULL UNIQUE,       -- RFC 5322 Message-ID
    subject         TEXT,
    from_address    VARCHAR(998)    NOT NULL,
    from_domain     VARCHAR(253)    NOT NULL,              -- extracted, indexed
    to_addresses    JSONB           NOT NULL DEFAULT '[]', -- array of strings
    reply_to        VARCHAR(998),
    received_at     TIMESTAMPTZ     NOT NULL,              -- original email date
    raw_eml_path    TEXT,                                  -- object storage path
    body_preview    VARCHAR(500),                          -- first 500 chars, sanitized
    has_attachments BOOLEAN         NOT NULL DEFAULT FALSE,
    attachment_count INTEGER        NOT NULL DEFAULT 0,
    source          VARCHAR(50)     NOT NULL DEFAULT 'api',
    priority        VARCHAR(10)     NOT NULL DEFAULT 'normal'
                    CHECK (priority IN ('low', 'normal', 'high')),
    status          VARCHAR(20)     NOT NULL DEFAULT 'queued'
                    CHECK (status IN ('queued', 'analyzing', 'complete', 'failed')),
    -- Denormalized for fast list queries (kept in sync by application after analysis)
    risk_score      SMALLINT        CHECK (risk_score BETWEEN 0 AND 100),
    risk_level      VARCHAR(10)     CHECK (risk_level IN ('critical', 'high', 'medium', 'low', 'safe')),
    submitted_by_user_id CHAR(26)   REFERENCES threat_platform.users(id),
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    deleted_at      TIMESTAMPTZ
);
```

---

### 3.3 `analyses`

```sql
CREATE TABLE threat_platform.analyses (
    id              CHAR(26)        PRIMARY KEY,
    email_id        CHAR(26)        NOT NULL UNIQUE
                    REFERENCES threat_platform.emails(id) ON DELETE CASCADE,
    status          VARCHAR(20)     NOT NULL DEFAULT 'queued'
                    CHECK (status IN ('queued', 'analyzing', 'complete', 'failed', 'skipped')),
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    duration_ms     INTEGER,
    risk_score      SMALLINT        CHECK (risk_score BETWEEN 0 AND 100),
    risk_level      VARCHAR(10),
    risk_factors    JSONB           NOT NULL DEFAULT '[]',
    -- Analysis layer results stored as JSONB for schema flexibility
    header_result   JSONB,          -- spf, dkim, dmarc, routing anomalies
    content_result  JSONB,          -- urgency signals, keywords, language
    sender_result   JSONB,          -- domain age, mx check, typosquat
    ml_result       JSONB,          -- model version, probability, confidence, features
    llm_result      JSONB,          -- narrative, categories, iocs, recommended_action
    error_message   TEXT,
    retry_count     SMALLINT        NOT NULL DEFAULT 0,
    model_versions  JSONB           NOT NULL DEFAULT '{}', -- {"ml": "v2.3.1", "llm": "llama-3.3-70b"}
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);
```

> **Why JSONB for analysis layers?** Analysis sub-results have evolving schemas as new detection capabilities are added. JSONB allows schema evolution without migrations for sub-fields, while still supporting `->` operator queries and GIN indexing.

---

### 3.4 `url_analyses`

```sql
CREATE TABLE threat_platform.url_analyses (
    id                      CHAR(26)    PRIMARY KEY,
    analysis_id             CHAR(26)    NOT NULL
                            REFERENCES threat_platform.analyses(id) ON DELETE CASCADE,
    raw_url                 TEXT        NOT NULL,
    expanded_url            TEXT,
    is_shortened            BOOLEAN     NOT NULL DEFAULT FALSE,
    reputation              VARCHAR(20) CHECK (reputation IN ('clean', 'suspicious', 'malicious', 'unknown')),
    homoglyph_score         REAL        CHECK (homoglyph_score BETWEEN 0.0 AND 1.0),
    homoglyph_target        VARCHAR(253),
    virustotal_positives    SMALLINT,
    virustotal_total        SMALLINT,
    virustotal_permalink    TEXT,
    checked_at              TIMESTAMPTZ,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

---

### 3.5 `attachment_analyses`

```sql
CREATE TABLE threat_platform.attachment_analyses (
    id                      CHAR(26)    PRIMARY KEY,
    analysis_id             CHAR(26)    NOT NULL
                            REFERENCES threat_platform.analyses(id) ON DELETE CASCADE,
    filename                TEXT        NOT NULL,
    mime_type               VARCHAR(255),
    size_bytes              BIGINT      NOT NULL,
    md5_hash                CHAR(32)    NOT NULL,
    sha256_hash             CHAR(64)    NOT NULL,
    reputation              VARCHAR(20) CHECK (reputation IN ('clean', 'suspicious', 'malicious', 'unknown')),
    virustotal_positives    SMALLINT,
    virustotal_total        SMALLINT,
    storage_path            TEXT,                          -- object storage path
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

---

### 3.6 `threat_indicators`

```sql
CREATE TABLE threat_platform.threat_indicators (
    id                  CHAR(26)    PRIMARY KEY,
    type                VARCHAR(20) NOT NULL
                        CHECK (type IN ('domain', 'ip', 'url', 'hash_md5', 'hash_sha256', 'email_address')),
    value               TEXT        NOT NULL,
    confidence          REAL        NOT NULL CHECK (confidence BETWEEN 0.0 AND 1.0),
    categories          TEXT[]      NOT NULL DEFAULT '{}',
    first_seen          TIMESTAMPTZ NOT NULL,
    last_seen           TIMESTAMPTZ NOT NULL,
    occurrence_count    INTEGER     NOT NULL DEFAULT 1,
    enrichment          JSONB       NOT NULL DEFAULT '{}',
    analyst_annotation  TEXT,
    is_false_positive   BOOLEAN     NOT NULL DEFAULT FALSE,
    tags                TEXT[]      NOT NULL DEFAULT '{}',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (type, value)            -- composite unique: same value can appear as different types
);
```

---

### 3.7 `email_threat_indicators` (Junction)

```sql
CREATE TABLE threat_platform.email_threat_indicators (
    email_id            CHAR(26)    NOT NULL
                        REFERENCES threat_platform.emails(id) ON DELETE CASCADE,
    threat_indicator_id CHAR(26)    NOT NULL
                        REFERENCES threat_platform.threat_indicators(id),
    analysis_id         CHAR(26)    REFERENCES threat_platform.analyses(id),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (email_id, threat_indicator_id)
);
```

---

### 3.8 `alerts`

```sql
CREATE TABLE threat_platform.alerts (
    id                  CHAR(26)    PRIMARY KEY,
    severity            VARCHAR(10) NOT NULL
                        CHECK (severity IN ('critical', 'high', 'medium', 'low')),
    title               VARCHAR(255) NOT NULL,
    message             TEXT        NOT NULL,
    trigger_rule        VARCHAR(100),                      -- name of the alert rule triggered
    related_email_ids   TEXT[]      NOT NULL DEFAULT '{}',
    acknowledged_by     CHAR(26)    REFERENCES threat_platform.users(id),
    acknowledged_at     TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

---

### 3.9 `audit_log`

```sql
CREATE TABLE threat_platform.audit_log (
    id              CHAR(26)    PRIMARY KEY,
    event_type      VARCHAR(50) NOT NULL,  -- e.g., EMAIL_SUBMITTED, ANALYSIS_COMPLETED
    actor_user_id   CHAR(26),              -- NULL for system events
    actor_ip        INET,
    resource_type   VARCHAR(50),           -- e.g., email, user, analysis
    resource_id     CHAR(26),
    action          VARCHAR(20) NOT NULL,  -- create, read, update, delete, trigger
    before_state    JSONB,                 -- state before change (for mutations)
    after_state     JSONB,                 -- state after change
    metadata        JSONB       NOT NULL DEFAULT '{}',
    correlation_id  UUID        NOT NULL,  -- request correlation ID
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
    -- NO updated_at — this table is append-only
);
```

> **Append-only enforcement:** A PostgreSQL rule or trigger prevents UPDATE/DELETE on `audit_log`. Application users never have UPDATE/DELETE grants on this table.

---

## 4. Index Strategy

```sql
-- emails table
CREATE INDEX idx_emails_from_domain      ON threat_platform.emails (from_domain);
CREATE INDEX idx_emails_received_at      ON threat_platform.emails (received_at DESC);
CREATE INDEX idx_emails_status           ON threat_platform.emails (status);
CREATE INDEX idx_emails_risk_level       ON threat_platform.emails (risk_level);
CREATE INDEX idx_emails_risk_score       ON threat_platform.emails (risk_score DESC);
CREATE INDEX idx_emails_created_at       ON threat_platform.emails (created_at DESC);
CREATE INDEX idx_emails_deleted_at       ON threat_platform.emails (deleted_at) WHERE deleted_at IS NULL;
-- Full-text search on subject + from_address
CREATE INDEX idx_emails_fts              ON threat_platform.emails
    USING GIN (to_tsvector('english', coalesce(subject,'') || ' ' || from_address));

-- analyses table
CREATE INDEX idx_analyses_email_id       ON threat_platform.analyses (email_id);
CREATE INDEX idx_analyses_status         ON threat_platform.analyses (status);
CREATE INDEX idx_analyses_completed_at   ON threat_platform.analyses (completed_at DESC);
CREATE INDEX idx_analyses_risk_score     ON threat_platform.analyses (risk_score DESC);
-- GIN index for JSONB fields used in WHERE clauses
CREATE INDEX idx_analyses_llm_categories ON threat_platform.analyses
    USING GIN ((llm_result -> 'threat_categories'));

-- threat_indicators
CREATE INDEX idx_threats_type_value      ON threat_platform.threat_indicators (type, value);
CREATE INDEX idx_threats_confidence      ON threat_platform.threat_indicators (confidence DESC);
CREATE INDEX idx_threats_last_seen       ON threat_platform.threat_indicators (last_seen DESC);
CREATE INDEX idx_threats_categories      ON threat_platform.threat_indicators USING GIN (categories);
CREATE INDEX idx_threats_tags            ON threat_platform.threat_indicators USING GIN (tags);

-- audit_log
CREATE INDEX idx_audit_created_at        ON threat_platform.audit_log (created_at DESC);
CREATE INDEX idx_audit_actor_user        ON threat_platform.audit_log (actor_user_id);
CREATE INDEX idx_audit_resource          ON threat_platform.audit_log (resource_type, resource_id);
CREATE INDEX idx_audit_event_type        ON threat_platform.audit_log (event_type);
CREATE INDEX idx_audit_correlation       ON threat_platform.audit_log (correlation_id);

-- url_analyses
CREATE INDEX idx_url_analyses_analysis   ON threat_platform.url_analyses (analysis_id);
CREATE INDEX idx_url_analyses_reputation ON threat_platform.url_analyses (reputation);

-- alerts
CREATE INDEX idx_alerts_severity         ON threat_platform.alerts (severity);
CREATE INDEX idx_alerts_created_at       ON threat_platform.alerts (created_at DESC);
CREATE INDEX idx_alerts_acknowledged     ON threat_platform.alerts (acknowledged_at) WHERE acknowledged_at IS NULL;
```

---

## 5. Query Patterns & Optimization

### Dashboard Summary Query

The primary dashboard query aggregates over `analyses` joined with `emails`:

```sql
-- Materialized or cached for up to 60s in Redis
SELECT
    COUNT(*)                                                    AS emails_processed,
    COUNT(*) FILTER (WHERE a.risk_level IN ('critical','high')) AS threats_detected,
    COUNT(*) FILTER (WHERE a.risk_level = 'critical')          AS critical_threats,
    AVG(a.risk_score)::NUMERIC(5,2)                            AS avg_risk_score,
    AVG(a.duration_ms)                                         AS avg_duration_ms
FROM threat_platform.analyses a
JOIN threat_platform.emails e ON e.id = a.email_id
WHERE a.completed_at >= NOW() - INTERVAL '7 days'
  AND e.deleted_at IS NULL;
```

### Timeline Query (for charts)

```sql
SELECT
    date_trunc('hour', a.completed_at)  AS bucket,
    COUNT(*)                            AS emails_analyzed,
    COUNT(*) FILTER (WHERE a.risk_level IN ('critical','high')) AS threats,
    AVG(a.risk_score)::NUMERIC(5,2)    AS avg_risk_score
FROM threat_platform.analyses a
WHERE a.completed_at >= NOW() - INTERVAL '24 hours'
GROUP BY bucket
ORDER BY bucket;
```

---

## 6. PostgreSQL Views

### `v_email_summary`

Fast read model for email list API endpoint:

```sql
CREATE VIEW threat_platform.v_email_summary AS
SELECT
    e.id,
    e.message_id,
    e.subject,
    e.from_address,
    e.from_domain,
    e.received_at,
    e.status,
    e.risk_score,
    e.risk_level,
    e.has_attachments,
    e.source,
    e.created_at,
    a.id AS analysis_id,
    COALESCE(a.llm_result -> 'threat_categories', '[]'::jsonb) AS threat_categories
FROM threat_platform.emails e
LEFT JOIN threat_platform.analyses a ON a.email_id = e.id
WHERE e.deleted_at IS NULL;
```

### `v_dashboard_summary`

Pre-computed aggregates for dashboard (refreshed by scheduler or MATERIALIZED VIEW):

```sql
CREATE MATERIALIZED VIEW threat_platform.v_dashboard_summary AS
SELECT
    date_trunc('day', a.completed_at)   AS day,
    COUNT(*)                            AS emails_processed,
    COUNT(*) FILTER (WHERE a.risk_level = 'critical') AS critical_count,
    COUNT(*) FILTER (WHERE a.risk_level = 'high')     AS high_count,
    COUNT(*) FILTER (WHERE a.risk_level = 'medium')   AS medium_count,
    COUNT(*) FILTER (WHERE a.risk_level = 'low')      AS low_count,
    COUNT(*) FILTER (WHERE a.risk_level = 'safe')     AS safe_count,
    AVG(a.risk_score)::NUMERIC(5,2)    AS avg_risk_score
FROM threat_platform.analyses a
WHERE a.status = 'complete'
GROUP BY date_trunc('day', a.completed_at)
WITH NO DATA;

-- Refresh index for concurrent refresh
CREATE UNIQUE INDEX ON threat_platform.v_dashboard_summary (day);

-- Refresh on schedule (Celery beat, every 5 minutes)
-- REFRESH MATERIALIZED VIEW CONCURRENTLY threat_platform.v_dashboard_summary;
```

---

## 7. Partitioning Strategy

### `audit_log` — Range Partition by Month

The audit log is expected to grow quickly (every API request generates an event). Partition by month for efficient archival:

```sql
CREATE TABLE threat_platform.audit_log (
    ...
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
) PARTITION BY RANGE (created_at);

-- Created automatically each month by maintenance job
CREATE TABLE threat_platform.audit_log_2026_09
    PARTITION OF threat_platform.audit_log
    FOR VALUES FROM ('2026-09-01') TO ('2026-10-01');
```

### `emails` — Partition consideration

For deployments processing >10M emails/year, consider partitioning `emails` by `received_at` year-month. Deferred until volume warrants it.

---

## 8. Migration Policy

- All schema changes go through Alembic migrations.
- Migration files are named with timestamp prefix: `YYYYMMDDHHMMSS_description.py`.
- Each migration includes `upgrade()` and `downgrade()` functions.
- Destructive migrations (DROP COLUMN, DROP TABLE) require a separate "cleanup" migration after a deprecation period.
- New NOT NULL columns must have a DEFAULT value or be added as nullable then backfilled.
- CI pipeline runs `alembic upgrade head` against a clean test DB on every PR.

### Alembic Configuration

```
backend/
  alembic.ini
  alembic/
    env.py
    versions/
      0001_initial_schema.py
      0002_add_audit_log_partitioning.py
      ...
```

---

## 9. Data Retention Policy

| Table | Retention | Mechanism |
|---|---|---|
| `emails` | 2 years | Soft delete + monthly archival job |
| `analyses` | 2 years | Cascades from `emails` |
| `url_analyses` | 2 years | Cascades from `analyses` |
| `attachment_analyses` | 2 years | Cascades; files purged from object storage |
| `threat_indicators` | Indefinite | Never deleted (threat intel value) |
| `audit_log` | 5 years (compliance) | Partition-based archival to cold storage |
| `alerts` | 1 year | Archival job |
| Raw EML files (object storage) | 90 days | Lifecycle policy on bucket |
