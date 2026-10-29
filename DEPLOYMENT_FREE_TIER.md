# Zero-Cost Demo Deployment Guide
## ThreatGuard: Email Threat & Security Detection Platform

This guide walks you through deploying the complete end-to-end Email Threat Detection platform **100% free of charge** using GitHub, Supabase, Render, and Vercel.

---

### Target Architecture (Zero-Cost Topology)

```
                       +-----------------------------+
                       |      Vercel (Free Tier)     |
                       |  React 18 + Vite Frontend   |
                       |  https://*.vercel.app       |
                       +--------------+--------------+
                                      |
                      HTTPS REST API  |  WSS / Adaptive Polling
                                      v
                       +-----------------------------+
                       |      Render (Free Tier)     |
                       |   FastAPI / Uvicorn Backend |
                       |   In-Process Async Worker   |
                       |   In-Memory Token Cache     |
                       |   https://*.onrender.com    |
                       +-------+-------------+-------+
                               |             |
           PostgreSQL + SSL    |             | HTTPS API Key
        Port 6543 Pooler       |             | (Server-Side Only)
                               v             v
                +-------------------+   +-------------------+
                | Supabase (Free)   |   |  Groq AI (Free)   |
                | Managed Postgres  |   | Llama 3.3 70B     |
                | 500 MB DB Storage |   | Semantic Analysis |
                +-------------------+   +-------------------+
```

---

## 1. Zero-Cost Free Tier Verification

| Service | Component | Free Tier Quota | Cost |
| :--- | :--- | :--- | :--- |
| **GitHub** | Code repository & CI/CD triggers | Public / Private repos, unlimited commits | **$0.00** |
| **Supabase** | Managed PostgreSQL database | 500 MB storage, 2 active projects, pooling | **$0.00** |
| **Render** | FastAPI Backend (Web Service) | 750 free instance hours/month, 512 MB RAM | **$0.00** |
| **Vercel** | React Vite Frontend (Static Hosting) | 100 GB bandwidth/month, unlimited builds | **$0.00** |
| **Groq** | Llama 3.3 70B Semantic Analysis | Free developer tier (generous rate limits) | **$0.00** |

> [!NOTE]
> All services are authenticated using your existing **GitHub** account. No paid addons, credit card dynos, or paid Redis instances are required.

---

## 2. Step 1: Initialize Git and Push to GitHub

Ensure your local repository is committed and pushed to your GitHub account:

```powershell
# Navigate to the workspace root
cd "c:\Users\Yash\OneDrive\Desktop\Email Phishing and Security Detection"

# Initialize git if not already initialized
git init

# Verify .gitignore protects all local .env files and virtual environments
git status

# Stage all project files
git add .

# Create initial release commit
git commit -m "feat: complete zero-cost cloud deployment setup for Render, Vercel, and Supabase"

# Create a new repository on https://github.com/new (e.g. email-threat-detection)
# Then link and push:
git branch -M main
git remote add origin https://github.com/<YOUR-GITHUB-USERNAME>/<YOUR-REPO-NAME>.git
git push -u origin main
```

---

## 3. Step 2: Supabase (Managed PostgreSQL)

1. Go to [database.new](https://database.new) or sign in to [supabase.com](https://supabase.com) with **GitHub**.
2. Click **New Project**:
   - **Name**: `email-threat-detection`
   - **Database Password**: Set a strong password (save this securely).
   - **Region**: Choose a region close to your Render deployment (e.g., `us-east-1` or `eu-central-1`).
   - **Pricing Plan**: Free Tier ($0/month).
3. Once the database is provisioned (1-2 minutes):
   - Navigate to **Project Settings** (gear icon in left sidebar) -> **Database**.
   - Under **Connection string**, select **URI**.
   - Select the **Transaction Pooler** (recommended for serverless, port `6543`, mode `Transaction`) or **Session Pooler** (port `5432`).
   - Copy the URI string. It will look like:
     ```text
     postgresql://postgres.[PROJECT-REF]:[YOUR-PASSWORD]@aws-0-[REGION].pooler.supabase.com:6543/postgres
     ```
   - Replace `[YOUR-PASSWORD]` with the actual password you created.

> [!TIP]
> The backend automatically converts `postgres://` or `postgresql://` into `postgresql+asyncpg://`, sets `ssl="require"`, and configures `statement_cache_size=0` so you do not have to worry about pooler prepared statement incompatibilities!

---

## 4. Step 3: Render (FastAPI Backend)

1. Sign in to [dashboard.render.com](https://dashboard.render.com) using **GitHub**.
2. Click **New +** -> **Web Service**.
3. Select **Build and deploy from a Git repository** and pick your repository.
4. Configure the Web Service settings:
   - **Name**: `email-threat-api` (or any preferred name)
   - **Region**: Same or close to your Supabase region (e.g., `Oregon (US West)` or `Frankfurt (EU Central)`)
   - **Branch**: `main`
   - **Root Directory**: `backend`
   - **Runtime**: `Python 3`
   - **Build Command**:
     ```bash
     pip install -r requirements.txt && alembic upgrade head
     ```
   - **Start Command**:
     ```bash
     uvicorn app.main:app --host 0.0.0.0 --port $PORT
     ```
   - **Instance Type**: `Free` ($0/mo)

5. Scroll down to **Advanced** -> **Health Check Path**:
   - Set to: `/health/live`

6. Add the **Environment Variables**:

| Variable Name | Value | Description |
| :--- | :--- | :--- |
| `APP_ENV` | `production` | Production mode |
| `LOG_LEVEL` | `INFO` | Structured JSON log verbosity |
| `REDIS_REQUIRED` | `false` | Enables in-process queue & memory token store |
| `DEMO_MODE` | `true` | Enables demo seed endpoints and sample tenant |
| `DEFAULT_TENANT_ID` | `a0000000-0000-0000-0000-000000000001` | Default organization UUID |
| `CORS_ORIGIN_REGEX` | `^https://.*\.vercel\.app$` | Permits all Vercel production and preview domains |
| `DATABASE_URL` | *Your Supabase connection string* | `postgresql+asyncpg://postgres.[REF]:[PASS]@aws-0-[REGION].pooler.supabase.com:6543/postgres` |
| `SECRET_KEY` | *(Click "Generate" or enter 32+ hex chars)* | JWT signing secret (backend only) |
| `GROQ_API_KEY` | *(Optional: gsk_...)* | Free Groq API key from [console.groq.com](https://console.groq.com) |

7. Click **Create Web Service**.
8. Wait for the build to complete. The build log will show `pip install`, followed by Alembic applying all migrations (`20260929_0001_initial_schema`, `20260930_0001_analytics_indexes`, `20261007_0001_performance_indexes`).
9. Once live, copy your Render URL: `https://email-threat-api.onrender.com`.

---

## 5. Step 4: Vercel (React Vite Frontend)

1. Sign in to [vercel.com](https://vercel.com) using **GitHub**.
2. Click **Add New...** -> **Project**.
3. Import your GitHub repository.
4. In the **Configure Project** screen:
   - **Project Name**: `email-threat-detection`
   - **Framework Preset**: `Vite`
   - **Root Directory**: Click **Edit** and select `frontend` (crucial: select `frontend`).
   - **Build and Output Settings**:
     - Build Command: `npm run build`
     - Output Directory: `dist`
5. Expand **Environment Variables** and add:

| Variable Name | Value | Note |
| :--- | :--- | :--- |
| `VITE_API_BASE_URL` | `https://<YOUR-RENDER-API>.onrender.com/api/v1` | Your live Render backend API URL |
| `VITE_WS_URL` | `wss://<YOUR-RENDER-API>.onrender.com` | Your live Render WebSocket URL |
| `VITE_APP_ENV` | `production` | UI environment indicator |

6. Click **Deploy**.
7. In ~60 seconds, Vercel will provide your production URL: `https://your-app.vercel.app`.

---

## 6. Step 5: Seed Realistic Demo Data into Supabase

Once both backend and database are live, you can populate the demo dataset through the real analysis pipeline:

### Method A: One-Click Browser / Postman Request
Make a single HTTP POST request to your deployed Render backend:
```bash
curl -X POST https://<YOUR-RENDER-API>.onrender.com/api/v1/dev/demo/seed
```
*Response:*
```json
{
  "status": "success",
  "message": "Demo seed completed",
  "emails_processed": 25,
  "successful_analyses": 25,
  "failed_analyses": 0
}
```

### Method B: From your Local Machine pointing to Supabase
You can also run the seed script locally pointing directly to your Supabase cloud DB:
```powershell
cd backend
$env:DATABASE_URL="postgresql+asyncpg://postgres.[REF]:[PASS]@aws-0-[REGION].pooler.supabase.com:6543/postgres"
.venv\Scripts\python -m app.scripts.seed_demo_emails
```

---

## 7. Step 6: End-to-End Verification Checklist

Verify each of the following in your live browser deployment:

- [ ] **Health & Readiness**:
  - Visit `https://<YOUR-RENDER-API>.onrender.com/health/live` -> returns `{"status":"live"}`.
  - Visit `https://<YOUR-RENDER-API>.onrender.com/health/ready` -> returns `{"status":"ready","database":"connected"}`.
- [ ] **Live Dashboard (`/dashboard`)**:
  - Open `https://<YOUR-VERCEL-APP>.vercel.app/dashboard`.
  - Metrics render: Total Emails Analyzed, Threats Detected, High Risk Ratio, Processing Latency.
  - Live charts render: Threat Trends, Attack Type Breakdown, Risk Tiers.
  - Connection indicator shows **Live (WebSocket)** or falls back smoothly to **Adaptive Polling (15s)**.
- [ ] **Email Analyzer (`/analyze`)**:
  - Click **Analyze Email**.
  - Submit a test email (e.g. Paste a suspicious executive payment request).
  - Watch real-time processing indicators move through: Preprocessing -> Deterministic Rules -> ML Classifier -> Groq Semantic Assessment -> Risk Engine.
- [ ] **Forensic Dossier (`/analysis/:id`)**:
  - Navigate to the result page.
  - Inspect authentication badges (SPF, DKIM, DMARC), extracted URLs, and evidence items.
- [ ] **Threats Database (`/threats`)**:
  - Filter by Critical, High, Phishing, Malware, Spoofing.
- [ ] **History Table (`/history`)**:
  - Pagination, search by subject or sender domain, date filters.
- [ ] **Analytics & Intelligence (`/analytics`)**:
  - Time window presets (24h, 7d, 30d, 90d).
  - Click **Export CSV** -> downloads live aggregated telemetry directly from Render.

---

## 8. Free-Tier Limitations & Mitigations

### 1. Render Free Tier Spin-Down (Cold Starts)
- **Limitation**: Free Render instances sleep after 15 minutes of inactivity. When a new request arrives, it takes ~30–50 seconds for the container to wake up.
- **Mitigation**:
  - The frontend Axios client has a **30-second timeout** and retry handling.
  - The health check endpoint `/health/live` is extremely lightweight (< 5 ms) for uptime monitors (like free UptimeRobot or Cron-job.org if you wish to keep it awake).
  - React Query's fallback polling automatically resumes whenever the container wakes up.

### 2. Supabase Connection Pooler
- **Limitation**: Free Supabase instances provide limited concurrent connection slots and will abort transactions if prepared statement caches conflict in transaction mode.
- **Mitigation**:
  - `backend/app/infrastructure/db/session.py` and `alembic/env.py` automatically inject `statement_cache_size=0`, `prepared_statement_cache_size=0`, and `ssl="require"` for any hostname matching `*.supabase.co` or `*.pooler.supabase.com`.
  - `pool_recycle=300` and `pool_pre_ping=True` prevent cloud NAT drops.

### 3. Redis Absence
- **Limitation**: Neither Render nor Supabase provides a free persistent Redis instance.
- **Mitigation**:
  - `REDIS_REQUIRED=false` switches the backend to run the asynchronous analysis queue as an in-process `asyncio.Queue` worker pool inside FastAPI's lifespan (`AnalysisWorkerPool`).
  - Revoked JWTs and rate limits run via a threadsafe in-memory cache with monotonic TTL expiration.
  - No fake metrics or mocked analysis results are ever used; the complete machine learning and security rule engines execute natively in Python.

### 4. Vercel Single-Page App (SPA) Routing
- **Limitation**: Refreshing a deep route like `/analysis/c9f131a4` on static hosting returns 404 because the static file does not exist on disk.
- **Mitigation**:
  - `vercel.json` rewrites all route requests `/(.*)` to `/index.html` so React Router can mount and resolve the deep link seamlessly.

---

## 9. Troubleshooting & FAQ

### Q: I see `CORS error` in browser developer console
**Fix:**
Ensure your Render `CORS_ORIGIN_REGEX` is set to `^https://.*\.vercel\.app$` (covers all Vercel domains), or set `ALLOWED_ORIGINS` to your exact Vercel URL (e.g. `https://email-threat-detection.vercel.app`). Render environment variable updates trigger a clean redeploy automatically.

### Q: Render build fails with `ModuleNotFoundError: No module named 'psycopg'`
**Fix:**
Ensure your `DATABASE_URL` starts with `postgresql+asyncpg://`. If you pasted `postgresql://`, the built-in validator in `settings.py` rewrites it automatically, but making sure `+asyncpg` is present avoids any ambiguity.

### Q: Why does Groq semantic analysis show "AI semantic analysis skipped"?
**Fix:**
This occurs if `GROQ_API_KEY` is not provided in Render's environment variables. The rest of the platform (ML classifiers, heuristics, sender authentication checks, URL defanging, threat risk engine) runs completely deterministically without requiring an LLM. Adding `GROQ_API_KEY` will immediately enable executive summaries and threat narratives.

### Q: Is there any risk of unexpected charges?
**Fix:**
No. Supabase, Render, and Vercel free tiers do not automatically convert to paid plans when limits are reached; they gracefully throttle or sleep. Groq's developer tier is completely free.
