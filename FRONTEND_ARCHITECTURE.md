# Frontend Architecture
## Email Threat Detection & Security Intelligence Platform

> **Version:** 1.0.0 | **Framework:** React 18 + TypeScript + Vite | **Date:** 2026-09-29

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Directory Structure](#2-directory-structure)
3. [Component Architecture](#3-component-architecture)
4. [State Management](#4-state-management)
5. [Routing & Navigation](#5-routing--navigation)
6. [API Client Layer](#6-api-client-layer)
7. [WebSocket Integration](#7-websocket-integration)
8. [Dashboard & Charts](#8-dashboard--charts)
9. [Authentication Flow](#9-authentication-flow)
10. [Design System](#10-design-system)
11. [Accessibility](#11-accessibility)
12. [Performance Strategy](#12-performance-strategy)
13. [Testing Strategy](#13-testing-strategy)
14. [Build & Deployment](#14-build--deployment)

---

## 1. Architecture Overview

### Architectural Pattern: Feature-Sliced Design (FSD)

The frontend follows **Feature-Sliced Design** — a layered architecture where modules are organized by feature domain, not by technical type. Dependencies flow strictly downward:

```
pages/          (route-level page components)
    └─► features/   (self-contained feature modules)
            └─► entities/   (domain business objects)
                    └─► shared/     (UI kit, utils, api client, types)
```

**Rules:**
- Higher layers may import from lower layers; never the reverse.
- Features do not import from other features directly — they communicate through shared state (Zustand stores) or page-level composition.
- All API calls go through the shared `api/` client — no `fetch`/`axios` calls in components.

### Technology Stack

| Concern | Library | Version |
|---|---|---|
| Framework | React | 18.x |
| Language | TypeScript | 5.x (strict mode) |
| Build Tool | Vite | 5.x |
| State Management | Zustand | 4.x |
| Server State | TanStack Query (React Query) | 5.x |
| HTTP Client | Axios | 1.x |
| Routing | React Router | 6.x |
| Charts | Recharts | 2.x |
| Styling | Tailwind CSS | 3.x |
| Component Library | shadcn/ui (Radix UI) | latest |
| Form Handling | React Hook Form + Zod | 7.x + 3.x |
| WebSocket | Native + custom hook | — |
| Testing | Vitest + @testing-library/react | — |
| E2E | Playwright | 1.x |
| Linting | ESLint + Prettier | — |
| Type checking | tsc --noEmit | — |

---

## 2. Directory Structure

```
frontend/
├── public/
│   └── favicon.ico
├── src/
│   ├── app/                         # App bootstrap
│   │   ├── App.tsx                  # Root component with providers
│   │   ├── providers.tsx            # QueryClient, Router, Theme providers
│   │   └── router.tsx               # Route definitions
│   │
│   ├── pages/                       # Route-level pages (thin wrappers)
│   │   ├── LoginPage.tsx
│   │   ├── DashboardPage.tsx
│   │   ├── EmailsPage.tsx
│   │   ├── EmailDetailPage.tsx
│   │   ├── ThreatsPage.tsx
│   │   ├── UsersPage.tsx
│   │   └── SettingsPage.tsx
│   │
│   ├── features/                    # Self-contained feature modules
│   │   ├── auth/
│   │   │   ├── components/
│   │   │   │   ├── LoginForm.tsx
│   │   │   │   └── UserMenu.tsx
│   │   │   ├── hooks/
│   │   │   │   └── useAuth.ts
│   │   │   └── index.ts
│   │   │
│   │   ├── dashboard/
│   │   │   ├── components/
│   │   │   │   ├── SummaryCards.tsx
│   │   │   │   ├── ThreatTimeline.tsx
│   │   │   │   ├── RiskDistributionChart.tsx
│   │   │   │   ├── TopThreatsPanel.tsx
│   │   │   │   └── LiveThreatFeed.tsx
│   │   │   ├── hooks/
│   │   │   │   └── useDashboardMetrics.ts
│   │   │   └── index.ts
│   │   │
│   │   ├── emails/
│   │   │   ├── components/
│   │   │   │   ├── EmailList.tsx
│   │   │   │   ├── EmailListItem.tsx
│   │   │   │   ├── EmailFilters.tsx
│   │   │   │   ├── EmailSubmitForm.tsx
│   │   │   │   └── EmailDetail/
│   │   │   │       ├── EmailDetail.tsx
│   │   │   │       ├── HeaderAnalysisPanel.tsx
│   │   │   │       ├── URLAnalysisPanel.tsx
│   │   │   │       ├── AttachmentPanel.tsx
│   │   │   │       ├── MLResultPanel.tsx
│   │   │   │       ├── LLMNarrativePanel.tsx
│   │   │   │       └── RiskScoreCard.tsx
│   │   │   ├── hooks/
│   │   │   │   ├── useEmails.ts
│   │   │   │   └── useEmailDetail.ts
│   │   │   └── index.ts
│   │   │
│   │   ├── threats/
│   │   │   ├── components/
│   │   │   │   ├── ThreatList.tsx
│   │   │   │   ├── ThreatCard.tsx
│   │   │   │   └── ThreatAnnotationModal.tsx
│   │   │   ├── hooks/
│   │   │   │   └── useThreats.ts
│   │   │   └── index.ts
│   │   │
│   │   └── users/
│   │       ├── components/
│   │       │   ├── UserTable.tsx
│   │       │   └── UserForm.tsx
│   │       ├── hooks/
│   │       │   └── useUsers.ts
│   │       └── index.ts
│   │
│   ├── entities/                    # Domain types mirroring backend schemas
│   │   ├── email.ts                 # Email, EmailSummary, EmailStatus types
│   │   ├── analysis.ts              # AnalysisResult, RiskLevel, RiskFactor types
│   │   ├── threat.ts                # ThreatIndicator, IOC types
│   │   ├── dashboard.ts             # DashboardSummary, TimelinePoint types
│   │   └── user.ts                 # User, UserRole types
│   │
│   ├── shared/
│   │   ├── api/                     # API client (single point of contact)
│   │   │   ├── client.ts            # Axios instance + interceptors
│   │   │   ├── auth.api.ts
│   │   │   ├── emails.api.ts
│   │   │   ├── analyses.api.ts
│   │   │   ├── threats.api.ts
│   │   │   ├── dashboard.api.ts
│   │   │   └── users.api.ts
│   │   │
│   │   ├── hooks/                   # Generic reusable hooks
│   │   │   ├── useWebSocket.ts      # WebSocket connection + message routing
│   │   │   ├── usePagination.ts
│   │   │   └── useDebounce.ts
│   │   │
│   │   ├── stores/                  # Zustand stores (global state)
│   │   │   ├── auth.store.ts        # User session, JWT tokens
│   │   │   ├── websocket.store.ts   # WS connection state
│   │   │   └── notification.store.ts # Toast notifications
│   │   │
│   │   ├── ui/                      # Reusable UI primitives
│   │   │   ├── RiskBadge.tsx        # Risk level colored badge
│   │   │   ├── StatusBadge.tsx
│   │   │   ├── DataTable.tsx        # Generic sortable/paginated table
│   │   │   ├── LoadingSpinner.tsx
│   │   │   ├── ErrorBoundary.tsx
│   │   │   ├── EmptyState.tsx
│   │   │   ├── ConfirmDialog.tsx
│   │   │   └── PageLayout.tsx       # Sidebar + header shell
│   │   │
│   │   ├── lib/
│   │   │   ├── utils.ts             # Generic utilities (cn, formatDate, etc.)
│   │   │   ├── constants.ts         # App-wide constants
│   │   │   └── queryKeys.ts         # React Query key factories
│   │   │
│   │   └── types/
│   │       ├── api.ts               # Generic ApiResponse<T>, PaginatedResponse<T>
│   │       └── env.d.ts             # import.meta.env type augmentation
│   │
│   ├── styles/
│   │   └── globals.css              # Tailwind directives + CSS variables
│   │
│   ├── main.tsx                     # Vite entry point
│   └── vite-env.d.ts
│
├── index.html
├── vite.config.ts
├── tsconfig.json
├── tsconfig.node.json
├── tailwind.config.ts
├── postcss.config.js
├── eslint.config.js
├── playwright.config.ts
└── vitest.config.ts
```

---

## 3. Component Architecture

### 3.1 Component Categories

| Category | Location | Description |
|---|---|---|
| **Page** | `pages/` | Route-level. Composes features. No direct API calls. |
| **Feature** | `features/*/components/` | Self-contained sections with data fetching hooks. |
| **Entity** | `entities/` + feature components | Domain-aware display components (e.g., `RiskScoreCard`). |
| **Shared UI** | `shared/ui/` | Dumb, generic components. Receive data via props only. |

### 3.2 Component Design Rules

1. **No direct API calls in JSX.** All data fetching goes through React Query hooks in `features/*/hooks/`.
2. **Shared UI components are prop-only.** They never access stores or call APIs.
3. **Feature components own their loading/error states.** Use React Query's `isLoading`, `isError` states.
4. **Forms use React Hook Form + Zod.** No uncontrolled inputs or manual validation.
5. **Every list component is paginated.** No unbounded lists.

### 3.3 Example Component Tree (Dashboard Page)

```
DashboardPage
├── PageLayout (shared/ui)
│   ├── Sidebar
│   └── Header (with UserMenu)
│
└── DashboardContent
    ├── SummaryCards          ← React Query: /dashboard/summary
    │   ├── EmailsProcessedCard
    │   ├── ThreatsDetectedCard
    │   ├── CriticalThreatCard
    │   └── AvgRiskScoreCard
    │
    ├── ThreatTimeline        ← React Query: /dashboard/timeline
    │   └── Recharts LineChart
    │
    ├── RiskDistributionChart ← data from SummaryCards (passed as prop)
    │   └── Recharts PieChart
    │
    ├── TopThreatsPanel       ← React Query: /dashboard/top-threats
    │
    └── LiveThreatFeed        ← useWebSocket() hook (real-time)
        └── ThreatFeedItem[]
```

---

## 4. State Management

### 4.1 State Layers

| Layer | Tool | Used For |
|---|---|---|
| **Server State** | TanStack Query | All API data — emails, analyses, threats, dashboard |
| **Global Client State** | Zustand | Auth session, WebSocket connection, notifications |
| **Local Component State** | `useState` / `useReducer` | UI-only: modals open, form steps, selected rows |
| **URL State** | React Router search params | Filters, pagination cursors, sort order |

### 4.2 Zustand Stores

**Auth Store** (`shared/stores/auth.store.ts`):
```typescript
interface AuthState {
  user: User | null;
  accessToken: string | null;
  isAuthenticated: boolean;
  setSession: (user: User, accessToken: string) => void;
  clearSession: () => void;
}
```

**WebSocket Store** (`shared/stores/websocket.store.ts`):
```typescript
interface WebSocketState {
  status: 'disconnected' | 'connecting' | 'connected' | 'error';
  lastPing: Date | null;
  subscribe: (channels: string[]) => void;
  unsubscribe: (channels: string[]) => void;
}
```

**Notification Store** (`shared/stores/notification.store.ts`):
```typescript
interface NotificationState {
  notifications: Notification[];
  push: (notification: Omit<Notification, 'id'>) => void;
  dismiss: (id: string) => void;
}
```

### 4.3 React Query Configuration

```typescript
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,           // 30s — dashboard data refreshes every 30s via WS anyway
      gcTime: 5 * 60 * 1000,      // 5 min garbage collection
      retry: (failureCount, error) => {
        if (error instanceof UnauthorizedError) return false;  // don't retry auth errors
        return failureCount < 3;
      },
      refetchOnWindowFocus: false, // WS handles real-time; avoid double-fetching
    },
    mutations: {
      onError: (error) => notificationStore.push({ type: 'error', message: getErrorMessage(error) }),
    },
  },
});
```

### 4.4 Query Key Factory

```typescript
// shared/lib/queryKeys.ts
export const queryKeys = {
  emails: {
    all: () => ['emails'] as const,
    list: (filters: EmailFilters) => ['emails', 'list', filters] as const,
    detail: (id: string) => ['emails', 'detail', id] as const,
  },
  analyses: {
    detail: (id: string) => ['analyses', 'detail', id] as const,
  },
  dashboard: {
    summary: (period: string) => ['dashboard', 'summary', period] as const,
    timeline: (period: string, interval: string) => ['dashboard', 'timeline', period, interval] as const,
    topThreats: (period: string) => ['dashboard', 'top-threats', period] as const,
  },
  threats: {
    all: () => ['threats'] as const,
    list: (filters: ThreatFilters) => ['threats', 'list', filters] as const,
  },
};
```

---

## 5. Routing & Navigation

### 5.1 Route Structure

```typescript
// app/router.tsx
const router = createBrowserRouter([
  {
    path: '/login',
    element: <LoginPage />,
  },
  {
    path: '/',
    element: <AuthGuard><PageLayout /></AuthGuard>,
    children: [
      { index: true, element: <Navigate to="/dashboard" replace /> },
      { path: 'dashboard',              element: <DashboardPage /> },
      { path: 'emails',                 element: <EmailsPage /> },
      { path: 'emails/:emailId',        element: <EmailDetailPage /> },
      { path: 'threats',                element: <ThreatsPage /> },
      {
        path: 'admin',
        element: <AdminGuard><Outlet /></AdminGuard>,
        children: [
          { path: 'users',              element: <UsersPage /> },
          { path: 'settings',           element: <SettingsPage /> },
        ],
      },
    ],
  },
  {
    path: '*',
    element: <NotFoundPage />,
  },
]);
```

### 5.2 Route Guards

```typescript
// AuthGuard — redirects to /login if not authenticated
function AuthGuard({ children }: { children: ReactNode }) {
  const isAuthenticated = useAuthStore(s => s.isAuthenticated);
  if (!isAuthenticated) return <Navigate to="/login" replace />;
  return <>{children}</>;
}

// AdminGuard — 403 page if not admin role
function AdminGuard({ children }: { children: ReactNode }) {
  const user = useAuthStore(s => s.user);
  if (user?.role !== 'admin') return <ForbiddenPage />;
  return <>{children}</>;
}
```

### 5.3 URL State for Filters

Email list filters are persisted in URL search params for shareable links and browser history:

```typescript
// features/emails/hooks/useEmails.ts
function useEmailFilters() {
  const [searchParams, setSearchParams] = useSearchParams();
  const filters = {
    status: searchParams.get('status') ?? undefined,
    riskLevel: searchParams.get('risk_level') ?? undefined,
    search: searchParams.get('q') ?? undefined,
    cursor: searchParams.get('cursor') ?? undefined,
  };
  const updateFilters = (updates: Partial<EmailFilters>) => {
    setSearchParams(prev => {
      Object.entries(updates).forEach(([k, v]) => {
        if (v) prev.set(k, v); else prev.delete(k);
      });
      return prev;
    });
  };
  return { filters, updateFilters };
}
```

---

## 6. API Client Layer

### 6.1 Axios Instance

```typescript
// shared/api/client.ts
const apiClient = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL,
  timeout: 30_000,
  headers: { 'Content-Type': 'application/json' },
});

// Request interceptor: attach auth token
apiClient.interceptors.request.use(config => {
  const token = useAuthStore.getState().accessToken;
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

// Response interceptor: handle 401 → auto-refresh
apiClient.interceptors.response.use(
  response => response.data,
  async error => {
    if (error.response?.status === 401 && !error.config._retry) {
      error.config._retry = true;
      await refreshAccessToken();  // see auth.api.ts
      return apiClient(error.config);
    }
    return Promise.reject(mapApiError(error));
  }
);
```

### 6.2 Typed API Functions

```typescript
// shared/api/emails.api.ts
export const emailsApi = {
  list: (filters: EmailFilters): Promise<PaginatedResponse<EmailSummary>> =>
    apiClient.get('/emails', { params: filters }),

  get: (id: string): Promise<ApiResponse<Email>> =>
    apiClient.get(`/emails/${id}`),

  submit: (formData: FormData): Promise<ApiResponse<EmailSubmitResult>> =>
    apiClient.post('/emails', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    }),

  delete: (id: string): Promise<void> =>
    apiClient.delete(`/emails/${id}`),
};
```

---

## 7. WebSocket Integration

### 7.1 `useWebSocket` Hook

```typescript
// shared/hooks/useWebSocket.ts
interface UseWebSocketOptions {
  channels: string[];
  onMessage: (message: WSMessage) => void;
  enabled?: boolean;
}

export function useWebSocket({ channels, onMessage, enabled = true }: UseWebSocketOptions) {
  const wsRef = useRef<WebSocket | null>(null);
  const setStatus = useWebSocketStore(s => s.setStatus);

  useEffect(() => {
    if (!enabled) return;

    const token = useAuthStore.getState().accessToken;
    const ws = new WebSocket(`${import.meta.env.VITE_WS_URL}/ws/live?token=${token}`);
    wsRef.current = ws;

    ws.onopen = () => {
      setStatus('connected');
      ws.send(JSON.stringify({ type: 'subscribe', channels }));
    };

    ws.onmessage = (event) => {
      const message = JSON.parse(event.data) as WSMessage;
      onMessage(message);
    };

    ws.onerror = () => setStatus('error');
    ws.onclose = () => {
      setStatus('disconnected');
      // Exponential backoff reconnection (max 30s)
      scheduleReconnect();
    };

    return () => ws.close();
  }, [enabled]);
}
```

### 7.2 LiveThreatFeed Component

```typescript
// features/dashboard/components/LiveThreatFeed.tsx
export function LiveThreatFeed() {
  const [events, setEvents] = useState<AnalysisCompletedEvent[]>([]);
  const queryClient = useQueryClient();

  useWebSocket({
    channels: ['threat_feed', 'metrics_update'],
    onMessage: (message) => {
      if (message.type === 'analysis_completed') {
        // Add to live feed
        setEvents(prev => [message.data, ...prev].slice(0, 50));
        // Invalidate dashboard summary to show updated counts
        queryClient.invalidateQueries({ queryKey: queryKeys.dashboard.summary('last_7_days') });
        // Invalidate emails list if visible
        queryClient.invalidateQueries({ queryKey: queryKeys.emails.all() });
      }
    },
  });

  return (
    <div role="feed" aria-label="Live threat events" aria-live="polite">
      {events.map(event => (
        <ThreatFeedItem key={event.analysis_id} event={event} />
      ))}
    </div>
  );
}
```

---

## 8. Dashboard & Charts

### 8.1 Chart Data Flow

All chart data flows from React Query hooks → Recharts components. No data transformation happens inside chart components.

```typescript
// features/dashboard/hooks/useDashboardMetrics.ts
export function useDashboardTimeline(period: string, interval: string) {
  return useQuery({
    queryKey: queryKeys.dashboard.timeline(period, interval),
    queryFn: () => dashboardApi.getTimeline({ period, interval }),
    select: (data) => ({
      // Transform API data to Recharts-compatible format here, not in the component
      chartData: data.series.map(point => ({
        time: formatChartTime(point.timestamp, interval),
        emails: point.emails_submitted,
        threats: point.threats_detected,
        avgRisk: point.average_risk_score,
      })),
    }),
    refetchInterval: 60_000,  // Fallback polling; WS pushes invalidation on events
  });
}
```

### 8.2 Threat Timeline Chart

```typescript
// features/dashboard/components/ThreatTimeline.tsx
export function ThreatTimeline({ period }: { period: string }) {
  const { data, isLoading } = useDashboardTimeline(period, '1h');

  if (isLoading) return <ChartSkeleton />;

  return (
    <ResponsiveContainer width="100%" height={300}>
      <LineChart data={data?.chartData}>
        <CartesianGrid strokeDasharray="3 3" />
        <XAxis dataKey="time" />
        <YAxis yAxisId="count" />
        <YAxis yAxisId="risk" orientation="right" domain={[0, 100]} />
        <Tooltip content={<ThreatTimelineTooltip />} />
        <Legend />
        <Line yAxisId="count" type="monotone" dataKey="emails" stroke="#6366f1" name="Emails" />
        <Line yAxisId="count" type="monotone" dataKey="threats" stroke="#ef4444" name="Threats" />
        <Line yAxisId="risk" type="monotone" dataKey="avgRisk" stroke="#f59e0b" name="Avg Risk" strokeDasharray="5 5" />
      </LineChart>
    </ResponsiveContainer>
  );
}
```

### 8.3 Risk Distribution Chart

```typescript
// Recharts PieChart with real risk_distribution data from /dashboard/summary
const RISK_COLORS = {
  critical: '#dc2626',
  high:     '#f97316',
  medium:   '#eab308',
  low:      '#3b82f6',
  safe:     '#22c55e',
};
```

---

## 9. Authentication Flow

### 9.1 Token Storage

- **Access token:** in-memory (Zustand store) — survives page navigation, lost on tab close
- **Refresh token:** `HttpOnly` cookie with `Secure; SameSite=Strict` — server-managed
- **Why:** XSS cannot access HttpOnly cookies; access token in memory avoids localStorage XSS risk

### 9.2 Login Flow

```
[User enters credentials] → LoginForm
    → POST /auth/login
    → Success: {access_token, user}
    → Store access_token + user in Zustand
    → Refresh token set as HttpOnly cookie by server
    → Navigate to /dashboard
```

### 9.3 Auto-Refresh Flow

```
[Axios interceptor detects 401]
    → POST /auth/refresh (cookie sent automatically by browser)
    → Success: {access_token}
    → Update Zustand accessToken
    → Retry original request
    → Failure: clear session → redirect to /login
```

---

## 10. Design System

### 10.1 Color Palette (CSS Variables)

```css
/* styles/globals.css */
:root {
  --color-bg-primary:     #0f172a;   /* slate-900 */
  --color-bg-secondary:   #1e293b;   /* slate-800 */
  --color-bg-card:        #1e293b;
  --color-text-primary:   #f1f5f9;   /* slate-100 */
  --color-text-muted:     #94a3b8;   /* slate-400 */
  --color-accent:         #6366f1;   /* indigo-500 */

  /* Risk level colors */
  --color-risk-critical:  #dc2626;   /* red-600 */
  --color-risk-high:      #f97316;   /* orange-500 */
  --color-risk-medium:    #eab308;   /* yellow-500 */
  --color-risk-low:       #3b82f6;   /* blue-500 */
  --color-risk-safe:      #22c55e;   /* green-500 */
}
```

### 10.2 Typography Scale

| Role | Size | Weight |
|---|---|---|
| Page Title | 2xl (24px) | Semibold |
| Section Heading | xl (20px) | Semibold |
| Card Title | base (16px) | Medium |
| Body | sm (14px) | Normal |
| Caption | xs (12px) | Normal |
| Metric Value | 3xl (30px) | Bold |

### 10.3 `RiskBadge` Component

```typescript
// shared/ui/RiskBadge.tsx
const riskConfig: Record<RiskLevel, { label: string; className: string }> = {
  critical: { label: 'Critical', className: 'bg-red-600/20 text-red-400 border-red-600/30' },
  high:     { label: 'High',     className: 'bg-orange-500/20 text-orange-400 border-orange-500/30' },
  medium:   { label: 'Medium',   className: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30' },
  low:      { label: 'Low',      className: 'bg-blue-500/20 text-blue-400 border-blue-500/30' },
  safe:     { label: 'Safe',     className: 'bg-green-500/20 text-green-400 border-green-500/30' },
};

export function RiskBadge({ level }: { level: RiskLevel }) {
  const config = riskConfig[level];
  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border ${config.className}`}
      aria-label={`Risk level: ${config.label}`}
    >
      {config.label}
    </span>
  );
}
```

---

## 11. Accessibility

### 11.1 Requirements (WCAG 2.1 AA)

- Minimum contrast ratio: 4.5:1 for text, 3:1 for UI components
- All interactive elements keyboard-navigable
- Screen reader support: proper ARIA roles, labels, live regions
- Focus management on modal open/close
- Skip-to-main-content link

### 11.2 Implementation Checklist

- [ ] `shadcn/ui` components have Radix UI accessibility built in
- [ ] All form inputs have associated `<label>` elements
- [ ] Charts have `role="img"` with `aria-label` describing the data
- [ ] Live threat feed uses `aria-live="polite"` (not `assertive`)
- [ ] Color is never the sole differentiator (risk badges have text labels)
- [ ] All icon-only buttons have `aria-label`
- [ ] Modal focus trap (handled by Radix Dialog)
- [ ] `prefers-reduced-motion` respected — disable chart animations when set

---

## 12. Performance Strategy

### 12.1 Bundle Splitting

```typescript
// vite.config.ts
export default defineConfig({
  build: {
    rollupOptions: {
      output: {
        manualChunks: {
          'vendor-react':    ['react', 'react-dom', 'react-router-dom'],
          'vendor-query':    ['@tanstack/react-query'],
          'vendor-charts':   ['recharts'],
          'vendor-ui':       ['@radix-ui/react-dialog', /* ... other radix packages */],
        },
      },
    },
  },
});
```

### 12.2 Code Splitting

- All page components are lazy-loaded: `const DashboardPage = lazy(() => import('./pages/DashboardPage'))`
- Wrapped with `Suspense` at the router level

### 12.3 Image & Asset Optimization

- No email body images rendered (security risk + performance)
- SVG icons inlined via `vite-plugin-svgr`
- Favicons preloaded

### 12.4 React Query Optimizations

- `prefetchQuery` on hover for email list items (preload detail view)
- `keepPreviousData: true` for paginated lists (no flash on page change)
- Background refetch interval for dashboard: 60s (WS is primary)

---

## 13. Testing Strategy

### 13.1 Unit Tests (Vitest)

```typescript
// features/emails/__tests__/EmailListItem.test.tsx
it('displays critical risk badge for critical emails', () => {
  render(<EmailListItem email={mockEmail({ riskLevel: 'critical' })} />);
  expect(screen.getByRole('status', { name: /risk level: critical/i })).toBeInTheDocument();
});
```

Coverage targets:
- `shared/ui/` components: 100%
- `shared/api/` functions: 100% (mock Axios)
- `features/*/hooks/`: 90%
- `features/*/components/`: 80%

### 13.2 E2E Tests (Playwright)

Critical user flows:

| Flow | Test |
|---|---|
| Login → Dashboard loads with data | `dashboard.spec.ts` |
| Submit email → analysis appears in list | `email-submit.spec.ts` |
| Click email → analysis detail shows all panels | `email-detail.spec.ts` |
| Filter emails by risk level | `email-filters.spec.ts` |
| WebSocket: new threat appears in live feed | `live-feed.spec.ts` |
| Admin creates new user | `user-management.spec.ts` |

---

## 14. Build & Deployment

### 14.1 Environment Variables

```bash
# .env.example (frontend)
VITE_API_BASE_URL=http://localhost:8000/api/v1
VITE_WS_URL=ws://localhost:8000
VITE_APP_ENV=development
```

### 14.2 Production Build

```bash
npm run build   # vite build → dist/
```

Production output served by Nginx (inside Docker container):
- HTML5 history API: `try_files $uri /index.html`
- Cache-Control: `max-age=31536000` for hashed assets; `no-cache` for `index.html`
- Gzip/Brotli compression enabled

### 14.3 Docker

```dockerfile
# Multi-stage: build + nginx serve
FROM node:22-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
```
