export const queryKeys = {
  health: () => ['health'] as const,
  emails: {
    all: () => ['emails'] as const,
    list: (filters: Record<string, unknown>) => ['emails', 'list', filters] as const,
    detail: (id: string) => ['emails', 'detail', id] as const,
  },
  analyses: {
    detail: (id: string) => ['analyses', 'detail', id] as const,
  },
  dashboard: {
    summary: (period: string) => ['dashboard', 'summary', period] as const,
    timeline: (period: string, interval: string) =>
      ['dashboard', 'timeline', period, interval] as const,
    topThreats: (period: string) => ['dashboard', 'top-threats', period] as const,
  },
  threats: {
    all: () => ['threats'] as const,
    list: (filters: Record<string, unknown>) => ['threats', 'list', filters] as const,
    detail: (id: string) => ['threats', 'detail', id] as const,
  },
  users: {
    all: () => ['users'] as const,
    detail: (id: string) => ['users', 'detail', id] as const,
  },
} as const
