import { apiClient } from './client'

export interface HealthCheck {
  status: 'healthy' | 'unhealthy' | 'degraded'
  version: string
  environment: string
  timestamp: string
  checks: Record<string, { status: 'ok' | 'error'; detail?: string }>
}

export const healthApi = {
  check: (): Promise<HealthCheck> =>
    apiClient.get<HealthCheck>('/health').then((r) => r.data),
}
