import axios, { type AxiosError, type InternalAxiosRequestConfig } from 'axios'

export interface ApiErrorData {
  code: string
  message: string
  details?: unknown[]
}

export class ApiError extends Error {
  constructor(
    public readonly code: string,
    message: string,
    public readonly status: number
  ) {
    super(message)
    this.name = 'ApiError'
  }
}

function getAccessToken(): string | null {
  try {
    return sessionStorage.getItem('access_token')
  } catch {
    return null
  }
}

function setAccessToken(token: string): void {
  sessionStorage.setItem('access_token', token)
}

export { setAccessToken }

export function getApiBaseUrl(): string {
  const envUrl = import.meta.env.VITE_API_BASE_URL
  if (!envUrl) return '/api/v1'
  const trimmed = envUrl.trim().replace(/\/+$/, '')
  return trimmed.endsWith('/api/v1') ? trimmed : `${trimmed}/api/v1`
}

export const apiClient = axios.create({
  baseURL: getApiBaseUrl(),
  timeout: 30_000,
  headers: { 'Content-Type': 'application/json' },
})

// Request interceptor: attach Bearer token
apiClient.interceptors.request.use((config: InternalAxiosRequestConfig) => {
  const token = getAccessToken()
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// Response interceptor: normalize errors
apiClient.interceptors.response.use(
  (response) => response,
  async (error: AxiosError<{ error?: ApiErrorData }>) => {
    const status = error.response?.status ?? 0
    const errorData = error.response?.data?.error
    throw new ApiError(
      errorData?.code ?? 'NETWORK_ERROR',
      errorData?.message ?? error.message,
      status
    )
  }
)
