import { useEffect, useRef, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { useAnalysisNotificationStore } from '../notifications'

interface DashboardWsEvent {
  analysis_id?: string
  status?: string
  stage?: string
  error_message?: string
  data?: {
    analysis_id?: string
    risk_score?: number
    verdict?: string
    severity?: string
    classification?: string
    subject?: string | null
    sender?: string | null
    explanation?: string | null
    findings?: string[]
    security_checks?: Record<string, unknown>
    threat_categories?: string[]
    recommendations?: string[]
    completed_at?: string | null
    [key: string]: unknown
  }
  timestamp?: string
}

/**
 * Resolves the WebSocket URL for the dashboard endpoint.
 * Priority:
 * 1. VITE_WS_URL (explicit override, e.g. wss://threatguard-backend.onrender.com)
 * 2. VITE_API_BASE_URL (derived by converting https->wss / http->ws and stripping /api/v1)
 * 3. Localhost fallback (ws://hostname:8000/ws/dashboard)
 */
export function resolveWsUrl(): string {
  const explicitWs = import.meta.env.VITE_WS_URL
  if (explicitWs) {
    const clean = explicitWs.trim().replace(/\/+$/, '')
    return `${clean}/ws/dashboard`
  }

  const apiBase = import.meta.env.VITE_API_BASE_URL
  if (apiBase) {
    const trimmed = apiBase.trim().replace(/\/+$/, '').replace(/\/api\/v1$/, '')
    const wsBase = trimmed.replace(/^http:/i, 'ws:').replace(/^https:/i, 'wss:')
    return `${wsBase}/ws/dashboard`
  }

  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  const host = window.location.hostname
  return `${protocol}//${host}:8000/ws/dashboard`
}

export function useDashboardWebSocket(onNewEvent?: (event: DashboardWsEvent) => void): {
  isConnected: boolean
} {
  const queryClient = useQueryClient()
  const [isConnected, setIsConnected] = useState(false)
  const wsRef = useRef<WebSocket | null>(null)
  const reconnectTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const onNewEventRef = useRef(onNewEvent)
  onNewEventRef.current = onNewEvent

  useEffect(() => {
    let unmounted = false

    function connect() {
      if (unmounted) return

      const wsUrl = resolveWsUrl()

      try {
        const ws = new WebSocket(wsUrl)
        wsRef.current = ws

        ws.onopen = () => {
          if (!unmounted) {
            setIsConnected(true)
          }
        }

        ws.onmessage = (messageEvent) => {
          try {
            const payload = JSON.parse(messageEvent.data) as DashboardWsEvent
            // When an analysis completes in the background worker:
            if (payload.status === 'completed' || payload.stage === 'completed') {
              // Invalidate dashboard queries so TanStack Query seamlessly refetches updated data
              queryClient.invalidateQueries({ queryKey: ['dashboard-metrics'] })
              queryClient.invalidateQueries({ queryKey: ['dashboard-charts'] })
              queryClient.invalidateQueries({ queryKey: ['recent-threats'] })
              if (onNewEventRef.current) {
                onNewEventRef.current(payload)
              }

              // Trigger instant notification popup if data payload is present
              if (payload.data && (payload.data.analysis_id || payload.analysis_id)) {
                const d = payload.data
                useAnalysisNotificationStore.getState().notifyAnalysis({
                  analysis_id: String(d.analysis_id || payload.analysis_id),
                  verdict: String(d.verdict || 'clean'),
                  severity: d.severity ? String(d.severity) : undefined,
                  risk_score: typeof d.risk_score === 'number' ? d.risk_score : 0,
                  subject: d.subject ? String(d.subject) : null,
                  sender: d.sender ? String(d.sender) : null,
                  explanation: d.explanation ? String(d.explanation) : null,
                  findings: Array.isArray(d.findings) ? d.findings : [],
                  security_checks: typeof d.security_checks === 'object' && d.security_checks !== null ? d.security_checks as Record<string, unknown> : undefined,
                  threat_categories: Array.isArray(d.threat_categories) ? d.threat_categories : [],
                  recommendations: Array.isArray(d.recommendations) ? d.recommendations : [],
                  completed_at: d.completed_at ? String(d.completed_at) : null,
                })
              }
            } else if (payload.status === 'failed') {
              useAnalysisNotificationStore.getState().notifyError({
                title: 'Analysis Failed',
                message: payload.error_message || 'Background analysis encountered an error.',
                analysis_id: payload.analysis_id,
              })
            }
          } catch {
            // Ignore non-json or ping frames
          }
        }

        ws.onclose = () => {
          if (!unmounted) {
            setIsConnected(false)
            reconnectTimeoutRef.current = setTimeout(connect, 4000)
          }
        }

        ws.onerror = () => {
          ws.close()
        }
      } catch {
        if (!unmounted) {
          setIsConnected(false)
          reconnectTimeoutRef.current = setTimeout(connect, 6000)
        }
      }
    }

    connect()

    return () => {
      unmounted = true
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current)
      }
      if (wsRef.current) {
        wsRef.current.close()
        wsRef.current = null
      }
      setIsConnected(false)
    }
  }, [queryClient])

  return { isConnected }
}

