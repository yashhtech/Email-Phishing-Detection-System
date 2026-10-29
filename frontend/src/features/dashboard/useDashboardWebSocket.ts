import { useEffect, useRef, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'

interface DashboardWsEvent {
  analysis_id?: string
  status?: string
  stage?: string
  data?: {
    risk_score?: number
    verdict?: string
    severity?: string
    classification?: string
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

