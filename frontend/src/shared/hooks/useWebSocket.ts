import { useEffect, useRef } from 'react'
import { useWebSocketStore } from '@/shared/stores/websocket.store'

export interface WsMessage {
  type: string
  channel?: string
  data?: unknown
  timestamp?: string
}

interface UseWebSocketOptions {
  channels: string[]
  onMessage: (message: WsMessage) => void
  enabled?: boolean
}

const RECONNECT_BASE_MS = 1_000
const RECONNECT_MAX_MS = 30_000

export function useWebSocket({ channels, onMessage, enabled = true }: UseWebSocketOptions): void {
  const setStatus = useWebSocketStore((s) => s.setStatus)
  const setLastPing = useWebSocketStore((s) => s.setLastPing)
  const wsRef = useRef<WebSocket | null>(null)
  const reconnectAttempt = useRef(0)
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  const channelKey = channels.join(',')

  useEffect(() => {
    if (!enabled) return

    function connect(): void {
      const token = sessionStorage.getItem('access_token')
      if (!token) return

      const wsUrl = (import.meta.env.VITE_WS_URL ?? 'ws://localhost:8000') + `/ws/live?token=${token}`
      setStatus('connecting')

      const ws = new WebSocket(wsUrl)
      wsRef.current = ws

      ws.onopen = () => {
        reconnectAttempt.current = 0
        setStatus('connected')
        ws.send(JSON.stringify({ type: 'subscribe', channels }))
      }

      ws.onmessage = (event: MessageEvent<string>) => {
        try {
          const msg = JSON.parse(event.data) as WsMessage
          if (msg.type === 'pong') {
            setLastPing(new Date())
            return
          }
          onMessage(msg)
        } catch {
          // Ignore malformed messages
        }
      }

      ws.onerror = () => setStatus('error')

      ws.onclose = () => {
        setStatus('disconnected')
        const delay = Math.min(
          RECONNECT_BASE_MS * 2 ** reconnectAttempt.current,
          RECONNECT_MAX_MS
        )
        reconnectAttempt.current++
        reconnectTimer.current = setTimeout(connect, delay)
      }
    }

    connect()

    return () => {
      if (reconnectTimer.current) clearTimeout(reconnectTimer.current)
      wsRef.current?.close()
      wsRef.current = null
      setStatus('disconnected')
    }
  }, [enabled, channelKey])
}
