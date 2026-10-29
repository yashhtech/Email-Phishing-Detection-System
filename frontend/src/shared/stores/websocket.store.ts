import { create } from 'zustand'

export type WsStatus = 'disconnected' | 'connecting' | 'connected' | 'error'

interface WebSocketState {
  status: WsStatus
  lastPing: Date | null
  setStatus: (status: WsStatus) => void
  setLastPing: (date: Date) => void
}

export const useWebSocketStore = create<WebSocketState>()((set) => ({
  status: 'disconnected',
  lastPing: null,
  setStatus: (status) => set({ status }),
  setLastPing: (date) => set({ lastPing: date }),
}))
