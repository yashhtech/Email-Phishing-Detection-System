import { create } from 'zustand'
import type { User } from '@/entities/user'
import { setAccessToken } from '@/shared/api/client'

interface AuthState {
  user: User | null
  isAuthenticated: boolean
  setSession: (user: User, accessToken: string) => void
  clearSession: () => void
}

export const useAuthStore = create<AuthState>()((set) => ({
  user: null,
  isAuthenticated: false,

  setSession: (user: User, accessToken: string) => {
    setAccessToken(accessToken)
    set({ user, isAuthenticated: true })
  },

  clearSession: () => {
    sessionStorage.removeItem('access_token')
    set({ user: null, isAuthenticated: false })
  },
}))
