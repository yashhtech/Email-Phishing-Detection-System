import { create } from 'zustand'

export type NotificationType = 'success' | 'error' | 'warning' | 'info'

export interface Notification {
  id: string
  type: NotificationType
  title: string
  message?: string
  duration?: number
}

interface NotificationState {
  notifications: Notification[]
  push: (notification: Omit<Notification, 'id'>) => void
  dismiss: (id: string) => void
}

let _idCounter = 0

export const useNotificationStore = create<NotificationState>()((set) => ({
  notifications: [],

  push: (notification) => {
    const id = `notif-${++_idCounter}`
    set((state) => ({
      notifications: [...state.notifications, { ...notification, id }],
    }))
    const duration = notification.duration ?? 5000
    setTimeout(() => {
      set((state) => ({
        notifications: state.notifications.filter((n) => n.id !== id),
      }))
    }, duration)
  },

  dismiss: (id) => {
    set((state) => ({
      notifications: state.notifications.filter((n) => n.id !== id),
    }))
  },
}))
