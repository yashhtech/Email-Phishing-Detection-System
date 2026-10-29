import { z } from 'zod'

export const UserRoleSchema = z.enum(['viewer', 'analyst', 'admin'])
export type UserRole = z.infer<typeof UserRoleSchema>

export const UserSchema = z.object({
  id: z.string(),
  email: z.string().email(),
  full_name: z.string(),
  role: UserRoleSchema,
  created_at: z.string().datetime({ offset: true }),
  last_login_at: z.string().datetime({ offset: true }).nullable(),
})

export type User = z.infer<typeof UserSchema>
