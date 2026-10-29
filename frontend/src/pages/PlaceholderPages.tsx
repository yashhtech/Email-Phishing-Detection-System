// Placeholder pages for nav items not yet fully implemented
// These use AppShell so the nav works correctly

import { type FC, type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { BarChart3, Clock, Globe, Zap } from 'lucide-react'
import { AppShell } from '../shared/layout/AppShell'
import { Button, EmptyState } from '../shared/ui'

interface PlaceholderPageProps {
  title: string
  description: string
  icon: ReactNode
}

const PlaceholderPage: FC<PlaceholderPageProps> = ({ title, description, icon }) => (
  <AppShell>
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-neutral-900">{title}</h1>
        <p className="text-sm text-neutral-500">{description}</p>
      </div>
      <EmptyState
        icon={icon}
        title={`${title} — Coming Soon`}
        description="This module is planned for a future release. Check back soon!"
        action={
          <Link to="/analyze">
            <Button variant="primary" size="sm" leftIcon={<Zap className="h-3.5 w-3.5" />}>
              Analyze an Email
            </Button>
          </Link>
        }
        className="py-24"
      />
    </div>
  </AppShell>
)

export const HistoryPage: FC = () => (
  <PlaceholderPage
    title="Analysis History"
    description="Browse all previously analyzed emails and filter by date, verdict, or domain."
    icon={<Clock className="h-6 w-6" />}
  />
)

export const ThreatIntelPage: FC = () => (
  <PlaceholderPage
    title="Threat Intelligence"
    description="Query reputation providers, browse IOC feeds, and explore domain/IP intelligence."
    icon={<Globe className="h-6 w-6" />}
  />
)

export const ReportsPage: FC = () => (
  <PlaceholderPage
    title="Reports"
    description="Scheduled reports, threat summaries, and analytics exports."
    icon={<BarChart3 className="h-6 w-6" />}
  />
)
