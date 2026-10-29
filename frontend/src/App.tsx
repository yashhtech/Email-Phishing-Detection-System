import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { LoginPage } from './pages/LoginPage'
import { DashboardPage } from './pages/DashboardPage'
import { EmailAnalyzerPage } from './pages/EmailAnalyzerPage'
import { NotFoundPage } from './pages/NotFoundPage'
import { AnalysisDetailPage } from './pages/AnalysisDetailPage'
import { AnalysisHistoryPage } from './pages/AnalysisHistoryPage'
import { AnalyticsPage } from './pages/AnalyticsPage'
import { ThreatIntelPage } from './pages/ThreatIntelPage'
import { ReportViewPage } from './pages/ReportViewPage'
import { ReportsPage } from './pages/ReportsPage'

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        {/* Auth */}
        <Route path="/login" element={<LoginPage />} />

        {/* App shell pages */}
        <Route path="/analyze" element={<EmailAnalyzerPage />} />
        <Route path="/dashboard" element={<DashboardPage />} />
        <Route path="/analytics" element={<AnalyticsPage />} />
        <Route path="/history" element={<AnalysisHistoryPage />} />
        <Route path="/threat-intel" element={<ThreatIntelPage />} />
        <Route path="/reports" element={<ReportsPage />} />
        <Route path="/analysis/:id" element={<AnalysisDetailPage />} />
        <Route path="/analysis/:id/report" element={<ReportViewPage />} />

        {/* Default redirect */}
        <Route path="/" element={<Navigate to="/analyze" replace />} />

        {/* 404 */}
        <Route path="*" element={<NotFoundPage />} />
      </Routes>
    </BrowserRouter>
  )
}
