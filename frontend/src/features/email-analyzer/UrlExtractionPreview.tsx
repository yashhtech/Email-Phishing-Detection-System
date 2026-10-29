import { type FC } from 'react'
import { Globe, ShieldAlert } from 'lucide-react'
import type { DetectedUrl } from './useEmailAnalyzer'
import { StatusBadge } from '../../shared/ui/AnalyzerPrimitives'

interface UrlExtractionPreviewProps {
  urls: DetectedUrl[]
}

export const UrlExtractionPreview: FC<UrlExtractionPreviewProps> = ({ urls }) => {
  if (urls.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center rounded-lg border border-dashed border-gray-200 p-6 text-center">
        <Globe className="h-7 w-7 text-gray-300 mb-2" />
        <p className="text-sm font-medium text-gray-500">No URLs detected</p>
        <p className="text-xs text-gray-400 mt-0.5">
          Type or paste links into the email body to preview extraction and defanging.
        </p>
      </div>
    )
  }

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between text-xs text-gray-500 mb-1">
        <span className="font-semibold text-gray-700">
          {urls.length} {urls.length === 1 ? 'URL' : 'URLs'} Extracted
        </span>
        <span className="text-gray-400">All links defanged for safe preview</span>
      </div>

      <div className="divide-y divide-gray-100 rounded-lg border border-gray-200 bg-white overflow-hidden shadow-sm">
        {urls.map((u, i) => (
          <div key={i} className="flex flex-col gap-1.5 p-3 sm:flex-row sm:items-center sm:justify-between hover:bg-violet-50/30 transition-colors">
            <div className="flex items-start gap-2.5 min-w-0">
              <span className="mt-0.5 shrink-0 text-violet-500">
                {u.isIp ? (
                  <ShieldAlert className="h-4 w-4 text-red-500" />
                ) : (
                  <Globe className="h-4 w-4 text-violet-500" />
                )}
              </span>
              <div className="min-w-0 space-y-0.5">
                <p className="font-mono text-xs font-semibold text-gray-900 break-all">
                  {u.defanged}
                </p>
                <div className="flex flex-wrap items-center gap-2 text-xs text-gray-400">
                  <span>Host: <strong className="font-medium text-gray-600">{u.domain || 'N/A'}</strong></span>
                  <span>•</span>
                  <span>Proto: <strong className="font-medium text-gray-600">{u.protocol}</strong></span>
                </div>
              </div>
            </div>

            <div className="shrink-0 flex items-center gap-2 pt-1 sm:pt-0">
              {u.isIp ? (
                <StatusBadge variant="fail" label="Bare IP" />
              ) : (
                <StatusBadge variant="clean" label="Domain" />
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
