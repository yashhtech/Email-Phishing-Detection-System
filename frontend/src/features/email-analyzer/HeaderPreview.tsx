import { useState, type FC } from 'react'
import { ChevronDown, ChevronRight, FileSpreadsheet, Shield } from 'lucide-react'
import { StatusBadge } from '../../shared/ui/AnalyzerPrimitives'

interface HeaderPreviewProps {
  headers: Record<string, string>
}

export const HeaderPreview: FC<HeaderPreviewProps> = ({ headers }) => {
  const [showAll, setShowAll] = useState(false)
  const headerKeys = Object.keys(headers)

  if (headerKeys.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center rounded-lg border border-dashed border-gray-200 p-6 text-center">
        <FileSpreadsheet className="h-7 w-7 text-gray-300 mb-2" />
        <p className="text-sm font-medium text-gray-500">No RFC 822 headers entered</p>
        <p className="text-xs text-gray-400 mt-0.5">
          Paste raw headers to preview SPF, DKIM, DMARC, and routing metadata.
        </p>
      </div>
    )
  }

  // Detect key security headers
  const authResults = headers['Authentication-Results'] || headers['authentication-results'] || ''
  const receivedSpf = headers['Received-SPF'] || headers['received-spf'] || ''
  const dkimSig = headers['DKIM-Signature'] || headers['dkim-signature'] || ''

  const spfPass = authResults.toLowerCase().includes('spf=pass') || receivedSpf.toLowerCase().startsWith('pass')
  const spfFail = authResults.toLowerCase().includes('spf=fail') || receivedSpf.toLowerCase().startsWith('fail')

  const dkimPass = authResults.toLowerCase().includes('dkim=pass') || (!!dkimSig && !authResults.toLowerCase().includes('dkim=fail'))
  const dkimFail = authResults.toLowerCase().includes('dkim=fail')

  const dmarcPass = authResults.toLowerCase().includes('dmarc=pass')
  const dmarcFail = authResults.toLowerCase().includes('dmarc=fail')

  const displayedKeys = showAll ? headerKeys : headerKeys.slice(0, 8)

  return (
    <div className="space-y-3">
      {/* Quick Security Status Chips */}
      <div className="flex flex-wrap items-center gap-2 rounded-lg bg-violet-50/60 p-3 border border-violet-100">
        <div className="flex items-center gap-1.5 text-xs">
          <Shield className="h-3.5 w-3.5 text-violet-600" />
          <span className="font-semibold text-gray-700">SPF:</span>
          {spfPass ? (
            <StatusBadge variant="pass" label="PASS" />
          ) : spfFail ? (
            <StatusBadge variant="fail" label="FAIL" />
          ) : (
            <StatusBadge variant="none" label="NOT TESTED" />
          )}
        </div>

        <span className="text-gray-300">|</span>

        <div className="flex items-center gap-1.5 text-xs">
          <Shield className="h-3.5 w-3.5 text-violet-600" />
          <span className="font-semibold text-gray-700">DKIM:</span>
          {dkimPass ? (
            <StatusBadge variant="pass" label="PASS" />
          ) : dkimFail ? (
            <StatusBadge variant="fail" label="FAIL" />
          ) : (
            <StatusBadge variant="none" label="NOT TESTED" />
          )}
        </div>

        <span className="text-gray-300">|</span>

        <div className="flex items-center gap-1.5 text-xs">
          <Shield className="h-3.5 w-3.5 text-violet-600" />
          <span className="font-semibold text-gray-700">DMARC:</span>
          {dmarcPass ? (
            <StatusBadge variant="pass" label="PASS" />
          ) : dmarcFail ? (
            <StatusBadge variant="fail" label="FAIL" />
          ) : (
            <StatusBadge variant="none" label="NOT TESTED" />
          )}
        </div>
      </div>

      {/* Header Key-Value Table */}
      <div className="rounded-lg border border-gray-200 bg-white overflow-hidden shadow-sm">
        <table className="w-full text-left text-xs">
          <thead className="bg-gray-50 border-b border-gray-100 text-gray-500 uppercase tracking-wider font-semibold">
            <tr>
              <th className="px-3.5 py-2.5 w-1/3">Header Name</th>
              <th className="px-3.5 py-2.5">Value</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100 font-mono">
            {displayedKeys.map((k) => (
              <tr key={k} className="hover:bg-violet-50/20 transition-colors">
                <td className="px-3.5 py-2 font-medium text-violet-800 break-all">{k}</td>
                <td className="px-3.5 py-2 text-gray-700 break-all">{headers[k]}</td>
              </tr>
            ))}
          </tbody>
        </table>

        {headerKeys.length > 8 && (
          <button
            type="button"
            onClick={() => setShowAll((prev) => !prev)}
            className="w-full py-2 bg-gray-50 border-t border-gray-100 text-center text-xs font-semibold text-violet-600 hover:text-violet-700 hover:bg-violet-50/40 transition-colors flex items-center justify-center gap-1"
          >
            {showAll ? (
              <>
                <ChevronDown className="h-3.5 w-3.5" /> Show Fewer Headers
              </>
            ) : (
              <>
                <ChevronRight className="h-3.5 w-3.5" /> Show All {headerKeys.length} Headers
              </>
            )}
          </button>
        )}
      </div>
    </div>
  )
}
