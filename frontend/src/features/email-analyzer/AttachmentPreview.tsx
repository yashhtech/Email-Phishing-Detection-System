import { type FC } from 'react'
import { AlertTriangle, Archive, FileCode, FileText, Paperclip, Trash2 } from 'lucide-react'
import type { AttachmentItem } from './useEmailAnalyzer'

interface AttachmentPreviewProps {
  attachments: AttachmentItem[]
  onRemove?: (id: string) => void
  disabled?: boolean
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

export const AttachmentPreview: FC<AttachmentPreviewProps> = ({
  attachments,
  onRemove,
  disabled,
}) => {
  if (attachments.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center rounded-lg border border-dashed border-gray-200 p-6 text-center">
        <Paperclip className="h-7 w-7 text-gray-300 mb-2" />
        <p className="text-sm font-medium text-gray-500">No attachments attached</p>
        <p className="text-xs text-gray-400 mt-0.5">
          Attach files below or upload a .eml bundle to inspect embedded artifacts.
        </p>
      </div>
    )
  }

  const totalSize = attachments.reduce((acc, a) => acc + a.size, 0)

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between text-xs text-gray-500 mb-1">
        <span className="font-semibold text-gray-700">
          {attachments.length} {attachments.length === 1 ? 'Attachment' : 'Attachments'}
        </span>
        <span className="text-gray-400">Total size: {formatBytes(totalSize)}</span>
      </div>

      <div className="divide-y divide-gray-100 rounded-lg border border-gray-200 bg-white overflow-hidden shadow-sm">
        {attachments.map((att) => (
          <div
            key={att.id}
            className="flex items-center justify-between p-3 hover:bg-violet-50/20 transition-colors"
          >
            <div className="flex items-center gap-3 min-w-0">
              <span className="shrink-0 p-2 rounded-lg bg-violet-50 text-violet-600">
                {att.isExecutable ? (
                  <FileCode className="h-4 w-4 text-red-500" />
                ) : att.isArchive ? (
                  <Archive className="h-4 w-4 text-amber-500" />
                ) : (
                  <FileText className="h-4 w-4 text-violet-500" />
                )}
              </span>

              <div className="min-w-0 space-y-0.5">
                <div className="flex items-center gap-2">
                  <p className="text-xs font-semibold text-gray-900 truncate">{att.name}</p>
                  {att.isExecutable && (
                    <span className="inline-flex items-center gap-1 rounded bg-red-100 px-1.5 py-0.5 text-[10px] font-bold text-red-700">
                      <AlertTriangle className="h-2.5 w-2.5" />
                      EXECUTABLE
                    </span>
                  )}
                  {att.isArchive && (
                    <span className="inline-flex items-center rounded bg-amber-100 px-1.5 py-0.5 text-[10px] font-semibold text-amber-800">
                      ARCHIVE
                    </span>
                  )}
                </div>
                <p className="text-xs text-gray-400">
                  {formatBytes(att.size)} • {att.type || 'unknown type'}
                </p>
              </div>
            </div>

            {onRemove && (
              <button
                type="button"
                disabled={disabled}
                onClick={() => onRemove(att.id)}
                aria-label={`Remove attachment ${att.name}`}
                className="shrink-0 p-1.5 text-gray-400 hover:text-red-500 hover:bg-red-50 rounded-md transition-colors disabled:opacity-50"
              >
                <Trash2 className="h-4 w-4" />
              </button>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}
