import { type ChangeEvent, type DragEvent, type FC, useRef, useState } from 'react'
import { AlertCircle, CheckCircle, FileUp, Paperclip, UploadCloud, X } from 'lucide-react'
import type { AttachmentItem } from './useEmailAnalyzer'
import { AttachmentPreview } from './AttachmentPreview'

interface EmlUploadZoneProps {
  emlFile: File | null
  onSetEmlFile: (file: File | null) => void
  attachments: AttachmentItem[]
  onAddAttachments: (files: FileList | File[]) => void
  onRemoveAttachment: (id: string) => void
  error?: string | null
  uploadProgress?: number
  disabled?: boolean
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

export const EmlUploadZone: FC<EmlUploadZoneProps> = ({
  emlFile,
  onSetEmlFile,
  attachments,
  onAddAttachments,
  onRemoveAttachment,
  error,
  uploadProgress = 0,
  disabled,
}) => {
  const [isDragOver, setIsDragOver] = useState(false)
  const emlInputRef = useRef<HTMLInputElement>(null)
  const attInputRef = useRef<HTMLInputElement>(null)

  const handleDragOver = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault()
    e.stopPropagation()
    if (!disabled) setIsDragOver(true)
  }

  const handleDragLeave = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault()
    e.stopPropagation()
    setIsDragOver(false)
  }

  const handleDrop = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault()
    e.stopPropagation()
    setIsDragOver(false)
    if (disabled) return

    const files = e.dataTransfer.files
    if (files.length === 0) return

    // Find first .eml file
    const droppedEml = Array.from(files).find(
      (f) =>
        f.name.toLowerCase().endsWith('.eml') ||
        f.name.toLowerCase().endsWith('.msg') ||
        f.name.toLowerCase().endsWith('.txt'),
    )

    if (droppedEml) {
      onSetEmlFile(droppedEml)
      // Any remaining files are treated as extra attachments
      const remaining = Array.from(files).filter((f) => f !== droppedEml)
      if (remaining.length > 0) {
        onAddAttachments(remaining)
      }
    } else {
      // If no .eml file was in the drop, treat as attachments if an eml is already selected
      onAddAttachments(files)
    }
  }

  const handleEmlChange = (e: ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      onSetEmlFile(e.target.files[0])
      e.target.value = ''
    }
  }

  const handleAttachmentChange = (e: ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      onAddAttachments(e.target.files)
      e.target.value = ''
    }
  }

  return (
    <div className="space-y-5">
      {/* Primary .eml Drag & Drop Zone */}
      {!emlFile ? (
        <div
          role="region"
          aria-label="Email file dropzone"
          tabIndex={0}
          onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ' ') {
              e.preventDefault()
              emlInputRef.current?.click()
            }
          }}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
          onClick={() => emlInputRef.current?.click()}
          className={`dropzone ${isDragOver ? 'dropzone-active' : ''} ${
            disabled ? 'opacity-50 cursor-not-allowed' : ''
          }`}
        >
          <div className="rounded-full bg-violet-100 p-4 text-violet-600 shadow-sm">
            <UploadCloud className="h-8 w-8" />
          </div>

          <div className="space-y-1">
            <p className="text-sm font-semibold text-gray-800">
              Drag & Drop your <span className="text-violet-600 font-bold">.eml</span> or{' '}
              <span className="text-violet-600 font-bold">.msg</span> file here
            </p>
            <p className="text-xs text-gray-500">
              or <span className="text-violet-600 underline font-medium">browse from your computer</span>
            </p>
          </div>

          <p className="text-[11px] text-gray-400">
            Supported formats: RFC 822 .eml, Outlook .msg, raw .txt (up to 25 MB)
          </p>

          <input
            ref={emlInputRef}
            type="file"
            className="hidden"
            accept=".eml,.msg,.txt"
            onChange={handleEmlChange}
            disabled={disabled}
          />
        </div>
      ) : (
        /* Selected File Card */
        <div className="rounded-xl border border-violet-200 bg-violet-50/50 p-4 shadow-sm space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3 min-w-0">
              <span className="p-2.5 rounded-lg bg-violet-600 text-white shadow-sm shrink-0">
                <FileUp className="h-5 w-5" />
              </span>

              <div className="min-w-0 space-y-0.5">
                <div className="flex items-center gap-2">
                  <p className="text-sm font-bold text-gray-900 truncate">{emlFile.name}</p>
                  <span className="inline-flex items-center gap-1 rounded bg-green-100 px-2 py-0.5 text-xs font-semibold text-green-800">
                    <CheckCircle className="h-3 w-3" /> Ready
                  </span>
                </div>
                <p className="text-xs text-gray-500">
                  {formatBytes(emlFile.size)} • Last modified{' '}
                  {new Date(emlFile.lastModified).toLocaleDateString()}
                </p>
              </div>
            </div>

            <button
              type="button"
              disabled={disabled}
              onClick={() => onSetEmlFile(null)}
              className="p-1.5 text-gray-400 hover:text-red-500 hover:bg-red-50 rounded-lg transition-colors"
              aria-label="Remove selected .eml file"
            >
              <X className="h-4 w-4" />
            </button>
          </div>

          {/* Upload Progress Bar (when uploading) */}
          {uploadProgress > 0 && uploadProgress < 100 && (
            <div className="space-y-1">
              <div className="flex justify-between text-xs text-gray-500">
                <span>Uploading payload...</span>
                <span className="font-semibold text-violet-700">{uploadProgress}%</span>
              </div>
              <div className="h-1.5 w-full bg-violet-100 rounded-full overflow-hidden">
                <div
                  className="h-full bg-violet-600 transition-all duration-300 rounded-full"
                  style={{ width: `${uploadProgress}%` }}
                />
              </div>
            </div>
          )}
        </div>
      )}

      {/* Validation Error Banner */}
      {error && (
        <div className="rounded-lg bg-red-50 border border-red-200 p-3 text-xs text-red-700 flex items-start gap-2" role="alert">
          <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" />
          <span>{error}</span>
        </div>
      )}

      {/* Optional Supplementary Attachments */}
      <div className="space-y-3 pt-3 border-t border-gray-100">
        <div className="flex items-center justify-between">
          <div>
            <h4 className="text-xs font-semibold uppercase tracking-wider text-gray-700">
              Optional Accompanying Attachments
            </h4>
            <p className="text-xs text-gray-400">
              Attach files that were extracted or forwarded separately from the email body.
            </p>
          </div>

          <button
            type="button"
            disabled={disabled}
            onClick={() => attInputRef.current?.click()}
            className="btn-secondary !py-1.5 !px-3 text-xs"
          >
            <Paperclip className="h-3.5 w-3.5" /> Add Attachments
          </button>
          <input
            ref={attInputRef}
            type="file"
            multiple
            className="hidden"
            onChange={handleAttachmentChange}
            disabled={disabled}
          />
        </div>

        {attachments.length > 0 && (
          <AttachmentPreview
            attachments={attachments}
            onRemove={onRemoveAttachment}
            disabled={disabled}
          />
        )}
      </div>
    </div>
  )
}
