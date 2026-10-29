import { type ChangeEvent, type FC, useRef } from 'react'
import { Code, FileText, Paperclip } from 'lucide-react'
import type { AttachmentItem, StructuredFormData } from './useEmailAnalyzer'
import { MAX_BODY_CHARS } from './useEmailAnalyzer'
import { AttachmentPreview } from './AttachmentPreview'
import { Textarea, TextInput } from '../../shared/ui/AnalyzerPrimitives'

interface StructuredEmailFormProps {
  data: StructuredFormData
  onChange: (patch: Partial<StructuredFormData>) => void
  errors: Record<string, string>
  attachments: AttachmentItem[]
  onAddAttachments: (files: FileList | File[]) => void
  onRemoveAttachment: (id: string) => void
  disabled?: boolean
}

export const StructuredEmailForm: FC<StructuredEmailFormProps> = ({
  data,
  onChange,
  errors,
  attachments,
  onAddAttachments,
  onRemoveAttachment,
  disabled,
}) => {
  const fileInputRef = useRef<HTMLInputElement>(null)

  const handleFileChange = (e: ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      onAddAttachments(e.target.files)
      e.target.value = ''
    }
  }

  return (
    <div className="space-y-5">
      {/* Sender and Recipients */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <TextInput
          id="from"
          label="From (Sender)"
          required
          placeholder="e.g. security-update@trusted-bank.com"
          value={data.from}
          error={errors.from}
          disabled={disabled}
          onChange={(v) => onChange({ from: v })}
          hint="Sender email address to authenticate via SPF/DKIM"
        />

        <TextInput
          id="to"
          label="To (Recipient)"
          required
          placeholder="e.g. employee@company.com"
          value={data.to}
          error={errors.to}
          disabled={disabled}
          onChange={(v) => onChange({ to: v })}
          hint="Multiple addresses separated by comma"
        />
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <TextInput
          id="cc"
          label="CC (Carbon Copy)"
          placeholder="e.g. audit@company.com"
          value={data.cc}
          error={errors.cc}
          disabled={disabled}
          onChange={(v) => onChange({ cc: v })}
          hint="Optional secondary recipients"
        />

        <TextInput
          id="replyTo"
          label="Reply-To"
          placeholder="e.g. support@external-provider.com"
          value={data.replyTo}
          error={errors.replyTo}
          disabled={disabled}
          onChange={(v) => onChange({ replyTo: v })}
          hint="Flagged if domain differs from sender"
        />
      </div>

      {/* Subject */}
      <TextInput
        id="subject"
        label="Subject"
        required
        placeholder="e.g. URGENT: Verify your account credentials immediately"
        value={data.subject}
        error={errors.subject}
        disabled={disabled}
        maxLength={500}
        onChange={(v) => onChange({ subject: v })}
      />

      {/* Body with Plain / HTML toggle */}
      <div className="space-y-1.5">
        <div className="flex items-center justify-between">
          <label htmlFor="body" className="form-label mb-0">
            Email Body Content <span className="text-red-500">*</span>
          </label>
          <div className="flex items-center rounded-lg border border-gray-200 bg-gray-50 p-0.5 text-xs font-medium">
            <button
              type="button"
              onClick={() => onChange({ bodyType: 'plain' })}
              className={`flex items-center gap-1 rounded-md px-2.5 py-1 transition-all ${
                data.bodyType === 'plain'
                  ? 'bg-white text-violet-700 shadow-sm font-semibold'
                  : 'text-gray-500 hover:text-gray-700'
              }`}
            >
              <FileText className="h-3 w-3" /> Plain Text
            </button>
            <button
              type="button"
              onClick={() => onChange({ bodyType: 'html' })}
              className={`flex items-center gap-1 rounded-md px-2.5 py-1 transition-all ${
                data.bodyType === 'html'
                  ? 'bg-white text-violet-700 shadow-sm font-semibold'
                  : 'text-gray-500 hover:text-gray-700'
              }`}
            >
              <Code className="h-3 w-3" /> Raw HTML
            </button>
          </div>
        </div>

        <Textarea
          id="body"
          label=""
          rows={7}
          required
          placeholder={
            data.bodyType === 'plain'
              ? 'Paste plain text body here. Any URLs or indicators will be automatically extracted...'
              : '<html><body><p>Paste raw HTML payload with anchor tags...</p></body></html>'
          }
          value={data.body}
          error={errors.body}
          disabled={disabled}
          maxLength={MAX_BODY_CHARS}
          onChange={(v) => onChange({ body: v })}
          hint="Supports up to 250,000 characters. URLs and phishing heuristics are inspected live."
        />
      </div>

      {/* Optional RFC Headers */}
      <div className="space-y-1">
        <Textarea
          id="headers"
          label="Optional RFC 822 Headers"
          rows={3}
          placeholder="Received-SPF: pass&#10;Authentication-Results: spf=pass dkim=pass dmarc=pass&#10;Message-ID: <12345@example.com>"
          value={data.headers}
          disabled={disabled}
          maxLength={50_000}
          onChange={(v) => onChange({ headers: v })}
          hint="Paste raw headers to simulate SPF, DKIM, DMARC, and transit hop analysis."
        />
      </div>

      {/* Attachments Section */}
      <div className="space-y-2 pt-2 border-t border-gray-100">
        <div className="flex items-center justify-between">
          <div>
            <h4 className="text-xs font-semibold uppercase tracking-wider text-gray-700">
              Attachments (Optional)
            </h4>
            <p className="text-xs text-gray-400">
              Max 10 MB per file, 25 MB total. Executables and archives are flagged.
            </p>
          </div>

          <button
            type="button"
            disabled={disabled}
            onClick={() => fileInputRef.current?.click()}
            className="btn-secondary !py-1.5 !px-3 text-xs"
          >
            <Paperclip className="h-3.5 w-3.5" /> Add Files
          </button>
          <input
            ref={fileInputRef}
            type="file"
            multiple
            className="hidden"
            onChange={handleFileChange}
            accept=".pdf,.doc,.docx,.xls,.xlsx,.ppt,.pptx,.zip,.7z,.tar,.gz,.txt,.csv,.png,.jpg,.jpeg,.eml,.msg,.exe,.bat"
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
