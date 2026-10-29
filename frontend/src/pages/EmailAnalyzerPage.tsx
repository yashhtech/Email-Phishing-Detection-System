import { type FC } from 'react'
import {
  AlertCircle,
  CheckCircle,
  FileCode,
  FileSpreadsheet,
  FileText,
  Globe,
  Paperclip,
  UploadCloud,
  Zap,
} from 'lucide-react'
import { AnalysisResultView } from '../features/email-analyzer/AnalysisResultView'
import { AttachmentPreview } from '../features/email-analyzer/AttachmentPreview'
import { EmlUploadZone } from '../features/email-analyzer/EmlUploadZone'
import { HeaderPreview } from '../features/email-analyzer/HeaderPreview'
import { RawEmailInput } from '../features/email-analyzer/RawEmailInput'
import { StructuredEmailForm } from '../features/email-analyzer/StructuredEmailForm'
import { UrlExtractionPreview } from '../features/email-analyzer/UrlExtractionPreview'
import { useEmailAnalyzer } from '../features/email-analyzer/useEmailAnalyzer'
import { SectionCard, Spinner } from '../shared/ui/AnalyzerPrimitives'
import { AppShell } from '../shared/layout/AppShell'
import { cn } from '../shared/lib/utils'

export const EmailAnalyzerPage: FC = () => {
  const {
    mode,
    setMode,
    status,
    error,
    uploadProgress,
    result,
    structuredData,
    setStructuredData,
    formErrors,
    rawEmail,
    setRawEmail,
    rawError,
    emlFile,
    setEmlFile,
    uploadAttachments,
    addAttachment,
    removeAttachment,
    uploadError,
    liveUrls,
    liveHeaders,
    analyzeEmail,
    resetAnalysis,
  } = useEmailAnalyzer()

  const isBusy = status === 'validating' || status === 'uploading' || status === 'analyzing'

  const tabs = [
    { key: 'structured' as const, label: 'Structured Form', icon: FileText },
    { key: 'raw' as const, label: 'Paste Email', icon: FileCode },
    { key: 'upload' as const, label: 'Upload .EML', icon: UploadCloud },
  ]

  return (
    <AppShell>
      {result ? (
        <AnalysisResultView result={result} onReset={resetAnalysis} />
      ) : (
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
          {/* ----------------------------------------------------------------
              Left 8 columns — Input Mode Tabs & Forms
          ---------------------------------------------------------------- */}
          <div className="space-y-6 lg:col-span-8">
            {/* Page title */}
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-neutral-900">
                Email Threat Analyzer
              </h1>
              <p className="text-sm text-neutral-500">
                Multi-layer analysis: header auth, URL reputation, ML classification, LLM reasoning
              </p>
            </div>

            {/* Mode selector + form card */}
            <div className="overflow-hidden rounded-2xl border border-neutral-150 bg-white shadow-sm">
              {/* Segmented tab bar */}
              <div className="border-b border-neutral-100 bg-neutral-50/70 p-2">
                <div
                  role="tablist"
                  aria-label="Email input mode"
                  className="grid grid-cols-3 gap-1 rounded-xl bg-neutral-200/60 p-1"
                >
                  {tabs.map(({ key, label, icon: Icon }) => (
                    <button
                      key={key}
                      type="button"
                      role="tab"
                      aria-selected={mode === key}
                      aria-controls={`panel-${key}`}
                      id={`tab-${key}`}
                      disabled={isBusy}
                      onClick={() => setMode(key)}
                      className={cn(
                        'flex items-center justify-center gap-2 rounded-lg py-2.5 text-xs font-semibold transition-all duration-120',
                        mode === key
                          ? 'bg-white text-violet-700 shadow-sm'
                          : 'text-neutral-600 hover:text-neutral-900',
                      )}
                    >
                      <Icon className="h-4 w-4" />
                      <span>{label}</span>
                    </button>
                  ))}
                </div>
              </div>

              {/* Form panels */}
              <div className="p-6">
                {mode === 'structured' && (
                  <div role="tabpanel" id="panel-structured" aria-labelledby="tab-structured">
                    <StructuredEmailForm
                      data={structuredData}
                      onChange={(patch) => setStructuredData((prev) => ({ ...prev, ...patch }))}
                      errors={formErrors}
                      attachments={uploadAttachments}
                      onAddAttachments={addAttachment}
                      onRemoveAttachment={removeAttachment}
                      disabled={isBusy}
                    />
                  </div>
                )}

                {mode === 'raw' && (
                  <div role="tabpanel" id="panel-raw" aria-labelledby="tab-raw">
                    <RawEmailInput
                      value={rawEmail}
                      onChange={setRawEmail}
                      error={rawError}
                      disabled={isBusy}
                    />
                  </div>
                )}

                {mode === 'upload' && (
                  <div role="tabpanel" id="panel-upload" aria-labelledby="tab-upload">
                    <EmlUploadZone
                      emlFile={emlFile}
                      onSetEmlFile={setEmlFile}
                      attachments={uploadAttachments}
                      onAddAttachments={addAttachment}
                      onRemoveAttachment={removeAttachment}
                      error={uploadError}
                      uploadProgress={uploadProgress}
                      disabled={isBusy}
                    />
                  </div>
                )}

                {/* Submission error */}
                {error && (
                  <div
                    role="alert"
                    className="mt-6 flex items-start gap-3 rounded-xl border border-red-200 bg-red-50 p-4 text-xs text-red-800"
                  >
                    <AlertCircle className="mt-0.5 h-5 w-5 shrink-0 text-red-600" />
                    <div className="space-y-0.5">
                      <p className="font-bold">Analysis Failed</p>
                      <p>{error}</p>
                    </div>
                  </div>
                )}

                {/* CTA */}
                <div className="mt-8 flex flex-col items-center justify-between gap-4 border-t border-neutral-100 pt-6 sm:flex-row">
                  <p className="text-xs text-neutral-500">
                    Inspection tier:{' '}
                    <strong className="font-semibold text-neutral-700">
                      Header + URL + Attachment + ML + LLM
                    </strong>
                  </p>

                  <button
                    type="button"
                    disabled={isBusy}
                    onClick={analyzeEmail}
                    aria-busy={isBusy}
                    className="btn-primary w-full min-w-[200px] !px-8 !py-3.5 text-base shadow-violet-300 sm:w-auto"
                  >
                    {isBusy ? (
                      <>
                        <Spinner size="sm" className="text-white" />
                        <span>
                          {status === 'validating'
                            ? 'Validating…'
                            : status === 'uploading'
                              ? `Uploading (${uploadProgress}%)…`
                              : 'Analyzing…'}
                        </span>
                      </>
                    ) : (
                      <>
                        <Zap className="h-5 w-5 fill-current" />
                        <span>Analyze Email</span>
                      </>
                    )}
                  </button>
                </div>
              </div>
            </div>
          </div>

          {/* ----------------------------------------------------------------
              Right 4 columns — Live Inspection Previews
          ---------------------------------------------------------------- */}
          <div className="space-y-6 lg:col-span-4">
            <SectionCard
              title="URL Extraction Preview"
              icon={<Globe className="h-4 w-4" />}
              badge={
                liveUrls.length > 0 ? (
                  <span className="rounded-full bg-violet-100 px-2 py-0.5 text-[11px] font-semibold text-violet-800">
                    {liveUrls.length} found
                  </span>
                ) : undefined
              }
            >
              <UrlExtractionPreview urls={liveUrls} />
            </SectionCard>

            <SectionCard
              title="Authentication & Headers"
              icon={<FileSpreadsheet className="h-4 w-4" />}
              badge={
                Object.keys(liveHeaders).length > 0 ? (
                  <span className="rounded-full bg-violet-100 px-2 py-0.5 text-[11px] font-semibold text-violet-800">
                    {Object.keys(liveHeaders).length} headers
                  </span>
                ) : undefined
              }
            >
              <HeaderPreview headers={liveHeaders} />
            </SectionCard>

            <SectionCard
              title="Attachment Telemetry"
              icon={<Paperclip className="h-4 w-4" />}
              badge={
                uploadAttachments.length > 0 ? (
                  <span className="rounded-full bg-violet-100 px-2 py-0.5 text-[11px] font-semibold text-violet-800">
                    {uploadAttachments.length} files
                  </span>
                ) : undefined
              }
            >
              <AttachmentPreview
                attachments={uploadAttachments}
                onRemove={removeAttachment}
                disabled={isBusy}
              />
            </SectionCard>

            {/* Privacy notice */}
            <div className="rounded-xl border border-neutral-200 bg-white p-4 text-xs text-neutral-500 shadow-xs space-y-1.5">
              <div className="flex items-center gap-1.5 font-semibold text-neutral-700">
                <CheckCircle className="h-4 w-4 text-success-600" />
                <span>Privacy & Zero-Direct-LLM Guarantee</span>
              </div>
              <p className="leading-relaxed">
                Raw emails are never transmitted directly to third-party LLMs from your browser. All
                telemetry passes through sanitized backend security gateways.
              </p>
            </div>
          </div>
        </div>
      )}
    </AppShell>
  )
}
