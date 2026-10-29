import { type FC } from 'react'
import { FileCode, RotateCcw, Sparkles } from 'lucide-react'
import { MAX_BODY_CHARS } from './useEmailAnalyzer'
import { Textarea } from '../../shared/ui/AnalyzerPrimitives'

interface RawEmailInputProps {
  value: string
  onChange: (val: string) => void
  error?: string | null
  disabled?: boolean
}

const SAMPLE_PHISHING_EMAIL = `From: "PayPal Security Team" <service@paypa1-verify-security.top>
To: recipient@target-company.com
Subject: URGENT: Your PayPal account has been limited due to suspicious activity
Date: Mon, 29 Sep 2026 13:45:00 +0000
Message-ID: <20260929134500.123456@paypa1-verify-security.top>
Reply-To: support-reply@phish-collector.com
Authentication-Results: spf=fail (sender IP 185.220.101.5 is not allowed) dkim=fail dmarc=fail
Received: from 185.220.101.5 by mail.target-company.com with ESMTP; Mon, 29 Sep 2026 13:45:01 +0000

Dear Valued Customer,

We detected an unauthorized login attempt on your account from an unrecognized IP address (194.26.29.112).
For your security, your account privileges have been restricted.

Please confirm your identity within 24 hours to prevent permanent suspension:
https://194.26.29.112/paypal-login/auth?id=992812

Alternatively, verify your billing records here:
http://paypa1-login-portal.top/verification/secure

Thank you for your prompt cooperation,
PayPal Global Fraud Prevention Department`

export const RawEmailInput: FC<RawEmailInputProps> = ({
  value,
  onChange,
  error,
  disabled,
}) => {
  return (
    <div className="space-y-4">
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h3 className="text-sm font-semibold text-gray-800">
            Paste Complete RFC 822 / MIME Email
          </h3>
          <p className="text-xs text-gray-500">
            Includes raw headers, MIME boundaries, base64 attachments, and HTML/text parts.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            disabled={disabled}
            onClick={() => onChange(SAMPLE_PHISHING_EMAIL)}
            className="btn-secondary !py-1 !px-2.5 text-xs text-violet-700 bg-violet-50 hover:bg-violet-100"
          >
            <Sparkles className="h-3.5 w-3.5 text-violet-600" />
            Load Phishing Sample
          </button>
          {value && (
            <button
              type="button"
              disabled={disabled}
              onClick={() => onChange('')}
              className="text-xs text-gray-400 hover:text-red-500 flex items-center gap-1 transition-colors px-2 py-1"
            >
              <RotateCcw className="h-3 w-3" /> Clear
            </button>
          )}
        </div>
      </div>

      <Textarea
        id="rawEmail"
        label=""
        rows={14}
        value={value}
        error={error || undefined}
        disabled={disabled}
        maxLength={MAX_BODY_CHARS}
        placeholder={`From: "Sender Name" <sender@domain.com>\nTo: <recipient@company.com>\nSubject: Important Update\nAuthentication-Results: spf=pass dkim=pass dmarc=pass\n\nEmail body content here with URLs...`}
        onChange={onChange}
        hint="Paste headers and body as exported from your mail client (.eml file source, Outlook, or webmail)."
      />

      <div className="rounded-lg bg-violet-50/50 border border-violet-100 p-3 text-xs text-violet-900 flex items-start gap-2.5">
        <FileCode className="h-4 w-4 text-violet-600 shrink-0 mt-0.5" />
        <p>
          The parser will automatically reconstruct the RFC headers tree, run SPF/DKIM/DMARC checks, defang all embedded URLs, and isolate any attachments encoded in the message.
        </p>
      </div>
    </div>
  )
}
