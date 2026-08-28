import { useState } from 'react'
import FindingCard from './FindingCard.jsx'

const SAMPLE = `From: PayPal Security <security@paypa1-verify.com>
Reply-To: attacker@evil-domain.example
Return-Path: <bounce@totally-different.example>
Subject: Urgent: Your account will be suspended
Message-ID: <abc123@mail.somehost.example>
Authentication-Results: mx.example.com; spf=fail smtp.mailfrom=paypa1-verify.com; dkim=fail; dmarc=fail
Content-Type: text/html

<html><body>
<p>Your account has been limited. Click here immediately to verify your account within 24 hours.</p>
<a href="http://192.0.2.5/login">https://paypal.com/login</a>
</body></html>`

const RISK_COLOR = {
  'High risk': '#E5484D',
  'Suspicious': '#F5A623',
  'Low risk': '#5B8DEF',
  'No strong indicators': '#3DD68C',
}

const CATEGORY_LABEL = {
  authentication: 'Authentication (SPF / DKIM / DMARC)',
  sender: 'Sender & domain analysis',
  links: 'Links & URLs',
  language: 'Language patterns',
  headers: 'Header anomalies',
  attachments: 'Attachments',
}

export default function PhishingAnalyzer() {
  const [raw, setRaw] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)

  async function runAnalysis(e) {
    e.preventDefault()
    if (!raw.trim()) return
    setLoading(true)
    setError(null)
    setResult(null)
    try {
      const resp = await fetch('/api/analyze-email', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ raw_email: raw }),
      })
      const data = await resp.json()
      if (data.error) {
        setError(data.error)
      } else {
        setResult(data)
      }
    } catch (err) {
      setError('Could not reach the analysis backend. Is the API server running?')
    } finally {
      setLoading(false)
    }
  }

  const grouped = result?.findings?.reduce((acc, f) => {
    acc[f.category] = acc[f.category] || []
    acc[f.category].push(f)
    return acc
  }, {}) || {}

  const riskColor = result ? (RISK_COLOR[result.risk_label] || '#8891A3') : '#8891A3'

  return (
    <div className="max-w-4xl">
      <header className="mb-6">
        <div className="text-xs font-mono text-accent/80 tracking-widest mb-1.5">MODULE 02</div>
        <h1 className="font-display text-2xl font-semibold text-ink mb-2">Phishing Email Analyzer</h1>
        <p className="text-muted text-sm leading-relaxed max-w-2xl">
          Paste the raw email source — full headers plus body. Checks authentication results,
          sender/domain mismatches, deceptive links, urgency language, and risky attachments.
          Heuristic triage for a human analyst, not an automated verdict.
        </p>
      </header>

      <form onSubmit={runAnalysis} className="mb-8">
        <div className="bg-surface border border-border rounded-lg focus-within:border-accent transition-colors overflow-hidden">
          <div className="flex items-center justify-between px-4 py-2 border-b border-border bg-surface2/60">
            <span className="text-xs font-mono text-muted">raw_email.eml</span>
            <button
              type="button"
              onClick={() => setRaw(SAMPLE)}
              className="text-xs font-mono text-accent hover:text-accent/80 transition-colors"
            >
              load sample →
            </button>
          </div>
          <textarea
            value={raw}
            onChange={(e) => setRaw(e.target.value)}
            placeholder={'From: sender@example.com\nTo: you@example.com\nSubject: ...\nAuthentication-Results: ...\n\n<body of the email>'}
            rows={12}
            spellCheck={false}
            className="w-full bg-transparent outline-none font-mono text-xs text-ink placeholder:text-muted/50 p-4 resize-y"
          />
        </div>
        <div className="flex justify-end mt-3">
          <button
            type="submit"
            disabled={loading}
            className="bg-accent hover:bg-accent/90 disabled:opacity-50 disabled:cursor-not-allowed text-white text-sm font-medium px-4 py-1.5 rounded-md transition-colors focus-ring"
          >
            {loading ? 'Analyzing…' : 'Analyze message'}
          </button>
        </div>
      </form>

      {error && (
        <div className="mb-6 rounded-md border border-risk-high/40 bg-risk-high/10 px-4 py-3 text-sm text-risk-high">
          {error}
        </div>
      )}

      {loading && (
        <div className="font-mono text-sm text-muted animate-pulse">Parsing headers and body…</div>
      )}

      {result && !error && (
        <div className="space-y-6">
          <div className="bg-surface border border-border rounded-lg p-5 flex flex-wrap items-center justify-between gap-4">
            <div>
              <div className="text-xs uppercase tracking-widest text-muted font-mono mb-1">Risk assessment</div>
              <div className="font-display text-xl font-semibold" style={{ color: riskColor }}>
                {result.risk_label}
              </div>
            </div>
            <div className="text-sm font-mono text-muted text-right">
              {result.summary?.from && <div className="text-ink break-all">From: {result.summary.from}</div>}
              {result.summary?.subject && <div>Subject: {result.summary.subject}</div>}
              <div className="mt-1">Score: {result.risk_score}/100</div>
            </div>
          </div>

          {Object.entries(CATEGORY_LABEL).map(([key, label]) =>
            grouped[key] ? (
              <div key={key}>
                <h3 className="text-xs font-mono uppercase tracking-widest text-muted mb-2.5">{label}</h3>
                <div className="space-y-3">
                  {grouped[key].map((f) => <FindingCard key={f.id} finding={f} />)}
                </div>
              </div>
            ) : null
          )}
        </div>
      )}

      {!result && !loading && !error && (
        <div className="border border-dashed border-border rounded-lg py-14 text-center">
          <p className="text-muted text-sm font-mono">Paste raw email source above, or load the sample.</p>
        </div>
      )}
    </div>
  )
}
