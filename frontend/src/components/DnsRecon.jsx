import { useState } from 'react'
import FindingCard from './FindingCard.jsx'

const RISK_COLOR = {
  'High risk': '#E5484D',
  'Suspicious': '#F5A623',
  'Low risk': '#5B8DEF',
  'No strong indicators': '#3DD68C',
}

const CATEGORY_LABEL = {
  registration: 'Domain registration',
  dns: 'DNS records',
  'email-auth': 'Email authentication (SPF / DMARC)',
}

export default function DnsRecon() {
  const [domain, setDomain] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)

  async function runRecon(e) {
    e.preventDefault()
    if (!domain.trim()) return
    setLoading(true)
    setError(null)
    setResult(null)
    try {
      const resp = await fetch('/api/recon-domain', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain }),
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

  const worstSeverity = result?.findings?.some((f) => f.severity === 'high')
    ? 'high'
    : result?.findings?.some((f) => f.severity === 'medium')
    ? 'medium'
    : 'pass'
  const summaryColor = { high: '#E5484D', medium: '#F5A623', pass: '#3DD68C' }[worstSeverity]

  return (
    <div className="max-w-4xl">
      <header className="mb-6">
        <div className="text-xs font-mono text-accent/80 tracking-widest mb-1.5">MODULE 03</div>
        <h1 className="font-display text-2xl font-semibold text-ink mb-2">DNS &amp; Domain Recon</h1>
        <p className="text-muted text-sm leading-relaxed max-w-2xl">
          Looks up a domain's registration age, DNS records, and email authentication (SPF/DMARC)
          setup. Freshly-registered domains and missing email auth are common phishing signals —
          pairs well with the Phishing Analyzer.
        </p>
      </header>

      <form onSubmit={runRecon} className="mb-8">
        <div className="flex items-center gap-2 bg-surface border border-border rounded-lg px-4 py-3 focus-within:border-accent transition-colors">
          <span className="font-mono text-accent select-none">$</span>
          <input
            type="text"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            placeholder="example.com"
            className="flex-1 bg-transparent outline-none font-mono text-sm text-ink placeholder:text-muted/60"
            spellCheck={false}
            autoCapitalize="off"
          />
          <button
            type="submit"
            disabled={loading}
            className="bg-accent hover:bg-accent/90 disabled:opacity-50 disabled:cursor-not-allowed text-white text-sm font-medium px-4 py-1.5 rounded-md transition-colors shrink-0 focus-ring"
          >
            {loading ? 'Looking up…' : 'Run recon'}
          </button>
        </div>
      </form>

      {error && (
        <div className="mb-6 rounded-md border border-risk-high/40 bg-risk-high/10 px-4 py-3 text-sm text-risk-high">
          {error}
        </div>
      )}

      {loading && (
        <div className="font-mono text-sm text-muted animate-pulse">Querying DNS and registration records…</div>
      )}

      {result && !error && (
        <div className="space-y-6">
          <div className="bg-surface border border-border rounded-lg p-5 flex flex-wrap items-center justify-between gap-4">
            <div>
              <div className="text-xs uppercase tracking-widest text-muted font-mono mb-1">Domain</div>
              <div className="font-display text-xl font-semibold text-ink">{result.domain}</div>
            </div>
            <div className="text-sm font-mono text-muted text-right">
              {result.summary?.registered && (
                <div>Registered: <span className="text-ink">{result.summary.registered}</span> ({result.summary.age_days} days ago)</div>
              )}
              {result.summary?.registrar && <div>Registrar: {result.summary.registrar}</div>}
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
          <p className="text-muted text-sm font-mono">Enter a domain above to run recon.</p>
        </div>
      )}
    </div>
  )
}
