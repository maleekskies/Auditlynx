import { useState } from 'react'
import FindingCard from './FindingCard.jsx'
import ScoreGauge from './ScoreGauge.jsx'

export default function HeadersChecker() {
  const [url, setUrl] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)

  async function runCheck(e) {
    e.preventDefault()
    if (!url.trim()) return
    setLoading(true)
    setError(null)
    setResult(null)
    try {
      const resp = await fetch('/api/check-headers', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
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
    acc[f.severity] = acc[f.severity] || []
    acc[f.severity].push(f)
    return acc
  }, {}) || {}

  return (
    <div className="max-w-4xl">
      <header className="mb-6">
        <div className="text-xs font-mono text-accent/80 tracking-widest mb-1.5">MODULE 01</div>
        <h1 className="font-display text-2xl font-semibold text-ink mb-2">Security Headers &amp; Config Checker</h1>
        <p className="text-muted text-sm leading-relaxed max-w-2xl">
          Fetches a target server-side and inspects its response for missing or misconfigured
          security headers, weak cookie flags, and information disclosure.
        </p>
      </header>

      <form onSubmit={runCheck} className="mb-8">
        <div className="flex items-center gap-2 bg-surface border border-border rounded-lg px-4 py-3 focus-within:border-accent transition-colors">
          <span className="font-mono text-accent select-none">$</span>
          <input
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="example.com or https://example.com/path"
            className="flex-1 bg-transparent outline-none font-mono text-sm text-ink placeholder:text-muted/60"
            spellCheck={false}
            autoCapitalize="off"
          />
          <button
            type="submit"
            disabled={loading}
            className="bg-accent hover:bg-accent/90 disabled:opacity-50 disabled:cursor-not-allowed text-white text-sm font-medium px-4 py-1.5 rounded-md transition-colors shrink-0 focus-ring"
          >
            {loading ? 'Scanning…' : 'Run scan'}
          </button>
        </div>
      </form>

      {error && (
        <div className="mb-6 rounded-md border border-risk-high/40 bg-risk-high/10 px-4 py-3 text-sm text-risk-high">
          {error}
        </div>
      )}

      {loading && (
        <div className="font-mono text-sm text-muted animate-pulse">Fetching response headers…</div>
      )}

      {result && !error && (
        <div className="space-y-6">
          <div className="bg-surface border border-border rounded-lg p-5 flex flex-wrap items-center justify-between gap-6">
            <ScoreGauge score={result.score} grade={result.grade} label="Overall grade" />
            <div className="text-sm font-mono text-muted">
              <div className="text-ink mb-1 break-all">{result.final_url}</div>
              <div>HTTP {result.status_code}</div>
            </div>
          </div>

          <div className="space-y-3">
            {['high', 'medium', 'low', 'pass'].map((sev) =>
              (grouped[sev] || []).map((f) => <FindingCard key={f.id} finding={f} />)
            )}
          </div>
        </div>
      )}

      {!result && !loading && !error && (
        <div className="border border-dashed border-border rounded-lg py-14 text-center">
          <p className="text-muted text-sm font-mono">Enter a domain above to run a scan.</p>
        </div>
      )}
    </div>
  )
}
