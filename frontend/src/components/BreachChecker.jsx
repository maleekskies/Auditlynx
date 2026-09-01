import { useState } from 'react'
import FindingCard from './FindingCard.jsx'

export default function BreachChecker() {
  const [email, setEmail] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)

  async function runCheck(e) {
    e.preventDefault()
    if (!email.trim()) return
    setLoading(true)
    setError(null)
    setResult(null)
    try {
      const resp = await fetch('/api/check-breach', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email }),
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

  const hasBreaches = result && result.breach_count > 0
  const statusColor = result ? (hasBreaches ? '#E5484D' : '#3DD68C') : '#8891A3'

  return (
    <div className="max-w-4xl">
      <header className="mb-6">
        <div className="text-xs font-mono text-accent/80 tracking-widest mb-1.5">MODULE 05</div>
        <h1 className="font-display text-2xl font-semibold text-ink mb-2">Breach Checker</h1>
        <p className="text-muted text-sm leading-relaxed max-w-2xl">
          Checks an email address against a database of known data breaches. Shows where it was
          exposed, what data was leaked, and what to do about it.
        </p>
        <p className="text-xs text-muted/70 leading-relaxed max-w-2xl mt-2 italic">
          No breach database is complete — a clean result is a good sign, not a guarantee.
          Nothing you enter here is stored.
        </p>
      </header>

      <form onSubmit={runCheck} className="mb-8">
        <div className="flex items-center gap-2 bg-surface border border-border rounded-lg px-4 py-3 focus-within:border-accent transition-colors">
          <span className="font-mono text-accent select-none">$</span>
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="you@example.com"
            className="flex-1 bg-transparent outline-none font-mono text-sm text-ink placeholder:text-muted/60"
            spellCheck={false}
            autoCapitalize="off"
          />
          <button
            type="submit"
            disabled={loading}
            className="bg-accent hover:bg-accent/90 disabled:opacity-50 disabled:cursor-not-allowed text-white text-sm font-medium px-4 py-1.5 rounded-md transition-colors shrink-0 focus-ring"
          >
            {loading ? 'Checking…' : 'Check email'}
          </button>
        </div>
      </form>

      {error && (
        <div className="mb-6 rounded-md border border-risk-high/40 bg-risk-high/10 px-4 py-3 text-sm text-risk-high">
          {error}
        </div>
      )}

      {loading && (
        <div className="font-mono text-sm text-muted animate-pulse">Checking against known breaches…</div>
      )}

      {result && !error && (
        <div className="space-y-6">
          <div className="bg-surface border border-border rounded-lg p-5 flex flex-wrap items-center justify-between gap-4">
            <div>
              <div className="text-xs uppercase tracking-widest text-muted font-mono mb-1">Result</div>
              <div className="font-display text-xl font-semibold" style={{ color: statusColor }}>
                {hasBreaches ? `Found in ${result.breach_count} breach${result.breach_count === 1 ? '' : 'es'}` : 'No breaches found'}
              </div>
            </div>
            <div className="text-sm font-mono text-muted">{result.email}</div>
          </div>

          <div className="space-y-3">
            {result.findings.map((f) => <FindingCard key={f.id} finding={f} />)}
          </div>
        </div>
      )}

      {!result && !loading && !error && (
        <div className="border border-dashed border-border rounded-lg py-14 text-center">
          <p className="text-muted text-sm font-mono">Enter an email above to check for breaches.</p>
        </div>
      )}
    </div>
  )
}
