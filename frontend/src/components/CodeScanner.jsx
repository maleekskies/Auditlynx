import { useState } from 'react'
import FindingCard from './FindingCard.jsx'

const RISK_COLOR = {
  'High risk': '#E5484D',
  'Needs attention': '#F5A623',
  'Minor issues': '#5B8DEF',
  'No obvious issues found': '#3DD68C',
}

const CATEGORY_LABEL = {
  secrets: 'Hardcoded secrets & credentials',
  injection: 'Injection risks',
  'unsafe-execution': 'Unsafe dynamic execution',
  xss: 'Cross-site scripting (XSS)',
  crypto: 'Weak or insecure cryptography',
  'transport-security': 'Transport security',
  cors: 'CORS configuration',
  configuration: 'Configuration',
  session: 'Session & cookies',
  other: 'Other',
  general: 'General',
}

const SAMPLE = `import os

API_KEY = "sk_live_abcdef1234567890abcd"

def run_backup(folder):
    os.system("tar -czf backup.tar.gz " + folder)

def render_comment(html):
    document.getElementById("out").innerHTML = html

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
)`

export default function CodeScanner() {
  const [code, setCode] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)

  async function runScan(e) {
    e.preventDefault()
    if (!code.trim()) return
    setLoading(true)
    setError(null)
    setResult(null)
    try {
      const resp = await fetch('/api/scan-code', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code }),
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
        <div className="text-xs font-mono text-accent/80 tracking-widest mb-1.5">MODULE 04</div>
        <h1 className="font-display text-2xl font-semibold text-ink mb-2">Code Security Scanner</h1>
        <p className="text-muted text-sm leading-relaxed max-w-2xl">
          Paste code from your app to check for common, high-impact security mistakes — hardcoded
          secrets, injection risks, weak crypto, unsafe CORS, and more. Each finding includes how
          to fix it.
        </p>
        <p className="text-xs text-muted/70 leading-relaxed max-w-2xl mt-2 italic">
          This is heuristic pattern-matching, not a full security audit — a clean scan doesn't mean
          the code is fully secure, only that it didn't match these specific known-risky patterns.
        </p>
      </header>

      <form onSubmit={runScan} className="mb-8">
        <div className="bg-surface border border-border rounded-lg focus-within:border-accent transition-colors overflow-hidden">
          <div className="flex items-center justify-between px-4 py-2 border-b border-border bg-surface2/60">
            <span className="text-xs font-mono text-muted">paste your code</span>
            <button
              type="button"
              onClick={() => setCode(SAMPLE)}
              className="text-xs font-mono text-accent hover:text-accent/80 transition-colors"
            >
              load sample →
            </button>
          </div>
          <textarea
            value={code}
            onChange={(e) => setCode(e.target.value)}
            placeholder={'Paste a file or snippet from your app...'}
            rows={14}
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
            {loading ? 'Scanning…' : 'Scan code'}
          </button>
        </div>
      </form>

      {error && (
        <div className="mb-6 rounded-md border border-risk-high/40 bg-risk-high/10 px-4 py-3 text-sm text-risk-high">
          {error}
        </div>
      )}

      {loading && (
        <div className="font-mono text-sm text-muted animate-pulse">Checking against known risk patterns…</div>
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
              <div>{result.lines_scanned} lines scanned</div>
              <div className="mt-1">Score: {result.risk_score}/100</div>
            </div>
          </div>

          {Object.entries(CATEGORY_LABEL).map(([key, label]) =>
            grouped[key] ? (
              <div key={key}>
                <h3 className="text-xs font-mono uppercase tracking-widest text-muted mb-2.5">{label}</h3>
                <div className="space-y-3">
                  {grouped[key].map((f) => (
                    <FindingCard
                      key={f.id}
                      finding={{
                        ...f,
                        detail: f.line ? `Line ${f.line}. ${f.detail}` : f.detail,
                        raw_value: f.snippet,
                      }}
                    />
                  ))}
                </div>
              </div>
            ) : null
          )}
        </div>
      )}

      {!result && !loading && !error && (
        <div className="border border-dashed border-border rounded-lg py-14 text-center">
          <p className="text-muted text-sm font-mono">Paste code above, or load the sample.</p>
        </div>
      )}
    </div>
  )
}
