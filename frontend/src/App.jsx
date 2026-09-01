import { useState } from 'react'
import Sidebar from './components/Sidebar.jsx'
import HeadersChecker from './components/HeadersChecker.jsx'
import PhishingAnalyzer from './components/PhishingAnalyzer.jsx'
import DnsRecon from './components/DnsRecon.jsx'
import CodeScanner from './components/CodeScanner.jsx'
import BreachChecker from './components/BreachChecker.jsx'

export default function App() {
  const [active, setActive] = useState('headers')
  const [mobileOpen, setMobileOpen] = useState(false)

  return (
    <div className="min-h-screen flex text-ink font-body">
      <Sidebar
        active={active}
        onSelect={setActive}
        mobileOpen={mobileOpen}
        onClose={() => setMobileOpen(false)}
      />

      <div className="flex-1 flex flex-col min-w-0">
        {/* Mobile top bar — hidden on desktop */}
        <div className="md:hidden flex items-center gap-3 px-4 py-3 border-b border-border bg-surface/60 sticky top-0 z-20">
          <button
            onClick={() => setMobileOpen(true)}
            className="text-ink p-1.5 -ml-1.5 focus-ring rounded"
            aria-label="Open menu"
          >
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M3 6h18M3 12h18M3 18h18" strokeLinecap="round" />
            </svg>
          </button>
          <span className="font-display font-semibold text-ink tracking-tight text-sm">Auditlynx</span>
        </div>

        <main className="flex-1 px-4 py-6 md:px-8 md:py-10 overflow-y-auto overflow-x-hidden">
          {active === 'headers' && <HeadersChecker />}
          {active === 'phishing' && <PhishingAnalyzer />}
          {active === 'dns' && <DnsRecon />}
          {active === 'codescan' && <CodeScanner />}
          {active === 'breach' && <BreachChecker />}
        </main>
      </div>
    </div>
  )
}
