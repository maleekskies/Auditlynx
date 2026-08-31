const MODULES = [
  { id: 'headers', num: '01', name: 'Headers Checker', hint: 'HTTP config scan' },
  { id: 'phishing', num: '02', name: 'Phishing Analyzer', hint: 'Email triage' },
  { id: 'dns', num: '03', name: 'DNS & Domain Recon', hint: 'Registration & DNS' },
  { id: 'codescan', num: '04', name: 'Code Security Scanner', hint: 'App vulnerability check' },
]

export default function Sidebar({ active, onSelect, mobileOpen, onClose }) {
  function handleSelect(id) {
    onSelect(id)
    onClose() // auto-close on mobile after picking a module
  }

  return (
    <>
      {/* Backdrop overlay — mobile only, shown when menu is open */}
      {mobileOpen && (
        <div
          className="fixed inset-0 bg-black/60 z-30 md:hidden"
          onClick={onClose}
          aria-hidden="true"
        />
      )}

      <aside
        className={`
          fixed inset-y-0 left-0 z-40 w-64 shrink-0 border-r border-border bg-surface
          flex flex-col transition-transform duration-200 ease-out
          md:static md:translate-x-0 md:bg-surface/60
          ${mobileOpen ? 'translate-x-0' : '-translate-x-full'}
        `}
      >
        <div className="px-5 py-5 border-b border-border flex items-center justify-between">
          <div>
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-risk-pass animate-pulse" />
              <span className="font-display font-semibold text-ink tracking-tight">Auditlynx</span>
            </div>
            <div className="text-[11px] font-mono text-muted mt-1">local instance · v1.0</div>
          </div>
          <button
            onClick={onClose}
            className="md:hidden text-muted hover:text-ink p-1 -mr-1 focus-ring rounded"
            aria-label="Close menu"
          >
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M18 6L6 18M6 6l12 12" strokeLinecap="round" />
            </svg>
          </button>
        </div>

        <nav className="flex-1 px-3 py-4 space-y-1">
          <div className="px-2 text-[10px] font-mono uppercase tracking-widest text-muted/70 mb-2">
            Modules
          </div>
          {MODULES.map((m) => {
            const isActive = active === m.id
            return (
              <button
                key={m.id}
                onClick={() => handleSelect(m.id)}
                className={`w-full text-left px-3 py-2.5 rounded-md flex items-center gap-3 transition-colors focus-ring ${
                  isActive ? 'bg-accent/15 border border-accent/40' : 'border border-transparent hover:bg-surface2'
                }`}
              >
                <span className={`font-mono text-[11px] ${isActive ? 'text-accent' : 'text-muted'}`}>{m.num}</span>
                <span className="flex-1">
                  <div className={`text-sm font-medium ${isActive ? 'text-ink' : 'text-ink/80'}`}>{m.name}</div>
                  <div className="text-[11px] text-muted font-mono">{m.hint}</div>
                </span>
              </button>
            )
          })}
        </nav>

        <div className="px-5 py-4 border-t border-border text-[11px] font-mono text-muted/70 leading-relaxed">
          Heuristic tooling for triage.
          <br />Always verify findings manually.
        </div>
      </aside>
    </>
  )
}
