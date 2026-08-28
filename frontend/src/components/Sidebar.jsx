const MODULES = [
  { id: 'headers', num: '01', name: 'Headers Checker', hint: 'HTTP config scan' },
  { id: 'phishing', num: '02', name: 'Phishing Analyzer', hint: 'Email triage' },
]

export default function Sidebar({ active, onSelect }) {
  return (
    <aside className="w-64 shrink-0 border-r border-border bg-surface/60 flex flex-col">
      <div className="px-5 py-5 border-b border-border">
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-risk-pass animate-pulse" />
          <span className="font-display font-semibold text-ink tracking-tight">SecOps Toolkit</span>
        </div>
        <div className="text-[11px] font-mono text-muted mt-1">local instance · v1.0</div>
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
              onClick={() => onSelect(m.id)}
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
  )
}
