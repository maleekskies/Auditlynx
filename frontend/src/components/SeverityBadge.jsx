const CONFIG = {
  high: { label: 'HIGH', color: '#E5484D', bg: 'rgba(229,72,77,0.12)' },
  medium: { label: 'MED', color: '#F5A623', bg: 'rgba(245,166,35,0.12)' },
  low: { label: 'LOW', color: '#5B8DEF', bg: 'rgba(91,141,239,0.12)' },
  pass: { label: 'PASS', color: '#3DD68C', bg: 'rgba(61,214,140,0.12)' },
}

export default function SeverityBadge({ severity }) {
  const cfg = CONFIG[severity] || CONFIG.low
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded px-2 py-0.5 text-[11px] font-mono font-semibold tracking-wider shrink-0"
      style={{ color: cfg.color, backgroundColor: cfg.bg }}
    >
      <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: cfg.color }} />
      {cfg.label}
    </span>
  )
}
