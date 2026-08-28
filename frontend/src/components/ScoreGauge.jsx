const GRADE_COLOR = {
  A: '#3DD68C', B: '#3DD68C', C: '#F5A623', D: '#F5A623', F: '#E5484D',
}

export default function ScoreGauge({ score, grade, label }) {
  const color = GRADE_COLOR[grade] || '#8891A3'
  const circumference = 2 * Math.PI * 42
  const offset = circumference - (Math.max(0, Math.min(100, score)) / 100) * circumference

  return (
    <div className="flex items-center gap-4">
      <div className="relative w-24 h-24 shrink-0">
        <svg viewBox="0 0 96 96" className="w-24 h-24 -rotate-90">
          <circle cx="48" cy="48" r="42" fill="none" stroke="#232838" strokeWidth="7" />
          <circle
            cx="48" cy="48" r="42" fill="none" stroke={color} strokeWidth="7"
            strokeDasharray={circumference} strokeDashoffset={offset} strokeLinecap="round"
            style={{ transition: 'stroke-dashoffset 0.6s ease' }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="font-display font-bold text-2xl" style={{ color }}>{grade}</span>
        </div>
      </div>
      <div>
        <div className="text-xs uppercase tracking-widest text-muted font-mono mb-0.5">{label}</div>
        <div className="font-mono text-sm text-ink">{score}<span className="text-muted">/100</span></div>
      </div>
    </div>
  )
}
