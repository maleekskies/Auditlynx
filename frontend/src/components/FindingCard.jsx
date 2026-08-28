import SeverityBadge from './SeverityBadge.jsx'

const BORDER_COLOR = {
  high: '#E5484D',
  medium: '#F5A623',
  low: '#5B8DEF',
  pass: '#3DD68C',
}

export default function FindingCard({ finding }) {
  const color = BORDER_COLOR[finding.severity] || BORDER_COLOR.low
  return (
    <div
      className="bg-surface2 rounded-md p-4 border border-border"
      style={{ borderLeft: `3px solid ${color}` }}
    >
      <div className="flex items-start justify-between gap-3 mb-1.5">
        <h4 className="font-display font-semibold text-sm text-ink">{finding.title}</h4>
        <SeverityBadge severity={finding.severity} />
      </div>
      <p className="text-sm text-muted leading-relaxed">{finding.detail}</p>
      {finding.recommendation && (
        <p className="text-xs text-accent/90 mt-2 font-mono">
          <span className="text-muted">fix →</span> {finding.recommendation}
        </p>
      )}
      {finding.raw_value && (
        <div className="mt-2 text-xs font-mono text-muted bg-base/60 rounded px-2 py-1.5 overflow-x-auto whitespace-pre-wrap break-all border border-border/60">
          {finding.raw_value}
        </div>
      )}
    </div>
  )
}
