import type { LogLine } from '../types'

const levelColor: Record<string, string> = {
  error: 'text-red-400',
  warn: 'text-amber-400',
  info: 'text-slate-300',
}

export function EventLog({ logs }: { logs: LogLine[] }) {
  if (logs.length === 0) {
    return <div className="px-4 py-3 text-xs text-slate-600">Aucun événement.</div>
  }
  return (
    <div className="max-h-40 overflow-y-auto px-4 py-2 font-mono text-[11px] leading-relaxed">
      {logs.map((l, i) => (
        <div key={i} className="flex gap-2">
          <span className="text-slate-600">{l.ts}</span>
          <span className={levelColor[l.level] ?? 'text-slate-300'}>{l.message}</span>
        </div>
      ))}
    </div>
  )
}
