import type { LogLine } from '../types'

/** Le niveau est porté par un liseré à gauche autant que par la couleur du texte. */
const LEVEL: Record<string, { text: string; rail: string }> = {
  error: { text: 'text-red-300', rail: 'bg-red-500' },
  warn: { text: 'text-amber-300', rail: 'bg-amber-500' },
  info: { text: 'text-slate-300', rail: 'bg-transparent' },
}

export function EventLog({ logs }: { logs: LogLine[] }) {
  return (
    <div className="flex max-h-48 flex-col">
      <div className="flex shrink-0 items-center justify-between border-b border-white/5 px-4 py-1.5">
        <span className="text-[10px] uppercase tracking-[0.16em] text-slate-500">Journal</span>
        <span className="font-mono text-[10px] tabular-nums text-slate-600">
          {logs.length} {logs.length > 1 ? 'entrées' : 'entrée'}
        </span>
      </div>

      {logs.length === 0 ? (
        <p className="px-4 py-3 text-xs text-slate-600">Aucun événement pour l’instant.</p>
      ) : (
        <div className="overflow-y-auto py-1 font-mono text-[11px] leading-relaxed">
          {logs.map((line, index) => {
            const level = LEVEL[line.level] ?? LEVEL.info
            return (
              <div key={index} className="flex items-start gap-2 px-4 py-px">
                <span className={`mt-1 h-3 w-0.5 shrink-0 rounded-full ${level.rail}`} />
                <span className="shrink-0 tabular-nums text-slate-600">{line.ts}</span>
                <span className={`min-w-0 break-words ${level.text}`}>{line.message}</span>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
