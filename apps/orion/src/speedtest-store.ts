/**
 * The speedtest that survives leaving the screen.
 *
 * # Why this is not component state
 *
 * A run takes about forty seconds. Every second of it, the view is the one
 * place in Orion a user has no reason to stay on: they start the measurement
 * and go read the log, or check which profile is selected. With the state
 * inside `SpeedTestView`, that navigation unmounted the component — the
 * promise kept running in Rust, its progress events landed on a listener that
 * no longer existed, and coming back showed « Prêt » as though nothing had
 * happened. The measurement was lost, and the only way to see one was to stare
 * at it.
 *
 * So the run lives here, at module scope, above the router. Mounting the view
 * subscribes to it; unmounting unsubscribes and changes nothing else.
 *
 * # Why there is a history
 *
 * A single result answers « combien maintenant ». The question an operator
 * actually has is « est-ce que ça a changé », and that needs the previous ones
 * beside it. Five is what a line of cards holds without scrolling, and it
 * spans a session's worth of checks.
 *
 * It is deliberately **not** persisted. These figures describe one tunnel at
 * one moment on one network; restoring them at the next launch would show
 * yesterday's café as today's fibre. The history is as long as the process.
 */

import * as api from './api'
import type { SpeedTestMode, SpeedTestProgress, SpeedTestResult } from './types'

/**
 * How many **previous** runs are kept beside the current one.
 *
 * The store holds one more record than this — the newest is the one the dial
 * shows, and the rows below it are the ones before it.
 */
export const HISTORY_LENGTH = 5

/**
 * How many live rates the curve of the run in progress keeps, per direction.
 *
 * The engine emits a frame about every 250 ms, so forty-eight of them span the
 * ten seconds of one throughput leg: the curve shows the whole leg without
 * ever redrawing more points than the 460 px it is given can distinguish.
 */
export const SAMPLE_LENGTH = 48

/** One finished measurement, and when it finished. */
export interface SpeedTestRecord {
  /**
   * Identity of the record, unique for the life of the process.
   *
   * Not `at`: two runs finishing inside the same millisecond — which back to
   * back against a fast gateway, or a test loop, does happen — would share a
   * React key, and the list would reuse one row for both.
   */
  id: number
  /** Milliseconds since the epoch — the moment the result came back. */
  at: number
  result: SpeedTestResult
}

export interface SpeedTestState {
  running: boolean
  result: SpeedTestResult | null
  progress: SpeedTestProgress | null
  error: string | null
  /**
   * Last rate seen in each direction while the run is under way.
   *
   * Kept rather than read off `progress`: the reception figure has to stay on
   * screen once emission takes over, otherwise the row the user was just
   * watching blanks out halfway through the run.
   */
  live: { down: number | null; up: number | null }
  /**
   * Rates seen during each throughput leg, oldest first.
   *
   * The curve on screen is the run itself, not a summary of it: a single
   * number rising and falling says nothing about whether the line is steady,
   * and stability is most of what a speedtest is asked to reveal.
   */
  samples: { down: number[]; up: number[] }
  /**
   * Every finished run, most recent first, capped at `HISTORY_LENGTH + 1`:
   * the newest is on the dial, and excluding it still leaves a full list of
   * previous ones.
   */
  history: SpeedTestRecord[]
}

const EMPTY: SpeedTestState = {
  running: false,
  result: null,
  progress: null,
  error: null,
  live: { down: null, up: null },
  samples: { down: [], up: [] },
  history: [],
}

let state: SpeedTestState = EMPTY
let nextRecordId = 1
const listeners = new Set<() => void>()

/**
 * Progress subscription, opened once and never closed.
 *
 * Not per-mount, which is the whole point: a run started from the view keeps
 * feeding this store while the user is on another screen. `listen` is async,
 * so the first call is memoised — two mounts must not open two subscriptions
 * and double every update.
 */
let subscription: Promise<unknown> | null = null

function publish(next: SpeedTestState) {
  state = next
  for (const listener of listeners) listener()
}

function ensureSubscribed() {
  if (subscription) return
  subscription = api
    .onSpeedTestProgress((update) => {
      // Ignored when no run is in flight: a late frame from a measurement that
      // already failed must not repaint the dial with a rate the store has
      // just disowned.
      if (!state.running) return
      publish({
        ...state,
        progress: update,
        live: liveAfter(state.live, update),
        samples: samplesAfter(state.samples, update),
      })
    })
    .catch(() => {
      // A shell without the event bridge still runs measurements; it simply
      // shows no intermediate rate. Failing the whole screen for that would
      // trade a degraded display for no display at all.
      subscription = null
    })
}

/**
 * Where each direction's live rate stands after one progress frame.
 *
 * **Throughput legs only.** The quality legs are driven at a rate deliberately
 * below the capacity TCP just found — they measure loss and jitter, not
 * speed — so letting them reach the rows would walk the reading down and then
 * snap it back when the result lands. The user would watch their line appear
 * to lose a third of its rate, for a reason nothing on screen explains.
 */
export function liveAfter(
  live: SpeedTestState['live'],
  update: SpeedTestProgress,
): SpeedTestState['live'] {
  if (update.phase === 'tcp_download') return { ...live, down: update.current_mbps }
  if (update.phase === 'tcp_upload') return { ...live, up: update.current_mbps }
  return live
}

/**
 * Where each direction's curve stands after one progress frame.
 *
 * Same restriction as `liveAfter`, for the same reason: a quality leg's paced
 * rate plotted on the reception curve would draw a cliff the line never had.
 */
export function samplesAfter(
  samples: SpeedTestState['samples'],
  update: SpeedTestProgress,
): SpeedTestState['samples'] {
  const append = (points: number[]) => [...points, update.current_mbps].slice(-SAMPLE_LENGTH)
  if (update.phase === 'tcp_download') return { ...samples, down: append(samples.down) }
  if (update.phase === 'tcp_upload') return { ...samples, up: append(samples.up) }
  return samples
}

export function getSnapshot(): SpeedTestState {
  return state
}

export function subscribe(listener: () => void): () => void {
  listeners.add(listener)
  ensureSubscribed()
  return () => {
    listeners.delete(listener)
  }
}

/**
 * Starts a measurement, unless one is already under way.
 *
 * The guard is not a nicety: two concurrent runs would share the dial, the
 * progress stream and the history slot, and report each other's rates.
 */
export async function start(mode: SpeedTestMode): Promise<void> {
  if (state.running) return
  ensureSubscribed()
  publish({
    ...state,
    running: true,
    error: null,
    result: null,
    progress: null,
    live: { down: null, up: null },
    samples: { down: [], up: [] },
  })
  try {
    const measured = await api.runSpeedTest(mode)
    publish({
      ...state,
      running: false,
      result: measured,
      history: [
        { id: nextRecordId++, at: Date.now(), result: measured },
        ...state.history,
      ].slice(0, HISTORY_LENGTH + 1),
    })
  } catch (cause) {
    publish({
      ...state,
      running: false,
      error: String(cause),
      // The dial falls back to «—» on failure; leaving the rows on the last
      // frames received would have the screen state a rate it just disowned.
      live: { down: null, up: null },
      samples: { down: [], up: [] },
      progress: null,
    })
  }
}

/** Empties the history, and only the history. */
export function clearHistory(): void {
  publish({ ...state, history: [] })
}

/** Test seam: drops every subscriber and returns to the initial state. */
export function resetForTests(): void {
  listeners.clear()
  subscription = null
  state = EMPTY
  nextRecordId = 1
}
