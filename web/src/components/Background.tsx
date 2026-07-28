import { lazy, Suspense, useMemo } from 'react'

// The three.js scene is code-split: its chunk no longer weighs on first render.
const BackgroundScene = lazy(() => import('./BackgroundScene'))

// CSS fallback — amber sun on the right. Shown instantly (first render),
// while the 3D chunk loads, and permanently if WebGL is unavailable
// (Tauri webview safety net / old GPU).
function Nebula({ dark }: { dark: boolean }) {
  return (
    <div className="fixed inset-0" style={{
      zIndex: 0,
      background: dark
        ? 'radial-gradient(ellipse 60% 55% at 80% 28%, rgba(245,158,11,0.22) 0%, transparent 55%), radial-gradient(circle at 50% 50%, #0a1226 0%, #03060f 72%)'
        : 'radial-gradient(ellipse 60% 55% at 80% 28%, rgba(251,191,36,0.45) 0%, transparent 55%), linear-gradient(160deg, #eef4ff 0%, #dbe7fb 100%)',
    }} />
  )
}

function hasWebGL(): boolean {
  try {
    const c = document.createElement('canvas')
    return !!(c.getContext('webgl2') || c.getContext('webgl'))
  } catch {
    return false
  }
}

export function Background({ dark }: { dark: boolean }) {
  const supported = useMemo(hasWebGL, [])

  return (
    <>
      <Nebula dark={dark} />
      {supported && (
        <Suspense fallback={null}>
          <BackgroundScene dark={dark} />
        </Suspense>
      )}
    </>
  )
}
