// Puts the WireGuardNT DLLs in place before Tauri bundles them.
//
// Tauri runs this from `beforeBuildCommand`, which is what lets a plain
// `npm run tauri build` still produce a complete installer: the DLL ships
// inside it, the end user downloads nothing.
//
// But `cargo xtask orion-msi` has already done the work in-process before
// spawning Tauri, and doing it twice is not merely wasteful on Windows: the
// nested `cargo` rebuilds `xtask` as soon as anything in its dependency
// graph looks stale, and relinking `target/debug/xtask.exe` while that very
// executable is running is refused by the OS — `Access is denied (os error
// 5)`, several minutes into the build. `ORION_DEPS_READY`, set by xtask
// right before it spawns npm, is what tells the two callers apart.
import { execFileSync } from 'node:child_process'

if (process.env.ORION_DEPS_READY === '1') {
  console.log('==> WireGuardNT: already provided by cargo xtask')
} else {
  try {
    execFileSync('cargo', ['xtask', 'orion-deps'], { stdio: 'inherit' })
  } catch {
    // `stdio: inherit` already showed cargo's own diagnosis; a Node stack
    // trace on top of it would only bury it.
    process.exit(1)
  }
}
