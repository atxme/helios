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
import { existsSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..')
const resourcesRoot = resolve(repositoryRoot, 'resources-windows')
const resourcesReady = existsSync(resolve(resourcesRoot, 'binaries/wireguard-amd64.dll'))
  && existsSync(resolve(resourcesRoot, 'binaries/wireguard-arm64.dll'))

if (process.env.ORION_DEPS_READY === '1' || resourcesReady) {
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

if (process.env.ORION_HELPER_READY === '1') {
  console.log('==> Astra helper: already provided by cargo xtask')
} else {
  try {
    execFileSync('cargo', ['xtask', 'orion-helper'], { stdio: 'inherit' })
  } catch {
    process.exit(1)
  }
}
