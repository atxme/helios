import { readFileSync } from 'node:fs'
import { relative, resolve } from 'node:path'

const [rustPath, uiPath] = process.argv.slice(2)
if (!rustPath) {
  throw new Error('usage: node scripts/coverage-summary.mjs <rust.json> [orion-ui-summary.json]')
}

const root = process.cwd()
const rust = JSON.parse(readFileSync(rustPath, 'utf8')).data[0]
const groups = { Orion: [], Helios: [] }

for (const file of rust.files) {
  const path = relative(root, file.filename)
  const product =
    path.startsWith('crates/orion-core/') || path.startsWith('apps/orion/src-tauri/')
      ? 'Orion'
      : 'Helios'
  groups[product].push(file)
}

function aggregate(files, metric) {
  const count = files.reduce((sum, file) => sum + file.summary[metric].count, 0)
  const covered = files.reduce((sum, file) => sum + file.summary[metric].covered, 0)
  return { count, covered, percent: count === 0 ? 100 : (covered / count) * 100 }
}

function renderRust(name, files) {
  const lines = aggregate(files, 'lines')
  const functions = aggregate(files, 'functions')
  const regions = aggregate(files, 'regions')
  console.log(
    `${name} Rust: ${lines.percent.toFixed(2)}% lines (${lines.covered}/${lines.count}), ` +
      `${functions.percent.toFixed(2)}% functions, ${regions.percent.toFixed(2)}% regions`,
  )
}

renderRust('Orion', groups.Orion)
renderRust('Helios', groups.Helios)

if (uiPath) {
  const ui = JSON.parse(readFileSync(resolve(uiPath), 'utf8')).total
  console.log(
    `Orion UI: ${ui.lines.pct.toFixed(2)}% lines (${ui.lines.covered}/${ui.lines.total}), ` +
      `${ui.functions.pct.toFixed(2)}% functions, ${ui.branches.pct.toFixed(2)}% branches`,
  )
}

console.log(`Rust HTML: ${relative(root, resolve('target/coverage/rust-html/html/index.html'))}`)
if (uiPath) {
  console.log(`Orion UI HTML: ${relative(root, resolve('target/coverage/orion-ui/index.html'))}`)
}
