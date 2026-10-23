"""Stub-only regression tests for scripts/coverage.sh."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

REAL_SCRIPT = Path(__file__).resolve().parents[1] / "coverage.sh"


class CoverageDriverTests(unittest.TestCase):
    def fixture(self, failure=""):
        temp = tempfile.TemporaryDirectory()
        base = Path(temp.name)
        root = base / "repo with spaces"
        scripts = root / "scripts"
        scripts.mkdir(parents=True)
        shutil.copy2(REAL_SCRIPT, scripts / "coverage.sh")
        (scripts / "cargo-budget.sh").write_text(
            'helios_budget_enter() { export CARGO_TARGET_DIR="$PWD/target"; mkdir -p "$CARGO_TARGET_DIR"; }\n'
        )
        fake_bin = base / "bin"
        fake_bin.mkdir()
        wrapper = scripts / "wsl-cargo"
        wrapper.write_text(r'''#!/usr/bin/env python3
import json, os, pathlib, sys
args = sys.argv[1:]
with open(os.environ['AUDIT_LOG'], 'a') as stream:
    stream.write(json.dumps({'args': args, 'offline': os.environ.get('CARGO_NET_OFFLINE'), 'npm_offline': os.environ.get('npm_config_offline')}) + '\n')
if args == ['llvm-cov', '--version']:
    print('cargo-llvm-cov test')
    raise SystemExit(0)
if os.environ.get('AUDIT_FAIL') == 'json' and '--json' in args:
    raise SystemExit(12)
if os.environ.get('AUDIT_FAIL') == 'lcov' and '--lcov' in args:
    raise SystemExit(13)
if '--output-path' in args:
    pathlib.Path(args[args.index('--output-path') + 1]).write_text('{}')
if '--output-dir' in args:
    path = pathlib.Path(args[args.index('--output-dir') + 1])
    path.mkdir(parents=True, exist_ok=True)
    (path / 'index.html').write_text('html')
''')
        wrapper.chmod(0o755)
        for name in ("npm", "node"):
            tool = fake_bin / name
            tool.write_text("#!/bin/sh\ntouch \"$AUDIT_UI_MARKER\"\n")
            tool.chmod(0o755)
        log = base / "calls.jsonl"
        env = dict(os.environ, PATH=str(fake_bin) + os.pathsep + os.environ["PATH"], AUDIT_LOG=str(log), AUDIT_FAIL=failure, AUDIT_UI_MARKER=str(base / "ui-called"), HELIOS_AUDIT_FRONTENDS_PREFLIGHTED="1")
        return temp, root, base, env, log

    def calls(self, log):
        return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []

    def test_help_does_not_run_cargo(self):
        temp, root, base, env, log = self.fixture()
        with temp:
            result = subprocess.run([str(root / "scripts" / "coverage.sh"), "--help"], env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Rust and Orion UI", result.stdout)
            self.assertFalse(log.exists())

    def test_no_argument_keeps_ui_pipeline_and_default_rust_flags(self):
        temp, root, base, env, log = self.fixture()
        with temp:
            result = subprocess.run([str(root / "scripts" / "coverage.sh")], env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            calls = self.calls(log)
            self.assertIn("--workspace", calls[1]["args"])
            self.assertIn("--all-features", calls[1]["args"])
            self.assertNotIn("--frozen", calls[1]["args"])
            self.assertFalse(any("--lcov" in call["args"] for call in calls))
            self.assertTrue((base / "ui-called").exists())

    def test_workspace_rust_only_order_offline_and_wrapped(self):
        temp, root, base, env, log = self.fixture()
        output = base / "report dir"
        with temp:
            result = subprocess.run([str(root / "scripts" / "coverage.sh"), "--rust-only", "--view", "workspace", "--output-dir", str(output)], env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            calls = self.calls(log)
            self.assertEqual(len(calls), 4)
            self.assertEqual(calls[0]["args"], ["llvm-cov", "--version"])
            self.assertIn("--workspace", calls[1]["args"])
            self.assertNotIn("--lib", calls[1]["args"])
            self.assertTrue(calls[1]["args"].index("--json") < len(calls[1]["args"]))
            self.assertTrue("--frozen" in calls[1]["args"])
            self.assertEqual(calls[2]["args"][0:2], ["llvm-cov", "report"])
            self.assertIn("--lcov", calls[2]["args"])
            self.assertNotIn("--frozen", calls[2]["args"])
            self.assertIn("--html", calls[3]["args"])
            self.assertTrue(all(call["offline"] == "true" for call in calls[1:]))
            self.assertTrue(all(call["npm_offline"] == "true" for call in calls[1:]))
            self.assertTrue((output / "workspace.json").exists())
            self.assertTrue((output / "workspace.lcov").exists())
            self.assertTrue((output / "rust-html" / "index.html").exists())
            self.assertFalse((base / "ui-called").exists())

    def test_libraries_view_and_compile_failure_stops_exports(self):
        temp, root, base, env, log = self.fixture(failure="json")
        output = base / "libs"
        with temp:
            result = subprocess.run([str(root / "scripts" / "coverage.sh"), "--rust-only", "--view", "libraries", "--output-dir", str(output)], env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 12)
            calls = self.calls(log)
            self.assertEqual(len(calls), 2)
            self.assertIn("--workspace", calls[1]["args"])
            self.assertIn("--lib", calls[1]["args"])
            self.assertFalse(any("report" in call["args"] for call in calls))
            self.assertFalse((base / "ui-called").exists())

    def test_lcov_failure_stops_html_export(self):
        temp, root, base, env, log = self.fixture(failure="lcov")
        output = base / "lcov-failure"
        with temp:
            result = subprocess.run([str(root / "scripts" / "coverage.sh"), "--rust-only", "--output-dir", str(output)], env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 13)
            calls = self.calls(log)
            self.assertEqual(len(calls), 3)
            self.assertIn("--lcov", calls[2]["args"])
            self.assertFalse(any("--html" in call["args"] for call in calls))


if __name__ == "__main__":
    unittest.main()
