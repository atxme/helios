import json
import importlib.util
import os
from pathlib import Path
import subprocess
import threading
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "audit-collect.py"


class AuditCollectTests(unittest.TestCase):
    def fixture(self, fail_coverage=False, fail_report=False, mutate_source=False, embed_web=False, add_orion=False, create_vite=False, npm_failure=False):
        temp = tempfile.TemporaryDirectory()
        base = Path(temp.name)
        root = base / "source tree"
        root.mkdir()
        (root / "scripts").mkdir()
        (root / "scripts" / "cargo-budget.sh").write_text("helios_budget_enter() { :; }\n")
        (root / "lib.rs").write_text("pub fn sample() {}\n")
        subprocess.run(["git", "init", "-q"], cwd=root, check=True)
        subprocess.run(["git", "-c", "user.name=test", "-c", "user.email=test@example", "commit", "--allow-empty", "-qm", "initial"], cwd=root, check=True)
        bin_dir = base / "bin"
        bin_dir.mkdir()
        cargo = bin_dir / "cargo"
        (root / "Cargo.toml").write_text("[workspace]\nmembers = ['.']\n")
        (root / "Cargo.lock").write_text("version = 4\n")
        cargo.write_text("#!/usr/bin/env python3\nimport json,os,sys\nif sys.argv[1:3] == ['llvm-cov','--version']:\n print('cargo-llvm-cov 1')\nelif sys.argv[1:2] == ['metadata']:\n from pathlib import Path\n packages=[{'id':'pkg 1','name':'pkg','features':{'default':[],'extra':[]},'manifest_path':str(Path.cwd()/'Cargo.toml')}]\n if os.environ.get('AUDIT_EMBED_WEB'):\n  packages.append({'id':'web pkg','name':'helios-api','features':{'embed-ui':[]},'manifest_path':str(Path.cwd()/'crates/helios-api/Cargo.toml')})\n if os.environ.get('AUDIT_ORION'):\n  packages.append({'id':'orion pkg','name':'orion','features':{},'manifest_path':str(Path.cwd()/'apps/orion/Cargo.toml')})\n print(json.dumps({'packages':packages,'workspace_members':[p['id'] for p in packages]}))\nelse:\n raise SystemExit(3)\n")
        cargo.chmod(0o755)
        wsl = root / "scripts" / "wsl-cargo"
        wsl.write_text("#!/usr/bin/env bash\nexec cargo \"$@\"\n")
        wsl.chmod(0o755)
        coverage = root / "scripts" / "coverage.sh"
        coverage.write_text("#!/usr/bin/env python3\nimport pathlib,sys\np=pathlib.Path(sys.argv[sys.argv.index('--output-dir')+1])\nif " + repr(fail_coverage) + ": raise SystemExit(9)\n(p/'workspace.json').write_text('{}')\n(p/'workspace.lcov').write_text('TN:\\n')\nif " + repr(mutate_source) + ": pathlib.Path('lib.rs').write_text('pub fn changed() {}\\n')\n")
        coverage.chmod(0o755)
        for name, content in (("rustc", "#!/bin/sh\necho 'rustc 1.0'\n"), ("rust-analyzer", "#!/bin/sh\necho 'rust-analyzer 1'\n"), ("llvm-cov", "#!/bin/sh\necho 'llvm-cov 1'\n"), ("rustfmt", "#!/bin/sh\necho 'rustfmt 1'\n")):
            tool = bin_dir / name
            if name == "rustc":
                tool.write_text("#!/bin/sh\nif [ \"$1\" = '-Vv' ] || [ \"$1\" = '-vV' ]; then printf 'rustc 1.0\\nhost: test-host\\n'; elif [ \"$1\" = '--print' ] && [ \"$2\" = 'sysroot' ]; then printf '%s\\n' \"$FAKE_SYSROOT\"; else echo 'feature=one'; fi\n")
            else:
                tool.write_text(content)
            tool.chmod(0o755)
        npm = bin_dir / "npm"
        npm.write_text("#!/usr/bin/env python3\nimport os,sys\nif sys.argv[1:] != ['ls','--depth=0','--silent'] or os.environ.get('npm_config_offline') != 'true': raise SystemExit(14)\nif os.environ.get('AUDIT_NPM_FAIL'): raise SystemExit(15)\n")
        npm.chmod(0o755)
        if add_orion:
            orion = root / "apps" / "orion"
            orion.mkdir(parents=True)
            (orion / "Cargo.toml").write_text("[package]\nname='orion'\n")
            if create_vite:
                vite = orion / "node_modules" / "vite" / "bin"
                vite.mkdir(parents=True)
                (vite / "vite.js").write_text("// stub\n")
        if embed_web:
            api = root / "crates" / "helios-api"
            api.mkdir(parents=True)
            (api / "Cargo.toml").write_text("[package]\nname='helios-api'\n")
        sysroot = base / "fake-sysroot" / "lib" / "rustlib" / "test-host" / "bin"
        sysroot.mkdir(parents=True)
        llvm = sysroot / "llvm-cov"
        llvm.write_text("#!/bin/sh\necho 'llvm-cov 1'\n")
        llvm.chmod(0o755)
        report = root / "scripts" / "audit-report.py"
        report.write_text("#!/usr/bin/env python3\nimport pathlib,sys\nif " + repr(fail_report) + ": raise SystemExit(8)\npathlib.Path(sys.argv[sys.argv.index('--output')+1]).write_text('{}')\n")
        report.chmod(0o755)
        env = dict(os.environ, PATH=str(bin_dir) + os.pathsep + os.environ["PATH"], FAKE_SYSROOT=str(base / "fake-sysroot"), AUDIT_EMBED_WEB="1" if embed_web else "", AUDIT_ORION="1" if add_orion else "", AUDIT_NPM_FAIL="1" if npm_failure else "")
        return temp, root, base / "reports", env

    def test_failure_keeps_partial_marker(self):
        temp, root, output, env = self.fixture(fail_coverage=True)
        with temp:
            result = subprocess.run(["python3", str(SCRIPT), "collect", "--root", str(root), "--view", "workspace", "--output-dir", str(output)], env=env, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(json.loads((output / "status.json").read_text())["status"], "partial")
            self.assertFalse((output / "provenance.json").exists())

    def test_nonempty_output_is_refused(self):
        temp, root, output, env = self.fixture()
        with temp:
            output.mkdir()
            (output / "keep").write_text("baseline")
            result = subprocess.run(["python3", str(SCRIPT), "collect", "--root", str(root), "--view", "workspace", "--output-dir", str(output)], env=env, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual((output / "keep").read_text(), "baseline")

    def test_output_is_rechecked_after_lock_wait(self):
        temp, root, output, env = self.fixture()
        with temp:
            spec = importlib.util.spec_from_file_location("audit_collect", SCRIPT)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            lock_entered = threading.Event()
            release_lock = threading.Event()
            errors = []

            def delayed_flock(_file, _operation):
                lock_entered.set()
                if not release_lock.wait(timeout=5):
                    raise TimeoutError("test lock was not released")

            module.fcntl.flock = delayed_flock

            def collect():
                try:
                    module.collect(root, "workspace", output)
                except Exception as error:  # expected refusal after the lock wait
                    errors.append(error)

            worker = threading.Thread(target=collect)
            worker.start()
            self.assertTrue(lock_entered.wait(timeout=5))
            (output / "baseline.json").write_text("keep")
            release_lock.set()
            worker.join(timeout=5)
            self.assertFalse(worker.is_alive())
            self.assertEqual(len(errors), 1)
            self.assertIn("became nonempty while waiting", str(errors[0]))
            self.assertEqual((output / "baseline.json").read_text(), "keep")
            self.assertFalse((output / "status.json").exists())

    def test_success_writes_complete_provenance(self):
        temp, root, output, env = self.fixture()
        with temp:
            result = subprocess.run(["python3", str(SCRIPT), "collect", "--root", str(root), "--view", "libraries", "--output-dir", str(output)], env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads((output / "status.json").read_text())["status"], "completed")
            provenance = json.loads((output / "provenance.json").read_text())
            self.assertEqual(provenance["view"], "libraries")
            self.assertEqual(provenance["target"], "test-host")
            self.assertTrue(provenance["tests_success"])
            self.assertEqual(provenance["source_sha256"]["lib.rs"], __import__("hashlib").sha256((root / "lib.rs").read_bytes()).hexdigest())
            self.assertEqual(provenance["artifacts_sha256"].keys(), {"coverage", "lcov", "metadata"})
            self.assertIn("Cargo.toml", provenance["build_input_sha256"])
            self.assertIn("Cargo.lock", provenance["build_input_sha256"])
            self.assertTrue((output / "report.json").exists())

    def test_build_override_is_rejected_before_coverage(self):
        temp, root, output, env = self.fixture()
        env["RUSTFLAGS"] = "-C opt-level=1"
        with temp:
            result = subprocess.run(["python3", str(SCRIPT), "collect", "--root", str(root), "--view", "workspace", "--output-dir", str(output)], env=env, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("RUSTFLAGS", result.stderr)
            self.assertFalse((output / "workspace.json").exists())

    def test_missing_web_dist_is_refused_before_coverage(self):
        temp, root, output, env = self.fixture(embed_web=True)
        with temp:
            result = subprocess.run(["python3", str(SCRIPT), "collect", "--root", str(root), "--view", "libraries", "--output-dir", str(output)], env=env, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("web/dist/index.html", result.stderr)
            self.assertFalse((output / "workspace.json").exists())

    def test_missing_orion_vite_is_refused_for_workspace_only(self):
        temp, root, output, env = self.fixture(add_orion=True)
        with temp:
            result = subprocess.run(["python3", str(SCRIPT), "collect", "--root", str(root), "--view", "workspace", "--output-dir", str(output)], env=env, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Orion frontend dependencies are missing", result.stderr)
            self.assertFalse((output / "workspace.json").exists())

    def test_libraries_view_skips_orion_frontend_preflight(self):
        temp, root, output, env = self.fixture(add_orion=True)
        with temp:
            result = subprocess.run(["python3", str(SCRIPT), "collect", "--root", str(root), "--view", "libraries", "--output-dir", str(output)], env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_orion_npm_dependency_check_is_offline_and_must_pass(self):
        temp, root, output, env = self.fixture(add_orion=True, create_vite=True, npm_failure=True)
        with temp:
            result = subprocess.run(["python3", str(SCRIPT), "collect", "--root", str(root), "--view", "workspace", "--output-dir", str(output)], env=env, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Orion frontend dependencies are unhealthy", result.stderr)
            self.assertFalse((output / "workspace.json").exists())

    def test_report_failure_keeps_partial_status(self):
        temp, root, output, env = self.fixture(fail_report=True)
        with temp:
            result = subprocess.run(["python3", str(SCRIPT), "collect", "--root", str(root), "--view", "workspace", "--output-dir", str(output)], env=env, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(json.loads((output / "status.json").read_text())["status"], "partial")

    def test_tool_preflight_failure_occurs_before_coverage(self):
        temp, root, output, env = self.fixture()
        with temp:
            analyzer = Path(env["PATH"].split(os.pathsep)[0]) / "rust-analyzer"
            analyzer.write_text("#!/bin/sh\nexit 127\n")
            result = subprocess.run(["python3", str(SCRIPT), "collect", "--root", str(root), "--view", "workspace", "--output-dir", str(output)], env=env, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((output / "workspace.json").exists())
            self.assertEqual(json.loads((output / "status.json").read_text())["status"], "partial")

    def test_source_drift_does_not_complete(self):
        temp, root, output, env = self.fixture(mutate_source=True)
        with temp:
            result = subprocess.run(["python3", str(SCRIPT), "collect", "--root", str(root), "--view", "workspace", "--output-dir", str(output)], env=env, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Source files changed", result.stderr)
            self.assertEqual(json.loads((output / "status.json").read_text())["status"], "partial")


if __name__ == "__main__":
    unittest.main()
