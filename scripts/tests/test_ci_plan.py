"""Checks that CI selection covers dependents without rebuilding unrelated apps."""

import importlib.util
from pathlib import Path
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "ci-plan.py"
SPEC = importlib.util.spec_from_file_location("ci_plan", SCRIPT)
ci_plan = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ci_plan)


def package(name, directory, dependencies=()):
    return {
        "name": name,
        "manifest_path": f"/repo/{directory}/Cargo.toml",
        "dependencies": [{"path": f"/repo/{dependency}"} for dependency in dependencies],
    }


class SelectionTests(unittest.TestCase):
    def setUp(self):
        self.metadata = {
            "workspace_root": "/repo",
            "packages": [
                package("aether", "crates/aether"),
                package("helios-api", "crates/helios-api", ["crates/aether"]),
                package("heliosd", "crates/heliosd", ["crates/helios-api"]),
                package("orion-core", "crates/orion-core", ["crates/aether"]),
                package("orion", "apps/orion/src-tauri", ["crates/orion-core"]),
                package("helios", "tools/helios", ["crates/orion-core"]),
                package("xtask", "tools/xtask"),
            ],
        }

    def select(self, *paths, full=False):
        return ci_plan.plan(self.metadata, paths, full=full)

    def test_docs_do_not_start_builds(self):
        result = self.select("docs/testing/TESTING.md", "README.md")
        self.assertFalse(any(result.values()))

    def test_cli_change_does_not_build_gateway_or_windows(self):
        result = self.select("tools/helios/src/inspect.rs")
        self.assertEqual(result["linux"], "-p helios")
        self.assertFalse(result["windows"])
        self.assertFalse(result["embed_web"])

    def test_api_change_covers_transitive_dependents_and_embedded_ui(self):
        result = self.select("crates/helios-api/src/internal.rs")
        self.assertEqual(result["linux"], "-p helios-api -p heliosd")
        self.assertTrue(result["embed_web"])
        self.assertFalse(result["windows"])

    def test_shared_contract_reaches_both_platforms(self):
        result = self.select("crates/aether/src/secrets.rs")
        self.assertIn("-p heliosd", result["linux"])
        self.assertIn("-p helios", result["linux"])
        self.assertNotIn("-p xtask", result["linux"])
        self.assertEqual(result["windows"], "-p orion -p orion-core")
        self.assertTrue(result["aether"])

    def test_target_build_and_dev_dependencies_are_followed_by_path(self):
        self.metadata["packages"][-1]["dependencies"] = [{
            "name": "renamed_contract", "path": "/repo/crates/aether",
            "kind": "dev", "target": "cfg(windows)", "optional": True,
        }]
        self.assertIn("-p xtask", self.select("crates/aether/src/lib.rs")["linux"])

    def test_frontend_change_starts_only_its_frontend(self):
        result = self.select("apps/orion/src/App.tsx")
        self.assertTrue(result["orion_ui"])
        self.assertFalse(result["web"])
        self.assertFalse(result["linux"])
        self.assertFalse(result["windows"])
        self.assertFalse(result["audit"])

    def test_rust_shell_change_starts_windows_without_frontend_tests(self):
        result = self.select("apps/orion/src-tauri/src/lib.rs")
        self.assertEqual(result["windows"], "-p orion")
        self.assertFalse(result["linux"])
        self.assertFalse(result["orion_ui"])

    def test_lockfile_change_covers_all_rust_and_audits(self):
        result = self.select("Cargo.lock")
        self.assertIn("-p xtask", result["linux"])
        self.assertIn("-p orion ", result["windows"])
        self.assertTrue(result["audit"])

    def test_npm_lockfile_starts_audits_without_rust_builds(self):
        result = self.select("web/package-lock.json")
        self.assertTrue(result["web"])
        self.assertTrue(result["audit"])
        self.assertFalse(result["linux"])

    def test_vendor_changes_cover_rust(self):
        self.assertIn("-p heliosd", self.select("vendor/rustables/src/lib.rs")["linux"])

    def test_deleted_files_are_selected_without_existence_check(self):
        self.assertEqual(self.select("tools/helios/src/deleted.rs")["linux"], "-p helios")

    def test_powershell_change_keeps_windows_validation(self):
        self.assertIn("-p orion", self.select("scripts/deploy-app.ps1")["windows"])

    def test_manual_and_ci_config_changes_exercise_all_checks(self):
        for result in [self.select(full=True), self.select(".github/workflows/regression.yml")]:
            self.assertTrue(all(result.values()))

    def test_invalid_package_name_fails_before_producing_shell_arguments(self):
        self.metadata["packages"][0]["name"] = "aether; false"
        with self.assertRaisesRegex(ValueError, "Unsupported Cargo package name"):
            self.select("Cargo.lock")


if __name__ == "__main__":
    unittest.main()
