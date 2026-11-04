"""Checks the version rule: what a merge bumps, and what the check refuses."""

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "version.py"
SPEC = importlib.util.spec_from_file_location("version", SCRIPT)
version = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(version)


def package(root, name, directory, number, dependencies=()):
    return {
        "name": name,
        "version": number,
        "manifest_path": f"{root}/{directory}/Cargo.toml",
        "dependencies": [
            {"name": dependency, "path": f"{root}/x", "kind": kind}
            for dependency, kind in dependencies
        ],
    }


def metadata(root="/repo"):
    return {
        "workspace_root": root,
        "packages": [
            package(root, "heliosd", "crates/heliosd", "2.40.1", [("aether", None), ("tester", "dev")]),
            package(root, "helios", "tools/helios", "2.40.1"),
            package(root, "helios-installer", "tools/helios-installer", "1.5.0"),
            package(root, "astra", "crates/astra", "1.2.11"),
            package(root, "orion", "apps/orion/src-tauri", "2.78.8", [("aether", None)]),
            package(root, "aether", "crates/aether", "2.27.1"),
            package(root, "tester", "crates/tester", "1.0.0"),
            package(root, "xtask", "tools/xtask", "1.8.0"),
        ],
    }


def commit(subject, *files, body=""):
    return version.Commit(subject, body, list(files))


class LevelTests(unittest.TestCase):
    def test_a_feature_is_a_minor_and_a_breaking_change_a_major(self):
        self.assertEqual(version.level_of(commit("feat(orion): x")), version.MINOR)
        self.assertEqual(version.level_of(commit("feat(orion)!: x")), version.MAJOR)
        self.assertEqual(version.level_of(commit("fix: x", body="BREAKING CHANGE: y")), version.MAJOR)

    def test_anything_else_is_a_patch(self):
        for subject in ("fix: x", "refactor(astra): x", "test: x", "Merge something", "harden: x"):
            self.assertEqual(version.level_of(commit(subject)), version.PATCH)

    def test_the_next_version_resets_what_follows(self):
        self.assertEqual(version.next_version("2.40.1", version.PATCH), "2.40.2")
        self.assertEqual(version.next_version("2.40.1", version.MINOR), "2.41.0")
        self.assertEqual(version.next_version("2.40.1", version.MAJOR), "3.0.0")


class PlanTests(unittest.TestCase):
    def test_a_shared_crate_bumps_both_products_and_itself(self):
        plan = version.plan(metadata(), [commit("feat(aether): x", "crates/aether/src/lib.rs")])
        self.assertEqual(plan, {"helios": version.MINOR, "orion": version.MINOR, "aether": version.MINOR})

    def test_a_product_touched_alone_leaves_the_other_one(self):
        plan = version.plan(metadata(), [commit("fix(orion): x", "apps/orion/src/App.tsx")])
        self.assertEqual(plan, {"orion": version.PATCH})
        plan = version.plan(metadata(), [commit("feat(web): x", "web/src/App.tsx")])
        self.assertEqual(plan, {"helios": version.MINOR})

    def test_every_binary_of_the_gateway_counts_for_helios(self):
        for path in ("tools/helios/src/main.rs", "tools/helios-installer/src/main.rs", "crates/astra/src/lib.rs", "deploy/astra/compose.yaml"):
            self.assertIn("helios", version.plan(metadata(), [commit("fix: x", path)]), path)

    def test_a_crate_of_a_product_has_no_number_of_its_own(self):
        plan = version.plan(metadata(), [commit("fix(heliosd): x", "crates/heliosd/src/main.rs")])
        self.assertEqual(plan, {"helios": version.PATCH})

    def test_a_tool_outside_the_products_bumps_only_itself(self):
        plan = version.plan(metadata(), [commit("feat(xtask): x", "tools/xtask/src/main.rs")])
        self.assertEqual(plan, {"xtask": version.MINOR})

    def test_a_test_only_dependency_does_not_reach_the_product(self):
        plan = version.plan(metadata(), [commit("fix(tester): x", "crates/tester/src/lib.rs")])
        self.assertEqual(plan, {"tester": version.PATCH})

    def test_documentation_changes_nothing(self):
        plan = version.plan(metadata(), [commit("docs: x", "docs/ROADMAP.md", "crates/aether/README.md")])
        self.assertEqual(plan, {})

    def test_the_highest_level_wins(self):
        commits = [commit("fix: x", "web/a.ts"), commit("feat: y", "web/b.ts"), commit("test: z", "web/c.ts")]
        self.assertEqual(version.plan(metadata(), commits), {"helios": version.MINOR})

    def test_the_lockfile_is_shipped_by_both_products(self):
        plan = version.plan(metadata(), [commit("fix: x", "Cargo.lock")])
        self.assertEqual(plan, {"helios": version.PATCH, "orion": version.PATCH})

    def test_a_release_commit_does_not_count(self):
        commits = [commit("chore(release): bump helios 2.41.0", "crates/heliosd/Cargo.toml", "Cargo.lock")]
        self.assertEqual(version.plan(metadata(), commits), {})


class FileTests(unittest.TestCase):
    def test_only_the_package_version_of_a_manifest_changes(self):
        manifest = (
            '[package]\nname = "x"\nversion = "1.0.0"\n\n'
            '[dependencies]\ny = { version = "1.0.0" }\n[other]\nversion = "1.0.0"\n'
        )
        updated = version.set_manifest_version(manifest, "1.1.0")
        self.assertEqual(updated, manifest.replace('version = "1.0.0"', 'version = "1.1.0"', 1))
        self.assertEqual(version.manifest_version(updated), "1.1.0")

    def test_the_lockfile_changes_only_the_workspace_package(self):
        lock = (
            '[[package]]\nname = "aether"\nversion = "2.1.0"\ndependencies = []\n\n'
            '[[package]]\nname = "serde"\nversion = "2.1.0"\nsource = "registry"\n'
        )
        updated = version.set_lock_versions(lock, {"aether": "2.2.0", "serde": "9.9.9"})
        self.assertIn('name = "aether"\nversion = "2.2.0"', updated)
        self.assertIn('name = "serde"\nversion = "2.1.0"\nsource', updated)

    def test_a_json_file_keeps_its_layout_and_its_dependencies(self):
        text = '{\n    "version": "0.1.0",\n  "deps": {"a": {"version": "0.1.0"}}\n}\n'
        self.assertEqual(
            version.set_json_version(text, "2.0.0", 1),
            text.replace('"version": "0.1.0"', '"version": "2.0.0"', 1),
        )


class RepositoryTests(unittest.TestCase):
    """A real repository, with only `cargo metadata` replaced."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.metadata = metadata(str(self.root))
        self.previous = Path.cwd()
        os.chdir(self.root)
        self.addCleanup(os.chdir, self.previous)
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.email", "test@example.invalid")
        self.git("config", "user.name", "test")
        lock = ""
        for item in self.metadata["packages"]:
            path = Path(item["manifest_path"])
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f'[package]\nname = "{item["name"]}"\nversion = "{item["version"]}"\n')
            lock += f'[[package]]\nname = "{item["name"]}"\nversion = "{item["version"]}"\n\n'
        (self.root / "Cargo.lock").write_text(lock)
        self.write_json("web/package.json", {"version": "2.40.1"})
        self.write_json("web/package-lock.json", {"version": "2.40.1", "packages": {"": {"version": "2.40.1"}}})
        self.write_json("apps/orion/package.json", {"version": "2.78.8"})
        self.write_json("apps/orion/package-lock.json", {"version": "2.78.8", "packages": {"": {"version": "2.78.8"}}})
        self.write_json("apps/orion/src-tauri/tauri.conf.json", {"version": "2.78.8"})
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "chore: start")

    def git(self, *arguments):
        return subprocess.run(
            ["git", *arguments], check=True, capture_output=True, text=True,
        ).stdout.strip()

    def write_json(self, path, value):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(value, indent=2) + "\n")

    def change(self, path, subject):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(subject)
        self.git("add", "-A")
        self.git("commit", "-q", "-m", subject)

    def fresh_metadata(self):
        """What `cargo metadata` would answer now, from the manifests."""
        fresh = json.loads(json.dumps(self.metadata))
        for item in fresh["packages"]:
            item["version"] = version.manifest_version(Path(item["manifest_path"]).read_text())
        return fresh

    def test_merge_bumps_what_the_branch_touched_and_commits_it(self):
        self.git("switch", "-q", "-c", "topic")
        self.change("web/src/a.ts", "feat(web): a")
        self.change("web/src/b.ts", "fix(web): b")
        self.git("switch", "-q", "main")
        version.merge("topic", self.fresh_metadata)
        self.assertEqual(self.git("log", "-1", "--format=%s"), "chore(release): bump helios 2.41.0")
        fresh = self.fresh_metadata()
        self.assertEqual(version.consistency_errors(self.root, fresh), [])
        self.assertEqual(json.loads((self.root / "web/package-lock.json").read_text())["packages"][""]["version"], "2.41.0")
        self.assertIn('name = "heliosd"\nversion = "2.41.0"', (self.root / "Cargo.lock").read_text())
        self.assertIn('name = "orion"\nversion = "2.78.8"', (self.root / "Cargo.lock").read_text())
        self.assertEqual(self.git("status", "--porcelain"), "")
        self.assertEqual(version.check("HEAD~3", self.root, fresh), [])

    def test_merge_reads_the_workspace_after_the_merge(self):
        self.git("switch", "-q", "-c", "topic")
        self.change("tools/new/src/main.rs", "feat(new): a")
        self.git("switch", "-q", "main")
        seen = []

        def load():
            seen.append((self.root / "tools/new/src/main.rs").exists())
            return self.fresh_metadata()

        version.merge("topic", load)
        self.assertEqual(seen, [True])

    def test_merge_refuses_outside_main(self):
        self.git("switch", "-q", "-c", "topic")
        with self.assertRaises(version.VersionError):
            version.merge("main", self.fresh_metadata)

    def test_merge_of_documentation_commits_nothing_more(self):
        self.git("switch", "-q", "-c", "topic")
        self.change("docs/a.md", "docs: a")
        self.git("switch", "-q", "main")
        version.merge("topic", self.fresh_metadata)
        self.assertEqual(self.git("log", "-1", "--format=%s"), "docs: a")

    def test_the_check_refuses_code_without_a_new_version(self):
        base = self.git("rev-parse", "HEAD")
        self.change("web/src/a.ts", "feat(web): a")
        errors = version.check(base, self.root, self.fresh_metadata())
        self.assertEqual(len(errors), 1)
        self.assertIn("helios", errors[0])

    def test_the_check_accepts_documentation_without_a_new_version(self):
        base = self.git("rev-parse", "HEAD")
        self.change("docs/a.md", "docs: a")
        self.assertEqual(version.check(base, self.root, self.fresh_metadata()), [])

    def test_the_check_refuses_files_that_disagree(self):
        self.write_json("apps/orion/src-tauri/tauri.conf.json", {"version": "0.26.0"})
        errors = version.consistency_errors(self.root, self.fresh_metadata())
        self.assertEqual(len(errors), 1)
        self.assertIn("tauri.conf.json", errors[0])

    def test_a_minor_the_windows_installer_cannot_carry_is_refused(self):
        for item in self.metadata["packages"]:
            if item["name"] == "orion":
                item["version"] = "2.255.0"
        self.change("apps/orion/src/a.ts", "feat(orion): a")
        with self.assertRaises(version.VersionError):
            version.bump("HEAD~1", self.metadata)


if __name__ == "__main__":
    unittest.main()
