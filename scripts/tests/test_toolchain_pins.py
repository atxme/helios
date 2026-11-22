"""Checks that the working toolchain pins agree across the repository."""

import importlib.util
import tempfile
from pathlib import Path
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "toolchain_pins.py"
SPEC = importlib.util.spec_from_file_location("toolchain_pins", SCRIPT)
toolchain_pins = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(toolchain_pins)

REPOSITORY = Path(__file__).resolve().parents[2]


def write_tree(root, *, dockerfile=True, docker_rust="1.100.0", docker_node="26.13.1",
               cargo_rust="1.100", setup_min="1.100", workflow_rust="1.100.0",
               workflow_node="26", workflow_extra=""):
    if dockerfile:
        build_env = root / "tools" / "build-env"
        build_env.mkdir(parents=True)
        (build_env / "Dockerfile").write_text(
            f"ARG RUST_VERSION={docker_rust}\nARG NODE_VERSION={docker_node}\nFROM debian\n"
        )
    (root / "Cargo.toml").write_text(f'[package]\nrust-version = "{cargo_rust}"\n')
    (root / "scripts").mkdir()
    (root / "scripts" / "setup-dev.sh").write_text(f'RUST_MIN="{setup_min}"\n')
    workflows = root / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "regression.yml").write_text(
        "steps:\n"
        f"  - uses: dtolnay/rust-toolchain@{workflow_rust}\n"
        "  - uses: actions/setup-node@v7\n"
        f"    with:\n      node-version: {workflow_node}\n"
        f"{workflow_extra}"
    )
    return root


class ToolchainPinsTest(unittest.TestCase):
    def check(self, **options):
        with tempfile.TemporaryDirectory() as directory:
            root = write_tree(Path(directory), **options)
            return toolchain_pins.mismatches(toolchain_pins.collect_pins(root))

    def test_matching_pins_report_nothing(self):
        self.assertEqual(self.check(), [])

    def test_a_stale_workflow_pin_is_named(self):
        problems = self.check(workflow_rust="1.95.0")
        self.assertEqual(len(problems), 1)
        self.assertIn("regression.yml", problems[0])
        self.assertIn("1.95", problems[0])

    def test_nightly_is_ignored(self):
        problems = self.check(workflow_extra="      - uses: dtolnay/rust-toolchain@nightly\n")
        self.assertEqual(problems, [])

    def test_node_major_mismatch_is_named(self):
        problems = self.check(workflow_node="24")
        self.assertEqual(len(problems), 1)
        self.assertIn("regression.yml", problems[0])
        self.assertIn("24", problems[0])

    def test_missing_dockerfile_is_not_an_error(self):
        self.assertEqual(self.check(dockerfile=False), [])

    def test_missing_dockerfile_still_compares_the_other_pins(self):
        problems = self.check(dockerfile=False, setup_min="1.95")
        self.assertEqual(len(problems), 1)
        self.assertIn("setup-dev.sh", problems[0])

    def test_repository_pins_agree(self):
        self.assertEqual(toolchain_pins.mismatches(toolchain_pins.collect_pins(REPOSITORY)), [])


if __name__ == "__main__":
    unittest.main()
