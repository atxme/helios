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
               workflow_node="26", workflow_extra="", astra_rust=None):
    """Writes a repository where a None pin means the source exists but states no version."""
    if dockerfile:
        build_env = root / "tools" / "build-env"
        build_env.mkdir(parents=True)
        arguments = ""
        if docker_rust is not None:
            arguments += f"ARG RUST_VERSION={docker_rust}\n"
        if docker_node is not None:
            arguments += f"ARG NODE_VERSION={docker_node}\n"
        (build_env / "Dockerfile").write_text(arguments + "FROM debian\n")
    if astra_rust is not None:
        astra = root / "deploy" / "astra"
        astra.mkdir(parents=True)
        (astra / "Dockerfile").write_text(f"FROM rust:{astra_rust}-trixie AS build\n")
    if cargo_rust is None:
        (root / "Cargo.toml").write_text('[package]\nname = "helios"\n')
    else:
        (root / "Cargo.toml").write_text(f'[package]\nrust-version = "{cargo_rust}"\n')
    (root / "scripts").mkdir()
    if setup_min is None:
        (root / "scripts" / "setup-dev.sh").write_text("# no minimum\n")
    else:
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

    def test_the_astra_image_pin_is_checked(self):
        self.assertEqual(self.check(astra_rust="1.100"), [])
        problems = self.check(astra_rust="1.95")
        self.assertEqual(len(problems), 1)
        self.assertIn("deploy/astra/Dockerfile", problems[0])
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

    def test_a_pin_source_without_a_rust_pin_is_a_mismatch(self):
        problems = self.check(cargo_rust=None)
        self.assertEqual(len(problems), 1)
        self.assertIn("Cargo.toml", problems[0])
        self.assertIn("aucune version", problems[0])

    def test_a_setup_script_without_a_minimum_is_a_mismatch(self):
        problems = self.check(setup_min=None)
        self.assertEqual(len(problems), 1)
        self.assertIn("setup-dev.sh", problems[0])

    def test_a_dockerfile_without_either_arg_is_a_mismatch(self):
        problems = self.check(docker_rust=None, docker_node=None)
        self.assertEqual(len(problems), 2)
        self.assertTrue(all("Dockerfile" in problem for problem in problems))
        self.assertTrue(any(problem.startswith("rust:") for problem in problems))
        self.assertTrue(any(problem.startswith("node:") for problem in problems))

    def test_a_dockerfile_without_a_node_arg_is_a_mismatch(self):
        problems = self.check(docker_node=None)
        self.assertEqual(len(problems), 1)
        self.assertTrue(problems[0].startswith("node:"))
        self.assertIn("Dockerfile", problems[0])

    def test_yaml_workflows_are_scanned(self):
        with tempfile.TemporaryDirectory() as directory:
            root = write_tree(Path(directory))
            (root / ".github" / "workflows" / "release.yaml").write_text(
                "steps:\n  - uses: dtolnay/rust-toolchain@1.95.0\n"
            )
            problems = toolchain_pins.mismatches(toolchain_pins.collect_pins(root))
        self.assertEqual(len(problems), 1)
        self.assertIn("release.yaml", problems[0])

    def test_the_dockerfile_is_the_reference_even_in_a_minority(self):
        with tempfile.TemporaryDirectory() as directory:
            root = write_tree(Path(directory), docker_rust="1.95.0", cargo_rust="1.100",
                              setup_min="1.100", workflow_rust="1.100.0")
            problems = toolchain_pins.mismatches(toolchain_pins.collect_pins(root))
        self.assertEqual(len(problems), 3)
        self.assertTrue(all("référence : tools/build-env/Dockerfile" in p for p in problems))

    def test_without_a_dockerfile_the_most_frequent_pin_is_the_reference(self):
        with tempfile.TemporaryDirectory() as directory:
            root = write_tree(Path(directory), dockerfile=False, setup_min="1.95")
            problems = toolchain_pins.mismatches(toolchain_pins.collect_pins(root))
        self.assertEqual(len(problems), 1)
        self.assertIn("setup-dev.sh", problems[0])

    def test_repository_pins_agree(self):
        self.assertEqual(toolchain_pins.mismatches(toolchain_pins.collect_pins(REPOSITORY)), [])


if __name__ == "__main__":
    unittest.main()
