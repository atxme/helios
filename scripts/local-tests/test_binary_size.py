"""Tests for the local, non-building binary size audit."""

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / "binary-size.py"
SPEC = importlib.util.spec_from_file_location("binary_size", SCRIPT)
binary_size = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(binary_size)


ELF18 = b"\x7fELF\x02\x01" + bytes(10) + b"\x03\x00"


def provenance(path="heliosd", contract="helios-update", revision="a" * 40):
    return {
        "version": 1,
        "revision": revision,
        "target": "x86_64-unknown-linux-gnu",
        "rustc": "rustc 1.95.0 (59807616e 2026-04-14)",
        "profile": "release",
        "features": ["all", "embed-ui"],
        "instrumented": False,
        "stripped": True,
        "artifacts": [{"path": path, "contract": contract}],
    }


def write_json(path, value):
    path.write_text(json.dumps(value), encoding="utf-8")


def make_root(directory, limit="16"):
    source = directory / "crates/helios-update/src"
    source.mkdir(parents=True)
    (source / "lib.rs").write_text(
        f"pub const MAX_BINARY_SIZE: u64 = {limit};\n", encoding="utf-8"
    )


class RustConstantTests(unittest.TestCase):
    def test_parses_only_literals_parentheses_and_multiplication(self):
        self.assertEqual(binary_size.parse_rust_integer_expression("128 * 1024 * 1024"), 134217728)
        self.assertEqual(binary_size.parse_rust_integer_expression("(2_u64 * 8)"), 16)

    def test_rejects_unknown_or_ambiguous_expression(self):
        for expression in ("LIMIT", "1 + 2", "1 / 2", "include!(\"x\")", "1; 2", ""):
            with self.subTest(expression=expression):
                with self.assertRaises(binary_size.AuditError):
                    binary_size.parse_rust_integer_expression(expression)

    def test_requires_one_canonical_declaration(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_root(root, "(8 * 2)")
            self.assertEqual(binary_size.read_update_limit(root), 16)
            source = root / binary_size.UPDATE_SOURCE
            source.write_text("pub const MAX_BINARY_SIZE: u64 = SIZE;\n", encoding="utf-8")
            with self.assertRaises(binary_size.AuditError):
                binary_size.read_update_limit(root)
            source.write_text(
                "pub const MAX_BINARY_SIZE: u64 = 16;\npub const MAX_BINARY_SIZE: u64 = 16;\n",
                encoding="utf-8",
            )
            with self.assertRaises(binary_size.AuditError):
                binary_size.read_update_limit(root)


class ProvenanceTests(unittest.TestCase):
    def test_rejects_unknown_fields_unordered_features_and_debug_build(self):
        value = provenance()
        value["unexpected"] = True
        with self.assertRaises(binary_size.AuditError):
            binary_size.validate_provenance(value)
        value = provenance()
        value["features"] = list(reversed(value["features"]))
        with self.assertRaises(binary_size.AuditError):
            binary_size.validate_provenance(value)
        value = provenance()
        value["profile"] = "debug"
        with self.assertRaises(binary_size.AuditError):
            binary_size.validate_provenance(value)
        value = provenance()
        value["instrumented"] = True
        with self.assertRaises(binary_size.AuditError):
            binary_size.validate_provenance(value)

    def test_rejects_traversal_duplicate_paths_and_unknown_contract(self):
        for path, contract in (("../outside", "unbounded"), ("heliosd", "msi")):
            with self.subTest(path=path, contract=contract):
                value = provenance(path, contract)
                with self.assertRaises(binary_size.AuditError):
                    binary_size.validate_provenance(value)
        value = provenance()
        value["artifacts"].append({"path": "heliosd", "contract": "unbounded"})
        with self.assertRaises(binary_size.AuditError):
            binary_size.validate_provenance(value)


class MeasurementTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        make_root(self.root, "18")
        self.artifacts = self.root / "dist"
        self.artifacts.mkdir()
        self.binary = self.artifacts / "heliosd"
        self.binary.write_bytes(ELF18)
        self.provenance_path = self.root / "provenance.json"
        write_json(self.provenance_path, provenance())

    def tearDown(self):
        self.temporary.cleanup()

    def measure(self, baseline=None):
        return binary_size.measure(self.root, self.artifacts, self.provenance_path, baseline)

    def test_accepts_exact_contract_limit_and_hashes_binary(self):
        report = self.measure()
        record = report["artifacts"][0]
        self.assertEqual(record["size_bytes"], 18)
        self.assertEqual(record["sha256"], __import__("hashlib").sha256(ELF18).hexdigest())
        self.assertEqual(report["size_limit_bytes"], 18)

    def test_rejects_one_byte_over_contract_limit(self):
        self.binary.write_bytes(ELF18 + b"x")
        with self.assertRaises(binary_size.SizeViolation):
            self.measure()

    def test_recognizes_executable_pe_and_macho_headers(self):
        pe = bytearray(88)
        pe[:2] = b"MZ"
        pe[60:64] = (64).to_bytes(4, "little")
        pe[64:68] = b"PE\0\0"
        pe[86:88] = (0x0002).to_bytes(2, "little")
        self.binary.write_bytes(pe)
        write_json(self.provenance_path, provenance(contract="unbounded"))
        self.assertEqual(self.measure()["artifacts"][0]["size_bytes"], 88)
        macho = bytearray(28)
        macho[:4] = b"\xfe\xed\xfa\xce"
        macho[12:16] = (2).to_bytes(4, "big")  # MH_EXECUTE
        self.binary.write_bytes(macho)
        self.assertEqual(self.measure()["artifacts"][0]["size_bytes"], 28)
        macho[12:16] = (1).to_bytes(4, "big")  # MH_OBJECT
        self.binary.write_bytes(macho)
        with self.assertRaises(binary_size.AuditError):
            self.measure()

    def test_main_returns_one_for_size_violation_and_two_for_invalid_input(self):
        self.binary.write_bytes(ELF18 + b"x")
        args = ["--root", str(self.root), "--artifacts", str(self.artifacts),
                "--provenance", str(self.provenance_path)]
        self.assertEqual(binary_size.main(args), 1)
        self.binary.write_bytes(ELF18)
        invalid = provenance()
        invalid["extra"] = True
        write_json(self.provenance_path, invalid)
        self.assertEqual(binary_size.main(args), 2)

    def test_unbounded_artifact_has_no_update_limit(self):
        self.binary.write_bytes(ELF18 + b"x")
        write_json(self.provenance_path, provenance(contract="unbounded"))
        self.assertEqual(self.measure()["artifacts"][0]["size_bytes"], 19)

    def test_rejects_empty_and_unrecognized_files(self):
        self.binary.write_bytes(b"")
        with self.assertRaises(binary_size.AuditError):
            self.measure()
        self.binary.write_bytes(b"not a binary")
        with self.assertRaises(binary_size.AuditError):
            self.measure()
        # ELF relocatable objects carry the ELF magic but are not executables.
        self.binary.write_bytes(b"\x7fELF\x02\x01" + bytes(10) + b"\x01\x00")
        with self.assertRaises(binary_size.AuditError):
            self.measure()

    def test_rejects_undeclared_files_and_symlinks(self):
        extra = self.artifacts / "other"
        extra.write_bytes(ELF18)
        with self.assertRaisesRegex(binary_size.AuditError, "undeclared"):
            self.measure()
        extra.unlink()
        link = self.artifacts / "linked"
        try:
            link.symlink_to(self.binary)
        except (NotImplementedError, OSError):
            self.skipTest("symlink creation unavailable")
        with self.assertRaisesRegex(binary_size.AuditError, "symlinks"):
            self.measure()

    def test_baseline_ignores_revision_but_checks_metadata_and_reports_delta(self):
        baseline_provenance = provenance(revision="b" * 40)
        baseline = {
            "report_type": binary_size.REPORT_TYPE,
            "version": 1,
            "provenance": baseline_provenance,
            "size_limit_bytes": 18,
            "artifacts": [{
                "path": "heliosd", "contract": "helios-update", "size_bytes": 12,
                "sha256": "0" * 64,
            }],
        }
        baseline_path = self.root / "baseline.json"
        write_json(baseline_path, baseline)
        report = self.measure(baseline_path)
        self.assertEqual(report["baseline"]["artifacts"][0]["delta_bytes"], 6)
        baseline["artifacts"][0]["size_bytes"] = 19
        write_json(baseline_path, baseline)
        with self.assertRaisesRegex(binary_size.AuditError, "exceeds its recorded size limit"):
            self.measure(baseline_path)
        baseline["artifacts"][0]["size_bytes"] = 12
        baseline["size_limit_bytes"] = 17
        write_json(baseline_path, baseline)
        with self.assertRaisesRegex(binary_size.AuditError, "size contract changed"):
            self.measure(baseline_path)
        baseline["size_limit_bytes"] = 18
        baseline["provenance"]["target"] = "aarch64-unknown-linux-gnu"
        write_json(baseline_path, baseline)
        with self.assertRaisesRegex(binary_size.AuditError, "incompatible"):
            self.measure(baseline_path)

    def _main_with_output(self, output, baseline=None):
        args = ["--root", str(self.root), "--artifacts", str(self.artifacts),
                "--provenance", str(self.provenance_path), "--output", str(output)]
        if baseline is not None:
            args.extend(["--baseline", str(baseline)])
        with contextlib.redirect_stderr(io.StringIO()):
            return binary_size.main(args)

    def test_output_refuses_artifact_inputs_source_existing_file_and_symlink(self):
        artifact_bytes = self.binary.read_bytes()
        provenance_bytes = self.provenance_path.read_bytes()
        source = self.root / binary_size.UPDATE_SOURCE
        source_bytes = source.read_bytes()
        self.assertEqual(self._main_with_output(self.binary), 2)
        self.assertEqual(self.binary.read_bytes(), artifact_bytes)
        self.assertEqual(self._main_with_output(self.provenance_path), 2)
        self.assertEqual(self.provenance_path.read_bytes(), provenance_bytes)
        self.assertEqual(self._main_with_output(source), 2)
        self.assertEqual(source.read_bytes(), source_bytes)
        inside = self.artifacts / "report.json"
        self.assertEqual(self._main_with_output(inside), 2)
        self.assertFalse(inside.exists())
        existing = self.root / "existing.json"
        existing.write_bytes(b"preserve me")
        self.assertEqual(self._main_with_output(existing), 2)
        self.assertEqual(existing.read_bytes(), b"preserve me")
        target = self.root / "symlink-target.json"
        target.write_bytes(b"also preserve me")
        link = self.root / "output-link.json"
        try:
            link.symlink_to(target)
        except (NotImplementedError, OSError):
            self.skipTest("symlink creation unavailable")
        self.assertEqual(self._main_with_output(link), 2)
        self.assertTrue(link.is_symlink())
        self.assertEqual(target.read_bytes(), b"also preserve me")

    def test_output_refuses_baseline_alias_and_write_errors_are_clean(self):
        baseline_path = self.root / "baseline.json"
        baseline = {
            "report_type": binary_size.REPORT_TYPE, "version": 1,
            "provenance": provenance(revision="b" * 40), "size_limit_bytes": 18,
            "artifacts": [{"path": "heliosd", "contract": "helios-update",
                           "size_bytes": 12, "sha256": "0" * 64}],
        }
        write_json(baseline_path, baseline)
        bytes_before = baseline_path.read_bytes()
        self.assertEqual(self._main_with_output(baseline_path, baseline_path), 2)
        self.assertEqual(baseline_path.read_bytes(), bytes_before)
        new_output = self.root / "new-report.json"
        with mock.patch.object(binary_size, "_write_output_exclusive", side_effect=OSError("disk full")):
            self.assertEqual(self._main_with_output(new_output), 2)
        self.assertFalse(new_output.exists())

    def test_main_writes_report_without_invoking_build_tools(self):
        output = self.root / "report.json"
        result = self._main_with_output(output)
        self.assertEqual(result, 0)
        self.assertEqual(json.loads(output.read_text(encoding="utf-8"))["version"], 1)
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertNotIn("subprocess", source)
        self.assertNotIn("cargo build", source)


if __name__ == "__main__":
    unittest.main()
