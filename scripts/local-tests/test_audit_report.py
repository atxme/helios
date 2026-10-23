"""Local-only checks for coverage provenance, conservative projection and gates."""

from contextlib import redirect_stderr, redirect_stdout
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / "audit-report.py"
SPEC = importlib.util.spec_from_file_location("audit_report", SCRIPT)
audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class CfgTests(unittest.TestCase):
    def value(self, expression):
        return audit.cfg_value(expression, {"unix", 'target_os="linux"', "debug_assertions"}, {"enabled"})

    def test_unknown_remains_unknown_through_not(self):
        self.assertIsNone(self.value("build_script_flag"))
        self.assertIsNone(self.value("not(build_script_flag)"))
        self.assertIsNone(self.value("not(not(build_script_flag))"))
        self.assertIsNone(self.value("all(unix, not(build_script_flag))"))

    def test_three_valued_composition_proves_only_known_results(self):
        self.assertIs(self.value("all(test, unknown)"), False)
        self.assertIs(self.value("any(unix, unknown)"), True)
        self.assertIsNone(self.value("any(windows, unknown)"))
        self.assertIs(self.value("all()"), True)
        self.assertIs(self.value("any()"), False)

    def test_target_and_feature_predicates(self):
        self.assertIs(self.value('all(not(test), unix, target_os="linux", feature="enabled")'), True)
        self.assertIs(self.value('any(windows, feature="disabled")'), False)
        self.assertIsNone(self.value('custom="value"'))
        self.assertIsNone(self.value("proc_macro"))

    def test_bad_cfg_is_an_explicit_error(self):
        for expression in ("not()", "not(test, unix)", "all(test,,unix)", "all(test"):
            with self.subTest(expression=expression), self.assertRaises(audit.AuditError):
                self.value(expression)


class LcovTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "file.rs").write_text("fn one() {}\nfn two() {}\n")
        self.sources = audit.Sources(self.root, "/original", {"file.rs": sha(self.root / "file.rs")})

    def read(self, body):
        return audit.parse_lcov(body, self.sources)

    def record(self, body="DA:1,1\nLF:1\nLH:1\n"):
        return "SF:/original/file.rs\n" + body + "end_of_record\n"

    def test_duplicate_file_records_merge_unique_da_with_max_hits(self):
        result = self.read(self.record() + self.record("DA:1,0\nDA:2,3\nLF:4\nLH:2\n"))["file.rs"]
        self.assertEqual(result["da"], {1: 1, 2: 3})
        self.assertEqual((result["lf"], result["lh"], result["records"]), (5, 3, 2))

    def test_lf_da_discrepancy_is_preserved(self):
        result = self.read(self.record("DA:1,1\nLF:12\nLH:9\n"))["file.rs"]
        self.assertEqual((result["lf"], len(result["da"])), (12, 1))

    def test_malformed_and_incomplete_records_fail(self):
        cases = ["SF:/original/file.rs\nDA:1,1\n", self.record("DA:0,1\nLF:1\nLH:1\n"),
                 self.record("DA:1,-1\nLF:1\nLH:0\n"), self.record("DA:1,1\nDA:1,2\nLF:1\nLH:1\n"),
                 self.record("DA:1,1\nLF:0\nLH:1\n"), self.record("DA:1,1\nLF:1\n"),
                 self.record("DA:1,1\nLF:1\nLH:1\nFNF:0\nFNH:1\n"),
                 self.record("DA:1,1\nLF:1\nLH:1\nBRF:1\n"), "end_of_record\n", "DA:1,2\n",
                 self.record("DA:1,1\nLF:1\nLH:1\nBOGUS:1\n")]
        for body in cases:
            with self.subTest(body=body), self.assertRaises(audit.AuditError):
                self.read(body)

    def test_traversal_and_outside_paths_fail(self):
        for path in ("/outside/file.rs", "../file.rs", "/original/../file.rs", "other.rs"):
            with self.subTest(path=path), self.assertRaises(audit.AuditError):
                self.read(self.record().replace("/original/file.rs", path))

    def test_symlink_outside_root_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            outside = Path(directory) / "outside.rs"
            outside.write_text("fn x() {}")
            (self.root / "escape.rs").symlink_to(outside)
            with self.assertRaisesRegex(audit.AuditError, "outside root"):
                audit.Sources(self.root, "/original", {"escape.rs": sha(outside)})


class Fixture:
    """A tiny complete collector export; no Cargo compilation is needed."""

    def __init__(self, root, source=None, fixtures=True):
        self.root = root
        self.directory = root / "crates/sample"
        if (self.directory / "src").exists():
            shutil.rmtree(self.directory / "src")
        (self.directory / "src").mkdir(parents=True)
        (root / "Cargo.toml").write_text('[workspace]\nmembers = ["crates/sample"]\n')
        (root / "Cargo.lock").write_text("version = 4\n")
        (self.directory / "Cargo.toml").write_text('[package]\nname="sample"\nversion="0.1.0"\nedition="2021"\n')
        default = ("pub fn live() -> bool {\n    true\n}\n"
                   "#[cfg(test)]\nmod fixtures;\n"
                   "#[test]\nfn direct_test() {\n    assert!(live());\n}\n"
                   "#[cfg(not(custom_build_flag))]\nfn unknown() {\n    let _x = 1;\n}\n")
        (self.directory / "src/lib.rs").write_text(source if source is not None else default)
        if fixtures:
            (self.directory / "src/fixtures.rs").write_text("pub fn fixture() {\n    let _fixture = 1;\n}\n")
        self.ident = "path+file:///original/crates/sample#0.1.0"
        self.metadata = {
            "workspace_root": "/original", "workspace_members": [self.ident],
            "packages": [{"id": self.ident, "name": "sample", "manifest_path": "/original/crates/sample/Cargo.toml",
                          "features": {}, "targets": [{"kind": ["lib"], "src_path": "/original/crates/sample/src/lib.rs"}]}],
        }
        self.coverage = {"type": "llvm.coverage.json.export", "version": "3.1.0", "data": [{"files": [], "totals": {}}]}
        self.lcov = ""
        for path in sorted(self.directory.rglob("*.rs")):
            name = path.relative_to(root).as_posix()
            lines = len(path.read_text().splitlines())
            counts = {"count": lines + 3, "covered": lines}
            self.coverage["data"][0]["files"].append({"filename": f"/original/{name}",
                                                          "summary": {key: dict(counts) for key in ("lines", "functions", "regions")}})
            self.lcov += (f"SF:/original/{name}\n" + "".join(f"DA:{line},1\n" for line in range(1, lines + 1)) +
                          f"LF:{lines + 3}\nLH:{lines}\nend_of_record\n")
        for key in ("lines", "functions", "regions"):
            self.coverage["data"][0]["totals"][key] = {
                field: sum(entry["summary"][key][field] for entry in self.coverage["data"][0]["files"])
                for field in ("count", "covered")}
        self.provenance = {
            "schema_version": 1, "view": "workspace", "tests_success": True,
            "source_root": "/original", "source_revision": "123abc", "source_dirty": False,
            "source_sha256": {path.relative_to(root).as_posix(): sha(path) for path in self.directory.rglob("*.rs")},
            "build_input_sha256": {path.relative_to(root).as_posix(): sha(path)
                                   for path in (root / "Cargo.toml", root / "Cargo.lock", self.directory / "Cargo.toml")},
            "features": {self.ident: []}, "target": "x86_64-unknown-linux-gnu", "rustc_version": "rustc fixture -Vv",
            "rustc_cfg": ["unix", 'target_os="linux"', "debug_assertions"],
            "tools": {"cargo_llvm_cov": "fixture", "llvm_cov": "fixture",
                      "rust_analyzer": subprocess.check_output(["rust-analyzer", "--version"], text=True).strip(),
                      "rustfmt": subprocess.check_output(["rustfmt", "--version"], text=True).strip()},
        }
        self.write()

    def write(self):
        (self.root / "coverage.json").write_text(json.dumps(self.coverage))
        (self.root / "workspace.lcov").write_text(self.lcov)
        (self.root / "metadata.json").write_text(json.dumps(self.metadata))
        self.provenance["artifacts_sha256"] = {key: sha(self.root / filename) for key, filename in
                                              (("coverage", "coverage.json"), ("lcov", "workspace.lcov"), ("metadata", "metadata.json"))}
        (self.root / "provenance.json").write_text(json.dumps(self.provenance))

    def summarize(self):
        return audit.summarize(self.root, self.root / "coverage.json", self.root / "workspace.lcov",
                               self.root / "metadata.json", self.root / "provenance.json", "workspace")


@unittest.skipUnless(shutil.which("rustfmt") and shutil.which("rust-analyzer"), "Rust parser tools are required")
class ProjectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.fixture = Fixture(self.root)

    def test_project_inline_test_and_external_fixture_with_proof(self):
        report = self.fixture.summarize()
        audit.validate_report(report)
        rows = {row["path"]: row for row in report["files"]}
        library = rows["crates/sample/src/lib.rs"]
        fixture = rows["crates/sample/src/fixtures.rs"]
        self.assertEqual(library["production"]["total"], 7)
        self.assertEqual(fixture["production"]["total"], 0)
        self.assertEqual(fixture["exclusions"][0]["reason"], "test_only_external_module")
        self.assertIn("#[cfg(test)]", fixture["exclusions"][0]["evidence"][0])
        self.assertEqual(library["lcov"]["llvm_minus_unique_da_total"], 3)
        self.assertEqual(library["lcov"]["lf_minus_unique_da_total"], 3)
        self.assertEqual(report["identity"]["features"], {"sample": []})

    def test_shared_line_with_production_is_preserved(self):
        self.fixture = Fixture(self.root, 'pub fn prod() {} #[test] fn test_it() {}\n', fixtures=False)
        report = self.fixture.summarize()
        self.assertEqual(report["production"]["total"], 1)
        self.assertEqual(report["files"][0]["exclusions"][0]["removed_lines"], [])

    def test_target_platform_context_preserves_windows_production(self):
        self.fixture = Fixture(self.root, '#[cfg(windows)]\npub fn win() {}\n', fixtures=False)
        self.fixture.provenance["target"] = "x86_64-pc-windows-msvc"
        self.fixture.provenance["rustc_cfg"] = ["windows", 'target_os="windows"']
        self.fixture.write()
        self.assertEqual(self.fixture.summarize()["production"]["total"], 2)

    def test_external_fixture_also_referenced_by_production_is_preserved(self):
        path = self.root / "crates/sample/src/lib.rs"
        path.write_text(path.read_text() + '#[path="fixtures.rs"]\nmod reusable;\n')
        self.fixture.provenance["source_sha256"]["crates/sample/src/lib.rs"] = sha(path)
        self.fixture.write()
        report = self.fixture.summarize()
        fixture = next(row for row in report["files"] if row["path"].endswith("fixtures.rs"))
        self.assertEqual(fixture["production"]["total"], 3)

    def test_literal_production_include_prevents_test_only_exclusion(self):
        path = self.root / "crates/sample/src/lib.rs"
        path.write_text(path.read_text() + 'include!("fixtures.rs");\n')
        self.fixture.provenance["source_sha256"]["crates/sample/src/lib.rs"] = sha(path)
        self.fixture.write()
        report = self.fixture.summarize()
        fixture = next(row for row in report["files"] if row["path"].endswith("fixtures.rs"))
        self.assertEqual(fixture["production"]["total"], 3)

    def test_unknown_dynamic_production_include_preserves_ambiguous_files(self):
        path = self.root / "crates/sample/src/lib.rs"
        path.write_text(path.read_text() + 'include!(concat!(env!("SOURCE_ROOT"), "/fixtures.rs"));\n')
        self.fixture.provenance["source_sha256"]["crates/sample/src/lib.rs"] = sha(path)
        self.fixture.write()
        report = self.fixture.summarize()
        fixture = next(row for row in report["files"] if row["path"].endswith("fixtures.rs"))
        self.assertEqual(fixture["production"]["total"], 3)

    def test_source_and_build_drift_reject_baseline(self):
        for filename, message in (("crates/sample/src/lib.rs", "Source hash mismatch"),
                                  ("Cargo.lock", "Build input hash mismatch")):
            path = self.root / filename
            original = path.read_text()
            path.write_text(original + "\n")
            try:
                with self.assertRaisesRegex(audit.AuditError, message):
                    self.fixture.summarize()
            finally:
                path.write_text(original)

    def test_new_source_and_missing_file_reject_baseline(self):
        path = self.root / "crates/sample/src/new.rs"
        path.write_text("pub fn added() {}\n")
        with self.assertRaisesRegex(audit.AuditError, "inventory drift"):
            self.fixture.summarize()
        path.unlink()
        (self.root / "crates/sample/src/fixtures.rs").unlink()
        with self.assertRaisesRegex(audit.AuditError, "Missing source file"):
            self.fixture.summarize()

    def test_failed_profile_and_schema_and_view_mismatch_rejected(self):
        for field, value, message in (("tests_success", False, "successful tests"),
                                      ("schema_version", 2, "schema_version"),
                                      ("view", "libraries", "view mismatch")):
            original = self.fixture.provenance[field]
            self.fixture.provenance[field] = value
            self.fixture.write()
            with self.assertRaisesRegex(audit.AuditError, message):
                self.fixture.summarize()
            self.fixture.provenance[field] = original

    def test_artifact_hash_and_unmatched_files_rejected(self):
        path = self.root / "workspace.lcov"
        path.write_text(path.read_text() + "\n")
        with self.assertRaisesRegex(audit.AuditError, "Artifact hash mismatch"):
            self.fixture.summarize()
        self.fixture.lcov = self.fixture.lcov.split("end_of_record\n", 1)[1]
        self.fixture.write()
        with self.assertRaisesRegex(audit.AuditError, "file mismatch"):
            self.fixture.summarize()

    def test_invalid_llvm_counts_and_incomplete_lcov_fail(self):
        counts = self.fixture.coverage["data"][0]["files"][0]["summary"]["lines"]
        counts["covered"] = -1
        self.fixture.write()
        with self.assertRaisesRegex(audit.AuditError, "nonnegative"):
            self.fixture.summarize()
        counts["covered"] = counts["count"] + 1
        self.fixture.write()
        with self.assertRaisesRegex(audit.AuditError, "covered exceeds"):
            self.fixture.summarize()

    def test_lcov_summary_corruption_and_incomplete_export_fail(self):
        original = self.fixture.lcov
        self.fixture.lcov = original.replace("LF:6", "LF:7", 1)
        self.fixture.write()
        with self.assertRaisesRegex(audit.AuditError, "LF/LH mismatch"):
            self.fixture.summarize()
        self.fixture.lcov = original.rsplit("end_of_record", 1)[0]
        self.fixture.write()
        with self.assertRaisesRegex(audit.AuditError, "Incomplete LCOV"):
            self.fixture.summarize()

    def test_existing_report_is_never_overwritten(self):
        output = self.root / "REPORT.json"
        output.write_text("existing evidence")
        with redirect_stderr(io.StringIO()), redirect_stdout(io.StringIO()):
            status = audit.main(["summarize", "--root", str(self.root), "--coverage", str(self.root / "coverage.json"),
                                 "--lcov", str(self.root / "workspace.lcov"), "--metadata", str(self.root / "metadata.json"),
                                 "--provenance", str(self.root / "provenance.json"), "--view", "workspace", "--output", str(output)])
        self.assertEqual(status, 2)
        self.assertEqual(output.read_text(), "existing evidence")

    def test_parser_failure_is_explicit(self):
        with self.assertRaisesRegex(audit.AuditError, "syntax validation failed"):
            audit.parse_rust("fn missing( {", "broken.rs")
        with mock.patch.object(audit.subprocess, "run", side_effect=FileNotFoundError(2, "missing", "rustfmt")):
            with self.assertRaisesRegex(audit.AuditError, "parser tool missing"):
                audit.parse_rust("fn okay() {}", "file.rs")

    def test_cli_error_leaves_no_report_and_returns_two(self):
        self.fixture.provenance["tests_success"] = False
        self.fixture.write()
        output = self.root / "REPORT.json"
        with redirect_stderr(io.StringIO()), redirect_stdout(io.StringIO()):
            status = audit.main(["summarize", "--root", str(self.root), "--coverage", str(self.root / "coverage.json"),
                                 "--lcov", str(self.root / "workspace.lcov"), "--metadata", str(self.root / "metadata.json"),
                                 "--provenance", str(self.root / "provenance.json"), "--view", "workspace", "--output", str(output)])
        self.assertEqual(status, 2)
        self.assertFalse(output.exists())


class ComparisonTests(unittest.TestCase):
    def report(self, values=(("sample", 10, 8),)):
        rows = []
        for index, (crate, total, covered) in enumerate(values):
            raw = {key: {"count": total, "covered": covered} for key in ("lines", "functions", "regions")}
            rows.append({"path": f"crates/{crate}/file{index}.rs", "crate": crate, "raw_llvm": raw,
                         "production": audit.production_metric(total, covered), "excluded_da": audit.metric(0, 0),
                         "lcov": {"reported": audit.metric(total, covered), "unique_da": audit.metric(total, covered)},
                         "exclusions": [], "uncovered_lines": list(range(1, total - covered + 1))})
        report = {"schema_version": 1, "projection_version": audit.PROJECTION_VERSION, "view": "workspace",
                  "identity": {"target": "host", "rustc_version": "rustc version", "rustc_cfg": ["unix"], "features": {},
                               "tools": {key: "v1" for key in audit.REQUIRED_TOOLS}},
                  "source": {"revision": "abc", "dirty": False, "validated": True,
                             "sha256": {row["path"]: "a" * 64 for row in rows}, "build_input_sha256": {"Cargo.lock": "b" * 64}},
                  "files": rows, "crates": [], "production": audit.sum_production(rows), "raw_llvm": audit.sum_llvm(rows),
                  "lcov": {"reported": audit.sum_metrics([row["lcov"]["reported"] for row in rows]),
                           "unique_da": audit.sum_metrics([row["lcov"]["unique_da"] for row in rows])}}
        for crate in sorted({row["crate"] for row in rows}):
            selected = [row for row in rows if row["crate"] == crate]
            report["crates"].append({"name": crate, "raw_llvm": audit.sum_llvm(selected),
                                      "production": audit.sum_production(selected)})
        return report

    def test_equal_and_improved_coverage_pass_with_source_changes(self):
        baseline = self.report()
        current = self.report((("sample", 10, 9),))
        current["source"]["revision"] = "def"
        current["source"]["sha256"] = {key: "b" * 64 for key in current["source"]["sha256"]}
        self.assertEqual(audit.compare(baseline, current)[1], 0)
        self.assertEqual(audit.compare(baseline, baseline)[1], 0)

    def test_global_and_per_crate_regressions_fail(self):
        baseline = self.report((("a", 10, 8), ("b", 10, 8)))
        current = self.report((("a", 10, 9), ("b", 10, 7)))
        comparison, status = audit.compare(baseline, current)
        self.assertEqual(status, 1)
        self.assertEqual([failure["scope"] for failure in comparison["failures"]], ["crate:b"])
        self.assertEqual(audit.compare(self.report(), self.report((("sample", 10, 7),)))[1], 1)

    def test_sub_display_precision_regression_fails(self):
        # Both display as 99.99999%; a one-line regression must still fail.
        baseline = self.report((("sample", 100000001, 100000000),))
        current = self.report((("sample", 100000001, 99999999),))
        self.assertEqual(audit.compare(baseline, current)[1], 1)

    def test_changed_denominator_or_identity_requires_explicit_rebaseline(self):
        baseline = self.report()
        with self.assertRaisesRegex(audit.AuditError, "denominator changed"):
            audit.compare(baseline, self.report((("sample", 11, 9),)))
        for key, value in (("view", "libraries"), ("projection_version", "different")):
            current = copy.deepcopy(baseline)
            current[key] = value
            with self.subTest(key=key), self.assertRaises(audit.AuditError):
                audit.compare(baseline, current)
        current = copy.deepcopy(baseline)
        current["identity"]["target"] = "another-target"
        with self.assertRaisesRegex(audit.AuditError, "identity differs"):
            audit.compare(baseline, current)

    def test_decimal_threshold_is_exact_and_global(self):
        report = self.report((("a", 10, 9), ("b", 10, 7)))
        self.assertEqual(audit.compare(report, report, "80")[1], 0)
        self.assertEqual(audit.compare(report, report, "80.0000000000000001")[1], 1)
        for value in ("NaN", "Infinity", "-1", "101", "bad"):
            with self.subTest(value=value), self.assertRaises(audit.AuditError):
                audit.compare(report, report, value)

    def test_invalid_or_unvalidated_report_is_rejected(self):
        baseline = self.report()
        for modify in (lambda value: value["source"].update(validated=False),
                       lambda value: value["production"].update(covered=-1),
                       lambda value: value["files"][0]["production"].update(total=-1)):
            invalid = copy.deepcopy(baseline)
            modify(invalid)
            with self.assertRaises(audit.AuditError):
                audit.compare(baseline, invalid)

    def test_zero_denominator_has_no_undefined_regression(self):
        report = self.report((("sample", 0, 0),))
        self.assertEqual(audit.compare(report, report, "100")[1], 0)


if __name__ == "__main__":
    unittest.main()
