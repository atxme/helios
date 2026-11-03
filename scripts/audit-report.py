#!/usr/bin/env python3
"""Strict local Rust coverage projection and portable, non-regression comparison.

LLVM's summary and LCOV's unique executable DA lines are different metrics. The
production projection removes only syntax-backed test/target exclusions from DA
lines. Unknown cfg predicates remain unknown even through negation. Macros are
not expanded; their generated coverage remains included unless the containing
item is proven excluded. This tool does not measure branch or hardware coverage.
"""

import argparse
from collections import defaultdict
from decimal import Decimal, InvalidOperation
from fractions import Fraction
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys

SCHEMA_VERSION = 1
PROJECTION_VERSION = "rust-ast-da-v1"
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
LIB_KINDS = {"lib", "rlib", "dylib", "cdylib", "staticlib", "proc-macro"}
REQUIRED_TOOLS = {"rust_analyzer", "rustfmt", "cargo_llvm_cov", "llvm_cov"}


class AuditError(ValueError):
    """An input cannot support a reproducible coverage claim."""


def require(condition, message):
    if not condition:
        raise AuditError(message)


def natural(value, label):
    require(type(value) is int and value >= 0, f"{label}: expected a nonnegative integer")
    return value


def nonempty(value, label):
    require(isinstance(value, str) and bool(value.strip()), f"{label}: expected a nonempty string")
    return value


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def json_read(path):
    def pairs(values):
        result = {}
        for key, value in values:
            require(key not in result, f"{path}: duplicate JSON key {key}")
            result[key] = value
        return result
    return json.loads(path.read_text(), object_pairs_hook=pairs,
                      parse_constant=lambda value: invalid_json(value))


def invalid_json(value):
    raise AuditError(f"Non-finite JSON value: {value}")


def relative_path(value):
    require(isinstance(value, str) and value and "\\" not in value,
            f"Invalid portable source path: {value!r}")
    path = PurePosixPath(value)
    require(not path.is_absolute() and ".." not in path.parts and str(path) == value,
            f"Invalid portable source path: {value!r}")
    return path


class Sources:
    """Translate collection paths without trusting paths outside the supplied root."""

    def __init__(self, root, original_root, hashes):
        self.root = Path(root).resolve(strict=True)
        self.original = Path(nonempty(original_root, "source_root"))
        require(self.original.is_absolute() and ".." not in self.original.parts,
                "source_root must be absolute and normalized")
        require(isinstance(hashes, dict) and hashes, "source_sha256 must be a nonempty object")
        self.hashes = hashes
        for name, expected in hashes.items():
            relative_path(name)
            require(name.endswith(".rs") and isinstance(expected, str) and SHA256.fullmatch(expected),
                    f"Invalid Rust source hash: {name}")
            path = self.local(name)
            require(path.is_file(), f"Missing source file: {name}")
            require(digest(path) == expected, f"Source hash mismatch: {name}; recollect coverage")

    def local(self, name):
        relative_path(name)
        path = self.root / name
        require(path.resolve().is_relative_to(self.root), f"Source outside root: {name}")
        return path

    def remap(self, value):
        path = Path(nonempty(value, "source path"))
        require(".." not in path.parts, f"Path traversal: {value}")
        if path.is_absolute():
            if path.is_relative_to(self.original):
                name = path.relative_to(self.original).as_posix()
            elif path.is_relative_to(self.root):
                name = path.relative_to(self.root).as_posix()
            else:
                raise AuditError(f"Source outside root: {value}")
        else:
            name = path.as_posix()
        self.local(name)
        return name


def cfg_parts(text):
    """Split a cfg argument list without splitting quoted strings or nested calls."""
    parts, start, depth, quoted, escaped = [], 0, 0, False, False
    for index, char in enumerate(text):
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif char == "," and depth == 0:
            parts.append(text[start:index].strip())
            start = index + 1
        require(depth >= 0, "Malformed cfg expression")
    require(not quoted and depth == 0, "Malformed cfg expression")
    parts.append(text[start:].strip())
    if parts[-1] == "":
        parts.pop()
    require(all(parts), "Malformed cfg argument list")
    return parts


def cfg_value(text, target_cfg, features):
    """Return True, False, or None; custom/build-script cfg values are unknown."""
    text = text.strip()
    composite = re.fullmatch(r"(all|any|not)\s*\((.*)\)", text, re.S)
    if composite:
        operator, body = composite.groups()
        values = [cfg_value(part, target_cfg, features) for part in cfg_parts(body)]
        if operator == "not":
            require(len(values) == 1, "cfg(not(...)) requires exactly one argument")
            return None if values[0] is None else not values[0]
        if operator == "all":
            return False if False in values else (None if None in values else True)
        return True if True in values else (None if None in values else False)
    atom = re.fullmatch(r'([A-Za-z_][A-Za-z_0-9]*)(?:\s*=\s*("(?:[^"\\]|\\.)*"))?', text)
    require(atom is not None, f"Unsupported cfg expression: {text}")
    key, value = atom.groups()
    if key == "test" and value is None:
        return False
    if key == "feature" and value is not None:
        return json.loads(value) in features
    compact = key if value is None else f"{key}={value}"
    if compact in target_cfg:
        return True
    # Only rustc target predicates and rustc-defined flags are a closed world.
    if key.startswith("target_") or key in {"unix", "windows", "debug_assertions"}:
        return False
    return None


def metric(total, covered):
    natural(total, "total")
    natural(covered, "covered")
    require(covered <= total, "Covered count exceeds total")
    return {"total": total, "covered": covered,
            "percent": None if total == 0 else 100 * covered / total}


def production_metric(total, covered):
    return {**metric(total, covered), "gap_to_80_percent": max(0, (4 * total + 4) // 5 - covered)}


def checked_metric(value, label):
    require(isinstance(value, dict), f"{label}: expected metric object")
    total = natural(value["count"], f"{label}.count")
    covered = natural(value["covered"], f"{label}.covered")
    require(covered <= total, f"{label}: covered exceeds count")
    if "notcovered" in value:
        require(natural(value["notcovered"], label) == total - covered,
                f"{label}: inconsistent notcovered")
    if "percent" in value:
        percent = value["percent"]
        require(type(percent) in {int, float} and math.isfinite(percent) and 0 <= percent <= 100,
                f"{label}: invalid percent")
        if total:
            require(math.isclose(percent, 100 * covered / total, abs_tol=1e-7),
                    f"{label}: inconsistent percent")
    return value


def llvm_read(value, sources):
    require(value["type"] == "llvm.coverage.json.export" and
            str(value["version"]).split(".")[0] == "3", "Unsupported LLVM coverage schema")
    require(len(value["data"]) == 1, "Expected exactly one LLVM coverage data object")
    data = value["data"][0]
    require(data["files"], "LLVM coverage contains no files")
    result = {}
    for entry in data["files"]:
        name = sources.remap(entry["filename"])
        require(name in sources.hashes, f"Coverage source has no provenance hash: {name}")
        require(name not in result, f"Duplicate LLVM source file: {name}")
        summary = entry["summary"]
        for key in ("lines", "functions", "regions"):
            require(key in summary, f"Missing LLVM {key} summary: {name}")
        for key, counts in summary.items():
            checked_metric(counts, f"{name}.{key}")
        result[name] = summary
    for key, counts in data["totals"].items():
        checked_metric(counts, f"LLVM totals.{key}")
        require(all(key in summary for summary in result.values()), f"Missing LLVM metric {key}")
        require(all(sum(summary[key][field] for summary in result.values()) == counts[field]
                    for field in ("count", "covered")), f"Inconsistent LLVM totals.{key}")
    require(all(key in data["totals"] for key in ("lines", "functions", "regions")),
            "Missing LLVM totals")
    return result, data["totals"]


def parse_lcov(text, sources):
    """Require complete per-file records; deduplicate DA lines across records by max."""
    files = {}
    record = None
    for index, line in enumerate(text.splitlines(), 1):
        if not line:
            continue
        key, separator, value = line.partition(":")
        if key == "TN":
            require(record is None, f"LCOV line {index}: TN inside record")
            continue
        if key == "SF":
            require(record is None and separator, f"LCOV line {index}: nested/incomplete record")
            name = sources.remap(value)
            require(name in sources.hashes, f"LCOV source has no provenance hash: {name}")
            record = {"path": name, "da": {}, "summary": {}}
        elif key == "end_of_record":
            require(record is not None and not separator, f"LCOV line {index}: unexpected end")
            summary = record["summary"]
            require("LF" in summary and "LH" in summary, "LCOV missing LF/LH")
            require(summary["LH"] <= summary["LF"], "LCOV LH exceeds LF")
            for found, hit in (("FNF", "FNH"), ("BRF", "BRH")):
                require((found in summary) == (hit in summary), f"LCOV incomplete {found}/{hit}")
                if found in summary:
                    require(summary[hit] <= summary[found], f"LCOV {hit} exceeds {found}")
            # LLVM may report LF independently of DA entries; preserve both.
            entry = files.setdefault(record["path"], {"da": {}, "lf": 0, "lh": 0, "records": 0})
            entry["lf"] += summary["LF"]
            entry["lh"] += summary["LH"]
            entry["records"] += 1
            for number, count in record["da"].items():
                entry["da"][number] = max(entry["da"].get(number, 0), count)
            record = None
        else:
            require(record is not None and separator, f"LCOV line {index}: record required")
            if key == "DA":
                fields = value.split(",")
                require(len(fields) in {2, 3} and all(re.fullmatch(r"\d+", item) for item in fields[:2]),
                        f"LCOV line {index}: malformed DA")
                number, count = map(int, fields[:2])
                require(number > 0 and number not in record["da"],
                        f"LCOV line {index}: zero or duplicate DA line")
                record["da"][number] = count
            elif key in {"LF", "LH", "FNF", "FNH", "BRF", "BRH"}:
                require(re.fullmatch(r"\d+", value) and key not in record["summary"],
                        f"LCOV line {index}: invalid/duplicate {key}")
                record["summary"][key] = int(value)
            elif key == "FN":
                require(re.fullmatch(r"[1-9]\d*,.+", value), f"LCOV line {index}: malformed FN")
            elif key == "FNDA":
                require(re.fullmatch(r"\d+,.+", value), f"LCOV line {index}: malformed FNDA")
            elif key == "BRDA":
                require(re.fullmatch(r"[1-9]\d*,\d+,\d+,(?:\d+|-)", value),
                        f"LCOV line {index}: malformed BRDA")
            else:
                raise AuditError(f"LCOV line {index}: unsupported field {key}")
    require(record is None, "Incomplete LCOV record: missing end_of_record")
    require(files, "LCOV contains no files")
    return files


def tokens(node):
    if node["type"] == "Token":
        return node["text"]
    return "".join(tokens(child) for child in node["children"])


def children(node):
    return [child for child in node.get("children", []) if child.get("type") == "Node"]


def parse_rust(source, label):
    # `rust-analyzer parse` omits parser diagnostics in its JSON output, including
    # some missing-token errors. rustfmt supplies the syntax-error exit status.
    try:
        checked = subprocess.run(["rustfmt", "--edition", "2021", "--emit", "stdout"],
                                 input=source, text=True, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.PIPE, check=False)
        require(checked.returncode == 0, f"Rust syntax validation failed for {label}: {checked.stderr.strip()}")
        parsed = subprocess.run(["rust-analyzer", "parse", "--json"], input=source,
                                text=True, capture_output=True, check=False)
    except FileNotFoundError as error:
        raise AuditError(f"Required parser tool missing: {error.filename}") from error
    require(parsed.returncode == 0 and not parsed.stderr.strip(),
            f"rust-analyzer parsing failed for {label}: {parsed.stderr.strip()}")
    try:
        ast = json.loads(parsed.stdout)
    except json.JSONDecodeError as error:
        raise AuditError(f"Unsupported rust-analyzer JSON AST for {label}: {error}") from error
    require(ast.get("kind") == "SOURCE_FILE", f"Unsupported rust-analyzer AST for {label}")

    source_length = len(source.encode())

    def validate(node):
        require(isinstance(node, dict) and node.get("type") in {"Node", "Token"},
                f"Unsupported rust-analyzer AST node: {label}")
        require(node.get("kind") != "ERROR", f"Rust parser error in {label}")
        for key in ("start", "end"):
            require(isinstance(node.get(key), list) and len(node[key]) == 3 and
                    all(type(item) is int and item >= 0 for item in node[key]),
                    f"Unsupported rust-analyzer AST positions: {label}")
        require(node["start"][0] <= node["end"][0] <= source_length,
                f"Invalid rust-analyzer AST range: {label}")
        if node["type"] == "Node":
            require(isinstance(node.get("children"), list), f"Unsupported AST children: {label}")
            for child in node["children"]:
                validate(child)
        else:
            require(isinstance(node.get("text"), str), f"Unsupported AST token: {label}")
    validate(ast)
    return ast


def compact_tokens(node):
    if node["type"] == "Token":
        return "" if node["kind"] in {"WHITESPACE", "COMMENT"} else node["text"]
    return "".join(compact_tokens(child) for child in children_and_tokens(node))


def children_and_tokens(node):
    return node.get("children", [])


def attrs(node):
    return [compact_tokens(child) for child in children(node) if child["kind"] == "ATTR"]


def exclusion_reason(node, target_cfg, features):
    for attribute in attrs(node):
        if re.fullmatch(r"#\[(?:test|tokio::test|async_std::test)(?:\(.*\))?\]", attribute, re.S):
            return "test_attribute", attribute
        cfg = re.fullmatch(r"#!?\[cfg\((.*)\)\]", attribute, re.S)
        if cfg and cfg_value(cfg[1], target_cfg, features) is False:
            return "cfg_false_for_production", attribute
    return None


def line_range(node):
    return node["start"][1] + 1, node["end"][1] + (1 if node["end"][2] else 0)


def project_ranges(ast, target_cfg, features, source):
    result = []
    raw = source.encode()
    def walk(node):
        reason = exclusion_reason(node, target_cfg, features)
        if reason:
            start, end = line_range(node)
            begin, finish = node["start"][0], node["end"][0]
            left = raw[raw.rfind(b"\n", 0, begin) + 1:begin]
            next_line = raw.find(b"\n", finish)
            right = raw[finish:next_line if next_line >= 0 else len(raw)]
            boundaries = set()
            if left.strip():
                boundaries.add(start)
            if right.strip():
                boundaries.add(end)
            result.append({"start_line": start, "end_line": end,
                           "reason": reason[0], "evidence": reason[1],
                           "preserved_boundary_lines": sorted(boundaries)})
            return
        for child in children(node):
            walk(child)
    walk(ast)
    return result


def package_sources(package_dirs, sources):
    found = set()
    for directory in package_dirs:
        for base, dirs, names in os.walk(sources.local(directory)):
            dirs[:] = [name for name in dirs if name not in {"target", "node_modules", ".git"}]
            for name in names:
                if name.endswith(".rs"):
                    found.add((Path(base) / name).relative_to(sources.root).as_posix())
    require(found == set(sources.hashes),
            "Rust source inventory drift: "
            f"unhashed={sorted(found - sources.hashes.keys())}, "
            f"missing={sorted(sources.hashes.keys() - found)}; recollect coverage")


def workspace(metadata, provenance, sources):
    require(sources.remap(metadata["workspace_root"]) in {"."}, "Metadata workspace_root mismatch")
    members = set(metadata["workspace_members"])
    packages = [package for package in metadata["packages"] if package["id"] in members]
    require(packages and len(packages) == len(members), "Incomplete workspace metadata")
    by_directory, features, roots = {}, {}, []
    require(set(provenance["features"]) == members, "Provenance feature package set differs from metadata")
    names = set()
    for package in packages:
        name = nonempty(package["name"], "package name")
        require(name not in names, f"Duplicate workspace package name: {name}")
        names.add(name)
        directory = str(PurePosixPath(sources.remap(package["manifest_path"])).parent)
        require(directory not in by_directory, f"Duplicate package directory: {directory}")
        enabled = provenance["features"][package["id"]]
        declared = sorted(package["features"])
        require(isinstance(enabled, list) and enabled == declared,
                f"Expected resolved --all-features feature set for {name}")
        by_directory[directory] = package
        features[name] = enabled
        for target in package["targets"]:
            path = sources.remap(target["src_path"])
            require(path in sources.hashes, f"Target source missing from provenance: {path}")
            kind = set(target["kind"])
            require(kind and kind <= LIB_KINDS | {"bin", "custom-build", "test", "bench", "example"},
                    f"Unsupported Cargo target kind: {target['kind']}")
            production = bool(kind & (LIB_KINDS | {"bin", "custom-build"}))
            roots.append((path, production))
    package_sources(by_directory, sources)

    def owner(path):
        candidates = [(len(PurePosixPath(directory).parts), package["name"])
                      for directory, package in by_directory.items()
                      if PurePosixPath(path).is_relative_to(PurePosixPath(directory))]
        require(candidates, f"Unmatched workspace source: {path}")
        return max(candidates)[1]
    return by_directory, features, roots, owner


def module_usage(asts, roots, sources, features, target_cfg, owner):
    """Record production reachability before excluding any external test module."""
    usage, proofs, seen = defaultdict(set), defaultdict(set), set()
    ambiguous_include_crates = set()

    def visit(path, production, proof):
        state = (path, production)
        if state in seen:
            return
        seen.add(state)
        usage[path].add(production)
        if not production:
            proofs[path].add(proof)
        stem = PurePosixPath(path)
        path_features = features[owner(path)]
        base = stem.parent if stem.name in {"lib.rs", "main.rs", "mod.rs"} or any(path == root for root, _ in roots) else stem.with_suffix("")

        def walk(node, directory, active):
            reason = exclusion_reason(node, target_cfg, path_features)
            active = active and reason is None
            if node["kind"] == "MACRO_CALL":
                macro_path = next((tokens(child).removeprefix("::") for child in children(node)
                                   if child["kind"] == "PATH"), None)
                if macro_path == "include":
                    body = next((compact_tokens(child) for child in children(node)
                                 if child["kind"] == "TOKEN_TREE"), "")
                    literal = re.fullmatch(r'[({\[]("(?:[^"\\]|\\.)*"),?[)}\]]', body)
                    if literal:
                        raw = json.loads(literal[1])
                        relative_path(raw)
                        included = str(stem.parent / raw)
                        sources.local(included)
                        require(included in asts, f"Included Rust source missing from provenance: {path}: {raw}")
                        visit(included, active, f"{path}:{node['start'][1] + 1} include! under {reason[1] if reason else proof}")
                    elif active:
                        # Without macro expansion, any workspace file in this
                        # package may be the dynamically selected include input.
                        ambiguous_include_crates.add(owner(path))
                    return
            if node["kind"] == "MODULE":
                name_node = next((child for child in children(node) if child["kind"] == "NAME"), None)
                require(name_node is not None, f"Module has no name: {path}")
                name = tokens(name_node).removeprefix("r#")
                blocks = [child for child in children(node) if child["kind"] == "ITEM_LIST"]
                if blocks:
                    walk(blocks[0], directory / name, active)
                    return
                attributes = attrs(node)
                require(not any(attribute.startswith("#[cfg_attr(") and "path=" in attribute
                                for attribute in attributes),
                        f"Unsupported conditional module path: {path}:{node['start'][1] + 1}")
                paths = [re.fullmatch(r'#!?\[path=("(?:[^"\\]|\\.)*")\]', attribute)
                         for attribute in attributes]
                paths = [match for match in paths if match]
                require(len(paths) <= 1, f"Multiple module paths: {path}")
                if paths:
                    raw = json.loads(paths[0][1])
                    require(".." not in PurePosixPath(raw).parts and not PurePosixPath(raw).is_absolute(),
                            f"Unsupported module path traversal: {path}: {raw}")
                    # Rust's #[path] is relative to the containing source file for
                    # top-level modules. Inline-module path rules differ; reject.
                    require(directory == base, f"Unsupported inline #[path] module: {path}")
                    candidates = [str(stem.parent / raw)]
                else:
                    candidates = [str(directory / f"{name}.rs"), str(directory / name / "mod.rs")]
                matches = [candidate for candidate in candidates if candidate in asts]
                require(len(matches) <= 1, f"Ambiguous external module: {path}: {name}")
                if not matches:
                    # A target-disabled declaration need not have an on-disk file.
                    require(not active, f"Unresolved production module: {path}: {name}")
                    return
                evidence = f"{path}:{node['start'][1] + 1} {reason[1] if reason else proof}"
                visit(matches[0], active, evidence)
                return
            for child in children(node):
                walk(child, directory, active)
        walk(asts[path], base, production)
    for path, production in roots:
        visit(path, production, "Cargo non-production target" if not production else "Cargo production target")
    for path in asts:
        if owner(path) in ambiguous_include_crates:
            usage[path].add(True)
    return usage, proofs


def validate_build_inputs(proof, packages, sources):
    expected = {"Cargo.toml", "Cargo.lock"}
    expected.update(str(PurePosixPath(directory) / "Cargo.toml") for directory in packages)
    expected.update(path.relative_to(sources.root).as_posix()
                    for path in (sources.root / ".cargo").glob("*.toml"))
    hashes = proof["build_input_sha256"]
    require(isinstance(hashes, dict) and set(hashes) == expected,
            "Build input inventory drift; recollect coverage")
    for name, value in hashes.items():
        path = sources.local(name)
        require(isinstance(value, str) and SHA256.fullmatch(value) and
                path.is_file() and digest(path) == value, f"Build input hash mismatch: {name}")


def validate_provenance(provenance, view, artifacts):
    require(type(provenance["schema_version"]) is int and provenance["schema_version"] == SCHEMA_VERSION,
            "Unsupported provenance schema_version")
    require(provenance["view"] == view, "Provenance view mismatch")
    require(provenance["tests_success"] is True, "Coverage profile did not come from successful tests")
    require(type(provenance["source_dirty"]) is bool, "Invalid source_dirty")
    nonempty(provenance["source_revision"], "source_revision")
    nonempty(provenance["target"], "target")
    nonempty(provenance["rustc_version"], "rustc_version")
    cfg = provenance["rustc_cfg"]
    require(isinstance(cfg, list) and cfg and len(cfg) == len(set(cfg)) and
            all(isinstance(item, str) and item for item in cfg), "Invalid rustc_cfg")
    require(not any(item == "test" or item.startswith("feature=") for item in cfg),
            "rustc_cfg must describe the target, without test/feature overrides")
    require(isinstance(provenance["tools"], dict) and REQUIRED_TOOLS <= provenance["tools"].keys(),
            "Missing tool versions in provenance")
    for name, version in provenance["tools"].items():
        nonempty(version, f"tools.{name}")
    for name, path in artifacts.items():
        expected = provenance["artifacts_sha256"][name]
        require(isinstance(expected, str) and SHA256.fullmatch(expected) and digest(path) == expected,
                f"Artifact hash mismatch: {name}")
    # The projection parser itself is part of the reproducible toolchain.
    for command, key in (("rust-analyzer", "rust_analyzer"), ("rustfmt", "rustfmt")):
        try:
            result = subprocess.run([command, "--version"], text=True, capture_output=True, check=False)
        except FileNotFoundError as error:
            raise AuditError(f"Required parser tool missing: {command}") from error
        require(result.returncode == 0 and result.stdout.strip() == provenance["tools"][key].strip(),
                f"Parser tool version mismatch: {command}")


def summarize(root, coverage, lcov, metadata, provenance, view):
    artifact_paths = {"coverage": Path(coverage), "lcov": Path(lcov), "metadata": Path(metadata)}
    proof = json_read(Path(provenance))
    validate_provenance(proof, view, artifact_paths)
    sources = Sources(root, proof["source_root"], proof["source_sha256"])
    packages, features, roots, owner = workspace(json_read(Path(metadata)), proof, sources)
    validate_build_inputs(proof, packages, sources)
    llvm, llvm_totals = llvm_read(json_read(Path(coverage)), sources)
    records = parse_lcov(Path(lcov).read_text(), sources)
    require(set(llvm) == set(records),
            f"LLVM/LCOV file mismatch: llvm_only={sorted(llvm.keys() - records.keys())}, "
            f"lcov_only={sorted(records.keys() - llvm.keys())}")
    for name, summary in llvm.items():
        require(records[name]["lf"] == summary["lines"]["count"] and
                records[name]["lh"] == summary["lines"]["covered"],
                f"LLVM/LCOV LF/LH mismatch: {name}; exports must come from the same profiles")
    asts = {name: parse_rust(sources.local(name).read_text(), name) for name in sorted(sources.hashes)}
    target_cfg = set(proof["rustc_cfg"])
    usage, proofs = module_usage(asts, roots, sources, features, target_cfg, owner)
    rows = []
    for name, summary in sorted(llvm.items()):
        crate = owner(name)
        da = records[name]["da"]
        source_lines = len(sources.local(name).read_text().splitlines())
        require(all(number <= source_lines for number in da), f"DA line exceeds source length: {name}")
        ranges = project_ranges(asts[name], target_cfg, features[crate], sources.local(name).read_text())
        if usage[name] == {False}:
            ranges = [{"start_line": 1, "end_line": source_lines,
                       "reason": "test_only_external_module", "evidence": sorted(proofs[name])}]
        if name == "crates/aether/src/fuzzing.rs":
            declaring = asts.get("crates/aether/src/lib.rs")
            matches = [node for node in children(declaring or {}) if node["kind"] == "MODULE"
                       and any(child["kind"] == "NAME" and tokens(child) == "fuzzing" for child in children(node))]
            require(len(matches) == 1 and "#[cfg(any(test,feature=\"fuzzing\"))]" in attrs(matches[0]),
                    "The explicit aether fuzz harness ownership proof changed; review projection policy")
            ranges = [{"start_line": 1, "end_line": source_lines, "reason": "owned_fuzz_harness",
                       "evidence": "crates/aether/src/lib.rs: #[cfg(any(test,feature=\"fuzzing\"))] mod fuzzing; explicit projection policy"}]
        removed = set()
        # A line can contain a production item and a test item. Exclude only DA
        # lines fully inside the excluded byte range, preserving boundary lines
        # that share source text with production. See conservative boundary guard.
        for item in ranges:
            selected = {line for line in da if item["start_line"] <= line <= item["end_line"]
                        and line not in item.get("preserved_boundary_lines", [])}
            item["removed_lines"] = sorted(selected - removed)
            removed |= selected
        kept = {line: count for line, count in da.items() if line not in removed}
        unique = metric(len(da), sum(count > 0 for count in da.values()))
        rows.append({"path": name, "crate": crate, "raw_llvm": summary,
                     "lcov": {"reported": metric(records[name]["lf"], records[name]["lh"]),
                              "unique_da": unique, "records": records[name]["records"],
                              "llvm_minus_unique_da_total": summary["lines"]["count"] - len(da),
                              "lf_minus_unique_da_total": records[name]["lf"] - len(da)},
                     "production": production_metric(len(kept), sum(count > 0 for count in kept.values())),
                     "excluded_da": metric(len(removed), sum(da[line] > 0 for line in removed)),
                     "uncovered_lines": sorted(line for line, count in kept.items() if count == 0),
                     "exclusions": ranges})
    crates = []
    for crate in sorted({row["crate"] for row in rows}):
        selected = [row for row in rows if row["crate"] == crate]
        crates.append({"name": crate, "raw_llvm": sum_llvm(selected),
                       "production": sum_production(selected)})
    # Detect source/artifact changes during AST analysis as well as before it.
    package_sources(packages, sources)
    validate_build_inputs(proof, packages, sources)
    for name, expected in sources.hashes.items():
        require(digest(sources.local(name)) == expected, f"Source changed during analysis: {name}")
    for name, path in artifact_paths.items():
        require(digest(path) == proof["artifacts_sha256"][name], f"Artifact changed during analysis: {name}")
    return {"schema_version": SCHEMA_VERSION, "projection_version": PROJECTION_VERSION, "view": view,
            "identity": {"target": proof["target"], "rustc_version": proof["rustc_version"],
                         "rustc_cfg": sorted(target_cfg), "features": features, "tools": proof["tools"]},
            "source": {"revision": proof["source_revision"], "dirty": proof["source_dirty"],
                       "sha256": sources.hashes, "build_input_sha256": proof["build_input_sha256"], "validated": True},
            "raw_llvm": llvm_totals,
            "lcov": {"reported": sum_metrics([row["lcov"]["reported"] for row in rows]),
                     "unique_da": sum_metrics([row["lcov"]["unique_da"] for row in rows])},
            "production": sum_production(rows), "crates": crates, "files": rows}


def sum_metrics(values):
    return metric(sum(value["total"] for value in values), sum(value["covered"] for value in values))


def sum_production(rows):
    counts = sum_metrics([row["production"] for row in rows])
    return production_metric(counts["total"], counts["covered"])


def sum_llvm(rows):
    keys = set(rows[0]["raw_llvm"])
    require(all(set(row["raw_llvm"]) == keys for row in rows), "Inconsistent LLVM metric sets")
    return {key: {"count": sum(row["raw_llvm"][key]["count"] for row in rows),
                  "covered": sum(row["raw_llvm"][key]["covered"] for row in rows)} for key in sorted(keys)}


def validate_report(report):
    require(type(report["schema_version"]) is int and report["schema_version"] == SCHEMA_VERSION
            and report["projection_version"] == PROJECTION_VERSION,
            "Unsupported report schema/projection version")
    require(report["view"] in {"workspace", "libraries"}, "Invalid report view")
    require(report["source"]["validated"] is True, "Report source was not validated")
    nonempty(report["source"]["revision"], "source.revision")
    require(type(report["source"]["dirty"]) is bool, "Invalid report source.dirty")
    for field in ("sha256", "build_input_sha256"):
        require(isinstance(report["source"][field], dict) and report["source"][field],
                f"Missing source.{field}")
        for name, value in report["source"][field].items():
            relative_path(name)
            require(isinstance(value, str) and SHA256.fullmatch(value), f"Invalid report source hash: {name}")
    require(report["files"] and report["crates"], "Empty coverage report")
    require(set(report["identity"]) == {"target", "rustc_version", "rustc_cfg", "features", "tools"},
            "Incomplete report identity")
    for key in ("target", "rustc_version"):
        nonempty(report["identity"][key], f"identity.{key}")
    require(REQUIRED_TOOLS <= report["identity"]["tools"].keys(), "Incomplete report tool versions")
    paths, crates = set(), set()
    for row in report["files"]:
        relative_path(row["path"])
        require(row["path"] not in paths, "Duplicate report file")
        paths.add(row["path"])
        source_hash = report["source"]["sha256"].get(row["path"], "")
        require(isinstance(source_hash, str) and SHA256.fullmatch(source_hash), "Missing report source hash")
        require(row["production"] == production_metric(row["production"]["total"], row["production"]["covered"]),
                f"Invalid production counts: {row['path']}")
        for key, counts in row["raw_llvm"].items():
            checked_metric(counts, key)
        for counts in (row["excluded_da"], row["lcov"]["reported"], row["lcov"]["unique_da"]):
            require(counts == metric(counts["total"], counts["covered"]), "Invalid DA counts")
        require(all(row["production"][key] + row["excluded_da"][key] == row["lcov"]["unique_da"][key]
                    for key in ("total", "covered")), "Inconsistent production/excluded DA counts")
        removed = set()
        for exclusion in row["exclusions"]:
            start = natural(exclusion["start_line"], "exclusion.start_line")
            end = natural(exclusion["end_line"], "exclusion.end_line")
            require(start > 0 and end >= start and exclusion["evidence"], "Invalid exclusion proof")
            numbers = exclusion["removed_lines"]
            require(isinstance(numbers, list) and numbers == sorted(set(numbers)) and
                    all(type(number) is int and start <= number <= end for number in numbers),
                    "Invalid excluded DA line set")
            require(not removed.intersection(numbers), "Double-counted excluded DA lines")
            removed.update(numbers)
        require(len(removed) == row["excluded_da"]["total"], "Missing excluded DA proof")
        uncovered = row["uncovered_lines"]
        require(isinstance(uncovered, list) and uncovered == sorted(set(uncovered)) and
                all(type(number) is int and number > 0 for number in uncovered) and
                len(uncovered) == row["production"]["total"] - row["production"]["covered"] and
                not removed.intersection(uncovered), "Inconsistent uncovered production lines")
    for crate in report["crates"]:
        require(crate["name"] not in crates, "Duplicate report crate")
        crates.add(crate["name"])
        selected = [row for row in report["files"] if row["crate"] == crate["name"]]
        require(selected and crate["production"] == sum_production(selected), "Inconsistent crate totals")
    require(crates == {row["crate"] for row in report["files"]}, "Crate/file set mismatch")
    require(report["production"] == sum_production(report["files"]), "Inconsistent report totals")
    for key, counts in report["raw_llvm"].items():
        checked_metric(counts, key)
        require(all(sum(row["raw_llvm"][key][field] for row in report["files"]) == counts[field]
                    for field in ("count", "covered")), "Inconsistent raw LLVM report totals")
    require(report["lcov"] == {"reported": sum_metrics([row["lcov"]["reported"] for row in report["files"]]),
                                "unique_da": sum_metrics([row["lcov"]["unique_da"] for row in report["files"]])},
            "Inconsistent LCOV report totals")


def compare(baseline, current, fail_under=None):
    validate_report(baseline)
    validate_report(current)
    for key in ("view", "projection_version", "identity"):
        require(baseline[key] == current[key], f"Non-comparable reports: {key} differs")
    old_files = {row["path"]: row["production"]["total"] for row in baseline["files"]}
    new_files = {row["path"]: row["production"]["total"] for row in current["files"]}
    require(old_files == new_files, "Non-comparable reports: file membership or production denominator changed; review and establish a new baseline")
    old = {crate["name"]: crate["production"] for crate in baseline["crates"]}
    new = {crate["name"]: crate["production"] for crate in current["crates"]}
    require(old.keys() == new.keys(), "Non-comparable reports: crate set changed")
    old = {f"crate:{name}": counts for name, counts in old.items()}
    new = {f"crate:{name}": counts for name, counts in new.items()}
    old["workspace"] = baseline["production"]
    new["workspace"] = current["production"]
    failures = []
    threshold = None
    if fail_under is not None:
        try:
            decimal = Decimal(str(fail_under))
            require(decimal.is_finite() and 0 <= decimal <= 100, "Invalid line threshold: expected 0..100")
            threshold = Fraction(decimal) / 100
        except InvalidOperation as error:
            raise AuditError("Invalid line threshold") from error
    for name, previous in sorted(old.items()):
        candidate = new[name]
        require(previous["total"] == candidate["total"], f"Non-comparable denominator for {name}")
        total = candidate["total"]
        # Integer cross products preserve sub-display-precision regressions.
        if total and candidate["covered"] * previous["total"] < previous["covered"] * total:
            failures.append({"scope": name, "reason": "line_coverage_regression",
                             "baseline": previous, "current": candidate})
        if name == "workspace" and threshold is not None and total and candidate["covered"] * threshold.denominator < total * threshold.numerator:
            failures.append({"scope": name, "reason": "line_coverage_below_threshold", "current": candidate})
    return {"status": "failed" if failures else "passed", "failures": failures}, 1 if failures else 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    summary = commands.add_parser("summarize", help="Validate provenance and project unique DA production lines")
    for key in ("root", "coverage", "lcov", "metadata", "provenance"):
        summary.add_argument(f"--{key}", required=True, type=Path)
    summary.add_argument("--view", required=True, choices=("workspace", "libraries"))
    summary.add_argument("--output", type=Path)
    comparison = commands.add_parser("compare", help="Compare identical coverage contracts; denominator changes exit 2")
    comparison.add_argument("--baseline", required=True, type=Path)
    comparison.add_argument("--current", required=True, type=Path)
    comparison.add_argument("--fail-under-lines")
    args = parser.parse_args(argv)
    try:
        if args.command == "summarize":
            report = summarize(args.root, args.coverage, args.lcov, args.metadata, args.provenance, args.view)
            rendered = json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n"
            if args.output:
                require(args.output.suffix == ".json", "Report output must have a .json extension")
                # Exclusive creation protects input artifacts, sources, symlinks
                # and previous reports. Rebaseline uses a newly named report.
                with args.output.open("x") as output:
                    output.write(rendered)
            else:
                print(rendered, end="")
            return 0
        report, status = compare(json_read(args.baseline), json_read(args.current), args.fail_under_lines)
        print(json.dumps(report, indent=2, sort_keys=True, allow_nan=False))
        return status
    except (AuditError, OSError, KeyError, TypeError, json.JSONDecodeError, RecursionError) as error:
        print(f"audit-report: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
