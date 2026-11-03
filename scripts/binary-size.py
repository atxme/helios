#!/usr/bin/env python3
"""Measure declared release binaries and enforce the signed-update size contract.

Provenance is a builder-supplied attestation. This tool checks its schema and
comparability but cannot prove which compiler flags produced a binary.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys

REPORT_TYPE = "helios-binary-size-report"
REPORT_VERSION = 1
PROVENANCE_VERSION = 1
UPDATE_SOURCE = Path("crates/helios-update/src/lib.rs")
MAX_U64 = (1 << 64) - 1
CHUNK_BYTES = 1024 * 1024


class AuditError(Exception):
    """Invalid input, incompatible provenance, or unsafe artifact tree."""


class SizeViolation(AuditError):
    """A declared update binary violates its source-defined size contract."""


def _exact_keys(value, expected, label):
    if not isinstance(value, dict):
        raise AuditError(f"{label} must be a JSON object")
    keys = set(value)
    if keys != set(expected):
        missing = sorted(set(expected) - keys)
        unknown = sorted(keys - set(expected))
        details = []
        if missing:
            details.append("missing: " + ", ".join(missing))
        if unknown:
            details.append("unknown: " + ", ".join(unknown))
        raise AuditError(f"{label} fields invalid ({'; '.join(details)})")


def _reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise AuditError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _read_json(path, label):
    try:
        with Path(path).open("r", encoding="utf-8") as stream:
            return json.load(stream, object_pairs_hook=_reject_duplicate_keys)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise AuditError(f"cannot read {label} {path}: {error}") from error


def _artifact_path(raw):
    if not isinstance(raw, str) or not raw or "\\" in raw:
        raise AuditError("artifact path must be a non-empty POSIX relative path")
    path = PurePosixPath(raw)
    if path.is_absolute() or any(part in ("", ".", "..") for part in raw.split("/")):
        raise AuditError(f"unsafe artifact path: {raw!r}")
    if path.as_posix() != raw:
        raise AuditError(f"artifact path is not canonical: {raw!r}")
    return raw


def validate_provenance(value):
    _exact_keys(value, {
        "version", "revision", "target", "rustc", "profile", "features",
        "instrumented", "stripped", "artifacts",
    }, "provenance")
    if type(value["version"]) is not int or value["version"] != PROVENANCE_VERSION:
        raise AuditError("unsupported provenance version")
    if not isinstance(value["revision"], str) or not re.fullmatch(
        r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})", value["revision"]
    ):
        raise AuditError("revision must be a 40- or 64-character hexadecimal git object ID")
    for key in ("target", "rustc"):
        if not isinstance(value[key], str) or not value[key].strip():
            raise AuditError(f"provenance.{key} must be a non-empty string")
    if value["profile"] != "release":
        raise AuditError("provenance.profile must be 'release'")
    features = value["features"]
    if not isinstance(features, list) or any(not isinstance(item, str) or not item for item in features):
        raise AuditError("provenance.features must be a list of non-empty strings")
    if features != sorted(set(features)):
        raise AuditError("provenance.features must be sorted and unique")
    if value["instrumented"] is not False or value["stripped"] is not True:
        raise AuditError("provenance must attest instrumented=false and stripped=true")
    artifacts = value["artifacts"]
    if not isinstance(artifacts, list) or not artifacts:
        raise AuditError("provenance.artifacts must be a non-empty list")
    seen = set()
    for index, artifact in enumerate(artifacts):
        label = f"provenance.artifacts[{index}]"
        _exact_keys(artifact, {"path", "contract"}, label)
        path = _artifact_path(artifact["path"])
        if path in seen:
            raise AuditError(f"duplicate artifact path: {path}")
        seen.add(path)
        if artifact["contract"] not in ("helios-update", "unbounded"):
            raise AuditError(f"{label}.contract must be 'helios-update' or 'unbounded'")
    return value


def _integer_literal(text):
    cleaned = text.replace("_", "")
    match = re.fullmatch(
        r"(0[xX][0-9a-fA-F]+|0[oO][0-7]+|0[bB][01]+|[0-9]+)(?:u64)?", cleaned
    )
    if not match:
        raise AuditError(f"unsupported Rust integer literal: {text!r}")
    token = match.group(1)
    if token.lower().startswith("0x"):
        return int(token[2:], 16)
    if token.lower().startswith("0o"):
        return int(token[2:], 8)
    if token.lower().startswith("0b"):
        return int(token[2:], 2)
    return int(token, 10)


def parse_rust_integer_expression(expression):
    """Parse integer literals, parentheses, and multiplication only."""
    expression = expression.strip()
    token_pattern = re.compile(
        r"\s*(0[xX][0-9a-fA-F_]+|0[oO][0-7_]+|0[bB][01_]+|[0-9][0-9_]*(?:u64)?|[()*])"
    )
    tokens = []
    cursor = 0
    while cursor < len(expression):
        if not expression[cursor:].strip():
            break
        match = token_pattern.match(expression, cursor)
        if not match:
            raise AuditError("MAX_BINARY_SIZE expression must contain only integer literals, parentheses, and '*'")
        tokens.append(match.group(1))
        cursor = match.end()
    if not tokens:
        raise AuditError("MAX_BINARY_SIZE expression is empty")
    position = 0

    def atom():
        nonlocal position
        if position >= len(tokens):
            raise AuditError("incomplete MAX_BINARY_SIZE expression")
        token = tokens[position]
        if token == "(":
            position += 1
            value = product()
            if position >= len(tokens) or tokens[position] != ")":
                raise AuditError("unbalanced MAX_BINARY_SIZE expression")
            position += 1
            return value
        if token in ("*", ")"):
            raise AuditError("invalid MAX_BINARY_SIZE expression")
        position += 1
        return _integer_literal(token)

    def product():
        nonlocal position
        value = atom()
        while position < len(tokens) and tokens[position] == "*":
            position += 1
            value *= atom()
            if value > MAX_U64:
                raise AuditError("MAX_BINARY_SIZE overflows u64")
        return value

    value = product()
    if position != len(tokens):
        raise AuditError("trailing tokens in MAX_BINARY_SIZE expression")
    if value <= 0 or value > MAX_U64:
        raise AuditError("MAX_BINARY_SIZE must be within 1..=u64::MAX")
    return value


def read_update_limit(root):
    source = Path(root) / UPDATE_SOURCE
    try:
        text = source.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise AuditError(f"cannot read canonical update contract {source}: {error}") from error
    pattern = re.compile(
        r"^\s*pub\s+const\s+MAX_BINARY_SIZE\s*:\s*u64\s*=\s*(.*?);\s*$",
        re.MULTILINE,
    )
    matches = pattern.findall(text)
    if len(matches) != 1:
        raise AuditError("expected exactly one simple pub const MAX_BINARY_SIZE: u64 declaration")
    return parse_rust_integer_expression(matches[0])


def _walk_artifacts(root):
    found = set()

    def walk(directory, prefix=""):
        try:
            entries = list(os.scandir(directory))
        except OSError as error:
            raise AuditError(f"cannot scan artifact directory {directory}: {error}") from error
        for entry in entries:
            relative = f"{prefix}/{entry.name}" if prefix else entry.name
            try:
                info = entry.stat(follow_symlinks=False)
            except OSError as error:
                raise AuditError(f"cannot inspect artifact path {relative}: {error}") from error
            if stat.S_ISLNK(info.st_mode):
                raise AuditError(f"symlinks are not allowed in artifact directory: {relative}")
            if stat.S_ISDIR(info.st_mode):
                walk(entry.path, relative)
            elif stat.S_ISREG(info.st_mode):
                found.add(relative)
            else:
                raise AuditError(f"special files are not allowed in artifact directory: {relative}")

    walk(root)
    return found


def _macho_executable(stream, offset, size, depth=0):
    if depth > 1:
        return False
    stream.seek(offset)
    head = stream.read(32)
    magic = head[:4]
    thin = {
        b"\xfe\xed\xfa\xce": ("big", 28), b"\xce\xfa\xed\xfe": ("little", 28),
        b"\xfe\xed\xfa\xcf": ("big", 32), b"\xcf\xfa\xed\xfe": ("little", 32),
    }
    if magic in thin:
        byte_order, minimum = thin[magic]
        return size >= minimum and int.from_bytes(head[12:16], byte_order) == 2
    fat = {
        b"\xca\xfe\xba\xbe": ("big", 20, 4), b"\xbe\xba\xfe\xca": ("little", 20, 4),
        b"\xca\xfe\xba\xbf": ("big", 32, 8), b"\xbf\xba\xfe\xca": ("little", 32, 8),
    }
    if magic not in fat or size < 8:
        return False
    byte_order, entry_size, offset_size = fat[magic]
    count = int.from_bytes(head[4:8], byte_order)
    if count == 0 or count > (size - 8) // entry_size:
        return False
    table_size = count * entry_size
    stream.seek(offset + 8)
    table = stream.read(table_size)
    if len(table) != table_size:
        return False
    for index in range(count):
        entry = table[index * entry_size:(index + 1) * entry_size]
        if offset_size == 4:
            slice_offset = int.from_bytes(entry[8:12], byte_order)
            slice_size = int.from_bytes(entry[12:16], byte_order)
        else:
            slice_offset = int.from_bytes(entry[8:16], byte_order)
            slice_size = int.from_bytes(entry[16:24], byte_order)
        if slice_offset > size or slice_size > size - slice_offset:
            return False
        if not _macho_executable(stream, offset + slice_offset, slice_size, depth + 1):
            return False
    return True


def _is_recognized_binary(path, size):
    try:
        with Path(path).open("rb") as stream:
            head = stream.read(64)
            if head.startswith(b"\x7fELF"):
                if len(head) < 18 or head[4] not in (1, 2) or head[5] not in (1, 2):
                    return False
                order = "little" if head[5] == 1 else "big"
                return int.from_bytes(head[16:18], order) in (2, 3)
            if head.startswith(b"MZ"):
                if len(head) < 64:
                    return False
                offset = int.from_bytes(head[60:64], "little")
                if offset < 64 or offset > size - 24:
                    return False
                stream.seek(offset)
                coff = stream.read(24)
                return coff[:4] == b"PE\0\0" and bool(int.from_bytes(coff[22:24], "little") & 0x0002)
            return _macho_executable(stream, 0, size)
    except OSError as error:
        raise AuditError(f"cannot inspect binary header {path}: {error}") from error


def _hash_file(path, max_size=None):
    flags = os.O_RDONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise AuditError(f"artifact is not a regular file: {path}")
            if before.st_size <= 0:
                raise AuditError(f"artifact is empty: {path}")
            digest = hashlib.sha256()
            total = 0
            while True:
                read_size = CHUNK_BYTES
                if max_size is not None:
                    read_size = min(read_size, max_size + 1 - total)
                block = stream.read(read_size)
                if not block:
                    break
                total += len(block)
                if max_size is not None and total > max_size:
                    raise SizeViolation(f"{path} grew beyond the {max_size}-byte contract while hashing")
                digest.update(block)
            after = os.fstat(stream.fileno())
            before_state = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            after_state = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            if total != before.st_size or before_state != after_state:
                raise AuditError(f"artifact changed while hashing: {path}")
            return total, digest.hexdigest()
    except OSError as error:
        raise AuditError(f"cannot open/hash artifact {path}: {error}") from error


def _report_baseline(path):
    report = _read_json(path, "baseline report")
    base_keys = {"report_type", "version", "provenance", "size_limit_bytes", "artifacts"}
    if not isinstance(report, dict) or set(report) not in (base_keys, base_keys | {"baseline"}):
        raise AuditError("baseline report fields invalid")
    if report["report_type"] != REPORT_TYPE or type(report["version"]) is not int or report["version"] != REPORT_VERSION:
        raise AuditError("unsupported baseline report type or version")
    provenance = validate_provenance(report["provenance"])
    if type(report["size_limit_bytes"]) is not int or report["size_limit_bytes"] <= 0:
        raise AuditError("baseline size_limit_bytes must be a positive integer")
    records = report["artifacts"]
    if not isinstance(records, list) or not records:
        raise AuditError("baseline artifacts must be a non-empty list")
    parsed = {}
    for index, record in enumerate(records):
        _exact_keys(record, {"path", "contract", "size_bytes", "sha256"}, f"baseline.artifacts[{index}]")
        path_value = _artifact_path(record["path"])
        if path_value in parsed:
            raise AuditError(f"duplicate baseline artifact: {path_value}")
        if type(record["size_bytes"]) is not int or record["size_bytes"] <= 0:
            raise AuditError(f"invalid baseline size for {path_value}")
        if record["contract"] == "helios-update" and record["size_bytes"] > report["size_limit_bytes"]:
            raise AuditError(f"baseline update artifact exceeds its recorded size limit: {path_value}")
        if not isinstance(record["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", record["sha256"]):
            raise AuditError(f"invalid baseline SHA-256 for {path_value}")
        parsed[path_value] = record
    declared = {item["path"]: item["contract"] for item in provenance["artifacts"]}
    recorded = {path: record["contract"] for path, record in parsed.items()}
    if declared != recorded:
        raise AuditError("baseline report artifacts do not match its provenance")
    if "baseline" in report and report["baseline"] is not None:
        comparison = report["baseline"]
        _exact_keys(comparison, {"revision", "artifacts"}, "baseline comparison")
        if not isinstance(comparison["revision"], str) or not re.fullmatch(
            r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})", comparison["revision"]
        ):
            raise AuditError("baseline comparison revision is invalid")
        if not isinstance(comparison["artifacts"], list):
            raise AuditError("baseline comparison artifacts must be a list")
        for index, item in enumerate(comparison["artifacts"]):
            _exact_keys(item, {"path", "baseline_size_bytes", "delta_bytes"}, f"baseline comparison artifacts[{index}]")
            _artifact_path(item["path"])
            if type(item["baseline_size_bytes"]) is not int or item["baseline_size_bytes"] <= 0:
                raise AuditError("baseline comparison size is invalid")
            if type(item["delta_bytes"]) is not int:
                raise AuditError("baseline comparison delta is invalid")
    return report


def _comparable(provenance):
    comparable = {key: provenance[key] for key in (
        "target", "rustc", "profile", "features", "instrumented", "stripped"
    )}
    comparable["artifacts"] = sorted(
        (item["path"], item["contract"]) for item in provenance["artifacts"]
    )
    return comparable


def measure(root, artifacts_dir, provenance_path, baseline_path=None):
    root = Path(root)
    artifacts_root = Path(artifacts_dir)
    if not artifacts_root.is_absolute():
        artifacts_root = root / artifacts_root
    if artifacts_root.is_symlink() or not artifacts_root.is_dir():
        raise AuditError("--artifacts must name an existing, non-symlink directory")
    try:
        artifacts_root = artifacts_root.resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as error:
        raise AuditError(f"cannot resolve artifact directory: {error}") from error
    provenance = validate_provenance(_read_json(provenance_path, "provenance"))
    declared = {item["path"]: item["contract"] for item in provenance["artifacts"]}
    actual = _walk_artifacts(artifacts_root)
    if actual != set(declared):
        missing = sorted(set(declared) - actual)
        extra = sorted(actual - set(declared))
        details = []
        if missing:
            details.append("missing files: " + ", ".join(missing))
        if extra:
            details.append("undeclared files: " + ", ".join(extra))
        raise AuditError("artifact directory and provenance differ (" + "; ".join(details) + ")")
    limit = read_update_limit(root)
    records = []
    for relative in sorted(declared):
        binary_path = artifacts_root.joinpath(*PurePosixPath(relative).parts)
        try:
            initial = binary_path.lstat()
        except OSError as error:
            raise AuditError(f"cannot inspect artifact {relative}: {error}") from error
        if not stat.S_ISREG(initial.st_mode):
            raise AuditError(f"artifact is not a regular file: {relative}")
        if initial.st_size <= 0:
            raise AuditError(f"artifact is empty: {relative}")
        contract = declared[relative]
        if contract == "helios-update" and initial.st_size > limit:
            raise SizeViolation(f"{relative} is {initial.st_size} bytes; helios-update maximum is {limit}")
        if not _is_recognized_binary(binary_path, initial.st_size):
            raise AuditError(f"artifact is not a recognized ELF, PE, or Mach-O binary: {relative}")
        size, digest = _hash_file(binary_path, limit if contract == "helios-update" else None)
        if contract == "helios-update" and size > limit:
            raise SizeViolation(f"{relative} is {size} bytes; helios-update maximum is {limit}")
        records.append({"path": relative, "contract": contract, "size_bytes": size, "sha256": digest})
    report = {
        "report_type": REPORT_TYPE,
        "version": REPORT_VERSION,
        "provenance": provenance,
        "size_limit_bytes": limit,
        "artifacts": records,
    }
    if baseline_path is not None:
        baseline = _report_baseline(baseline_path)
        if baseline["size_limit_bytes"] != limit:
            raise AuditError("baseline is incompatible: helios-update size contract changed")
        if _comparable(provenance) != _comparable(baseline["provenance"]):
            raise AuditError("baseline is incompatible: target/toolchain/profile/features/flags/artifact declarations differ")
        baseline_records = {record["path"]: record for record in baseline["artifacts"]}
        report["baseline"] = {
            "revision": baseline["provenance"]["revision"],
            "artifacts": [{
                "path": current["path"],
                "baseline_size_bytes": baseline_records[current["path"]]["size_bytes"],
                "delta_bytes": current["size_bytes"] - baseline_records[current["path"]]["size_bytes"],
            } for current in records],
        }
    return report


def _safe_output_path(output, root, artifacts_dir, provenance_path, baseline_path):
    """Resolve a new report path and reject aliases of any measured/input file."""
    output = Path(output)
    if not output.is_absolute():
        output = Path.cwd() / output
    if output.is_symlink():
        raise AuditError("--output must not be a symlink")
    try:
        parent = output.parent.resolve(strict=True)
        if not parent.is_dir():
            raise AuditError("--output parent must be an existing directory")
        destination = parent / output.name
        protected = {
            (root / UPDATE_SOURCE).resolve(strict=True),
            Path(provenance_path).resolve(strict=True),
        }
        if baseline_path is not None:
            protected.add(Path(baseline_path).resolve(strict=True))
        if destination in protected:
            raise AuditError("--output aliases provenance, baseline, or canonical update source")
        artifacts = Path(artifacts_dir)
        if not artifacts.is_absolute():
            artifacts = root / artifacts
        artifacts_root = artifacts.resolve(strict=True)
        try:
            destination.relative_to(artifacts_root)
        except ValueError:
            pass
        else:
            raise AuditError("--output must be outside the artifact directory")
        if os.path.lexists(destination):
            raise AuditError("--output must name a new file; existing files and symlinks are refused")
        return destination
    except AuditError:
        raise
    except (OSError, RuntimeError, ValueError) as error:
        raise AuditError(f"cannot safely resolve --output: {error}") from error


def _write_output_exclusive(path, rendered):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = None
    identity = None
    try:
        descriptor = os.open(path, flags, 0o600)
        current = os.fstat(descriptor)
        identity = (current.st_dev, current.st_ino)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            descriptor = None
            stream.write(rendered)
            stream.flush()
    except (OSError, ValueError) as error:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if identity is not None:
            try:
                current = path.lstat()
                if (current.st_dev, current.st_ino) == identity:
                    path.unlink()
            except OSError:
                pass
        raise AuditError(f"cannot create --output exclusively: {error}") from error


def _parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1],
                        help="repository root (default: parent of scripts/)")
    parser.add_argument("--artifacts", required=True, type=Path,
                        help="dedicated directory containing only declared release binaries; relative to --root")
    parser.add_argument("--provenance", required=True, type=Path,
                        help="strict version-1 provenance JSON")
    parser.add_argument("--baseline", type=Path,
                        help="prior report JSON emitted by this script; revision may differ")
    parser.add_argument("--output", type=Path,
                        help="write report to a new path outside artifacts and inputs (default: stdout)")
    parser.epilog = (
        "Provenance is a builder-supplied attestation; this tool cannot prove compiler flags. "
        "Exit status: 0 valid; 1 helios-update size violation; "
        "2 invalid input, unsafe artifacts, or incompatible baseline."
    )
    return parser


def main(argv=None):
    args = _parser().parse_args(argv)
    try:
        root = args.root.resolve(strict=True)
        output_path = None
        if args.output is not None:
            output_path = _safe_output_path(
                args.output, root, args.artifacts, args.provenance, args.baseline
            )
        report = measure(root, args.artifacts, args.provenance, args.baseline)
        rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
        if output_path is not None:
            _write_output_exclusive(output_path, rendered)
        else:
            sys.stdout.write(rendered)
        baseline_records = {}
        if "baseline" in report:
            baseline_records = {item["path"]: item["delta_bytes"] for item in report["baseline"]["artifacts"]}
        for record in report["artifacts"]:
            delta = f" ({baseline_records[record['path']]:+d} bytes vs baseline)" if baseline_records else ""
            print(f"{record['path']}: {record['size_bytes']} bytes sha256={record['sha256']}{delta}", file=sys.stderr)
        return 0
    except SizeViolation as error:
        print(f"binary-size: size violation: {error}", file=sys.stderr)
        return 1
    except AuditError as error:
        print(f"binary-size: invalid input: {error}", file=sys.stderr)
        return 2
    except (OSError, ValueError, RuntimeError) as error:
        print(f"binary-size: invalid input: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
