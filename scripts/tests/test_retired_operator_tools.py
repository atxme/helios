"""Guard: no message still tells an operator to run the retired astra-signer.

The operator tool is Orion. Comments may still describe the legacy
astra-signer files and journals; anything that a person reads as a
command, in code or in a script, must point to Orion instead.
"""

import unittest
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[2]
SCANNED_ROOTS = (
    "crates",
    "apps/orion/src",
    "apps/orion/src-tauri/src",
    "tools",
    "scripts",
    "deploy",
    "web/src",
)
SCANNED_SUFFIXES = (".rs", ".ts", ".tsx", ".sh", ".py", ".yaml", ".yml")
SCANNED_NAMES = ("Dockerfile",)
EXCLUDED_NAMES = ("tests.rs", "security_tests.rs")
EXCLUDED_SUFFIXES = (".test.ts", ".test.tsx")
EXCLUDED_DIRECTORIES = ("node_modules", "target", "tests")
COMMENT_PREFIXES = ("//", "/*", "*", "#")
PROTOCOL_LABEL = "helios-astra-signer-request-v5"
FORBIDDEN = ("astra-signer", "enroll document")


def scanned(path: Path) -> bool:
    relative = path.relative_to(REPOSITORY)
    if any(part in EXCLUDED_DIRECTORIES for part in relative.parts[:-1]):
        return False
    if path.name in EXCLUDED_NAMES or path.name.endswith(EXCLUDED_SUFFIXES):
        return False
    return path.name.endswith(SCANNED_SUFFIXES) or path.name in SCANNED_NAMES


def offending_lines():
    found = []
    for root in SCANNED_ROOTS:
        for path in sorted((REPOSITORY / root).rglob("*")):
            if not path.is_file() or not scanned(path):
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            for number, line in enumerate(text.splitlines(), start=1):
                stripped = line.strip()
                if stripped.startswith(COMMENT_PREFIXES):
                    continue
                code = stripped.replace(PROTOCOL_LABEL, "")
                if any(word in code for word in FORBIDDEN):
                    found.append(f"{path.relative_to(REPOSITORY)}:{number}: {stripped}")
    return found


class RetiredOperatorToolTests(unittest.TestCase):
    def test_no_message_names_the_retired_astra_signer(self):
        found = offending_lines()
        self.assertEqual(found, [], "\n".join(found))


if __name__ == "__main__":
    unittest.main()
