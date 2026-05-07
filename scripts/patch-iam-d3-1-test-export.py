"""Add a test-only export of extractStatements to lib/iam.ts.

Required by scripts/smoke-iam.ts. Naming convention __testFoo signals
internal-only use; the export is harmless in production but lets the
local smoke validate the parser without copy-pasting code.

Run from repo root:
    python scripts\\patch-iam-d3-1-test-export.py
"""
from __future__ import annotations

import sys
from pathlib import Path

PATH = Path("lib/iam.ts")

ANCHOR = "// ---------- Orchestration ----------\n"
EXPORT_LINE = (
    "// Test-only export. Do not use outside of scripts/smoke-iam.ts.\n"
    "export const __testExtractStatements = extractStatements\n"
    "\n"
)


def main() -> int:
    if not PATH.exists():
        print(f"ERROR: {PATH} not found.")
        return 1

    text = PATH.read_text(encoding="utf-8")

    if "__testExtractStatements" in text:
        print("Test export already present. Skipping.")
        return 0

    if text.count(ANCHOR) != 1:
        print("ERROR: anchor not found exactly once.")
        return 1

    text = text.replace(ANCHOR, EXPORT_LINE + ANCHOR, 1)
    PATH.write_text(text, encoding="utf-8", newline="\n")
    print("OK: __testExtractStatements export added.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
