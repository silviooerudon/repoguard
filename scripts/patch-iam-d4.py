"""Patch lib/iam.ts to wire detectAdminEquivalents (D4).

Two edits:
  1. Add `import { detectAdminEquivalents } from "./iam-admin"` after
     the existing import from "./iam-privesc".
  2. Add `findings.push(...detectAdminEquivalents(stmts, batch[j].path))`
     after the privesc invocation in assessIAM's per-file loop.

Run from repo root:
    python scripts\\patch-iam-d4.py
"""
from __future__ import annotations

import sys
from pathlib import Path

PATH = Path("lib/iam.ts")

OLD_IMPORT = 'import { detectPrivilegeEscalation } from "./iam-privesc"\n'
NEW_IMPORT = (
    'import { detectPrivilegeEscalation } from "./iam-privesc"\n'
    'import { detectAdminEquivalents } from "./iam-admin"\n'
)

OLD_LOOP = (
    '      findings.push(...detectPrivilegeEscalation(stmts, batch[j].path))\n'
)
NEW_LOOP = (
    '      findings.push(...detectPrivilegeEscalation(stmts, batch[j].path))\n'
    '      findings.push(...detectAdminEquivalents(stmts, batch[j].path))\n'
)


def main() -> int:
    if not PATH.exists():
        print(f"ERROR: {PATH} not found. Run from repo root.")
        return 1

    text = PATH.read_text(encoding="utf-8")

    if 'from "./iam-admin"' in text:
        print("Import already present, skipping import edit.")
    else:
        if text.count(OLD_IMPORT) != 1:
            print("ERROR: import anchor not found exactly once.")
            return 1
        text = text.replace(OLD_IMPORT, NEW_IMPORT, 1)
        print("Edit 1/2: import added.")

    if "detectAdminEquivalents(stmts" in text:
        print("Loop already wired, skipping loop edit.")
    else:
        if text.count(OLD_LOOP) != 1:
            print("ERROR: loop anchor not found exactly once.")
            return 1
        text = text.replace(OLD_LOOP, NEW_LOOP, 1)
        print("Edit 2/2: loop wired.")

    PATH.write_text(text, encoding="utf-8", newline="\n")
    print("Wrote lib/iam.ts")
    return 0


if __name__ == "__main__":
    sys.exit(main())
