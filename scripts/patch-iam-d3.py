"""Patch lib/iam.ts to wire detectPrivilegeEscalation (D3).

Two edits:
  1. Add `import { detectPrivilegeEscalation } from "./iam-privesc"` after
     the existing import from "./scan".
  2. Refactor the per-file inner loop in assessIAM so privilege escalation
     runs once per file (file-level detector requires all stmts of the file
     in one call), and oidc continues to run per statement.

Run from repo root:
    python scripts\patch-iam-d3.py
"""
from __future__ import annotations

import io
import sys
from pathlib import Path

PATH = Path("lib/iam.ts")

OLD_IMPORT = 'import { GitHubRateLimitError, parseGitHubRateLimit } from "./scan"\n'
NEW_IMPORT = (
    'import { GitHubRateLimitError, parseGitHubRateLimit } from "./scan"\n'
    'import { detectPrivilegeEscalation } from "./iam-privesc"\n'
)

OLD_LOOP = (
    '      const stmts = extractStatements(content, batch[j].path)\n'
    '      for (const stmt of stmts) {\n'
    '        findings.push(...detectOidcWeaknesses(stmt, batch[j].path))\n'
    '      }\n'
)
NEW_LOOP = (
    '      const stmts = extractStatements(content, batch[j].path)\n'
    '      for (const stmt of stmts) {\n'
    '        findings.push(...detectOidcWeaknesses(stmt, batch[j].path))\n'
    '      }\n'
    '      findings.push(...detectPrivilegeEscalation(stmts, batch[j].path))\n'
)


def main() -> int:
    if not PATH.exists():
        print(f"ERROR: {PATH} not found. Run from repo root.")
        return 1

    text = PATH.read_text(encoding="utf-8")

    if "from \"./iam-privesc\"" in text:
        print("Import already present, skipping import edit.")
    else:
        if text.count(OLD_IMPORT) != 1:
            print("ERROR: import anchor not found exactly once.")
            return 1
        text = text.replace(OLD_IMPORT, NEW_IMPORT, 1)
        print("Edit 1/2: import added.")

    if "detectPrivilegeEscalation(stmts" in text:
        print("Loop already wired, skipping loop edit.")
    else:
        if text.count(OLD_LOOP) != 1:
            print("ERROR: loop anchor not found exactly once.")
            print("File may have drifted. Inspect lib/iam.ts manually.")
            return 1
        text = text.replace(OLD_LOOP, NEW_LOOP, 1)
        print("Edit 2/2: loop wired.")

    # Write UTF-8 without BOM, LF line endings (let git normalize).
    PATH.write_text(text, encoding="utf-8", newline="\n")
    print("Wrote lib/iam.ts")
    return 0


if __name__ == "__main__":
    sys.exit(main())
