"""Patch both scan pages to render IamCard below PostureCard (D5).

Three edits per file:
  1. Add `import { IamCard } from "@/app/components/iam-card"` after the
     existing PostureCard import.
  2. Add `import type { IAMResult } from "@/lib/iam"` after the existing
     PostureResult import.
  3. Extend ScanResultFull with `iam?: IAMResult` after the existing
     `posture?: PostureResult` line.
  4. Render `<IamCard iam={result.iam} />` below the existing PostureCard
     render, guarded by `result.iam &&`.

Run from repo root:
    python scripts\\patch-iam-d5-pages.py
"""
from __future__ import annotations

import sys
from pathlib import Path

PAGES = [
    Path("app/dashboard/scan/[owner]/[repo]/page.tsx"),
    Path("app/scan-public/[owner]/[repo]/page.tsx"),
]

OLD_IMPORT_POSTURE_CARD = (
    'import { PostureCard } from "@/app/components/posture-card"\n'
)
NEW_IMPORT_POSTURE_CARD = (
    'import { PostureCard } from "@/app/components/posture-card"\n'
    'import { IamCard } from "@/app/components/iam-card"\n'
)

OLD_IMPORT_POSTURE_TYPE = (
    'import type { PostureResult } from "@/lib/posture"\n'
)
NEW_IMPORT_POSTURE_TYPE = (
    'import type { PostureResult } from "@/lib/posture"\n'
    'import type { IAMResult } from "@/lib/iam"\n'
)

OLD_TYPE_FIELD = '  posture?: PostureResult\n'
NEW_TYPE_FIELD = (
    '  posture?: PostureResult\n'
    '  iam?: IAMResult\n'
)

OLD_RENDER = (
    '      {result.posture && <PostureCard posture={result.posture} />}\n'
)
NEW_RENDER = (
    '      {result.posture && <PostureCard posture={result.posture} />}\n'
    '      {result.iam && <IamCard iam={result.iam} />}\n'
)

EDITS = [
    ("import IamCard", OLD_IMPORT_POSTURE_CARD, NEW_IMPORT_POSTURE_CARD, "iam-card"),
    ("import IAMResult type", OLD_IMPORT_POSTURE_TYPE, NEW_IMPORT_POSTURE_TYPE, "IAMResult"),
    ("extend ScanResultFull", OLD_TYPE_FIELD, NEW_TYPE_FIELD, "iam?: IAMResult"),
    ("render IamCard", OLD_RENDER, NEW_RENDER, "<IamCard"),
]


def patch_file(path: Path) -> int:
    if not path.exists():
        print(f"ERROR: {path} not found.")
        return 1

    text = path.read_text(encoding="utf-8")
    changed = False

    for label, old, new, sentinel in EDITS:
        if sentinel in text:
            print(f"  [skip] {label}: already applied")
            continue
        if text.count(old) != 1:
            print(f"  [ERROR] {label}: anchor not found exactly once "
                  f"(found {text.count(old)})")
            return 1
        text = text.replace(old, new, 1)
        print(f"  [ok]   {label}")
        changed = True

    if changed:
        path.write_text(text, encoding="utf-8", newline="\n")
        print(f"  Wrote {path}")
    else:
        print(f"  No changes needed for {path}")
    return 0


def main() -> int:
    rc = 0
    for page in PAGES:
        print(f"\nPatching {page}")
        if patch_file(page) != 0:
            rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main())
