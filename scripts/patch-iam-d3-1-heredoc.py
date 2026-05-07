"""Patch lib/iam.ts to support Terraform heredoc policy syntax (D3.1 hotfix).

TerraGoat and most real Terraform code uses:

    resource "aws_iam_role_policy" "x" {
      policy = <<EOF
        { "Version": ..., "Statement": [...] }
      EOF
    }

The current extractStatementsFromTerraform only handles jsonencode({...}) and
data "aws_iam_policy_document" blocks, so heredoc-style policies produce zero
statements. This patch adds a third regex pass for heredoc and feeds the
extracted JSON into the existing walkForStatements.

Run from repo root:
    python scripts\\patch-iam-d3-1-heredoc.py
"""
from __future__ import annotations

import sys
from pathlib import Path

PATH = Path("lib/iam.ts")

# Anchor: end of the existing extractStatementsFromTerraform function.
# We insert a new regex pass before the final "return statements".
OLD_BLOCK = (
    '  const dataDocRe = /data\\s+"aws_iam_policy_document"[^{]*\\{([\\s\\S]*?)\\n\\}\\s*$/gm\n'
    '  while ((m = dataDocRe.exec(content)) !== null) {\n'
    '    const body = m[1]\n'
    '    extractHclStatementBlocks(body, content, statements)\n'
    '  }\n'
    '\n'
    '  return statements\n'
    '}\n'
)

NEW_BLOCK = (
    '  const dataDocRe = /data\\s+"aws_iam_policy_document"[^{]*\\{([\\s\\S]*?)\\n\\}\\s*$/gm\n'
    '  while ((m = dataDocRe.exec(content)) !== null) {\n'
    '    const body = m[1]\n'
    '    extractHclStatementBlocks(body, content, statements)\n'
    '  }\n'
    '\n'
    '  // Heredoc-style policies: policy = <<EOF { ... } EOF\n'
    '  // Common in aws_iam_role_policy, aws_iam_user_policy, aws_iam_policy.\n'
    '  // Supports both <<EOF and <<-EOF (indented), and any tag name (EOF, POLICY, etc.)\n'
    '  const heredocRe = /<<-?([A-Z_][A-Z0-9_]*)\\s*\\n([\\s\\S]*?)\\n\\s*\\1\\s*$/gm\n'
    '  while ((m = heredocRe.exec(content)) !== null) {\n'
    '    const inner = m[2]\n'
    '    // Heredoc bodies may contain Terraform interpolations like ${var.x}.\n'
    '    // Replace them with a JSON-safe placeholder so JSON.parse succeeds.\n'
    '    const cleaned = inner.replace(/\\$\\{[^}]+\\}/g, "PLACEHOLDER")\n'
    '    try {\n'
    '      const parsed = JSON.parse(cleaned)\n'
    '      walkForStatements(parsed, statements, content)\n'
    '    } catch {\n'
    '      // skip blocks that are not valid JSON (e.g. shell scripts in user_data)\n'
    '    }\n'
    '  }\n'
    '\n'
    '  return statements\n'
    '}\n'
)


def main() -> int:
    if not PATH.exists():
        print(f"ERROR: {PATH} not found. Run from repo root.")
        return 1

    text = PATH.read_text(encoding="utf-8")

    if "Heredoc-style policies" in text:
        print("Heredoc parser already present. Skipping.")
        return 0

    if text.count(OLD_BLOCK) != 1:
        print("ERROR: anchor block not found exactly once. Inspect lib/iam.ts manually.")
        # debug aid:
        print(f"Occurrences found: {text.count(OLD_BLOCK)}")
        return 1

    text = text.replace(OLD_BLOCK, NEW_BLOCK, 1)
    PATH.write_text(text, encoding="utf-8", newline="\n")
    print("OK: heredoc parser injected into extractStatementsFromTerraform.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
