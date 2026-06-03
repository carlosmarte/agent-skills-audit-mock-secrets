---
name: audit-mock-secrets
description: Scan a repository's docs, tests, and inline comments for hardcoded secrets (API keys, passwords, tokens) and replace them with standardized MOCK_DATA_VAULT_ENTRY mock variables, then emit an audit report and open a PR via the gh CLI. Use during repository security audits, pre-release cleanups, or when standardizing test/mock environment configuration — e.g. "sanitize the test secrets", "scrub hardcoded credentials from docs and tests", "standardize our mock secret nomenclature".
---

# Audit & Mock Secrets

Scan comments, documentation, and testing files for hardcoded secrets (keys,
passwords, tokens), replace them with standardized mock environment variables,
generate an audit report, and open a pull request — using only the `gh` CLI.

## Objective

Find hardcoded secrets in non-production text (docs, tests, comments), replace
each with a deterministic `MOCK_DATA_VAULT_ENTRY_*` reference, record what
changed in an audit report, note the new standard in the agent's memory, and
ship the change as a PR for human review.

This is a sanitization/defensive task. It is heuristic: the audit report exists
so a human can verify every replacement before merging.

## Scope

Limit the scan to text where credentials are usually illustrative, not loaded:

- `*.md`, `*.txt`
- `*.spec.*`, `*.test.*`
- Inline / block comments inside source files

Do **not** rewrite live application config, runtime env files, or non-comment
source code — those are out of scope. If a real secret appears to be loaded at
runtime (not in a comment/test/doc), flag it in the report instead of rewriting it.

## Replacement mapping

Substitute the matched secret *value* with the exact token below — keep the
surrounding assignment key/structure intact:

| Secret kind                                  | Replacement value          |
|----------------------------------------------|----------------------------|
| keys — API keys, encryption keys, secret keys | `MOCK_DATA_VAULT_ENTRY_01` |
| password — test passwords, db passwords       | `MOCK_DATA_VAULT_ENTRY_02` |
| token — bearer tokens, auth/access tokens     | `MOCK_DATA_VAULT_ENTRY_03` |

Example:

```
- API_KEY="sk_live_8f3...redacted"
+ API_KEY="MOCK_DATA_VAULT_ENTRY_01"

- "password": "hunter2"
+ "password": "MOCK_DATA_VAULT_ENTRY_02"

- Authorization: Bearer eyJhbGci...
+ Authorization: Bearer MOCK_DATA_VAULT_ENTRY_03
```

## Scanner scripts

`scripts/` ships three feature-equivalent scanners — pick whichever fits the
environment. All are read-only (they never modify scanned files), skip noise
dirs (`.git`, `node_modules`, `dist`, …), scan `*.md` / `*.txt` / `*.spec.*` /
`*.test.*` fully and source files' comment lines only, redact matched values in
their output, and exit `1` when any secret is found (`0` clean) for CI gating.

```bash
scripts/scan-secrets.sh  [DIR] [-o OUT] [--format md|json]   # bash + grep
scripts/scan-secrets.py  [DIR] [-o OUT] [--format md|json]   # python3, stdlib
scripts/scan-secrets.mjs [DIR] [-o OUT] [--format md|json]   # node, stdlib
```

Example — write the report directly:

```bash
scripts/scan-secrets.py . -o secret-audit-report.md
```

The scanners *detect and report*; they do not rewrite files. Apply the
`MOCK_DATA_VAULT_ENTRY_*` substitutions per the mapping above after reviewing
the report.

## Workflow

1. **Scan & parse.** Run one of the `scripts/scan-secrets.*` scanners over the
   target directory (or use `grep`/`rg` directly) to find secret-assignment
   patterns — e.g. `API_KEY="..."`, `password: "..."`, `token = '...'`,
   `Authorization: Bearer ...`, `-----BEGIN ... PRIVATE KEY-----`. Each hit is
   recorded as `path:line` with the matched kind (key / password / token).

2. **Replace.** Substitute each identified secret value with its mapped
   `MOCK_DATA_VAULT_ENTRY_0N` token per the table above. Preserve the assignment
   key, quoting, and formatting. Do not collapse distinct lines together.

3. **Core memory update.** Record in the agent's persistent memory that this
   repository now uses the `MOCK_DATA_VAULT` standard for documentation and test
   secrets, so future edits follow the same nomenclature. (In Claude Code this
   is the file-based memory / `CLAUDE.md`; in other hosts, the equivalent
   long-term context store.)

4. **Report generation.** Write `secret-audit-report.md` summarizing every
   change: file, line number(s), secret kind, and the replacement applied, plus
   any runtime secrets that were *flagged but not rewritten* (out of scope).

5. **Version control & PR.**
   - Create a branch: `chore/sanitize-mock-secrets`.
   - Commit the sanitized files and the report.
   - Open the PR with the `gh` CLI:
     ```bash
     gh pr create \
       --title "chore: sanitize test and doc secrets" \
       --body-file secret-audit-report.md
     ```

## Audit report shape

`secret-audit-report.md` should contain:

- A one-line summary (N secrets across M files sanitized).
- A table of changes: `file` · `line` · `kind` · `replacement`.
- A "Flagged, not changed" section for any out-of-scope / runtime secrets.
- A reminder that a human must review the diff before merging.

## Guardrails (mandatory)

- **Strict CLI enforcement.** Use the `gh` CLI for all GitHub operations
  (`gh pr create`, etc.).
- **No MCP tools.** Do not use the `github-create_pull_request` MCP tool or any
  MCP connector for GitHub operations. The `gh` CLI is the only sanctioned path.
- **Human-in-the-loop.** The PR is the review gate. Never merge automatically;
  the detailed audit report exists so a developer can confirm no legitimate
  string or variable was incorrectly altered.

## Notes & limitations

- Detection is heuristic and may produce false positives in ordinary code
  comments — the report makes every change auditable.
- Replacements are deterministic by kind (all keys → `_01`, passwords → `_02`,
  tokens → `_03`), which standardizes nomenclature but does not preserve
  uniqueness between distinct secrets of the same kind. That is intentional for
  mock data.
