#!/usr/bin/env python3
"""Scan a directory for hardcoded secrets and emit an audit report.

Part of the `audit-mock-secrets` skill. Detects API keys, passwords, and tokens
in documentation (`*.md`, `*.txt`), test/spec files (`*.spec.*`, `*.test.*`),
and source-code comments. Each finding is classified by kind and annotated with
the MOCK_DATA_VAULT_ENTRY replacement that the skill would apply.

Read-only: this script never modifies the files it scans.

Usage:
    scan-secrets.py [TARGET_DIR] [-o OUT] [--format md|json]

Exit codes: 0 = clean, 1 = secrets found, 2 = usage error.
"""
import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone

REPLACEMENT = {
    "key": "MOCK_DATA_VAULT_ENTRY_01",
    "password": "MOCK_DATA_VAULT_ENTRY_02",
    "token": "MOCK_DATA_VAULT_ENTRY_03",
}

SKIP_DIRS = {
    ".git", "node_modules", "dist", "build", "vendor", ".venv", "venv",
    "__pycache__", ".next", ".cache", "coverage", ".idea",
}

SOURCE_EXTS = {
    ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".py", ".rb", ".go",
    ".java", ".rs", ".php", ".c", ".cpp", ".h", ".hpp", ".cs", ".kt",
    ".swift", ".scala", ".sh", ".bash", ".zsh", ".yaml", ".yml", ".toml",
    ".ini", ".cfg", ".env", ".properties",
}

COMMENT_PREFIXES = ("#", "//", "/*", "*", "<!--", "--", ";")


def _p(rx, kind, group=1):
    return (re.compile(rx, re.IGNORECASE), kind, group)


# Order matters: first match on a line wins. High-signal value patterns first.
PATTERNS = [
    _p(r"(-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----)", "key"),
    _p(r"\b(AKIA[0-9A-Z]{16})\b", "key"),
    _p(r"\b(sk_(?:live|test)_[A-Za-z0-9]{8,})\b", "key"),
    _p(r"\b(gh[pousr]_[A-Za-z0-9]{20,})\b", "token"),
    _p(r"\b(eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)\b", "token"),
    _p(r"\bBearer\s+([A-Za-z0-9._\-]{12,})", "token"),
    _p(r"(?:api[_-]?key|secret[_-]?key|encryption[_-]?key|access[_-]?key|"
       r"client[_-]?secret|private[_-]?key|apikey)\s*[:=]\s*['\"]([^'\"]{4,})['\"]", "key"),
    _p(r"(?:password|passwd|pwd)\s*[:=]\s*['\"]([^'\"]{3,})['\"]", "password"),
    _p(r"(?:auth[_-]?token|access[_-]?token|refresh[_-]?token|bearer[_-]?token|"
       r"id[_-]?token|api[_-]?token|token)\s*[:=]\s*['\"]([^'\"]{4,})['\"]", "token"),
]


def in_text_scope(name):
    n = name.lower()
    return n.endswith(".md") or n.endswith(".txt") or ".spec." in n or ".test." in n


def is_source(name):
    return os.path.splitext(name)[1].lower() in SOURCE_EXTS


def is_comment_line(line):
    return line.strip().startswith(COMMENT_PREFIXES)


def redact(val):
    val = val.strip()
    if len(val) <= 4:
        return "*" * len(val)
    return val[:4] + "*" * min(len(val) - 4, 8)


def scan_file(path, root):
    findings = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except OSError:
        return findings
    name = os.path.basename(path)
    text_scope = in_text_scope(name)
    source = is_source(name)
    for i, line in enumerate(lines, 1):
        # In source files (not test/spec/doc), only inspect comment lines.
        if not text_scope and source and not is_comment_line(line):
            continue
        for rx, kind, grp in PATTERNS:
            m = rx.search(line)
            if not m:
                continue
            val = m.group(grp)
            preview = line.rstrip("\n").replace(val, redact(val)).strip()[:120]
            findings.append({
                "file": os.path.relpath(path, root),
                "line": i,
                "kind": kind,
                "replacement": REPLACEMENT[kind],
                "preview": preview,
            })
            break  # one finding per line
    return findings


def walk(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            if in_text_scope(fn) or is_source(fn):
                yield os.path.join(dirpath, fn)


def render_md(findings, root):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    files = len({f["file"] for f in findings})
    out = [
        "# Secret Audit Report",
        "",
        f"- Generated: {ts}",
        f"- Target: {root}",
        f"- Findings: {len(findings)} across {files} file(s)",
        "",
    ]
    if not findings:
        out.append("No hardcoded secrets detected in scope. ✅")
        return "\n".join(out) + "\n"
    out.append("| File | Line | Kind | Replacement | Match (redacted) |")
    out.append("|------|------|------|-------------|------------------|")
    for f in findings:
        prev = f["preview"].replace("|", "\\|")
        out.append(f"| {f['file']} | {f['line']} | {f['kind']} | "
                   f"`{f['replacement']}` | `{prev}` |")
    out.append("")
    out.append("> Heuristic detection — review each row before applying replacements.")
    return "\n".join(out) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description="Scan a directory for hardcoded secrets.")
    ap.add_argument("target", nargs="?", default=".", help="directory to scan (default: .)")
    ap.add_argument("-o", "--output", help="write report to this file (default: stdout)")
    ap.add_argument("--format", choices=["md", "json"], default="md", help="report format")
    args = ap.parse_args(argv)

    root = os.path.abspath(args.target)
    if not os.path.isdir(root):
        print(f"error: not a directory: {args.target}", file=sys.stderr)
        return 2

    findings = []
    for path in walk(root):
        findings.extend(scan_file(path, root))
    findings.sort(key=lambda f: (f["file"], f["line"]))

    report = (json.dumps(findings, indent=2) + "\n") if args.format == "json" else render_md(findings, root)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report)
        print(f"{len(findings)} finding(s) — report written to {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(report)

    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
