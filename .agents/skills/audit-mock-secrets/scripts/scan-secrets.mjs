#!/usr/bin/env node
/**
 * Scan a directory for hardcoded secrets and emit an audit report.
 *
 * Part of the `audit-mock-secrets` skill. Detects API keys, passwords, and
 * tokens in documentation (*.md, *.txt), test/spec files (*.spec.*, *.test.*),
 * and source-code comments. Each finding is classified by kind and annotated
 * with the MOCK_DATA_VAULT_ENTRY replacement the skill would apply.
 *
 * Read-only: never modifies scanned files. Zero dependencies (Node stdlib).
 *
 * Usage:  scan-secrets.mjs [TARGET_DIR] [-o OUT] [--format md|json]
 * Exit:   0 = clean, 1 = secrets found, 2 = usage error.
 */
import fs from "node:fs";
import path from "node:path";

const REPLACEMENT = {
  key: "MOCK_DATA_VAULT_ENTRY_01",
  password: "MOCK_DATA_VAULT_ENTRY_02",
  token: "MOCK_DATA_VAULT_ENTRY_03",
};

const SKIP_DIRS = new Set([
  ".git", "node_modules", "dist", "build", "vendor", ".venv", "venv",
  "__pycache__", ".next", ".cache", "coverage", ".idea",
]);

const SOURCE_EXTS = new Set([
  ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".py", ".rb", ".go",
  ".java", ".rs", ".php", ".c", ".cpp", ".h", ".hpp", ".cs", ".kt",
  ".swift", ".scala", ".sh", ".bash", ".zsh", ".yaml", ".yml", ".toml",
  ".ini", ".cfg", ".env", ".properties",
]);

const COMMENT_PREFIXES = ["#", "//", "/*", "*", "<!--", "--", ";"];

// Order matters: first match on a line wins. High-signal value patterns first.
const PATTERNS = [
  [/(-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----)/i, "key", 1],
  [/\b(AKIA[0-9A-Z]{16})\b/i, "key", 1],
  [/\b(sk_(?:live|test)_[A-Za-z0-9]{8,})\b/i, "key", 1],
  [/\b(gh[pousr]_[A-Za-z0-9]{20,})\b/i, "token", 1],
  [/\b(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b/i, "token", 1],
  [/\bBearer\s+([A-Za-z0-9._-]{12,})/i, "token", 1],
  [/(?:api[_-]?key|secret[_-]?key|encryption[_-]?key|access[_-]?key|client[_-]?secret|private[_-]?key|apikey)\s*[:=]\s*['"]([^'"]{4,})['"]/i, "key", 1],
  [/(?:password|passwd|pwd)\s*[:=]\s*['"]([^'"]{3,})['"]/i, "password", 1],
  [/(?:auth[_-]?token|access[_-]?token|refresh[_-]?token|bearer[_-]?token|id[_-]?token|api[_-]?token|token)\s*[:=]\s*['"]([^'"]{4,})['"]/i, "token", 1],
];

function inTextScope(name) {
  const n = name.toLowerCase();
  return n.endsWith(".md") || n.endsWith(".txt") || n.includes(".spec.") || n.includes(".test.");
}
const isSource = (name) => SOURCE_EXTS.has(path.extname(name).toLowerCase());
const isCommentLine = (line) => {
  const s = line.trimStart();
  return COMMENT_PREFIXES.some((p) => s.startsWith(p));
};

function redact(val) {
  val = val.trim();
  if (val.length <= 4) return "*".repeat(val.length);
  return val.slice(0, 4) + "*".repeat(Math.min(val.length - 4, 8));
}

function scanFile(file, root) {
  const findings = [];
  let lines;
  try {
    lines = fs.readFileSync(file, "utf8").split(/\r?\n/);
  } catch {
    return findings;
  }
  const name = path.basename(file);
  const textScope = inTextScope(name);
  const source = isSource(name);
  lines.forEach((line, idx) => {
    if (!textScope && source && !isCommentLine(line)) return;
    for (const [rx, kind, grp] of PATTERNS) {
      const m = rx.exec(line);
      if (!m) continue;
      const val = m[grp];
      const preview = line.replace(val, redact(val)).trim().slice(0, 120);
      findings.push({
        file: path.relative(root, file),
        line: idx + 1,
        kind,
        replacement: REPLACEMENT[kind],
        preview,
      });
      break; // one finding per line
    }
  });
  return findings;
}

function* walk(root) {
  let entries;
  try {
    entries = fs.readdirSync(root, { withFileTypes: true });
  } catch {
    return;
  }
  for (const e of entries) {
    const full = path.join(root, e.name);
    if (e.isDirectory()) {
      if (SKIP_DIRS.has(e.name)) continue;
      yield* walk(full);
    } else if (e.isFile() && (inTextScope(e.name) || isSource(e.name))) {
      yield full;
    }
  }
}

function isoNow() {
  // toISOString -> 2026-06-03T00:00:00.000Z ; trim millis for stable shape
  return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}

function renderMd(findings, root) {
  const files = new Set(findings.map((f) => f.file)).size;
  const out = [
    "# Secret Audit Report",
    "",
    `- Generated: ${isoNow()}`,
    `- Target: ${root}`,
    `- Findings: ${findings.length} across ${files} file(s)`,
    "",
  ];
  if (findings.length === 0) {
    out.push("No hardcoded secrets detected in scope. ✅");
    return out.join("\n") + "\n";
  }
  out.push("| File | Line | Kind | Replacement | Match (redacted) |");
  out.push("|------|------|------|-------------|------------------|");
  for (const f of findings) {
    const prev = f.preview.replace(/\|/g, "\\|");
    out.push(`| ${f.file} | ${f.line} | ${f.kind} | \`${f.replacement}\` | \`${prev}\` |`);
  }
  out.push("");
  out.push("> Heuristic detection — review each row before applying replacements.");
  return out.join("\n") + "\n";
}

function main(argv) {
  let target = ".";
  let output = null;
  let format = "md";
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "-o" || a === "--output") output = argv[++i];
    else if (a === "--format") format = argv[++i];
    else if (a === "-h" || a === "--help") {
      console.log("usage: scan-secrets.mjs [TARGET_DIR] [-o OUT] [--format md|json]");
      return 0;
    } else if (!a.startsWith("-")) target = a;
    else {
      console.error(`unknown option: ${a}`);
      return 2;
    }
  }
  if (format !== "md" && format !== "json") {
    console.error("error: --format must be md or json");
    return 2;
  }
  const root = path.resolve(target);
  if (!fs.existsSync(root) || !fs.statSync(root).isDirectory()) {
    console.error(`error: not a directory: ${target}`);
    return 2;
  }

  const findings = [];
  for (const file of walk(root)) findings.push(...scanFile(file, root));
  findings.sort((a, b) => (a.file === b.file ? a.line - b.line : a.file < b.file ? -1 : 1));

  const report = format === "json" ? JSON.stringify(findings, null, 2) + "\n" : renderMd(findings, root);
  if (output) {
    fs.writeFileSync(output, report);
    console.error(`${findings.length} finding(s) — report written to ${output}`);
  } else {
    process.stdout.write(report);
  }
  return findings.length ? 1 : 0;
}

process.exit(main(process.argv.slice(2)));
