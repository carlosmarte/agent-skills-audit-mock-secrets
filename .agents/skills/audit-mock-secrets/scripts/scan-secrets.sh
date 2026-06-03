#!/usr/bin/env bash
#
# Scan a directory for hardcoded secrets and emit an audit report.
#
# Part of the `audit-mock-secrets` skill. Detects API keys, passwords, and
# tokens in documentation (*.md, *.txt), test/spec files (*.spec.*, *.test.*),
# and source-code comments. Each finding is classified by kind and annotated
# with the MOCK_DATA_VAULT_ENTRY replacement the skill would apply.
#
# Read-only: never modifies scanned files. Depends only on coreutils + grep.
#
# Usage:  scan-secrets.sh [TARGET_DIR] [-o OUT] [--format md|json]
# Exit:   0 = clean, 1 = secrets found, 2 = usage error.
set -euo pipefail

TARGET="."
OUTPUT=""
FORMAT="md"

while [ $# -gt 0 ]; do
  case "$1" in
    -o|--output) OUTPUT="${2:?missing value for $1}"; shift 2;;
    --format)    FORMAT="${2:?missing value for $1}"; shift 2;;
    -h|--help)   grep -E '^# ' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
    -*)          echo "unknown option: $1" >&2; exit 2;;
    *)           TARGET="$1"; shift;;
  esac
done

[ -d "$TARGET" ] || { echo "error: not a directory: $TARGET" >&2; exit 2; }
case "$FORMAT" in md|json) ;; *) echo "error: --format must be md or json" >&2; exit 2;; esac

# Character classes for a quote / a non-quote, built without escaping headaches.
Q='["'"'"']'      # matches a single OR double quote
NQ='[^"'"'"']'    # matches any char that is NOT a quote

# kind -> replacement token
repl() {
  case "$1" in
    key)      printf 'MOCK_DATA_VAULT_ENTRY_01';;
    password) printf 'MOCK_DATA_VAULT_ENTRY_02';;
    token)    printf 'MOCK_DATA_VAULT_ENTRY_03';;
  esac
}

# Per-kind detection regexes (POSIX ERE). Value patterns + keyword=assignment.
RX_KEY="(api[_-]?key|secret[_-]?key|encryption[_-]?key|access[_-]?key|client[_-]?secret|private[_-]?key|apikey)[[:space:]]*[:=][[:space:]]*${Q}${NQ}{4,}${Q}|AKIA[0-9A-Z]{16}|sk_(live|test)_[A-Za-z0-9]{8,}|-----BEGIN ([A-Z ]+ )?PRIVATE KEY-----"
RX_PASSWORD="(password|passwd|pwd)[[:space:]]*[:=][[:space:]]*${Q}${NQ}{3,}${Q}"
RX_TOKEN="(auth[_-]?token|access[_-]?token|refresh[_-]?token|bearer[_-]?token|id[_-]?token|api[_-]?token|token)[[:space:]]*[:=][[:space:]]*${Q}${NQ}{4,}${Q}|Bearer[[:space:]]+[A-Za-z0-9._-]{12,}|gh[pousr]_[A-Za-z0-9]{20,}|eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"

is_text_scope() {  # filename in {*.md,*.txt,*.spec.*,*.test.*}
  case "$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')" in
    *.md|*.txt|*.spec.*|*.test.*) return 0;;
    *) return 1;;
  esac
}

is_source() {
  case "$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')" in
    *.js|*.mjs|*.cjs|*.ts|*.tsx|*.jsx|*.py|*.rb|*.go|*.java|*.rs|*.php|*.c|*.cpp|*.h|*.hpp|*.cs|*.kt|*.swift|*.scala|*.sh|*.bash|*.zsh|*.yaml|*.yml|*.toml|*.ini|*.cfg|*.env|*.properties) return 0;;
    *) return 1;;
  esac
}

is_comment() {  # trimmed line starts with a comment marker
  case "$1" in
    \#*|//*|/\**|\**|"<!--"*|--*|\;*) return 0;;
    *) return 1;;
  esac
}

redact() {  # keep first 4 chars, mask the rest (up to 8 stars)
  local s="$1" n=${#1}
  if [ "$n" -le 4 ]; then printf '%*s' "$n" '' | tr ' ' '*'; return; fi
  local stars=$(( n - 4 )); [ "$stars" -gt 8 ] && stars=8
  printf '%s%s' "${s:0:4}" "$(printf '%*s' "$stars" '' | tr ' ' '*')"
}

TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

scan_one() {  # $1=file  $2=kind  $3=regex  $4=comment_only(0|1)
  local file="$1" kind="$2" rx="$3" comment_only="$4" repl_tok
  repl_tok="$(repl "$kind")"
  # `|| true`: a no-match grep exits 1, which would trip `set -e`/pipefail.
  { grep -nE -- "$rx" "$file" 2>/dev/null || true; } | while IFS= read -r m; do
    local lineno="${m%%:*}" content="${m#*:}"
    if [ "$comment_only" = "1" ]; then
      local trimmed="${content#"${content%%[![:space:]]*}"}"
      is_comment "$trimmed" || continue
    fi
    local match red
    match="$(printf '%s' "$content" | grep -oE -- "$rx" 2>/dev/null | head -n1 || true)"
    red="$(redact "$match")"
    local rel="${file#"$TARGET"/}"; rel="${rel#./}"
    # TSV: file \t line \t kind \t replacement \t redacted
    printf '%s\t%s\t%s\t%s\t%s\n' "$rel" "$lineno" "$kind" "$repl_tok" "$red" >> "$TMP"
  done
}

# Walk the tree, skipping noise dirs, and scan in-scope files.
while IFS= read -r -d '' file; do
  base="$(basename "$file")"
  if is_text_scope "$base"; then
    comment_only=0
  elif is_source "$base"; then
    comment_only=1
  else
    continue
  fi
  scan_one "$file" key      "$RX_KEY"      "$comment_only"
  scan_one "$file" password "$RX_PASSWORD" "$comment_only"
  scan_one "$file" token    "$RX_TOKEN"    "$comment_only"
done < <(find "$TARGET" \
  \( -name .git -o -name node_modules -o -name dist -o -name build \
     -o -name vendor -o -name .venv -o -name venv -o -name __pycache__ \
     -o -name .next -o -name .cache -o -name coverage -o -name .idea \) -prune \
  -o -type f -print0)

# Dedupe (first kind wins per file:line), then sort by file, line.
SORTED="$(sort -t"$(printf '\t')" -k1,1 -k2,2n "$TMP" 2>/dev/null \
  | awk -F'\t' '!seen[$1 FS $2]++')"
COUNT="$(printf '%s' "$SORTED" | grep -c . || true)"
FILES="$(printf '%s\n' "$SORTED" | awk -F'\t' 'NF{print $1}' | sort -u | grep -c . || true)"
TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

emit() {
  if [ "$FORMAT" = "json" ]; then
    printf '[\n'
    local first=1
    while IFS=$'\t' read -r f l k r red; do
      [ -z "$f" ] && continue
      [ "$first" = 0 ] && printf ',\n'
      first=0
      printf '  {"file":"%s","line":%s,"kind":"%s","replacement":"%s","preview":"%s"}' \
        "$f" "$l" "$k" "$r" "$red"
    done <<< "$SORTED"
    printf '\n]\n'
    return
  fi
  printf '# Secret Audit Report\n\n'
  printf -- '- Generated: %s\n' "$TS"
  printf -- '- Target: %s\n' "$TARGET"
  printf -- '- Findings: %s across %s file(s)\n\n' "$COUNT" "$FILES"
  if [ "$COUNT" -eq 0 ]; then
    printf 'No hardcoded secrets detected in scope. \xe2\x9c\x85\n'
    return
  fi
  printf '| File | Line | Kind | Replacement | Match (redacted) |\n'
  printf '|------|------|------|-------------|------------------|\n'
  while IFS=$'\t' read -r f l k r red; do
    [ -z "$f" ] && continue
    red="${red//|/\\|}"
    printf '| %s | %s | %s | `%s` | `%s` |\n' "$f" "$l" "$k" "$r" "$red"
  done <<< "$SORTED"
  printf '\n> Heuristic detection — review each row before applying replacements.\n'
}

if [ -n "$OUTPUT" ]; then
  emit > "$OUTPUT"
  echo "$COUNT finding(s) — report written to $OUTPUT" >&2
else
  emit
fi

[ "$COUNT" -eq 0 ] && exit 0 || exit 1
