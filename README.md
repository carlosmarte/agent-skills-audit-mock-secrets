# agent-skills-audit-mock-secrets

A skill repository for Claude Code centered on **secret sanitization** — finding
hardcoded credentials in documentation, tests, and comments and replacing them
with standardized mock references. Each skill lives under `.agents/skills/<name>/`
and is mirrored into `.claude/skills/<name>` as a relative symlink so the Claude
Code harness auto-discovers it.

## Skills

| Skill | What it does |
|-------|--------------|
| [`audit-mock-secrets`](.agents/skills/audit-mock-secrets/SKILL.md) | Scans a repo's docs, tests, and inline comments for hardcoded secrets (API keys, passwords, tokens) and replaces them with standardized `MOCK_DATA_VAULT_ENTRY` mock variables, then emits an audit report and opens a PR via the `gh` CLI. |

## Install

### Per skill — `npx skills add`

Install any single skill into Claude Code:

```bash
npx skills add carlosmarte/agent-skills-audit-mock-secrets \
  --skill audit-mock-secrets -a claude-code
```

### One-shot — add every skill

This repo ships no `install.sh`. To add all skills at once, clone the repo and
loop `npx skills add` over each skill directory:

```bash
git clone https://github.com/carlosmarte/agent-skills-audit-mock-secrets.git
cd agent-skills-audit-mock-secrets
for s in .agents/skills/*/; do
  npx skills add carlosmarte/agent-skills-audit-mock-secrets \
    --skill "$(basename "$s")" -a claude-code
done
```

## Layout

```
.agents/skills/<name>/SKILL.md                          # source of truth for each skill
.claude/skills/<name> -> ../../.agents/skills/<name>    # relative symlink (harness-discovered)
```
