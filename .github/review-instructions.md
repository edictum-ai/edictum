# Review Template Instructions

Read `.github/review-template.md` and fill in the placeholders.

## Placeholder values

### Status

- `{status}`: One of `pass`, `warn`, `fail`
- `{status_icon}`: Use based on status:
  - pass: `✅`
  - warn: `⚠️`
  - fail: `🚨`
- `{status_summary}`: One line based on status:
  - pass: `**All checks passed.** No issues found in this PR.`
  - warn: `**{n} warning(s) found.** No critical issues, but some items need attention.`
  - fail: `**{n} issue(s) found** including **{c} critical**. These should be resolved before merging.`

### Sections

Only include a section if it has content. Remove the placeholder entirely if empty.

`{critical_section}` — if there are critical issues:
```markdown
### 🔴 Critical

> **These must be fixed before merging.**

| # | File | Issue | Violates |
|---|------|-------|----------|
| 1 | `src/edictum/foo.py:42` | Description of issue | [CLAUDE.md — ONE RULE](CLAUDE.md) |
| 2 | ... | ... | ... |

<details>
<summary>Details</summary>

**1. `src/edictum/foo.py:42` — Short title**

Description of the issue with context.

**Suggested fix:**
```python
# suggestion here
```

</details>
```

`{warnings_section}` — if there are warnings:
```markdown
### 🟡 Warnings

| # | File | Issue | Violates |
|---|------|-------|----------|
| 1 | `docs/guide.md:15` | Description | [.docs-style-guide.md — Terminology](.docs-style-guide.md) |

<details>
<summary>Details</summary>

**1. `docs/guide.md:15` — Short title**

Description with context.

</details>
```

`{suggestions_section}` — if there are suggestions:
```markdown
### 🔵 Suggestions

| # | File | Suggestion |
|---|------|------------|
| 1 | `src/edictum/bar.py` | Description |

<details>
<summary>Details</summary>

**1. `src/edictum/bar.py` — Short title**

Description.

</details>
```

`{clean_section}` — only when status is `pass`:
```markdown
### ✅ Checks passed

| Check | Status |
|-------|--------|
| Tier boundary | ✅ Clean |
| Terminology | ✅ Clean |
| Security | ✅ Clean |
| ... | ... |
```

Only list checks that were actually applied (based on file types changed).

### File list

`{file_count}`: Number of files reviewed.

`{file_list}`: Markdown list of changed files with status:
```markdown
- ✏️ `src/edictum/pipeline.py` (modified)
- ✨ `.github/workflows/review.yml` (new)
- 🗑️ `.github/workflows/old.yml` (deleted)
- 📄 `docs/guide.md` (modified)
```

### Checks applied

`{checks_applied}`: Comma-separated list of check categories that were relevant, e.g.:
`Tier boundary · Code quality · Terminology · Security · Governance consistency`

## Rules

- Always start the comment with `<!-- edictum-review -->` (first line, no exceptions)
- Keep the summary table compact — details go in expandable sections
- Link "Violates" references to the actual file in the repo
- If zero issues: status is `pass`, include `{clean_section}`, omit issue sections
- If only suggestions: status is `pass` (suggestions do NOT elevate to warn)
- If any warnings: status is `warn`
- If any critical: status is `fail`
- A PR with only suggestions is a PASSING review — do not set status to warn
