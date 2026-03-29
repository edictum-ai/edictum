---
name: fix-audit-issue
description: Fix a single audit issue in a git worktree. Creates a feature branch, follows fix-bug procedure, and creates a PR. Designed for parallel execution by spawned agents.
allowed-tools: Read, Edit, Write, Bash, Grep, Glob
---

# Fix Audit Issue (Worktree Workflow)

This skill wraps the `fix-bug` procedure for agents running in git worktrees.

## Step 1: Create branch

```bash
git checkout -b fix/{short-description}
```

Use a descriptive branch name based on the issue (e.g., `fix/redaction-policy-merge`, `fix/crewai-double-callback`).

## Step 2: Scenarios & use cases (for features/design changes)

If the issue involves adding a new feature or changing API behavior (not just a simple bug fix), write down BEFORE implementing:
- What concrete scenarios does this enable? (e.g., "send Slack alert on block", "test env-specific rules in CI")
- What user personas benefit? (developer debugging vs. platform team in production)
- Does this overlap with existing features? Explain when to use which.
- Does this surface related features that should be designed separately? Note them for future work.

Include this analysis in BOTH:
- The PR body under a `## Scenarios` section
- The docs page under a `## When to use this` section (see `.docs-style-guide.md` page structure pattern)

## Step 3: Follow fix-bug procedure

Execute all 8 steps from the `fix-bug` skill:
1. Understand the bug
2. Root cause analysis
3. Write failing behavior test FIRST
4. Fix the source code
5. Verify the fix
6. Check regression scope
7. Docs-code sync check
8. Full verification

## Step 3: Commit and push

```bash
git add {specific files}
git commit -m "fix: {description}"
git push -u origin fix/{short-description}
```

## Step 4: Create PR

```bash
gh pr create --title "fix: {short description}" --body "$(cat <<'EOF'
## Summary
{one-line summary}

## Scenarios
{what concrete use cases does this enable — skip for trivial bug fixes}

## Root Cause
{what the code did wrong and why tests didn't catch it}

## Fix
{what was changed}

## Test Plan
- [ ] Behavior test added in tests/test_behavior/
- [ ] Full test suite passes
- [ ] Lint passes
- [ ] Docs build passes
- [ ] Docs-code sync passes
EOF
)"
```

## Conventions

- One issue per branch, one issue per PR
- Conventional commit: `fix: {description}`
- No Co-Authored-By
- No banned terminology — check `.docs-style-guide.md` before writing any user-facing string
- Branch from `main`, target `main`
