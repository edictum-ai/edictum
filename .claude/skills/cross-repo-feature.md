# Cross-Repo Feature Implementation Guide

You are implementing a feature that affects multiple edictum repos. Follow this pipeline exactly.

## Prerequisites

This skill requires sibling repos to be cloned:
- `../edictum/` (Python reference implementation)
- `../edictum-schemas/` (shared fixtures)

If either is absent, **stop and notify the user** before proceeding.

## Step 1: Check Fixture Coverage

Before writing any code, **read** the Python reference implementation and check if shared behavioral fixtures exist:

```bash
# Read the relevant module source (not just list files)
cat ../edictum/src/edictum/<module>.py
cat ../edictum/tests/test_behavior/test_<module>_behavior.py

# Check existing fixtures
cat ../edictum-schemas/fixtures/behavioral/<feature>.fixtures.yaml
cat ../edictum-schemas/fixtures/adversarial/<feature>.fixtures.yaml
```

If the Python reference or fixtures don't exist for the behavior you're changing, **write them first**. This is mandatory — no feature ships without fixtures.

## Step 2: Write Fixtures (if needed)

Create or update fixture files in `../edictum-schemas/fixtures/behavioral/`:

```yaml
suite: feature-name
version: 1
description: "What this tests"

fixtures:
  - id: "feature-001"
    description: "When X, expect Y"
    ruleset:
      apiVersion: edictum/v1
      kind: Ruleset
      metadata: { name: test, version: "1.0" }
      defaults: { action: block }
      rules: [...]
    envelope:
      tool_name: "ToolName"
      arguments: { key: "value" }
    expected:
      verdict: blocked|allowed
      message_contains: "expected text"
```

For security features, also add adversarial fixtures in `fixtures/adversarial/`.

Push fixtures as a separate PR to edictum-schemas FIRST.

## Step 3: Implement in Python (Reference)

This repo is the reference implementation. Implement here first:

1. Write the code in `src/edictum/`
2. Write behavior tests in `tests/test_behavior/test_{module}_behavior.py` (one file per module, under 200 lines)
3. Write security tests with `@pytest.mark.security` if touching a security boundary
4. Verify shared fixtures pass: `pytest tests/test_behavioral_fixtures.py --fixtures-dir=../edictum-schemas/fixtures/`
5. Run full suite: `uv run pytest tests/ -v`
6. Create PR with `feature:NAME` label

## Step 4: Notify Ports

After Python PR merges, the `notify-parity.yml` workflow auto-creates tracking issues in edictum-ts and edictum-go. If it doesn't exist yet, manually create issues:

```bash
gh issue create --repo edictum-ai/edictum-ts --title "Port feature: NAME" --label "parity:blocking" --body "Python reference landed in PR#XX. Fixtures: edictum-schemas/fixtures/behavioral/NAME.fixtures.yaml"
gh issue create --repo edictum-ai/edictum-go --title "Port feature: NAME" --label "parity:blocking" --body "Python reference landed in PR#XX. Fixtures: edictum-schemas/fixtures/behavioral/NAME.fixtures.yaml"
```

## Step 5: Cross-Repo Issues

If you find a bug that exists in multiple repos, file ONE issue in `edictum-ai/.github` with the `cross-repo` label — not in individual repos.

## Checklist Before Merging

- [ ] Shared fixtures exist in edictum-schemas
- [ ] Python implementation passes fixtures
- [ ] Behavior tests written
- [ ] Security tests written (if security boundary)
- [ ] Terminology matches `.docs-style-guide.md`
- [ ] PR has `feature:NAME` label (if cross-repo)
- [ ] Tracking issues created in TS/Go repos
