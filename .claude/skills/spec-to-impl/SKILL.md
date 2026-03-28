---
name: spec-to-impl
description: Transform a feature spec into audited, implementation-ready prompts. Use when starting a new feature, designing a new adapter, or turning a design doc into sequenced build steps. Covers spec audit against project rules, gap identification, decision collection, and prompt generation.
argument-hint: [spec-file-path]
---

# Spec-to-Implementation Pipeline

Transform a feature specification into audited, implementation-ready sequenced prompts. This is a multi-phase process — do NOT skip phases or combine them.

**Input:** A spec file path (via `$ARGUMENTS`) or a feature description that needs a spec written first.

## Output Directory

All artifacts go into `.claude/skills/spec-to-impl/{feature-slug}/`:

```
.claude/skills/spec-to-impl/{feature-slug}/
  README.md              <-- execution order, status tracking, dependency graph
  SPEC-AUDIT.md          <-- Phase 2 violations (persisted for reference)
  SPEC-DECISIONS.md      <-- Phase 3 decisions log
  P1-{SCOPE}.md          <-- first implementation prompt
  P2-{SCOPE}.md          <-- second implementation prompt
  ...
```

The `{feature-slug}` is derived from the spec file name or feature description (lowercase, hyphens, no spaces). Example: `google-adk-adapter`, `sandbox-rules`, `hitl-approval`.

Create the directory at the start of Phase 2 (once you know the feature name).

---

## Phase 1: Gather Context

Before auditing anything, read the project rules. These are the audit criteria:

1. `CLAUDE.md` — Architecture (core vs server boundary), non-negotiable principles, build/test commands, code conventions, API design checklist, security review checklist, terminology enforcement, pre-merge verification
2. `.docs-style-guide.md` — Binding terminology reference, canonical terms, page structure pattern, pipeline description, cross-reference conventions
3. `docs/architecture.md` — Pipeline overview, source layout, adapter responsibilities, what lives where

Then read the actual codebase to understand current state:

4. **Core modules** — Read the relevant modules in `src/edictum/` to know what already exists. Key files:
   - `__init__.py` (Edictum class, public API, `__all__` exports)
   - `pipeline.py` (CheckPipeline, PreDecision, PostDecision)
   - `envelope.py` (ToolCall, Principal, create_envelope, SideEffect, ToolRegistry)
   - `session.py` (Session, counter keys)
   - `audit.py` (AuditEvent, AuditAction, AuditSink, RedactionPolicy, sinks)
   - `violations.py` (Violation, PostCallResult, build_violations)
   - `telemetry.py` (GovernanceTelemetry, start_tool_span, record_block)
   - `approval.py` (ApprovalBackend, ApprovalRequest, ApprovalDecision, ApprovalStatus)
5. **Existing adapter patterns** — Read at least 2 adapters in `src/edictum/adapters/` to understand the established pattern (constructor, _pre/_post, _block, _check_tool_success, _emit_audit_pre, pending state, observe mode, on_block/on_allow callbacks, approval handling). Good choices:
   - One simple adapter (e.g., `openai_agents.py` — clean pre/post with guardrails)
   - One complex adapter (e.g., `nanobot.py` — inline execution + approval handling)
6. **Test patterns** — Read `tests/conftest.py` (shared fixtures: NullAuditSink, CapturingAuditSink, make_guard pattern), `tests/test_adapter_parity.py` (parity test tiers and helper function conventions), and one adapter test file (e.g., `tests/test_adapter_openai_agents.py`) to understand framework-mocking strategy.
7. **Docs patterns** — Docs live in a separate repo (edictum-docs). Check README.md for any code examples that need updating.

**Output of Phase 1:** Internal understanding. No user-facing output yet.

---

## Phase 2: Audit the Spec

Read the spec file. Audit every section against every rule. Be brutally honest.

Check for these categories of violations:

### Architecture Violations (CRITICAL)
- Does anything contradict CLAUDE.md's core vs server boundary? (evaluation = core, coordination = server)
- Does it introduce runtime dependencies that violate "zero runtime deps in core"?
- Does it add imports from `src/edictum/server/` into core code?
- Does it bypass the CheckPipeline and implement governance logic in the adapter?
- Does it add features listed in CLAUDE.md's "Dropped Features" section?

### Adapter Pattern Violations (HIGH)
- Does the adapter follow the established constructor pattern? (guard, session_id, principal, principal_resolver)
- Does it implement ALL required internal methods? (_pre, _post, _emit_audit_pre, _check_tool_success, _block, set_principal, _resolve_principal, session_id property)
- Does it follow the correct pre-execution flow? (create_envelope → increment_attempts → start_span → pre_execute → observe/block/allow handling)
- Does it follow the correct post-execution flow? (pop pending → check_success → post_execute → record_execution → emit audit → end span → build_violations)
- Does pending state management match the framework's execution model? (dict for parallel, single-slot for sequential, none for inline)
- Does it handle observe mode correctly? (block → allow with CALL_WOULD_DENY audit)
- Does it handle per-rule observed blocks?
- Does it call on_block/on_allow/on_postcondition_warn callbacks at the right place?

### API Design Checklist (HIGH)
- Does every new parameter have an observable effect with a behavior test?
- Do collection parameters have documented merge semantics?
- Do block decisions propagate end-to-end through the adapter?
- Do callbacks fire exactly once?
- Is the new feature handled by ALL adapters (or documented why not)?
- Are there ghost features? (documented but not implemented)

### Security Review (HIGH)
- Does path handling use `os.path.realpath()` not just `normpath()`?
- Does tool_name validation reject null bytes, newlines, path separators?
- Do error handling paths fail-closed?
- Do audit events reflect what actually happened?
- Are read-modify-write operations protected with `asyncio.Lock`?

### Shared Module Duplication (HIGH)
- Does the spec define types that already exist in core? (Principal, ToolCall, AuditEvent, Violation, PostCallResult)
- Does it propose utility functions that core already provides? (create_envelope, build_violations, _check_tool_success pattern)
- Does it redefine patterns that adapters already share?

### Test Coverage Gaps (MEDIUM)
- Does it include adapter parity test entries for ALL tiers? (_all_adapter_configs, _all_adapter_pre_post_configs, _all_adapter_configs_with_pre2)
- Does it include behavior tests for every new parameter?
- Does it include security tests (marked `@pytest.mark.security`) for every new boundary?
- Does it mock framework imports via `sys.modules` instead of requiring framework installation?
- Does it use `NullAuditSink`/`CapturingAuditSink` from conftest?

### Terminology (MEDIUM)
- Any forbidden terms? Check against `.docs-style-guide.md`:
  - contract/contracts → rule/rules
  - denied → blocked
  - engine → pipeline
  - shadow·mode → observe mode
  - finding → violation
  - guard/guards → (avoid in prose)
  - policy → rule (in prose context)
- Any marketing language? (powerful, seamless, robust, elegant)
- Any incorrect metaphors? (gatekeeper, guardian, shield, firewall)

### Documentation Gaps (MEDIUM)
- Does the docs page follow `.docs-style-guide.md` page structure? (opening → example → when to use this → explanation → reference → next steps)
- Does it include a "When to use this" section with 2-4 concrete scenarios?
- Are code examples copy-pasteable?
- Does `test_docs_sync.py` need updates?

### Design Gaps (LOW)
- Are dependency decisions made (not "consider X or Y")?
- Are edge cases covered? (concurrent calls, nested event loops, missing context fields)
- Are framework version constraints specified?

**Output of Phase 2:**

1. Create the output directory: `.claude/skills/spec-to-impl/{feature-slug}/`
2. Write violations to `SPEC-AUDIT.md` in that directory (persisted for reference)
3. Present violations to the user as a prioritized table:

```
| Priority | # | Issue | Action needed |
|----------|---|-------|---------------|
| CRITICAL | 1 | ... | Decision: A, B, or C |
| HIGH | 2 | ... | Fix: specify X |
| ...
```

Group by priority. For each issue, state:
- What the rule says (with file + line reference)
- What the spec says (with section reference)
- What needs to happen (decision from user, or a specific fix)

---

## Phase 3: Collect Decisions

Wait for the user to respond to every issue. They will say things like:
- "your suggestion" — apply your recommended fix
- "fix it" — apply the obvious fix
- "option A" — apply that specific option
- "I don't understand" — explain the issue more clearly
- A custom answer

Do NOT proceed to Phase 4 until every issue has a decision.

**Output of Phase 3:** Write `SPEC-DECISIONS.md` in the output directory with each issue number, the user's decision, and what will change.

---

## Phase 4: Update the Spec

Apply all decisions to the spec file. This means editing the actual file, not just listing changes. After editing:

- Re-read the updated spec
- Verify no new issues were introduced by the fixes
- If new issues exist, flag them (short cycle — these should be minor)

**Output of Phase 4:** Confirm the spec is updated. List any remaining minor items.

---

## Phase 5: Generate Implementation Prompts

Slice the spec into sequenced prompts. Each prompt must be:

### Sizing Rules
- **One reviewable deliverable per prompt.** The user must be able to test the output before moving on.
- **Core before adapter.** If the feature needs core changes (new pipeline capability, new envelope fields), those come first.
- **Adapter before tests.** Implementation must exist before parity tests can reference it.
- **Tests before docs.** Tests validate the implementation is correct before documenting it.
- **Foundation before features.** Internal methods (_pre, _post, _deny) before public API methods (as_plugin, as_agent_callbacks).
- **Simple before complex.** The most straightforward integration path first. Edge cases and optional features last.
- **Dependencies explicit.** Each prompt states what it depends on.

### Prompt Structure (every prompt must include)

1. **Header:** Scope, depends-on, deliverable, verification command
2. **Required reading:** Specific files to read before coding (actual paths in the repo)
3. **Shared modules table:** What to import, from where — prevents duplication of existing patterns
4. **Files to create/modify:** Each file with its responsibilities and estimated line count
5. **Wiring instructions:** How to connect new code to existing code (imports, parity test entries, architecture.md updates)
6. **Verification checklist:** Specific commands and assertions:
   - `pytest tests/test_adapter_<name>.py -v` (unit tests pass)
   - `pytest tests/test_adapter_parity.py -v` (parity tests pass)
   - `pytest tests/test_behavior/test_<name>_behavior.py -v` (behavior tests pass)
   - `ruff check src/ tests/` (lint clean)
   - `pytest tests/test_docs_sync.py -v` (docs sync)
   - No banned terminology (`grep -rn` check)
   - Framework imports only inside public API methods (lazy imports)
   - `from __future__ import annotations` in every new file

### What NOT to include in prompts
- Don't repeat the entire spec — reference sections by number
- Don't include full code that should be figured out during implementation
- Don't include aspirational features — only what's in scope for this prompt
- Don't include code for frameworks the user hasn't asked for

### Prompt Naming and Location
Write each prompt as `P{N}-{SCOPE}.md` inside the output directory (`.claude/skills/spec-to-impl/{feature-slug}/`).

Examples: `P1-CORE.md`, `P2-ADAPTER.md`, `P3-TESTS.md`, `P4-PARITY.md`, `P5-DOCS.md`.

### README.md Generation

After writing all prompts, generate a `README.md` in the output directory. This is the execution guide:

```markdown
# {Feature Name} — Implementation Prompts

**Spec:** `{path-to-spec-file}`
**Generated:** {date}
**Status:** Not started

## Execution Order

| # | Prompt | Scope | Deliverable | Status | Depends On |
|---|--------|-------|-------------|--------|------------|
| 1 | [P1-CORE.md](P1-CORE.md) | ... | ... | [ ] | — |
| 2 | [P2-ADAPTER.md](P2-ADAPTER.md) | ... | ... | [ ] | P1 |
| 3 | [P3-TESTS.md](P3-TESTS.md) | ... | ... | [ ] | P2 |
| ...

## Dependency Graph

```
P1-CORE ──> P2-ADAPTER ──> P3-TESTS ──> P4-PARITY
                                    └──> P5-DOCS
```

## Verification (run after all prompts complete)

```bash
pytest tests/ -v
ruff check src/ tests/
pytest tests/test_docs_sync.py -v
```

## Artifacts

- [SPEC-AUDIT.md](SPEC-AUDIT.md) — Audit violations from Phase 2
- [SPEC-DECISIONS.md](SPEC-DECISIONS.md) — User decisions from Phase 3
```

The Status column uses `[ ]` (not started), `[~]` (in progress), `[x]` (done), `[!]` (stalled). Update as prompts are executed.

**Output of Phase 5:** All prompt files and README.md written. Present the summary table to the user.

---

## Phase 6: Final Review

Read all generated prompts in the output directory in sequence. Verify:
- No gaps between prompts (nothing falls through the cracks)
- Dependencies are correct (no prompt references something built in a later prompt)
- The dependency graph in README.md matches the actual depends-on headers in prompts
- Verification checklists are testable (specific pytest commands, specific grep patterns — not vague)
- The full feature is covered (every section of the spec maps to at least one prompt)
- Every new file has `from __future__ import annotations`
- No prompt introduces banned terminology
- Parity test additions are accounted for
- Docs sync requirements are covered
- README.md links are valid (all prompt files exist, relative links correct)

If issues found, fix the prompts and README, then note what changed.

**Output of Phase 6:** Confirm the output directory is complete. Print the path:

```
Implementation prompts ready at:
  .claude/skills/spec-to-impl/{feature-slug}/README.md
```

---

## Key Principles

- **Rules exist in files, not in heads.** Every audit violation must point to a specific rule in a specific file (CLAUDE.md, .docs-style-guide.md, architecture.md).
- **The codebase is ground truth.** Read actual adapter code, actual test patterns, actual core interfaces — not what the spec assumes.
- **The user stays in decision mode.** Present violations and options. Don't make architectural decisions without user input.
- **Each prompt = one testable deliverable.** No "build everything then check."
- **Adapters translate, they don't govern.** Governance logic lives in CheckPipeline. Adapters only create envelopes, manage pending state, and translate decisions into framework-native format.
- **Tests verify, not just exist.** Every test must assert a concrete observable behavior, not just call a method and assert True.
