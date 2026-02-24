---
name: edictum-oss
description: Implement features in the Edictum OSS core (src/edictum/). Use when the task touches pipeline, adapters, YAML engine, CLI, audit, envelope, or session. Core NEVER imports from ee/.
---

# Edictum Core Implementation

Read CLAUDE.md first. Understand the boundary principle before writing code.

## Scope

Everything under `src/edictum/` is the core library (MIT). This includes:

- Pipeline (`pipeline.py`) — GovernancePipeline, PreDecision, PostDecision
- Envelope (`envelope.py`) — ToolEnvelope, Principal, create_envelope()
- Contracts (`contracts.py`) — @precondition, @postcondition, @session_contract, Verdict
- YAML engine (`yaml_engine/`) — loader, evaluator, compiler (including sandbox compilation), templates
- Adapters (`adapters/`) — all 7 framework adapters
- Audit (`audit.py`) — AuditEvent, StdoutAuditSink, FileAuditSink, RedactionPolicy
- Session (`session.py`) — Session, MemoryBackend
- CLI (`cli/`) — validate, check, diff, replay, test
- Telemetry (`telemetry.py`) — OTel spans, GovernanceTelemetry
- Server SDK (`server/`) — client components for connecting to edictum-server

## Architecture

Two deployment units:

- **Core** (`pip install edictum`) — runs fully standalone. All 4 contract types (pre, post, session, sandbox), pipeline, 7 adapters, CLI, local audit, local approval.
- **Server** (`edictum-server`) — separate deployment, coming soon. The Server SDK (`pip install edictum[server]`) provides the client-side connectivity.

Core provides protocols and interfaces. The server SDK provides HTTP-backed implementations.

## What needs the server

Most features work without the server. These require it:

| Feature | Core | Server |
|---|---|---|
| Contract evaluation (all 4 types) | Yes | -- |
| `outside: deny` / `effect: deny` | Yes | -- |
| `outside: approve` / `effect: approve` (dev) | Yes (LocalApprovalBackend) | -- |
| `outside: approve` / `effect: approve` (production) | -- | Yes (ServerApprovalBackend) |
| Audit to stdout/file/OTel | Yes | -- |
| Centralized audit dashboard | -- | Yes (ServerAuditSink) |
| Session tracking (single process) | Yes (MemoryBackend) | -- |
| Session tracking (multi-process) | -- | Yes (ServerBackend) |
| Hot-reload contracts | -- | Yes (ServerContractSource) |

## Workflow

1. **Read CLAUDE.md** — understand boundaries and dropped features
2. **Read the Linear ticket** or user description
3. **Read relevant source files** before proposing changes
4. **Scenarios & use cases** — before implementing, write down:
   - What concrete scenarios does this feature enable?
   - What user personas benefit?
   - Does this overlap with existing features?
   - Does this surface related features that should be designed separately?
   - Include this analysis in BOTH:
     - The PR body under a `## Scenarios` section
     - The docs page under a `## When to use this` section (see `.docs-style-guide.md` page structure pattern)
5. **Scope with user** — confirm approach before writing code
6. **Implement** — small, focused changes
7. **Behavior test** — every new/changed API parameter gets a test in `tests/test_behavior/test_{module}_behavior.py`
8. **Docs-code sync** — `pytest tests/test_docs_sync.py -v`
9. **Adapter parity** — if touching adapters: `pytest tests/test_adapter_parity.py -v`
10. **Test** — `pytest tests/ -v` then `ruff check src/ tests/`
11. **Commit** — conventional commits, no Co-Authored-By

## Conventions

- Frozen dataclasses for immutable data
- All pipeline/session/audit methods are async
- `from __future__ import annotations` in every file
- Type hints everywhere
- Test file per module: `tests/test_{module}.py`

## Do NOT

- Implement Redis/DB StorageBackend — dropped feature
- Accept a parameter without testing its observable effect — if it's accepted, it must DO something testable
- Document a feature that doesn't exist in code — `pytest tests/test_docs_sync.py -v` catches this
- Ship an adapter change without running parity checks — `pytest tests/test_adapter_parity.py -v`
