#!/usr/bin/env python3
"""OpenAI Agents SDK + Edictum demo — file cleanup agent.

Uses GPT-4o-mini via OpenAI, routed through the OpenAI Agents adapter's
_pre / _post hooks to show governance in action.

Usage:
    bash setup.sh                      # create /tmp/messy_files/
    python demo_openai_agents.py       # WITHOUT Edictum
    python demo_openai_agents.py --guard   # WITH Edictum

Requires: OPENAI_API_KEY
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import uuid

from openai import OpenAI
from tools import (
    EDICTUM_TOOLS_CONFIG,
    OPENAI_TOOLS,
    SYSTEM_PROMPT,
    TOOL_DISPATCH,
    WORKSPACE,
    DemoMetrics,
    now_s,
    record_llm,
    record_tool,
    write_metrics_summary,
)


def run_without_guard(client: OpenAI) -> None:
    """Run the agent with no governance."""
    metrics = DemoMetrics()
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": f"Clean up and organize {WORKSPACE}. Read every file first."},
    ]

    print("=" * 60)
    print("  OpenAI Agents SDK Demo: WITHOUT Edictum")
    print("=" * 60)
    print()

    call_count = 0
    for _ in range(30):
        llm_start = now_s()
        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=messages,
            tools=OPENAI_TOOLS,
            tool_choice="auto",
        )
        record_llm(metrics, resp, now_s() - llm_start)
        msg = resp.choices[0].message
        messages.append(msg)

        if not msg.tool_calls:
            print(f"\n{'─' * 60}\nAgent: {msg.content or '(done)'}")
            break

        for tc in msg.tool_calls:
            call_count += 1
            args = json.loads(tc.function.arguments)
            print(f"[#{call_count}] {tc.function.name}({json.dumps(args)})")

            tool_start = now_s()
            result = TOOL_DISPATCH[tc.function.name](args)
            record_tool(metrics, now_s() - tool_start)
            preview = result[:200] + "..." if len(result) > 200 else result
            print(f"  -> {preview}\n")

            messages.append({"role": "tool", "tool_call_id": tc.id, "content": result})

    print(f"\n{'─' * 60}")
    print(f"Total calls: {call_count}  |  Audit: NONE  |  Secrets protection: NONE")
    write_metrics_summary(metrics, "/tmp/edictum_openai_agents_metrics.json", {"mode": "without_guard"})


async def run_with_guard(client: OpenAI) -> None:
    """Run the same agent, governed by Edictum via the OpenAI Agents adapter.

    The OpenAI Agents SDK uses input/output guardrails. Here we call
    _pre(name, args, call_id) -> str | None and _post(call_id, result).
    """
    from rules import ALL_CONTRACTS

    from edictum import Edictum, FileAuditSink
    from edictum.adapters.openai_agents import OpenAIAgentsAdapter

    audit_path = "/tmp/edictum_openai_agents_audit.jsonl"
    metrics_path = "/tmp/edictum_openai_agents_metrics.json"
    if os.path.exists(audit_path):
        os.remove(audit_path)

    metrics = DemoMetrics()
    guard = Edictum(
        environment="demo",
        mode="enforce",
        rules=ALL_CONTRACTS,
        tools=EDICTUM_TOOLS_CONFIG,
        audit_sink=FileAuditSink(audit_path),
    )
    adapter = OpenAIAgentsAdapter(guard, session_id="demo-openai-agents")

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": f"Clean up and organize {WORKSPACE}. Read every file first."},
    ]

    print("=" * 60)
    print("  OpenAI Agents SDK Demo: WITH Edictum")
    print("=" * 60)
    print()

    call_count = 0
    denied_count = 0

    for _ in range(30):
        llm_start = now_s()
        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=messages,
            tools=OPENAI_TOOLS,
            tool_choice="auto",
        )
        record_llm(metrics, resp, now_s() - llm_start)
        msg = resp.choices[0].message
        messages.append(msg)

        if not msg.tool_calls:
            print(f"\n{'─' * 60}\nAgent: {msg.content or '(done)'}")
            break

        for tc in msg.tool_calls:
            call_count += 1
            args = json.loads(tc.function.arguments)
            fn_name = tc.function.name
            call_id = str(uuid.uuid4())
            print(f"[#{call_count}] {fn_name}({json.dumps(args)})")

            # Route through OpenAI Agents adapter (pre -> execute -> post)
            pre_result = await adapter._pre(fn_name, args, call_id)

            if pre_result is not None:
                denied_count += 1
                result = pre_result
                print(f"  ** EDICTUM: {result}\n")
            else:
                tool_start = now_s()
                result = TOOL_DISPATCH[fn_name](args)
                record_tool(metrics, now_s() - tool_start)
                await adapter._post(call_id, result)
                preview = result[:200] + "..." if len(result) > 200 else result
                print(f"  -> {preview}\n")

            messages.append({"role": "tool", "tool_call_id": tc.id, "content": result})

    print(f"\n{'─' * 60}")
    print(f"Total calls: {call_count}  |  Denied: {denied_count}  |  Audit: {audit_path}")
    write_metrics_summary(
        metrics,
        metrics_path,
        {"mode": "with_guard", "denied": denied_count, "audit": audit_path},
    )
    _print_audit(audit_path)


def _print_audit(path: str) -> None:
    if not os.path.exists(path):
        return
    with open(path) as f:
        events = [json.loads(line) for line in f if line.strip()]
    print(f"\nAudit trail ({len(events)} events):")
    for ev in events:
        action = ev.get("action", "?")
        tool = ev.get("tool_name", "?")
        reason = ev.get("reason", "")
        suffix = f" -- {reason[:70]}" if reason else ""
        print(f"  {action:20s} | {tool}{suffix}")


def main() -> None:
    parser = argparse.ArgumentParser(description="OpenAI Agents SDK + Edictum demo")
    parser.add_argument("--guard", action="store_true", help="Enable Edictum governance")
    args = parser.parse_args()

    if not os.environ.get("OPENAI_API_KEY"):
        print("ERROR: Set OPENAI_API_KEY")
        sys.exit(1)
    if not os.path.isdir(WORKSPACE):
        print(f"ERROR: {WORKSPACE} not found. Run `bash setup.sh` first.")
        sys.exit(1)

    client = OpenAI()
    if args.guard:
        asyncio.run(run_with_guard(client))
    else:
        run_without_guard(client)


if __name__ == "__main__":
    main()
