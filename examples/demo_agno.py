#!/usr/bin/env python3
"""Agno + Edictum demo — file cleanup agent.

Uses GPT-4o-mini via OpenAI, routed through the Agno adapter's
_hook_async wrap-around pattern to show governance in action.

Usage:
    bash setup.sh              # create /tmp/messy_files/
    python demo_agno.py        # WITHOUT Edictum
    python demo_agno.py --guard    # WITH Edictum

Requires: OPENAI_API_KEY
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys

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
    tool_bash,
    tool_list_files,
    tool_move_file,
    tool_read_file,
    write_metrics_summary,
)

# Agno's _hook_async calls function_call(**arguments), so callables must accept kwargs.
AGNO_DISPATCH = {
    "read_file": lambda **kw: tool_read_file(kw["path"]),
    "list_files": lambda **kw: tool_list_files(kw["directory"]),
    "bash": lambda **kw: tool_bash(kw["command"]),
    "move_file": lambda **kw: tool_move_file(kw["source"], kw["destination"]),
}


def run_without_guard(client: OpenAI) -> None:
    """Run the agent with no governance."""
    metrics = DemoMetrics()
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": f"Clean up and organize {WORKSPACE}. Read every file first."},
    ]

    print("=" * 60)
    print("  Agno Demo: WITHOUT Edictum")
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
    write_metrics_summary(metrics, "/tmp/edictum_agno_metrics.json", {"mode": "without_guard"})


async def run_with_guard(client: OpenAI) -> None:
    """Run the same agent, governed by Edictum via the Agno adapter.

    Agno uses a wrap-around pattern: the hook receives (name, callable, args)
    and must call the callable itself or return a denial string.
    """
    from rules import ALL_CONTRACTS

    from edictum import Edictum, FileAuditSink
    from edictum.adapters.agno import AgnoAdapter

    audit_path = "/tmp/edictum_agno_audit.jsonl"
    metrics_path = "/tmp/edictum_agno_metrics.json"
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
    adapter = AgnoAdapter(guard, session_id="demo-agno")

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": f"Clean up and organize {WORKSPACE}. Read every file first."},
    ]

    print("=" * 60)
    print("  Agno Demo: WITH Edictum")
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
            print(f"[#{call_count}] {fn_name}({json.dumps(args)})")

            # Route through Agno adapter (wrap-around: pre -> execute -> post)
            # Agno calls function_call(**arguments), so we use kwargs-compatible dispatch
            tool_start = now_s()
            result = await adapter._hook_async(fn_name, AGNO_DISPATCH[fn_name], args)
            record_tool(metrics, now_s() - tool_start)
            if not isinstance(result, str):
                result = str(result)

            if result.startswith("DENIED:"):
                denied_count += 1
                print(f"  ** EDICTUM: {result}\n")
            else:
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
    parser = argparse.ArgumentParser(description="Agno + Edictum demo")
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
