#!/usr/bin/env python3
"""Claude Agent SDK + Edictum demo — file cleanup agent.

Uses Claude Haiku 4.5 via OpenRouter, routed through the Claude Agent SDK
adapter's to_hook_callables() hooks to show governance in action.

Usage:
    bash setup.sh                         # create /tmp/messy_files/
    python demo_claude_agent_sdk.py       # WITHOUT Edictum
    python demo_claude_agent_sdk.py --guard   # WITH Edictum

Requires: OPENROUTER_API_KEY
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
    print("  Claude Agent SDK Demo: WITHOUT Edictum")
    print("=" * 60)
    print()

    call_count = 0
    for _ in range(30):
        llm_start = now_s()
        resp = client.chat.completions.create(
            model="anthropic/claude-haiku-4.5",
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
    write_metrics_summary(metrics, "/tmp/edictum_claude_sdk_metrics.json", {"mode": "without_guard"})


async def run_with_guard(client: OpenAI) -> None:
    """Run the same agent, governed by Edictum via the Claude Agent SDK adapter.

    The Claude SDK uses pre/post tool hooks that return dicts:
    - {} means allow
    - {"hookSpecificOutput": {"permissionDecision": "block", ...}} means block
    """
    from rules import ALL_CONTRACTS

    from edictum import Edictum, FileAuditSink
    from edictum.adapters.claude_agent_sdk import ClaudeAgentSDKAdapter

    audit_path = "/tmp/edictum_claude_sdk_audit.jsonl"
    metrics_path = "/tmp/edictum_claude_sdk_metrics.json"
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
    adapter = ClaudeAgentSDKAdapter(guard, session_id="demo-claude-sdk")
    hooks = adapter.to_hook_callables()

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": f"Clean up and organize {WORKSPACE}. Read every file first."},
    ]

    print("=" * 60)
    print("  Claude Agent SDK Demo: WITH Edictum")
    print("=" * 60)
    print()

    call_count = 0
    denied_count = 0

    for _ in range(30):
        llm_start = now_s()
        resp = client.chat.completions.create(
            model="anthropic/claude-haiku-4.5",
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
            tool_use_id = tc.id or str(uuid.uuid4())
            print(f"[#{call_count}] {fn_name}({json.dumps(args)})")

            # Route through Claude Agent SDK adapter
            pre_result = await hooks["pre_tool_use"](fn_name, args, tool_use_id)

            # Check if denied: non-empty dict with permissionDecision == "block"
            hook_output = pre_result.get("hookSpecificOutput", {})
            if hook_output.get("permissionDecision") == "block":
                denied_count += 1
                reason = hook_output.get("permissionDecisionReason", "denied")
                result = f"DENIED: {reason}"
                print(f"  ** EDICTUM: {result}\n")
            else:
                tool_start = now_s()
                result = TOOL_DISPATCH[fn_name](args)
                record_tool(metrics, now_s() - tool_start)
                await hooks["post_tool_use"](tool_use_id, result)
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
    parser = argparse.ArgumentParser(description="Claude Agent SDK + Edictum demo")
    parser.add_argument("--guard", action="store_true", help="Enable Edictum governance")
    args = parser.parse_args()

    if not os.environ.get("OPENROUTER_API_KEY"):
        print("ERROR: Set OPENROUTER_API_KEY")
        sys.exit(1)
    if not os.path.isdir(WORKSPACE):
        print(f"ERROR: {WORKSPACE} not found. Run `bash setup.sh` first.")
        sys.exit(1)

    client = OpenAI(
        base_url="https://openrouter.ai/api/v1",
        api_key=os.environ["OPENROUTER_API_KEY"],
    )
    if args.guard:
        asyncio.run(run_with_guard(client))
    else:
        run_without_guard(client)


if __name__ == "__main__":
    main()
