"""Shared Edictum rules for all adapter demos."""

from __future__ import annotations

from edictum import Decision, precondition, session_contract


@precondition(
    "read_file",
    when=lambda e: any(
        p in (e.args.get("path") or "") for p in [".env", ".secret", "credentials", "id_rsa", ".pem", ".key"]
    ),
)
def block_sensitive_reads(tool_call):
    """Block reads of sensitive files."""
    return Decision.fail(
        f"DENIED: reading sensitive file '{tool_call.args.get('path')}'. "
        "Skip this file and continue with non-sensitive files."
    )


@precondition("bash", when=lambda e: e.args.get("command") is not None)
def block_destructive_commands(tool_call):
    """Block destructive shell commands."""
    cmd = tool_call.args.get("command", "")
    destructive = ["rm -rf", "rm -r", "rmdir", "dd if=", "mkfs", "> /dev/"]
    for pattern in destructive:
        if pattern in cmd:
            return Decision.fail(
                f"DENIED: destructive command '{pattern}' detected. "
                "Use 'mv' to relocate files instead of deleting them."
            )
    return Decision.pass_()


@precondition(
    "bash",
    when=lambda e: any(
        p in (e.args.get("command") or "") for p in [".env", ".secret", "credentials", "id_rsa", ".pem", ".key"]
    ),
)
def block_sensitive_bash(tool_call):
    """Block bash commands that touch sensitive files."""
    return Decision.fail("DENIED: bash command references sensitive file. Skip sensitive files and continue.")


@precondition("move_file", when=lambda e: e.args.get("destination") is not None)
def require_organized_target(tool_call):
    """File moves must target /tmp/organized/."""
    dest = tool_call.args.get("destination", "")
    if not dest.startswith("/tmp/organized/"):
        return Decision.fail(
            f"DENIED: destination '{dest}' is not under /tmp/organized/. "
            "Move files to /tmp/organized/<category>/ instead."
        )
    return Decision.pass_()


def make_session_limit(max_ops: int = 25):
    @session_contract
    async def limit_operations(session):
        count = await session.execution_count()
        if count >= max_ops:
            return Decision.fail(f"Session limit reached: {count}/{max_ops} tool calls. Summarize progress and stop.")
        return Decision.pass_()

    return limit_operations


ALL_CONTRACTS = [
    block_sensitive_reads,
    block_destructive_commands,
    block_sensitive_bash,
    require_organized_target,
    make_session_limit(25),
]
