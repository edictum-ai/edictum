"""Built-in pre-rules for common safety patterns."""

from __future__ import annotations

from collections.abc import Callable

from edictum.envelope import ToolCall
from edictum.rules import Decision, precondition


def deny_sensitive_reads(
    sensitive_paths: list[str] | None = None,
    sensitive_commands: list[str] | None = None,
) -> Callable:
    """Built-in pre-rule: block reads of sensitive files and data.

    Default blocked paths:
    - ~/.ssh/
    - /var/run/secrets/ (k8s)
    - /.env, /.aws/credentials
    - /.git-credentials
    - /id_rsa, /id_ed25519

    Default blocked commands:
    - printenv, env (dump all env vars)
    """
    default_paths = [
        "/.ssh/",
        "/var/run/secrets/",
        "/.env",
        "/.aws/credentials",
        "/.git-credentials",
        "/id_rsa",
        "/id_ed25519",
    ]
    default_commands = ["printenv", "env"]

    paths = sensitive_paths or default_paths
    commands = sensitive_commands or default_commands

    @precondition("*")
    def _deny_sensitive(tool_call: ToolCall) -> Decision:
        # Check file paths
        if tool_call.file_path:
            for pattern in paths:
                if pattern in tool_call.file_path:
                    return Decision.fail(
                        f"Access to sensitive path blocked: {tool_call.file_path}. "
                        "This file may contain secrets or credentials."
                    )

        # Check bash commands
        if tool_call.bash_command:
            cmd = tool_call.bash_command.strip()
            for blocked in commands:
                if cmd == blocked or cmd.startswith(blocked + " "):
                    return Decision.fail(
                        f"Sensitive command blocked: {blocked}. "
                        "This command may expose secrets or environment variables."
                    )
            # Check if bash is reading a sensitive path
            for pattern in paths:
                if pattern in cmd:
                    return Decision.fail(
                        f"Bash command accesses sensitive path: {pattern}. "
                        "This file may contain secrets or credentials."
                    )

        return Decision.pass_()

    _deny_sensitive.__name__ = "deny_sensitive_reads"
    return _deny_sensitive
