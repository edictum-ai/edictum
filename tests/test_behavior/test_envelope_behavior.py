"""Behavior tests for envelope module — BashClassifier and ToolEnvelope validation."""

from __future__ import annotations

import pytest

from edictum.envelope import BashClassifier, SideEffect, ToolEnvelope, create_envelope

pytestmark = pytest.mark.security


class TestBareVariableExpansionDetected:
    """Bare $VAR expansions must classify as IRREVERSIBLE to prevent secret exfiltration."""

    def test_echo_bare_var_is_irreversible(self):
        assert BashClassifier.classify("echo $AWS_SECRET_KEY") == SideEffect.IRREVERSIBLE

    def test_cat_bare_var_path_is_irreversible(self):
        assert BashClassifier.classify("cat $HOME/.ssh/id_rsa") == SideEffect.IRREVERSIBLE

    def test_braced_var_still_irreversible(self):
        """Regression: ${VAR} must still be caught."""
        assert BashClassifier.classify("echo ${VAR}") == SideEffect.IRREVERSIBLE

    def test_command_substitution_still_irreversible(self):
        """Regression: $(cmd) must still be caught."""
        assert BashClassifier.classify("echo $(whoami)") == SideEffect.IRREVERSIBLE


class TestNoFalsePositivesFromDollarOperator:
    """Commands without $ must not be affected by the new operator."""

    def test_ls_tmp_still_read(self):
        assert BashClassifier.classify("ls /tmp") == SideEffect.READ

    def test_cat_file_still_read(self):
        assert BashClassifier.classify("cat file.txt") == SideEffect.READ

    def test_echo_literal_still_read(self):
        assert BashClassifier.classify("echo hello") == SideEffect.READ

    def test_grep_still_read(self):
        assert BashClassifier.classify("grep pattern somefile") == SideEffect.READ

    def test_git_status_still_read(self):
        assert BashClassifier.classify("git status") == SideEffect.READ


class TestToolEnvelopeDirectConstructionValidation:
    """ToolEnvelope.__post_init__ must reject dangerous tool_name values,
    closing the bypass where callers skip create_envelope().
    """

    def test_null_byte_rejected(self):
        with pytest.raises(ValueError, match="Invalid tool_name"):
            ToolEnvelope(tool_name="\x00evil", args={})

    def test_newline_rejected(self):
        with pytest.raises(ValueError, match="Invalid tool_name"):
            ToolEnvelope(tool_name="evil\ntool", args={})

    def test_forward_slash_rejected(self):
        with pytest.raises(ValueError, match="Invalid tool_name"):
            ToolEnvelope(tool_name="evil/tool", args={})

    def test_backslash_rejected(self):
        with pytest.raises(ValueError, match="Invalid tool_name"):
            ToolEnvelope(tool_name="evil\\tool", args={})

    def test_empty_string_rejected(self):
        with pytest.raises(ValueError, match="Invalid tool_name"):
            ToolEnvelope(tool_name="", args={})

    def test_carriage_return_rejected(self):
        with pytest.raises(ValueError, match="Invalid tool_name"):
            ToolEnvelope(tool_name="evil\rtool", args={})

    def test_tab_rejected(self):
        with pytest.raises(ValueError, match="Invalid tool_name"):
            ToolEnvelope(tool_name="evil\ttool", args={})

    def test_delete_char_rejected(self):
        with pytest.raises(ValueError, match="Invalid tool_name"):
            ToolEnvelope(tool_name="evil\x7ftool", args={})

    def test_valid_name_accepted(self):
        envelope = ToolEnvelope(tool_name="ValidTool", args={})
        assert envelope.tool_name == "ValidTool"

    def test_create_envelope_still_works(self):
        """create_envelope() must not regress — validation is idempotent."""
        envelope = create_envelope("ValidTool", {"key": "value"})
        assert envelope.tool_name == "ValidTool"
        assert envelope.args == {"key": "value"}
