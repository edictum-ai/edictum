"""Behavior tests for from_template(template_dirs=) and list_templates()."""

from __future__ import annotations

import pytest

from edictum import Edictum, EdictumConfigError, EdictumDenied, TemplateInfo

CUSTOM_TEMPLATE = """\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: support-agent
  description: "Custom template for support agents."
defaults:
  mode: enforce
rules:
  - id: block-ticket-leak
    type: pre
    tool: send_message
    when:
      args.body: { contains: "TICKET-" }
    then:
      action: block
      message: "Ticket references must not be in customer messages."
"""


@pytest.fixture()
def custom_dir(tmp_path):
    """Create a temp directory with a custom template."""
    tpl = tmp_path / "support-agent.yaml"
    tpl.write_text(CUSTOM_TEMPLATE)
    return tmp_path


@pytest.fixture()
def override_dir(tmp_path):
    """Create a temp directory with a template that overrides a built-in."""
    tpl = tmp_path / "file-agent.yaml"
    tpl.write_text(CUSTOM_TEMPLATE.replace("support-agent", "file-agent-custom"))
    return tmp_path


class TestFromTemplateBackwardCompat:
    """Existing from_template() calls still work without template_dirs."""

    def test_builtin_loads_without_template_dirs(self):
        guard = Edictum.from_template("file-agent")
        assert guard is not None
        assert len(guard._state.preconditions) > 0

    def test_missing_template_raises(self):
        with pytest.raises(EdictumConfigError, match="not found"):
            Edictum.from_template("nonexistent")


class TestFromTemplateCustomDirs:
    """template_dirs parameter enables loading templates from user directories."""

    def test_loads_from_custom_dir(self, custom_dir):
        guard = Edictum.from_template("support-agent", template_dirs=[custom_dir])
        assert guard is not None
        assert len(guard._state.preconditions) == 1

    @pytest.mark.asyncio
    async def test_custom_template_enforces(self, custom_dir):
        guard = Edictum.from_template(
            "support-agent",
            template_dirs=[custom_dir],
            audit_sink=_null_sink(),
        )
        with pytest.raises(EdictumDenied, match="Ticket references"):
            await guard.run("send_message", {"body": "See TICKET-123"}, _dummy_tool)


class TestFromTemplateSearchOrder:
    """User directories are searched before built-in templates."""

    def test_user_dir_overrides_builtin(self, override_dir):
        guard = Edictum.from_template("file-agent", template_dirs=[override_dir])
        # The override template has 1 rule, the built-in has 3
        assert len(guard._state.preconditions) == 1

    def test_builtin_used_as_fallback(self, custom_dir):
        # custom_dir only has support-agent, so file-agent falls through
        guard = Edictum.from_template("file-agent", template_dirs=[custom_dir])
        assert len(guard._state.preconditions) == 3  # built-in file-agent has 3

    def test_first_user_dir_wins(self, tmp_path):
        dir_a = tmp_path / "a"
        dir_a.mkdir()
        dir_b = tmp_path / "b"
        dir_b.mkdir()

        # Same name in both dirs, different content
        (dir_a / "my-agent.yaml").write_text(CUSTOM_TEMPLATE.replace("support-agent", "my-agent"))
        alt_yaml = CUSTOM_TEMPLATE.replace("support-agent", "my-agent").replace("block-ticket-leak", "alt-rule")
        (dir_b / "my-agent.yaml").write_text(alt_yaml)

        guard = Edictum.from_template("my-agent", template_dirs=[dir_a, dir_b])
        # Should load from dir_a (first in list)
        rule_id = getattr(guard._state.preconditions[0], "_edictum_id", None)
        assert rule_id == "block-ticket-leak"


class TestFromTemplateErrorMessage:
    """Error message lists templates from all searched directories."""

    def test_error_includes_custom_templates(self, custom_dir):
        with pytest.raises(EdictumConfigError, match="support-agent") as exc_info:
            Edictum.from_template("nope", template_dirs=[custom_dir])
        # Also includes built-in templates
        assert "file-agent" in str(exc_info.value)

    def test_nonexistent_dir_ignored(self, tmp_path):
        fake = tmp_path / "does-not-exist"
        # Should not raise on the dir itself, only on missing template
        with pytest.raises(EdictumConfigError, match="not found"):
            Edictum.from_template("nope", template_dirs=[fake])


class TestListTemplatesBuiltins:
    """list_templates() discovers built-in templates."""

    def test_returns_builtin_templates(self):
        templates = Edictum.list_templates()
        names = [t.name for t in templates]
        assert "file-agent" in names
        assert "research-agent" in names
        assert "devops-agent" in names

    def test_builtin_flag_is_true(self):
        templates = Edictum.list_templates()
        assert all(t.builtin for t in templates)

    def test_returns_template_info_type(self):
        templates = Edictum.list_templates()
        assert all(isinstance(t, TemplateInfo) for t in templates)


class TestListTemplatesCustomDirs:
    """list_templates(template_dirs=) discovers user templates."""

    def test_includes_custom_templates(self, custom_dir):
        templates = Edictum.list_templates(template_dirs=[custom_dir])
        names = [t.name for t in templates]
        assert "support-agent" in names
        # Built-ins still present
        assert "file-agent" in names

    def test_custom_template_not_builtin(self, custom_dir):
        templates = Edictum.list_templates(template_dirs=[custom_dir])
        custom = [t for t in templates if t.name == "support-agent"]
        assert len(custom) == 1
        assert custom[0].builtin is False

    def test_user_template_shadows_builtin(self, override_dir):
        templates = Edictum.list_templates(template_dirs=[override_dir])
        file_agents = [t for t in templates if t.name == "file-agent"]
        assert len(file_agents) == 1
        assert file_agents[0].builtin is False

    def test_nonexistent_dir_ignored(self, tmp_path):
        fake = tmp_path / "does-not-exist"
        templates = Edictum.list_templates(template_dirs=[fake])
        # Should still return built-in templates
        assert len(templates) >= 3


class TestListTemplatesOrder:
    """list_templates() returns user templates before built-in templates."""

    def test_user_templates_come_first(self, custom_dir):
        templates = Edictum.list_templates(template_dirs=[custom_dir])
        user_indices = [i for i, t in enumerate(templates) if not t.builtin]
        builtin_indices = [i for i, t in enumerate(templates) if t.builtin]
        if user_indices and builtin_indices:
            assert max(user_indices) < min(builtin_indices)


# -- Helpers --


async def _dummy_tool(**kwargs):
    return "ok"


def _null_sink():
    class _Sink:
        async def emit(self, event):
            pass

    return _Sink()
