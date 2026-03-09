"""Docs-code sync verification.

Catches ghost features (documented but not implemented) and
ensures documentation references match actual source code.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).parent.parent
SRC_ROOT = PROJECT_ROOT / "src" / "edictum"


class TestExportsImportable:
    """Every symbol in __all__ must be importable."""

    def test_all_exports_importable(self):
        import edictum

        missing = []
        for name in edictum.__all__:
            if getattr(edictum, name, None) is None:
                missing.append(name)
        assert not missing, (
            f"These names are in __all__ but cannot be imported: {missing}. "
            "Either implement them or remove from __all__."
        )


class TestClaudeMdReferences:
    """Files referenced in CLAUDE.md must exist on disk."""

    def test_source_files_in_claude_md_exist(self):
        claude_md = PROJECT_ROOT / "CLAUDE.md"
        if not claude_md.exists():
            pytest.skip("CLAUDE.md not found")

        content = claude_md.read_text()
        # Match *.py references in the source layout section
        py_files = re.findall(r"[├└]── (\w+\.py)", content)

        missing = []
        for filename in py_files:
            found = any(
                (d / filename).exists()
                for d in [
                    SRC_ROOT,
                    SRC_ROOT / "adapters",
                    SRC_ROOT / "cli",
                    SRC_ROOT / "yaml_engine",
                    SRC_ROOT / "core",
                    SRC_ROOT / "gate",
                    SRC_ROOT / "gate" / "formats",
                ]
            )
            if not found:
                missing.append(filename)

        assert not missing, (
            f"CLAUDE.md references these files but they don't exist: {missing}. "
            "Either create them or remove the references."
        )
