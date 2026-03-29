"""Behavior tests for JSON Schema validation of boolean expressions (#66)."""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from edictum import Edictum

_ROOT = Path(__file__).resolve().parents[2]
YAML_ENGINE_SCHEMA_PATH = _ROOT / "src" / "edictum" / "yaml_engine" / "edictum-v1.schema.json"
STANDALONE_SCHEMA_PATH = _ROOT / "schemas" / "edictum-v1.schema.json"

_schema_cache: dict[str, dict] = {}


def _load_schema(path: str) -> dict:
    if path not in _schema_cache:
        _schema_cache[path] = json.loads(Path(path).read_text())
    return _schema_cache[path]


def _make_bundle(when_expr: dict) -> dict:
    return {
        "apiVersion": "edictum/v1",
        "kind": "Ruleset",
        "metadata": {"name": "test"},
        "defaults": {"mode": "enforce"},
        "rules": [
            {
                "id": "test-rule",
                "type": "pre",
                "tool": "test_tool",
                "when": when_expr,
                "then": {"action": "block", "message": "denied"},
            }
        ],
    }


BOTH_SCHEMAS = [str(YAML_ENGINE_SCHEMA_PATH), str(STANDALONE_SCHEMA_PATH)]


@pytest.mark.parametrize("schema_path", BOTH_SCHEMAS)
class TestNotExpressionValidates:
    """not: expressions pass schema validation after the ExprLeaf fix."""

    def test_not_expression_validates(self, schema_path):
        schema = _load_schema(schema_path)
        doc = _make_bundle({"not": {"args.to": {"ends_with": "@company.com"}}})
        jsonschema.validate(doc, schema)

    def test_nested_all_not_expression_validates(self, schema_path):
        schema = _load_schema(schema_path)
        doc = _make_bundle({"all": [{"args.x": {"equals": 1}}, {"not": {"args.y": {"equals": 2}}}]})
        jsonschema.validate(doc, schema)

    def test_nested_any_not_expression_validates(self, schema_path):
        schema = _load_schema(schema_path)
        doc = _make_bundle({"any": [{"args.x": {"equals": 1}}, {"not": {"args.y": {"equals": 2}}}]})
        jsonschema.validate(doc, schema)

    def test_double_nested_not_validates(self, schema_path):
        schema = _load_schema(schema_path)
        doc = _make_bundle({"not": {"not": {"args.x": {"equals": 1}}}})
        jsonschema.validate(doc, schema)


@pytest.mark.parametrize("schema_path", BOTH_SCHEMAS)
class TestExistingExpressionsStillValidate:
    """Regression guards: leaf, all, any expressions still pass."""

    def test_leaf_expression_still_validates(self, schema_path):
        schema = _load_schema(schema_path)
        doc = _make_bundle({"args.command": {"contains": "rm"}})
        jsonschema.validate(doc, schema)

    def test_all_expression_still_validates(self, schema_path):
        schema = _load_schema(schema_path)
        doc = _make_bundle({"all": [{"args.x": {"equals": 1}}]})
        jsonschema.validate(doc, schema)

    def test_any_expression_still_validates(self, schema_path):
        schema = _load_schema(schema_path)
        doc = _make_bundle({"any": [{"args.x": {"equals": 1}}]})
        jsonschema.validate(doc, schema)


@pytest.mark.parametrize("schema_path", BOTH_SCHEMAS)
class TestInvalidExpressionRejected:
    """Malformed expressions are still rejected by schema validation."""

    def test_invalid_expression_still_rejected(self, schema_path):
        schema = _load_schema(schema_path)
        doc = _make_bundle({})
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(doc, schema)


class TestNotExpressionIntegration:
    """from_yaml_string() loads a not: rule end-to-end."""

    def test_not_expression_loads_via_from_yaml_string(self):
        yaml_content = """\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: not-test
defaults:
  mode: enforce
rules:
  - id: no-external-email
    type: pre
    tool: send_email
    when:
      not:
        args.to: { ends_with: "@company.com" }
    then:
      action: block
      message: "External email denied"
"""
        guard = Edictum.from_yaml_string(yaml_content)
        assert len(guard._state.preconditions) >= 1
