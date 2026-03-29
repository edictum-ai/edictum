"""Conformance runner for shared rejection fixtures from edictum-schemas.

Two levels of parity are tested independently:

  1. **Rejection parity** (test_malformed_bundle_rejected) — every fixture
     with ``expected.rejected: true`` MUST raise ``EdictumConfigError``.
     Hard assertion, no exceptions.

  2. **Error-message parity** (test_error_message_parity) — the error text
     SHOULD contain ``expected.error_contains``.  Fixtures where jsonschema's
     error format is known to diverge are marked ``xfail(strict=True)`` so
     that unexpected passes surface immediately for cleanup.

Fixture discovery (first match wins):
  1. EDICTUM_SCHEMAS_DIR env var
  2. <repo-root>/edictum-schemas/   (CI: actions/checkout puts it here)
  3. <repo-root>/../edictum-schemas/ (local: sibling directory)

Environment flags:
  EDICTUM_CONFORMANCE_REQUIRED=1  — fail collection when fixtures are
      missing (set this in CI).  Without it the module skips gracefully.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
import yaml

from edictum._exceptions import EdictumConfigError
from edictum.yaml_engine.loader import load_bundle_string

# ---------------------------------------------------------------------------
# Fixture discovery
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parents[2]
_CONFORMANCE_REQUIRED = os.environ.get("EDICTUM_CONFORMANCE_REQUIRED") == "1"


def _find_rejection_dir() -> Path | None:
    candidates: list[Path] = []

    env = os.environ.get("EDICTUM_SCHEMAS_DIR")
    if env:
        candidates.append(Path(env) / "fixtures" / "rejection")

    candidates.append(_REPO_ROOT / "edictum-schemas" / "fixtures" / "rejection")
    candidates.append(_REPO_ROOT.parent / "edictum-schemas" / "fixtures" / "rejection")

    for c in candidates:
        if c.is_dir():
            return c
    return None


REJECTION_DIR = _find_rejection_dir()

# ---------------------------------------------------------------------------
# Error-message xfail set
# ---------------------------------------------------------------------------
# jsonschema reports two classes of error that omit the field name the
# fixture expects:
#
#   oneOf dispatch — rule-level structural errors produce
#       "is not valid under any of the given schemas"
#
#   value-level reporting — top-level field errors name the bad value
#       ("'not-an-object' is not of type 'object'") not the field
#       ("metadata")
#
# These are NOT bugs in the Python loader.  The bundle IS rejected.
# strict=True ensures we notice if jsonschema improves and the xfail
# starts passing unexpectedly.

_ERROR_MSG_XFAIL: frozenset[str] = frozenset(
    {
        # rule-structure: oneOf dispatch
        "rej-014",
        "rej-016",
        "rej-017",
        "rej-018",
        "rej-019",
        "rej-020",
        "rej-021",
        "rej-022",
        "rej-023",
        "rej-024",
        "rej-025",
        "rej-026",
        "rej-027",
        "rej-028",
        "rej-029",
        "rej-030",
        # required-fields: value-level reporting
        "rej-002",
        "rej-005",
        "rej-006",
        # constraints: value-level reporting
        "rej-062",
    }
)

# ---------------------------------------------------------------------------
# Collection
# ---------------------------------------------------------------------------


def _collect() -> tuple[list, list]:
    """Return (rejection_params, errmsg_params) from the fixture corpus."""
    if REJECTION_DIR is None:
        return [], []

    rejection_params: list = []
    errmsg_params: list = []

    for path in sorted(REJECTION_DIR.glob("*.rejection.yaml")):
        suite = yaml.safe_load(path.read_text())
        suite_name = suite.get("suite", path.stem)
        for fix in suite.get("fixtures", []):
            fid = fix["id"]
            test_id = f"{suite_name}/{fid}"
            bundle_yaml = yaml.dump(fix["bundle"], default_flow_style=False)
            expected = fix["expected"]

            rejection_params.append(
                pytest.param(bundle_yaml, expected, id=test_id),
            )

            if "error_contains" in expected:
                marks: list = []
                if fid in _ERROR_MSG_XFAIL:
                    marks.append(
                        pytest.mark.xfail(
                            reason="jsonschema oneOf/value-level error reporting",
                            strict=True,
                        )
                    )
                errmsg_params.append(
                    pytest.param(bundle_yaml, expected, id=test_id, marks=marks),
                )

    return rejection_params, errmsg_params


_REJECTION_PARAMS, _ERRMSG_PARAMS = _collect()

# ---------------------------------------------------------------------------
# CI gate: fail collection when required but missing
# ---------------------------------------------------------------------------

if _CONFORMANCE_REQUIRED and not _REJECTION_PARAMS:
    raise FileNotFoundError(
        "EDICTUM_CONFORMANCE_REQUIRED=1 but rejection fixtures not found. "
        "Set EDICTUM_SCHEMAS_DIR or ensure edictum-schemas is checked out."
    )

pytestmark = pytest.mark.skipif(
    not _REJECTION_PARAMS,
    reason="edictum-schemas not found (set EDICTUM_SCHEMAS_DIR)",
)

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bundle_yaml,expected", _REJECTION_PARAMS)
def test_malformed_bundle_rejected(bundle_yaml: str, expected: dict) -> None:
    """Rejection parity: malformed bundle MUST raise EdictumConfigError."""
    assert expected.get("rejected") is True

    with pytest.raises(EdictumConfigError):
        load_bundle_string(bundle_yaml)


@pytest.mark.parametrize("bundle_yaml,expected", _ERRMSG_PARAMS)
def test_error_message_parity(bundle_yaml: str, expected: dict) -> None:
    """Error-message parity: error text SHOULD contain expected substring."""
    with pytest.raises(EdictumConfigError) as exc_info:
        load_bundle_string(bundle_yaml)

    needle = expected["error_contains"]
    msg = str(exc_info.value).lower()
    assert needle.lower() in msg, f"Expected error to contain '{needle}', got: {exc_info.value}"
