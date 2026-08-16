#!/usr/bin/env bash
# Run CrewAI real-framework smokes at floor (1.5.0) and latest (1.15.16).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PINS=("1.5.0" "1.15.16")
status=0
for pin in "${PINS[@]}"; do
  echo "======== crewai==${pin} ========"
  venv="$(mktemp -d)"
  python3 -m venv "$venv"
  "$venv/bin/pip" install -q -U pip
  if ! "$venv/bin/pip" install -q -e "${ROOT}[dev,yaml]" "crewai==${pin}"; then
    echo "RED: failed to install claimed host crewai==${pin}"
    status=1
    rm -rf "$venv"
    continue
  fi
  if ! EDICTUM_CREWAI_SMOKE=1 "$venv/bin/pytest" -o addopts= "${ROOT}/tests/test_adapter_crewai_smoke.py" -v --tb=short; then
    echo "RED: smokes failed on crewai==${pin}"
    status=1
  fi
  rm -rf "$venv"
done
exit "$status"
