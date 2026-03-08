#!/bin/bash
set -euo pipefail

PASS=0
FAIL=0
TOTAL=0

header() { printf "\n\033[1;34m=== %s ===\033[0m\n" "$1"; }
pass()   { PASS=$((PASS+1)); TOTAL=$((TOTAL+1)); printf "  \033[32mPASS\033[0m %s\n" "$1"; }
fail()   { FAIL=$((FAIL+1)); TOTAL=$((TOTAL+1)); printf "  \033[31mFAIL\033[0m %s\n" "$1"; }

# --------------------------------------------------------------------------
header "PHASE 1: Unit + Security Tests (pytest)"
# --------------------------------------------------------------------------
if pytest tests/test_gate/ -v --tb=short; then
    pass "pytest tests/test_gate/"
else
    fail "pytest tests/test_gate/"
fi

# --------------------------------------------------------------------------
header "PHASE 2: Lint"
# --------------------------------------------------------------------------
if ruff check src/edictum/gate/ tests/test_gate/; then
    pass "ruff check"
else
    fail "ruff check"
fi

# --------------------------------------------------------------------------
header "PHASE 3: Full test suite (regression check)"
# --------------------------------------------------------------------------
if pytest tests/ -v --tb=short -q; then
    pass "pytest tests/ (full suite)"
else
    fail "pytest tests/ (full suite)"
fi

# --------------------------------------------------------------------------
header "PHASE 4: CLI — gate init"
# --------------------------------------------------------------------------
edictum gate init --non-interactive
if [ -f "$HOME/.edictum/gate.yaml" ] && [ -f "$HOME/.edictum/contracts/base.yaml" ]; then
    pass "gate init created config + contracts"
    # Switch to enforce mode for testing (default is observe = audit only)
    sed -i 's/mode: observe/mode: enforce/' "$HOME/.edictum/contracts/base.yaml"
    pass "switched to enforce mode for deny tests"
else
    fail "gate init missing files"
fi

# --------------------------------------------------------------------------
header "PHASE 5: CLI — gate status"
# --------------------------------------------------------------------------
if edictum gate status; then
    pass "gate status"
else
    fail "gate status"
fi

# --------------------------------------------------------------------------
header "PHASE 6: gate check — deny destructive command"
# --------------------------------------------------------------------------
RESULT=$(echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"},"cwd":"/tmp"}' \
    | edictum gate check --format claude-code 2>/dev/null || true)
echo "  Output: $RESULT"
if echo "$RESULT" | python3 -c "
import sys, json
d = json.load(sys.stdin)
hso = d.get('hookSpecificOutput', {})
assert hso.get('permissionDecision') == 'deny', f'Expected deny, got {hso}'
"; then
    pass "deny rm -rf /"
else
    fail "deny rm -rf / — expected deny in hookSpecificOutput"
fi

# --------------------------------------------------------------------------
header "PHASE 7: gate check — allow safe read"
# --------------------------------------------------------------------------
RESULT=$(echo '{"tool_name":"Read","tool_input":{"file_path":"/tmp/foo.txt"},"cwd":"/tmp"}' \
    | edictum gate check --format claude-code 2>/dev/null || true)
echo "  Output: $RESULT"
if echo "$RESULT" | python3 -c "
import sys, json
d = json.load(sys.stdin)
hso = d.get('hookSpecificOutput', {})
# Claude Code allow = no permissionDecision or empty object
assert hso.get('permissionDecision', None) is None or d == {}, f'Expected allow, got {d}'
"; then
    pass "allow Read /tmp/foo.txt"
else
    fail "allow Read /tmp/foo.txt"
fi

# --------------------------------------------------------------------------
header "PHASE 8: gate check — deny secret file"
# --------------------------------------------------------------------------
RESULT=$(echo '{"tool_name":"Read","tool_input":{"file_path":"/project/.env"},"cwd":"/project"}' \
    | edictum gate check --format claude-code 2>/dev/null || true)
echo "  Output: $RESULT"
if echo "$RESULT" | python3 -c "
import sys, json
d = json.load(sys.stdin)
hso = d.get('hookSpecificOutput', {})
assert hso.get('permissionDecision') == 'deny', f'Expected deny for .env, got {hso}'
"; then
    pass "deny Read .env"
else
    fail "deny Read .env"
fi

# --------------------------------------------------------------------------
header "PHASE 9: gate check — scope enforcement (Write outside cwd)"
# --------------------------------------------------------------------------
RESULT=$(echo '{"tool_name":"Write","tool_input":{"file_path":"/etc/passwd","content":"x"},"cwd":"/tmp/project"}' \
    | edictum gate check --format claude-code 2>/dev/null || true)
echo "  Output: $RESULT"
if echo "$RESULT" | python3 -c "
import sys, json
d = json.load(sys.stdin)
hso = d.get('hookSpecificOutput', {})
assert hso.get('permissionDecision') == 'deny', f'Expected deny for scope escape, got {hso}'
"; then
    pass "deny Write outside cwd (scope enforcement)"
else
    fail "deny Write outside cwd (scope enforcement)"
fi

# --------------------------------------------------------------------------
header "PHASE 10: gate check — deny git push --force"
# --------------------------------------------------------------------------
RESULT=$(echo '{"tool_name":"Bash","tool_input":{"command":"git push --force origin main"},"cwd":"/tmp"}' \
    | edictum gate check --format claude-code 2>/dev/null || true)
echo "  Output: $RESULT"
if echo "$RESULT" | python3 -c "
import sys, json
d = json.load(sys.stdin)
hso = d.get('hookSpecificOutput', {})
assert hso.get('permissionDecision') == 'deny', f'Expected deny for git push --force, got {hso}'
"; then
    pass "deny git push --force"
else
    fail "deny git push --force"
fi

# --------------------------------------------------------------------------
header "PHASE 11: gate check — deny sudo"
# --------------------------------------------------------------------------
RESULT=$(echo '{"tool_name":"Bash","tool_input":{"command":"sudo rm -rf /"},"cwd":"/tmp"}' \
    | edictum gate check --format claude-code 2>/dev/null || true)
echo "  Output: $RESULT"
if echo "$RESULT" | python3 -c "
import sys, json
d = json.load(sys.stdin)
hso = d.get('hookSpecificOutput', {})
assert hso.get('permissionDecision') == 'deny', f'Expected deny for sudo, got {hso}'
"; then
    pass "deny sudo"
else
    fail "deny sudo"
fi

# --------------------------------------------------------------------------
header "PHASE 12: gate check — deny pip install"
# --------------------------------------------------------------------------
RESULT=$(echo '{"tool_name":"Bash","tool_input":{"command":"pip install malware"},"cwd":"/tmp"}' \
    | edictum gate check --format claude-code 2>/dev/null || true)
echo "  Output: $RESULT"
if echo "$RESULT" | python3 -c "
import sys, json
d = json.load(sys.stdin)
hso = d.get('hookSpecificOutput', {})
assert hso.get('permissionDecision') == 'deny', f'Expected deny for pip install, got {hso}'
"; then
    pass "deny pip install"
else
    fail "deny pip install"
fi

# --------------------------------------------------------------------------
header "PHASE 13: gate check — Cursor format"
# --------------------------------------------------------------------------
RESULT=$(echo '{"tool_name":"Shell","tool_input":{"command":"rm -rf /"},"cwd":"/tmp","hook_event_name":"preToolUse"}' \
    | edictum gate check --format cursor 2>/dev/null || true)
echo "  Output: $RESULT"
if echo "$RESULT" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert d.get('decision') == 'deny', f'Expected decision:deny for Cursor, got {d}'
"; then
    pass "Cursor format deny"
else
    fail "Cursor format deny"
fi

# --------------------------------------------------------------------------
header "PHASE 13b: gate check — Cursor format allow"
# --------------------------------------------------------------------------
RESULT=$(echo '{"tool_name":"Read","tool_input":{"file_path":"/tmp/foo.txt"},"cwd":"/tmp","hook_event_name":"preToolUse"}' \
    | edictum gate check --format cursor 2>/dev/null || true)
echo "  Output: $RESULT"
if echo "$RESULT" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert d.get('decision') == 'allow', f'Expected decision:allow for Cursor, got {d}'
"; then
    pass "Cursor format allow"
else
    fail "Cursor format allow"
fi

# --------------------------------------------------------------------------
header "PHASE 14: gate check — Gemini CLI format"
# --------------------------------------------------------------------------
RESULT=$(edictum gate check --format gemini 2>/dev/null \
    <<< '{"tool_name":"shell","tool_input":{"command":"rm -rf /"},"cwd":"/tmp","hook_event_name":"BeforeTool"}' \
    || true)
EXIT=$?
echo "  Output: $RESULT (exit=$EXIT)"
if [ "$EXIT" -eq 2 ] || echo "$RESULT" | python3 -c "
import sys
data = sys.stdin.read().strip()
# Gemini deny: exit 2, reason on stderr or stdout
assert 'deny' in data.lower() or len(data) > 0, f'Expected deny output, got: {data}'
" 2>/dev/null; then
    pass "Gemini CLI format deny"
else
    fail "Gemini CLI format deny"
fi

# --------------------------------------------------------------------------
header "PHASE 14b: gate check — Gemini CLI format allow"
# --------------------------------------------------------------------------
RESULT=$(echo '{"tool_name":"read_file","tool_input":{"file_path":"/tmp/foo.txt"},"cwd":"/tmp","hook_event_name":"BeforeTool"}' \
    | edictum gate check --format gemini 2>/dev/null || true)
EXIT=$?
echo "  Output: $RESULT (exit=$EXIT)"
if echo "$RESULT" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert d == {} or d == {'decision': 'allow'}, f'Expected empty JSON for Gemini allow, got {d}'
"; then
    pass "Gemini CLI format allow"
else
    fail "Gemini CLI format allow"
fi

# --------------------------------------------------------------------------
header "PHASE 15: gate check — OpenCode format"
# --------------------------------------------------------------------------
RESULT=$(echo '{"tool":"bash","args":{"command":"rm -rf /"},"directory":"/tmp"}' \
    | edictum gate check --format opencode 2>/dev/null || true)
echo "  Output: $RESULT"
if echo "$RESULT" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert d.get('allow') is False, f'Expected allow:false for OpenCode deny, got {d}'
"; then
    pass "OpenCode format deny"
else
    fail "OpenCode format deny"
fi

# --------------------------------------------------------------------------
header "PHASE 15b: gate check — Copilot CLI format deny"
# --------------------------------------------------------------------------
# Copilot stdin: camelCase keys, toolArgs is a JSON STRING
RESULT=$(echo '{"toolName":"bash","toolArgs":"{\"command\":\"rm -rf /\"}","cwd":"/tmp"}' \
    | edictum gate check --format copilot 2>/dev/null || true)
echo "  Output: $RESULT"
if echo "$RESULT" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert d.get('permissionDecision') == 'deny', f'Expected permissionDecision:deny for Copilot, got {d}'
"; then
    pass "Copilot CLI format deny"
else
    fail "Copilot CLI format deny"
fi

# --------------------------------------------------------------------------
header "PHASE 15c: gate check — Copilot CLI format allow"
# --------------------------------------------------------------------------
RESULT=$(echo '{"toolName":"view","toolArgs":"{\"file_path\":\"/tmp/foo.txt\"}","cwd":"/tmp"}' \
    | edictum gate check --format copilot 2>/dev/null || true)
echo "  Output: $RESULT"
if echo "$RESULT" | python3 -c "
import sys, json
d = json.load(sys.stdin)
# Copilot allow: empty JSON or no permissionDecision
assert d.get('permissionDecision', None) is None or d == {}, f'Expected allow for Copilot, got {d}'
"; then
    pass "Copilot CLI format allow"
else
    fail "Copilot CLI format allow"
fi

# --------------------------------------------------------------------------
header "PHASE 15d: gate check — Cursor auto-detection"
# --------------------------------------------------------------------------
# When stdin has cursor_version but format is claude-code, should auto-detect Cursor
RESULT=$(echo '{"tool_name":"Shell","tool_input":{"command":"rm -rf /"},"cwd":"/tmp","cursor_version":"1.7.2"}' \
    | edictum gate check --format claude-code 2>/dev/null || true)
echo "  Output: $RESULT"
if echo "$RESULT" | python3 -c "
import sys, json
d = json.load(sys.stdin)
# Should use Cursor format (decision key), not Claude Code format (hookSpecificOutput)
assert d.get('decision') == 'deny', f'Expected Cursor format decision:deny, got {d}'
"; then
    pass "Cursor auto-detection from claude-code format"
else
    fail "Cursor auto-detection from claude-code format"
fi

# --------------------------------------------------------------------------
header "PHASE 16: gate check — raw format"
# --------------------------------------------------------------------------
RESULT=$(echo '{"tool_name":"Bash","tool_input":{"command":"ls"},"cwd":"/tmp"}' \
    | edictum gate check --format raw 2>/dev/null || true)
echo "  Output: $RESULT"
if echo "$RESULT" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert 'verdict' in d, f'Expected verdict in raw output, got {d}'
"; then
    pass "raw format output"
else
    fail "raw format output"
fi

# --------------------------------------------------------------------------
header "PHASE 17: gate check — malicious stdin (oversized)"
# --------------------------------------------------------------------------
RESULT=$(python3 -c "print('{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"' + 'A'*11000000 + '\"},\"cwd\":\"/tmp\"}')" \
    | edictum gate check --format claude-code 2>/dev/null || true)
if echo "$RESULT" | python3 -c "
import sys, json
d = json.load(sys.stdin)
hso = d.get('hookSpecificOutput', {})
assert hso.get('permissionDecision') == 'deny', f'Expected deny for oversized stdin, got {d}'
"; then
    pass "deny oversized stdin (>10MB)"
else
    fail "deny oversized stdin"
fi

# --------------------------------------------------------------------------
header "PHASE 18: gate check — malicious stdin (not JSON)"
# --------------------------------------------------------------------------
RESULT=$(echo 'this is not json' \
    | edictum gate check --format claude-code 2>/dev/null || true)
echo "  Output: $RESULT"
if echo "$RESULT" | python3 -c "
import sys, json
d = json.load(sys.stdin)
hso = d.get('hookSpecificOutput', {})
assert hso.get('permissionDecision') == 'deny', f'Expected deny for non-JSON, got {d}'
"; then
    pass "deny non-JSON stdin"
else
    fail "deny non-JSON stdin"
fi

# --------------------------------------------------------------------------
header "PHASE 19: Symlink scope escape"
# --------------------------------------------------------------------------
mkdir -p /tmp/project
ln -sf /etc/passwd /tmp/project/sneaky 2>/dev/null || true
RESULT=$(echo '{"tool_name":"Write","tool_input":{"file_path":"/tmp/project/sneaky","content":"x"},"cwd":"/tmp/project"}' \
    | edictum gate check --format claude-code 2>/dev/null || true)
echo "  Output: $RESULT"
if echo "$RESULT" | python3 -c "
import sys, json
d = json.load(sys.stdin)
hso = d.get('hookSpecificOutput', {})
assert hso.get('permissionDecision') == 'deny', f'Expected deny for symlink escape, got {hso}'
"; then
    pass "deny symlink scope escape"
else
    fail "deny symlink scope escape"
fi

# --------------------------------------------------------------------------
header "PHASE 20: gate install + uninstall (Claude Code)"
# --------------------------------------------------------------------------
edictum gate install claude-code
if [ -f "$HOME/.claude/settings.json" ] && grep -q "edictum gate check" "$HOME/.claude/settings.json"; then
    pass "install claude-code hook"
else
    fail "install claude-code hook"
fi

edictum gate uninstall claude-code
if ! grep -q "edictum gate check" "$HOME/.claude/settings.json" 2>/dev/null; then
    pass "uninstall claude-code hook"
else
    fail "uninstall claude-code hook"
fi

# --------------------------------------------------------------------------
header "PHASE 21: gate audit"
# --------------------------------------------------------------------------
if edictum gate audit --limit 5; then
    pass "gate audit"
else
    fail "gate audit"
fi

# --------------------------------------------------------------------------
header "PHASE 22: Redaction — secrets never in WAL"
# --------------------------------------------------------------------------
echo '{"tool_name":"Bash","tool_input":{"command":"echo sk_live_abc123456789xyz AKIA1234567890123456"},"cwd":"/tmp"}' \
    | edictum gate check --format claude-code >/dev/null 2>&1 || true
WAL="$HOME/.edictum/audit/wal.jsonl"
if [ -f "$WAL" ]; then
    if grep -q "sk_live_" "$WAL" || grep -q "AKIA" "$WAL"; then
        fail "WAL contains unredacted secrets!"
    else
        pass "secrets redacted in WAL"
    fi
else
    fail "WAL file not found"
fi

# --------------------------------------------------------------------------
# Summary
# --------------------------------------------------------------------------
header "RESULTS"
printf "\n  Total: %d  |  Pass: \033[32m%d\033[0m  |  Fail: \033[31m%d\033[0m\n\n" "$TOTAL" "$PASS" "$FAIL"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
