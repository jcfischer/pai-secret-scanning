#!/usr/bin/env bash
# PAI Secret Scanning — Detection Test Suite
#
# Validates all acceptance criteria for the secret scanning gate.
# Creates temp git repos, stages test content, verifies detection.
#
# Usage: ./tests/test-detection.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CONFIG="$PROJECT_DIR/.gitleaks.toml"
HOOK="$PROJECT_DIR/pre-commit"
TMPDIR=""
PASSED=0
FAILED=0
TOTAL=0

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

# Cleanup on exit
cleanup() {
  if [ -n "$TMPDIR" ] && [ -d "$TMPDIR" ]; then
    rm -rf "$TMPDIR"
  fi
}
trap cleanup EXIT

# Create a fresh temp git repo
setup_repo() {
  TMPDIR=$(mktemp -d /tmp/gitleaks-test-XXXXXX)
  cd "$TMPDIR"
  git init -q
  git config user.email "test@test.local"
  git config user.name "Test"
  # Initial commit so we can stage files
  echo "init" > .init
  git add .init
  git commit -q -m "init"
}

# Test helper: assert gitleaks exits with expected code
assert_detect() {
  local desc="$1"
  local file="$2"
  local content="$3"
  local expected_exit="$4"  # 0 = no leaks, 1 = leaks found
  TOTAL=$((TOTAL + 1))

  # Reset staged files — must unstage index first, then clean working tree
  cd "$TMPDIR"
  git reset -q HEAD -- . 2>/dev/null || true
  git checkout -q -- . 2>/dev/null || true
  git clean -fdq 2>/dev/null || true

  # Create and stage the file
  mkdir -p "$(dirname "$file")"
  printf '%s\n' "$content" > "$file"
  git add "$file"

  # Run gitleaks protect --staged
  local actual_exit=0
  gitleaks protect --staged --config "$CONFIG" --no-banner --exit-code 1 &>/dev/null || actual_exit=$?

  if [ "$actual_exit" -eq "$expected_exit" ]; then
    echo -e "  ${GREEN}PASS${NC} [$TOTAL] $desc"
    PASSED=$((PASSED + 1))
  else
    echo -e "  ${RED}FAIL${NC} [$TOTAL] $desc (expected exit=$expected_exit, got exit=$actual_exit)"
    FAILED=$((FAILED + 1))
  fi
}

# Test helper: assert hook behavior via git commit
assert_hook() {
  local desc="$1"
  local file="$2"
  local content="$3"
  local expected_exit="$4"  # 0 = commit succeeds, non-zero = blocked
  TOTAL=$((TOTAL + 1))

  cd "$TMPDIR"
  git reset -q HEAD -- . 2>/dev/null || true
  git checkout -q -- . 2>/dev/null || true
  git clean -fdq 2>/dev/null || true

  # Configure hook in this repo
  mkdir -p "$TMPDIR/.config/git/hooks"
  cp "$HOOK" "$TMPDIR/.config/git/hooks/pre-commit"
  chmod +x "$TMPDIR/.config/git/hooks/pre-commit"
  git config core.hooksPath "$TMPDIR/.config/git/hooks"

  # Set config path for hook
  export GITLEAKS_CONFIG="$CONFIG"

  mkdir -p "$(dirname "$file")"
  echo "$content" > "$file"
  git add "$file"

  local actual_exit=0
  git commit -q -m "test commit" &>/dev/null || actual_exit=$?

  if { [ "$expected_exit" -eq 0 ] && [ "$actual_exit" -eq 0 ]; } ||
     { [ "$expected_exit" -ne 0 ] && [ "$actual_exit" -ne 0 ]; }; then
    echo -e "  ${GREEN}PASS${NC} [$TOTAL] $desc"
    PASSED=$((PASSED + 1))
  else
    echo -e "  ${RED}FAIL${NC} [$TOTAL] $desc (expected exit=$expected_exit, got exit=$actual_exit)"
    FAILED=$((FAILED + 1))
  fi
}

echo ""
echo "PAI Secret Scanning — Test Suite"
echo "================================="
echo ""

# --- Prerequisite check ---
if ! command -v gitleaks &>/dev/null; then
  echo -e "${RED}ERROR: gitleaks not installed. Run: brew install gitleaks${NC}"
  exit 1
fi

# --- Setup ---
setup_repo

echo "Detection tests (gitleaks protect --staged):"
echo ""

# Test 1: OpenAI API key detection
assert_detect \
  "Detects OpenAI API key" \
  "config.ts" \
  'export const API_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ab";' \
  1

# Test 2: Anthropic key detection
assert_detect \
  "Detects Anthropic API key" \
  "client.ts" \
  'const key = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz1234567890abcdefghij";' \
  1

# Test 3: Personal path detection
assert_detect \
  "Detects personal macOS path" \
  "setup.ts" \
  'const config = "/Users/fischer/.config/pai/settings.json";' \
  1

# Test 4: Telegram token detection
assert_detect \
  "Detects Telegram bot token" \
  "bot.ts" \
  'const TOKEN = "123456789:AAF-xvHj5kFh-abc123def456ghi789jklm";' \
  1

# Test 5: Replicate API token detection
assert_detect \
  "Detects Replicate API token" \
  "ai-config.ts" \
  'const REPLICATE_TOKEN = "r8_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789abcd";' \
  1

# Test 6: HuggingFace API token detection
assert_detect \
  "Detects HuggingFace API token" \
  "hf-client.ts" \
  'export const HF_TOKEN = "hf_aBcDeFgHiJkLmNoPqRsTuVwXyZ01234567";' \
  1

# Test 7: Groq API key detection
assert_detect \
  "Detects Groq API key" \
  "groq-client.ts" \
  'const GROQ_KEY = "gsk_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789abcdefghijklmnopqr";' \
  1

# Test 8: Clean file passes
assert_detect \
  "Passes clean TypeScript file" \
  "clean.ts" \
  'const MAX_RETRIES = 3; export default MAX_RETRIES;' \
  0

# Test 6: Markdown allowlisted
assert_detect \
  "Allows paths in markdown files" \
  "docs/setup.md" \
  'Install to `/Users/fischer/.config/gitleaks/` for global setup.' \
  0

# Test 7: Allowlist works for lock files
assert_detect \
  "Allows patterns in lock files" \
  "something.lock" \
  'resolved "https://registry.npmjs.org/sk-ant-test-aaaabbbbccccddddeeeeffffgggghhhh"' \
  0

# Test 8: Performance (20 staged files)
TOTAL=$((TOTAL + 1))
echo ""
echo "Performance test (20 staged files):"
cd "$TMPDIR"
git reset -q HEAD -- . 2>/dev/null || true
git checkout -q -- . 2>/dev/null || true
git clean -fdq 2>/dev/null || true
for i in $(seq 1 20); do
  echo "export const module_$i = { name: 'mod-$i', version: '1.0.$i' };" > "module_$i.ts"
done
git add .
START=$(date +%s%N 2>/dev/null || python3 -c 'import time; print(int(time.time()*1e9))')
gitleaks protect --staged --config "$CONFIG" --no-banner &>/dev/null
END=$(date +%s%N 2>/dev/null || python3 -c 'import time; print(int(time.time()*1e9))')
ELAPSED_MS=$(( (END - START) / 1000000 ))
if [ "$ELAPSED_MS" -lt 2000 ]; then
  echo -e "  ${GREEN}PASS${NC} [$TOTAL] 20 staged files scanned in ${ELAPSED_MS}ms (< 2000ms)"
  PASSED=$((PASSED + 1))
else
  echo -e "  ${RED}FAIL${NC} [$TOTAL] 20 staged files scanned in ${ELAPSED_MS}ms (>= 2000ms)"
  FAILED=$((FAILED + 1))
fi

# Hook integration tests
echo ""
echo "Hook integration tests (git commit with pre-commit hook):"
echo ""

# Need a fresh repo for hook tests
cleanup
setup_repo

# Test 9: Hook blocks commit with secret
assert_hook \
  "Hook blocks commit with Anthropic key" \
  "secret.ts" \
  'const k = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz1234567890abcdefghij";' \
  1

# Test 10: Hook passes clean commit
assert_hook \
  "Hook passes clean commit" \
  "clean.ts" \
  'const x = 42; export default x;' \
  0

# --- Summary ---
echo ""
echo "================================="
if [ "$FAILED" -eq 0 ]; then
  echo -e "${GREEN}All $TOTAL tests passed${NC}"
  exit 0
else
  echo -e "${RED}$FAILED/$TOTAL tests failed${NC}"
  exit 1
fi
