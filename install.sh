#!/usr/bin/env bash
# PAI Secret Scanning — Idempotent Installer
#
# Installs gitleaks, configures global pre-commit hook, sets up detection rules.
# Safe to re-run — checks each step before acting.
#
# Usage: ./install.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GITLEAKS_CONFIG_DIR="$HOME/.config/gitleaks"
GIT_HOOKS_DIR="$HOME/.config/git/hooks"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

info()  { echo -e "${BLUE}[INFO]${NC} $1"; }
ok()    { echo -e "${GREEN}[OK]${NC}   $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
fail()  { echo -e "${RED}[FAIL]${NC} $1"; exit 1; }

echo ""
echo "PAI Secret Scanning — Installation"
echo "==================================="
echo ""

# --- Step 1: Install gitleaks ---
if command -v gitleaks &>/dev/null; then
  ok "gitleaks already installed ($(gitleaks version))"
else
  if command -v brew &>/dev/null; then
    info "Installing gitleaks via Homebrew..."
    brew install gitleaks
  elif command -v apt-get &>/dev/null; then
    info "Installing gitleaks via apt..."
    sudo apt-get install -y gitleaks 2>/dev/null || {
      info "Not in apt — installing from GitHub releases..."
      LATEST=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest | grep tag_name | cut -d '"' -f 4)
      curl -sSL "https://github.com/gitleaks/gitleaks/releases/download/${LATEST}/gitleaks_${LATEST#v}_linux_x64.tar.gz" | sudo tar xz -C /usr/local/bin gitleaks
    }
  else
    fail "No supported package manager found. Install gitleaks manually: https://github.com/gitleaks/gitleaks#installing"
  fi
  ok "gitleaks installed ($(gitleaks version))"
fi

# --- Step 2: Deploy .gitleaks.toml ---
mkdir -p "$GITLEAKS_CONFIG_DIR"
if [ -f "$GITLEAKS_CONFIG_DIR/.gitleaks.toml" ]; then
  if diff -q "$SCRIPT_DIR/.gitleaks.toml" "$GITLEAKS_CONFIG_DIR/.gitleaks.toml" &>/dev/null; then
    ok ".gitleaks.toml already deployed (up to date)"
  else
    info "Updating .gitleaks.toml..."
    cp "$SCRIPT_DIR/.gitleaks.toml" "$GITLEAKS_CONFIG_DIR/.gitleaks.toml"
    ok ".gitleaks.toml updated"
  fi
else
  cp "$SCRIPT_DIR/.gitleaks.toml" "$GITLEAKS_CONFIG_DIR/.gitleaks.toml"
  ok ".gitleaks.toml deployed to $GITLEAKS_CONFIG_DIR/"
fi

# --- Step 3: Deploy pre-commit hook ---
mkdir -p "$GIT_HOOKS_DIR"
if [ -f "$GIT_HOOKS_DIR/pre-commit" ]; then
  if diff -q "$SCRIPT_DIR/pre-commit" "$GIT_HOOKS_DIR/pre-commit" &>/dev/null; then
    ok "pre-commit hook already deployed (up to date)"
  else
    info "Updating pre-commit hook..."
    cp "$SCRIPT_DIR/pre-commit" "$GIT_HOOKS_DIR/pre-commit"
    chmod +x "$GIT_HOOKS_DIR/pre-commit"
    ok "pre-commit hook updated"
  fi
else
  cp "$SCRIPT_DIR/pre-commit" "$GIT_HOOKS_DIR/pre-commit"
  chmod +x "$GIT_HOOKS_DIR/pre-commit"
  ok "pre-commit hook deployed to $GIT_HOOKS_DIR/"
fi

# --- Step 4: Configure global hooksPath ---
CURRENT_HOOKS_PATH=$(git config --global core.hooksPath 2>/dev/null || echo "")
if [ "$CURRENT_HOOKS_PATH" = "$GIT_HOOKS_DIR" ]; then
  ok "core.hooksPath already set to $GIT_HOOKS_DIR"
elif [ -n "$CURRENT_HOOKS_PATH" ]; then
  warn "core.hooksPath is currently set to: $CURRENT_HOOKS_PATH"
  warn "Overwriting with: $GIT_HOOKS_DIR"
  warn "(Previous hooks at $CURRENT_HOOKS_PATH may need manual chaining)"
  git config --global core.hooksPath "$GIT_HOOKS_DIR"
  ok "core.hooksPath updated to $GIT_HOOKS_DIR"
else
  git config --global core.hooksPath "$GIT_HOOKS_DIR"
  ok "core.hooksPath set to $GIT_HOOKS_DIR"
fi

# --- Step 5: Verification ---
info "Running verification..."
TMPFILE=$(mktemp)
echo 'ANTHROPIC_API_KEY=sk-ant-api03-testkey1234567890abcdefghijklmnop' > "$TMPFILE"
if gitleaks detect --no-git --config "$GITLEAKS_CONFIG_DIR/.gitleaks.toml" --source "$TMPFILE" --no-banner --exit-code 1 &>/dev/null; then
  warn "Verification: gitleaks did NOT detect test secret (check rules)"
  rm -f "$TMPFILE"
else
  ok "Verification passed — gitleaks correctly detects secrets"
  rm -f "$TMPFILE"
fi

# --- Done ---
echo ""
echo "==================================="
echo -e "${GREEN}Secret scanning installed successfully${NC}"
echo ""
echo "  Config:  $GITLEAKS_CONFIG_DIR/.gitleaks.toml"
echo "  Hook:    $GIT_HOOKS_DIR/pre-commit"
echo "  Scope:   All repositories (global hook)"
echo ""
echo "  Bypass:  git commit --no-verify"
echo "  Test:    gitleaks protect --staged"
echo ""
