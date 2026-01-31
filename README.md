# PAI Secret Scanning

Automated secret detection for [PAI](https://github.com/danielmiessler/PAI) operators. Catches API keys, personal paths, tokens, and credentials before they reach git history.

Built on [gitleaks](https://github.com/gitleaks/gitleaks) with PAI-specific detection rules.

## What It Detects

**PAI-specific rules** (on top of ~150 built-in gitleaks patterns):

| Rule | Pattern | Example |
|------|---------|---------|
| Anthropic API keys | `sk-ant-*` | `sk-ant-api03-abc...` |
| OpenAI API keys | `sk-[proj-]*` | `sk-proj-abc123...` |
| ElevenLabs API keys | `elevenlabs*key = hex{32}` | `ELEVENLABS_KEY=a1b2...` |
| Telegram bot tokens | `digits:alphanum{35}` | `123456789:AAF-xyz...` |
| Telegram chat IDs | `chat_id = digits` | `telegram_chat_id = -100123...` |
| Personal macOS paths | `/Users/username/` | `/Users/fischer/.config/...` |
| Personal Linux paths | `/home/username/` | `/home/andreas/projects/...` |
| .env inline values | `KEY=VALUE` in .env files | `API_KEY=sk-live-...` |

**Smart allowlists:** Markdown, lock files, and documentation are excluded from path detection to avoid false positives.

## Install

```bash
git clone https://github.com/jcfischer/pai-secret-scanning.git
cd pai-secret-scanning
./install.sh
```

This will:
1. Install gitleaks (via Homebrew or apt)
2. Deploy `.gitleaks.toml` to `~/.config/gitleaks/`
3. Deploy the pre-commit hook to `~/.config/git/hooks/`
4. Set `git config --global core.hooksPath` for all repos
5. Verify detection works

**Safe to re-run** — the installer is idempotent.

## How It Works

Every `git commit` across all repositories runs the pre-commit hook:

```
git add secret.ts
git commit -m "add config"
# → gitleaks protect --staged scans staged files
# → Blocks if secrets detected, passes if clean
```

**Bypass** (when needed): `git commit --no-verify`

The CI workflow (`.github/workflows/secret-scan.yml`) provides a second layer — catches anything that bypasses the local hook on push/PR.

## Usage in Your Repo

### Option 1: Global protection (recommended)

Run `./install.sh` once. All repos on your machine are protected.

### Option 2: Per-repo CI gate

Copy the workflow to your repo:

```bash
mkdir -p .github/workflows
cp .github/workflows/secret-scan.yml your-repo/.github/workflows/
cp .gitleaks.toml your-repo/
```

### Option 3: Manual scan

```bash
# Scan staged files
gitleaks protect --staged --config ~/.config/gitleaks/.gitleaks.toml

# Scan entire repo history
gitleaks detect --config ~/.config/gitleaks/.gitleaks.toml
```

## Tests

```bash
./tests/test-detection.sh
```

Runs 10 tests covering:
- Secret detection (OpenAI, Anthropic, Telegram, personal paths)
- Clean file passes (no false positives)
- Allowlist behavior (markdown, lock files)
- Performance (20 files under 2 seconds)
- Hook integration (blocks/passes via git commit)

## Customization

Edit `.gitleaks.toml` to add rules or allowlist entries:

```toml
# Add a new detection rule
[[rules]]
id = "my-custom-secret"
description = "My service API key"
regex = '''myservice-[A-Za-z0-9]{32}'''
tags = ["custom", "api-key"]

# Allowlist a specific file
[rules.allowlist]
paths = ['''test-fixtures/''']
```

After editing, re-run `./install.sh` to deploy the updated config.

## File Structure

```
pai-secret-scanning/
├── .gitleaks.toml           # Detection rules + allowlists
├── pre-commit               # Git hook script
├── install.sh               # One-command installer
├── .github/workflows/
│   └── secret-scan.yml      # CI gate for push/PR
├── tests/
│   ├── test-detection.sh    # 10-test validation suite
│   └── fixtures/            # Synthetic test data
├── LICENSE                  # MIT
└── README.md
```

## Background

Built as part of the [KAI improvement roadmap](https://github.com/jcfischer/kai-improvement-roadmap) (F-086). Designed for the [pai-collab](https://github.com/mellanon/pai-collab) collaboration where automated secret scanning is a unanimous prerequisite for cross-project integration.

## License

MIT
