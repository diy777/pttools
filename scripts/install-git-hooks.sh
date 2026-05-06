#!/usr/bin/env bash
# Install pre-push git hooks for pentest-tools contributors.
#
# Each developer runs this once after cloning. The hook lives in
# .git/hooks/pre-push and is NOT version-controlled. We DO version
# control its source here so the hook stays in sync across contributors.
#
# Usage: bash scripts/install-git-hooks.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOOK_DIR="$REPO_ROOT/.git/hooks"

if [[ ! -d "$REPO_ROOT/.git" ]]; then
    echo "error: not in a git repo"
    exit 1
fi

mkdir -p "$HOOK_DIR"

cat > "$HOOK_DIR/pre-push" <<'PREPUSH'
#!/usr/bin/env bash
# pentest-tools pre-push hook
# Catches ruff failures BEFORE they hit CI, eliminating most failure emails.
#
# Skip with: git push --no-verify   (use sparingly, breaks the trust model)

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

# Find a python that has ruff
RUFF_BIN=""
if [[ -x ".venv/bin/ruff" ]]; then
    RUFF_BIN=".venv/bin/ruff"
elif command -v ruff >/dev/null 2>&1; then
    RUFF_BIN="ruff"
else
    echo "[pre-push] ruff not found; skipping lint check"
    echo "[pre-push] install: pip install -e .[dev]"
    exit 0
fi

# Only check if any Python files are about to be pushed
if git diff --name-only @{u}.. 2>/dev/null | grep -qE '\.(py)$'; then
    echo "[pre-push] running ruff check"
    if ! "$RUFF_BIN" check .; then
        echo ""
        echo "[pre-push] ruff failed. Fix with: $RUFF_BIN check --fix ."
        echo "[pre-push] To bypass (not recommended): git push --no-verify"
        exit 1
    fi
fi

# Optional: run a fast subset of tests if pytest is available and the user
# is pushing changed Python under engine/, agents/, api/, cli/, or tools/.
if [[ -x ".venv/bin/pytest" ]]; then
    if git diff --name-only @{u}.. 2>/dev/null | grep -qE '^(engine|agents|api|cli|tools|tests)/.*\.py$'; then
        echo "[pre-push] running pytest tests/ -q (fast)"
        if ! .venv/bin/pytest tests/ -q --tb=line --timeout=30 2>/dev/null; then
            echo "[pre-push] tests failed. Push anyway with: git push --no-verify"
            exit 1
        fi
    fi
fi

echo "[pre-push] checks passed"
exit 0
PREPUSH

chmod +x "$HOOK_DIR/pre-push"
echo "installed pre-push hook at $HOOK_DIR/pre-push"
echo "run 'git push --no-verify' to bypass when needed"
