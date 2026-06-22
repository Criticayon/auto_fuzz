#!/usr/bin/env bash
# ============================================================
# Vulnerability Discovery Pipeline - One-click Deploy
# 检查环境 → 安装 skills → 安装依赖 → 启动 Web UI
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

info()  { echo -e "${CYAN}[INFO]${NC} $1"; }
ok()    { echo -e "${GREEN}[OK]${NC}   $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }

echo ""
echo "============================================"
echo " Vulnerability Discovery Pipeline Deploy"
echo "============================================"
echo ""

# ──────────────────────────────────────────────
# Step 1: Check Claude Code environment
# ──────────────────────────────────────────────
echo "─────────────────────────────────────────────"
info "Step 1/4: Checking Claude Code environment..."
echo ""

if command -v claude &>/dev/null; then
    ok "Claude CLI found: $(claude --version 2>/dev/null || echo 'unknown version')"
else
    warn "Claude CLI not found in PATH."
    echo "  Please install Claude Code first:"
    echo "    npm install -g @anthropic-ai/claude-code"
    echo ""
    echo "  Or visit: https://docs.anthropic.com/en/docs/claude-code"
    echo ""
    read -rp "Press Enter after installing Claude Code, or Ctrl+C to abort..."
    if ! command -v claude &>/dev/null; then
        echo "[ERROR] Claude CLI still not found. Aborting."
        exit 1
    fi
    ok "Claude CLI found"
fi

# ──────────────────────────────────────────────
# Step 2: Install skills
# ──────────────────────────────────────────────
echo ""
echo "─────────────────────────────────────────────"
info "Step 2/4: Installing pipeline skills..."
echo ""

SKILLS_TARGET="${HOME}/.claude/skills"
SKILLS_SRC="${SCRIPT_DIR}/skills"

SKILLS_LIST=(
    "program-analysis:program-analysis.md"
    "auto-fuzz:auto-fuzz.md"
    "auto-fuzz-exec:auto-fuzz-exec.md"
    "crash-reporter:crash-reporter.md"
    "issue-generator:issue-generator.md"
)

echo "  Skills will be installed to: ${SKILLS_TARGET}/"
echo ""
echo "  Skills to install:"
for entry in "${SKILLS_LIST[@]}"; do
    dir_name="${entry%%:*}"
    echo "    - /${dir_name}"
done
echo ""

read -rp "Install pipeline skills now? [Y/n] " yn
yn="${yn:-Y}"
if [[ "$yn" =~ ^[Yy] ]]; then
    for entry in "${SKILLS_LIST[@]}"; do
        dir_name="${entry%%:*}"
        src_file="${entry##*:}"
        src_path="${SKILLS_SRC}/${src_file}"
        target_dir="${SKILLS_TARGET}/${dir_name}"
        target_file="${target_dir}/SKILL.md"

        if [ ! -f "$src_path" ]; then
            warn "Source not found: ${src_path} — skipping"
            continue
        fi

        mkdir -p "$target_dir"
        cp "$src_path" "$target_file"
        ok "${dir_name}/SKILL.md"
    done

    # 复制 plugin.json
    if [ -f "${SCRIPT_DIR}/plugin.json" ]; then
        cp "${SCRIPT_DIR}/plugin.json" "${SKILLS_TARGET}/vulnerability-pipeline-plugin.json"
        ok "plugin.json"
    fi

    echo ""
    ok "All skills installed."
else
    warn "Skipping skill installation."
fi

# ──────────────────────────────────────────────
# Step 3: Check Python dependencies
# ──────────────────────────────────────────────
echo ""
echo "─────────────────────────────────────────────"
info "Step 3/4: Checking Python dependencies..."
echo ""

# 检查 Python 版本
PY_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || python -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || echo "0")
PY_MAJOR=$(echo "$PY_VER" | cut -d. -f1)
PY_MINOR=$(echo "$PY_VER" | cut -d. -f2)

if [ "$PY_MAJOR" -lt 3 ] || { [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 10 ]; }; then
    warn "Python 3.10+ required (found ${PY_VER})"
    echo "  Please install Python 3.10 or later."
    exit 1
fi
ok "Python ${PY_VER}"

# 检查依赖是否已安装
MISSING=""
python3 -c "import anyio" 2>/dev/null || MISSING="$MISSING anyio"
python3 -c "import docker" 2>/dev/null || MISSING="$MISSING docker"
python3 -c "import fastapi" 2>/dev/null || MISSING="$MISSING fastapi"
python3 -c "import uvicorn" 2>/dev/null || MISSING="$MISSING uvicorn"
python3 -c "import claude_agent_sdk" 2>/dev/null || MISSING="$MISSING claude-agent-sdk"

if [ -n "$MISSING" ]; then
    warn "Missing packages:$MISSING"
    echo ""
    read -rp "Install missing Python packages now? [Y/n] " yn
    yn="${yn:-Y}"
    if [[ "$yn" =~ ^[Yy] ]]; then
        echo "  Running: pip install -e ."
        pip install -e .
        echo ""
        ok "Python dependencies installed."
    else
        warn "Skipping package installation."
        echo "  You can install manually later: pip install -e ."
    fi
else
    ok "All Python packages installed."
fi

# ──────────────────────────────────────────────
# Step 4: Check Docker and start Web UI
# ──────────────────────────────────────────────
echo ""
echo "─────────────────────────────────────────────"
info "Step 4/4: Checking Docker container..."
echo ""

if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^afl$"; then
    ok "AFL++ container 'afl' is running"
elif docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q "^afl$"; then
    warn "Container 'afl' exists but is not running."
    read -rp "Start it now? [Y/n] " yn
    yn="${yn:-Y}"
    if [[ "$yn" =~ ^[Yy] ]]; then
        docker start afl
        ok "Container started"
    fi
else
    warn "Container 'afl' does not exist."
    read -rp "Create and start container with 'docker compose up -d'? [Y/n] " yn
    yn="${yn:-Y}"
    if [[ "$yn" =~ ^[Yy] ]]; then
        docker compose up -d
        ok "Container started"
    else
        warn "Container not started. Web UI may not work correctly."
    fi
fi

echo ""
echo "─────────────────────────────────────────────"
info "Starting Web UI..."
echo ""
echo "  ${GREEN}http://localhost:8765${NC}"
echo ""

read -rp "Launch Web UI now? [Y/n] " yn
yn="${yn:-Y}"
if [[ "$yn" =~ ^[Yy] ]]; then
    echo ""
    python -m pipeline.webui
else
    echo ""
    echo "  You can start manually later:"
    echo "    cd ${SCRIPT_DIR}"
    echo "    python -m pipeline.webui"
    echo "    → http://localhost:8765"
    echo ""
fi
