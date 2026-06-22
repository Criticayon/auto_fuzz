---
name: auto-fuzz
description: "Automated AFL++ vulnerability discovery workflow for open-source projects. Trigger when user asks to fuzz a project, find bugs, do vulnerability discovery, 漏洞挖掘, or similar security testing of a target application."
license: Apache-2.0
compatibility: "Linux (primary), macOS, Windows (WSL). Requires AFL++ installed and in PATH."
metadata:
  version: "2.0"
---

# Auto-Fuzz: Automated AFL++ Vulnerability Discovery

An automated fuzzing pre-processor. Given a target project, this skill compiles it with AFL++ instrumentation, analyzes source code to design targeted fuzzing strategies, generates seed corpora, and produces a fuzz_manifest.json defining all strategies.

---

## Workflow Overview

```
Phase 1: Compile         → Build target with AFL++ + sanitizers
Phase 2: Load Analysis   → Read 4 analysis files from program-analysis skill
Phase 3: Strategy Design → Convert command combos → fuzz strategies, priority by vuln score
Phase 4: Corpus Gen      → Extract seeds from tests / generate minimal corpus, output fuzz_manifest.json
```

---

## Phase 1: Compile the Target

### Setup: directory layout (container)

In the container, project source and fuzz outputs are in **separate directories**:

```
/workspace/
├── <project-dir>/       # cloned target project (e.g. libjpeg-turbo)
│   └── ...              # BUILD here — cmake, make all happen inside this tree
└── fuzz_<project-dir>/  # fuzz workspace
    ├── seeds/           # seed corpora
    ├── out_<strategy>/  # fuzz output dirs
    ├── all_crashes/
    └── reports/
```

**Rules:**
- **Build (`cmake`, `make`, `./configure`)** → always inside `/workspace/<project-dir>/`
- **Fuzz outputs (`out_*`, `seeds/`, reports)** → always under `/workspace/fuzz_<project-dir>/`
- Never create build artifacts under the fuzz workspace, and never put fuzz outputs in the project source tree.

Set the project directory name (absolute path):

```bash
# IMPORTANT: set this before all subsequent commands
PROJ="/workspace/<project-dir-name>"  # e.g. PROJ="/workspace/libjpeg-turbo"
```

All subsequent commands use `$PROJ/` to reference project files and binaries.

---

### Install build dependencies on demand

Don't pre-install anything. Try compiling first. If `./configure`, `cmake`, or `make` fails with `header not found` / `library not found`, install the specific missing package and retry:

```bash
# Identify the missing package and install it
apt-get install -y -qq <package-name> 2>/dev/null || \
  (apt-get update -qq && apt-get install -y -qq <package-name>)
```

---

### Determine the build system

### Autotools (./configure)

ASAN 构建用 `afl-clang-fast`（LTO + ASAN 容易链接冲突）：
```bash
cd "$PROJ"
AFL_USE_ASAN=1 CC=afl-clang-fast CXX=afl-clang-fast++ ./configure --disable-shared --enable-static --disable-werror
make -j"$(nproc)"
cd ..
```

### CMake

ASAN 构建用 `afl-clang-fast`：
```bash
cd "$PROJ"
mkdir -p build_afl && cd build_afl
AFL_USE_ASAN=1 CC=afl-clang-fast CXX=afl-clang-fast++ cmake .. -DCMAKE_BUILD_TYPE=Debug -DBUILD_SHARED_LIBS=OFF
make -j"$(nproc)"
cd ../..
```

### Meson

ASAN 构建用 `afl-clang-fast`：
```bash
cd "$PROJ"
AFL_USE_ASAN=1 CC=afl-clang-fast CXX=afl-clang-fast++ meson setup build_afl -Ddefault_library=static --buildtype=debug
ninja -C build_afl
cd ..
```

### Plain Makefile

ASAN 构建用 `afl-clang-fast`：
```bash
cd "$PROJ"
AFL_USE_ASAN=1 CC=afl-clang-fast CXX=afl-clang-fast++ AFL_HARDEN=1 make -j"$(nproc)"
cd ..
```

### CMPLOG build (for Redqueen, highly recommended)

Since CMPLOG builds also use ASAN, use `afl-clang-fast` (LTO + ASAN 容易链接冲突):

```bash
cd "$PROJ"
AFL_LLVM_CMPLOG=1 AFL_USE_ASAN=1 CC=afl-clang-fast CXX=afl-clang-fast++ ./configure --disable-shared
make -j"$(nproc)"
cd ..
# Place the binary at a distinct path, e.g. `$PROJ/target_cmplog`
```

**Rules:**
- **ASAN is always on** (`AFL_USE_ASAN=1`) for all builds — including CMPLOG variants.
- **ASAN 必须搭配 `afl-clang-fast` 使用**，不要用 `afl-clang-lto`（LTO + ASAN 容易链接冲突，且模型会错误地调高内存去解决）。fuzz 主二进制和 CMPLOG 二进制都用 `afl-clang-fast`。
- 如果项目支持且无冲突，可额外用 `afl-clang-lto` 编译一个**无 ASAN** 的二进制，用于 CMPLOG 的 Redqueen 辅助（`-c` 参数），此时不加 `AFL_USE_ASAN=1`。
- Prefer static linking (`--disable-shared`, `BUILD_SHARED_LIBS=OFF`) to avoid missing instrumented libraries.
- If ASAN overhead causes extreme slowdown, increase `-t` timeout rather than disabling ASAN.

### Important: Handle ASAN virtual memory issue

AFL++ 启动时可能会遇到两种 ASAN 虚拟内存相关的情况：

#### 情况 1：非致命警告（可忽略）

AFL++ 打印警告但 fork server 正常启动：

```
The AFL++ binary needs too much virtual memory for afl-fuzz.
```

原因：
- ASAN 的虚拟内存映射大（shadow memory 预留），但**实际物理内存消耗并不高**。
- 只要用了 `-m 4096` 就足够，程序不会 crash 在 ASAN 内存限制上。
- **如果因此切换到无 ASAN 的 fuzz 二进制，漏洞检测能力会大幅下降**（ASAN 能检测 heap-buffer-overflow、use-after-free、stack-buffer-overflow 等大量内存错误，覆盖率远超 AFL++ 自身）。
- 正确的做法：无视该警告，继续用 ASAN 二进制 fuzz。如果 exec speed 太慢，加 `-t` 超时时间即可。

#### 情况 2：fork server 崩溃（需要 AFL_NO_FORKSRV=1）

ASAN 的 shadow memory 需要约 20TB 虚拟地址空间映射（mmap）。在某些配置下，AFL++ 的 fork server 会因虚拟地址空间不足而**直接崩溃**（不是警告），表现为：

```
Fork server crash: mmap() failed
或
afl-fuzz 启动后立即报错退出
```

解决方案：设置环境变量 `AFL_NO_FORKSRV=1`，让 AFL++ 绕过 fork server，每次执行直接 fork：

```bash
AFL_NO_FORKSRV=1 afl-fuzz -i seeds -o out_default -m 4096 -t 10000 -- ./target @@
```

`AFL_NO_FORKSRV=1` 的代价是每次执行都重新 fork（而不是从 fork server 快照克隆），exec speed 会下降约 10-20%，但**这是兼容 ASAN 的正确方式**。

> **⛔ 记住 HARD RULE：任何时候都禁止用 `-m none` 来绕过这个问题。只能用 `AFL_NO_FORKSRV=1`，且必须保持 `-m 4096` 不变。如果加了 `AFL_NO_FORKSRV=1` 后目标仍然内存超限，则去掉 ASAN 重新编译，不要用 `-m none`。**

### Compiler Selection Guide

| 编译器 | 说明 | 推荐 |
|--------|------|------|
| `afl-clang-fast` / `afl-clang-fast++` | LLVM instrumentation，兼容性好 | ⭐ **ASAN 首选** |
| `afl-clang-lto` / `afl-clang-lto++` | LLVM LTO 模式，覆盖率精度最高、性能最好 | ⭐ 无 ASAN 时首选 |
| `afl-gcc-fast` / `afl-gcc-fast++` | GCC plugin 模式 | GCC-only 项目用 |
| `afl-cc` / `afl-c++` | 自动 wrapper，自动选择 backend | 通用入口/兜底 |

**推荐顺序：**
1. **ASAN 构建** → 用 `afl-clang-fast` / `afl-clang-fast++`（避免 LTO + ASAN 链接冲突）
2. **无 ASAN 构建**（如纯 CMPLOG 辅助二进制）→ 用 `afl-clang-lto` / `afl-clang-lto++` 获得最佳覆盖率
3. GCC-only 项目 → 用 `afl-gcc-fast` / `afl-gcc-fast++`
4. 最后兜底 → `afl-cc` / `afl-c++`

### Record target metadata

After the build succeeds, record the project's version info for later reports:

```bash
# Save commit hash and version info
cd "$PROJ"
COMMIT_HASH=$(git rev-parse HEAD 2>/dev/null || echo "N/A")
PROJECT_VERSION=$(git describe --tags 2>/dev/null || git describe --always 2>/dev/null || echo "N/A")
REPORT_DATE=$(date +%Y-%m-%d)
cd ..

cat > target_metadata.sh <<- METADATA
PROJ="${PROJ}"
COMMIT_HASH="${COMMIT_HASH}"
PROJECT_VERSION="${PROJECT_VERSION}"
REPORT_DATE="${REPORT_DATE}"
METADATA

echo "Target: ${PROJECT_VERSION} (${COMMIT_HASH}), date: ${REPORT_DATE}"
```

These variables will be sourced in later phases for report generation.

---

## Phase 2: Load Program Analysis Output

先确认同文件夹下存在 program-analysis-skill 生成的 4 个分析文件：

| 文件 | 用途 |
|------|------|
| `command_combinations.json` | 所有合法的 CLI 命令组合 |
| `vulnerability_path_scores.md` | 按漏洞分数排序的命令组合排名 |
| `call_tree.md` | 调用链树 |
| `coverage_summary.md` | 逐函数覆盖率标注 |

```bash
for f in command_combinations.json vulnerability_path_scores.md call_tree.md coverage_summary.md; do
  if [ ! -f "$f" ]; then
    echo "缺少 $f — 请先运行 program-analysis-skill"
    exit 1
  fi
done
```

从 `command_combinations.json` 提取各组合的 command 和 action，从 `vulnerability_path_scores.md` 获取优先级排序。

---

## Phase 3: Fuzzing Strategy Design

结合 Phase 2 加载的分析结果和以下通用原则设计策略。

### 从 command_combinations.json 构建策略

将每个命令组合中的输入文件占位符替换为 AFL 的 `@@`，辅助文件保留原路径。

| 分析输出的命令 | → | Fuzz 命令 |
|---------------|----|-----------|
| `["prog", "-V", "-m", "<file>", "-p", "<pub>"]` | → | `afl-fuzz ... -- ./prog -V -m @@ -p <pub>` |
| `["prog", "-S", "-m", "<file>"]` | → | `afl-fuzz ... -- ./prog -S -m @@` |

按 `vulnerability_path_scores.md` 的分数排序确定优先级，高分组合优先 fuzz、给更多实例。

### 策略选择原则：工具全覆盖

**首要目标：覆盖项目中所有不同的 CLI 工具/入口点**，而不是只 Fuzz 分数最高的几个组合。

例如 Graphviz 有 20 个 CLI 工具（dot、neato、twopi、gvpr、unflatten...），策略应尽量覆盖不同的工具。同一工具的不同参数组合里再按分数选最优的。

选择流程：
1. 从 `command_combinations.json` 的 `tools[]` 数组遍历，每个 tool 对象自带 `combinations[]`
2. 每个工具选**分数最高的 1 个组合**作为代表策略
3. 剩余策略槽位（见下方 Maximum 限制）再从所有工具中按分数补全

（如果vulnerability_path_scores.md没有对应命令分数也需要进行尝试，这不是一个紧急的任务，我们希望的是覆盖尽可能高有助于挖出漏洞）

### Strategy design principles

| Code Pattern Found | Likely Function | Fuzzing Strategy |
|---|---|---|
| JPEG/PNG decoder | `read_jpeg()`, `decode_png()` | Fuzz with `--format=jpeg @@` using image seeds |
| XML/JSON/INI parser | `parse_config()`, `load_config()` | Fuzz config file via `--config @@` |
| Network protocol handler | `handle_packet()`, `process_msg()` | Fuzz binary input via `@@` |
| Expression evaluator | `eval()`, `exec_expression()` | Fuzz with `--eval @@` subcommand |
| Template engine | `render()`, `compile_template()` | Fuzz with `--template @@` flag |
| Compression codec | `compress()` / `decompress()` | Fuzz both `compress @@` and `decompress @@` |
| Multiple format support | `read_image()` dispatching by type | One strategy per format |
| CMPLOG variant | — | Add a CMPLOG strategy for magic byte bypass |

**Rules:**
- **First pass:** cover each distinct CLI tool/entry point with at least one strategy.
- **Second pass:** fill remaining slots by vulnerability score (highest first).
- Include a **CMPLOG strategy** whenever a CMPLOG binary was built. Apply it to the highest-prio tool.
- Maximum **5–8 strategies** total to fit within the 1-week campaign window.
- Vary power schedules (`-p`) across strategies: `explore`, `rare`, `fast`, `coe`.
- Different strategies that need different seed formats should use different seed directories.

### Generate Fuzz Command Manifest

**必须**直接从 `command_combinations.json` 和 `vulnerability_path_scores.md` 映射生成。manifest 中的每条策略对应 analysis 中的一个组合，禁止凭空编造。

映射规则：

| 分析文件 | manifest 字段 |
|---------|--------------|
| `command_combinations.json` 中的 `command` | 将输入文件替换为 `@@`，其余不变，拼成完整 afl-fuzz 命令 |
| `vulnerability_path_scores.md` 中的排名 | 按分数从高到低排序，写入 `batch_size: 4` 分批 |
| `vulnerability_path_scores.md` 中的 `Rank N: xxx (id=M)` | `name` = 组合名，`id` = 组合编号 |

```bash
# 从 analysis 文件逐条映射，禁止自创内容
# 例如 command_combinations.json 中有条目:
#   {"id": 5, "command": ["uncrustify", "-c", "CFG", "-f", "FILE", "-o", "OUT", "-p", "DUMP", "-ds", "STEPS", "-l", "CPP", "--set", "indent_width=4"]}
#  vulnerability_path_scores.md 中对应:
#   "Rank 1: Single file + full debug (id=5) — Score: 78"
#
# 映射为 manifest 条目:
#   "id": 5
#   "name": "single_file_full_debug"
#   "command": "afl-fuzz -M main -i seeds -o out_id5 -m 4096 -t 10000 -p explore -- $PROJ/uncrustify -c CFG -f @@ -o /dev/null -p /dev/null"
#   "vuln_score": 78
#   "priority": "critical"

cat > fuzz_manifest.json << 'EOF'
{
  "batch_size": 4,
  "strategies": [
    {
      "id": 5,
      "name": "single_file_full_debug",
      "command": "afl-fuzz ... -- $PROJ/target -c CFG -f @@ -o OUT -p DUMP",
      "vuln_score": 78,
      "priority": "critical",
      "desc": "从 analysis Rank 1 映射"
    },
    {
      "id": 9,
      "name": "check_mode",
      "command": "afl-fuzz ... -- $PROJ/target -c CFG -f @@ --check",
      "vuln_score": 63,
      "priority": "high",
      "desc": "从 analysis Rank 2 映射"
    }
  ]
}
EOF
```

---

## Phase 4: Corpus Generation

Source seed inputs in priority order:

### 4a. Extract from project tests (best)
```bash
# Find test input files (under $PROJ/)
find "$PROJ" -type f \( -name "*.txt" -o -name "*.bin" -o -name "*.dat" -o -name "*.xml" -o -name "*.json" -o -name "*.conf" \) -path "*/test*" 2>/dev/null
find "$PROJ" -type f \( -name "*.jpg" -o -name "*.png" -o -name "*.wav" -o -name "*.mp4" \) -path "*/test*" 2>/dev/null

# Copy candidate seeds (to seeds/ at parent level)
mkdir -p seeds
cp $(find "$PROJ" -type f -path "*/test*" -name "*.txt") seeds/ 2>/dev/null
```

### 4b. Generate minimal valid inputs manually
If no test data exists, create the smallest valid input for the target format. For example:
- Markdown/HTML parser: create a minimal valid document
- Config parser: create a minimal config file
- Image parser: create a small valid image (e.g. 1x1 pixel BMP/PNG)
- Network protocol: capture a sample exchange or craft a minimal valid packet

If a strategy from Phase 3 needs a **different seed format** (e.g. JPEG seeds for a JPEG decode strategy), create a separate seed directory for it (e.g. `seeds_jpeg/`).

**IMPORTANT: Different file extensions = different format = separate seed directories. For example: `seeds_dot/` for `.dot/.gv`, `seeds_gml/` for `.gml`, `seeds_emf/` for `.emf`. Do NOT mix extensions in one dir.**

### 4c. Deduplicate and minimize corpus
```bash
mkdir -p seeds_min
afl-cmin -i seeds -o seeds_min -- $PROJ/target @@
```
If `afl-cmin` produces empty output (all seeds crash or fail), fall back to using raw seeds without minimization — the target may need valid inputs to function.

### 4d. Create dictionary (optional but powerful)
If the format has keywords, structure tokens, or magic bytes, create a dictionary file:
```bash
# afl++ dictionary format:
# keyword="value"
echo -e 'magic="\\x00\\x01"' > target.dict
echo 'header="<html>"' >> target.dict
```

The skill ends after Phase 4 with a completed `fuzz_manifest.json` in the fuzz workspace.

## Trigger Examples

When user says any of these, activate this skill:
- "Fuzz project X to find vulnerabilities"
- "帮我挖一下 X 的漏洞"
- "Run AFL on repository X"
- "Do vulnerability discovery on X"
- "Automated fuzzing of X"
- "Security testing for X"
- "Find bugs in X using fuzz testing"
