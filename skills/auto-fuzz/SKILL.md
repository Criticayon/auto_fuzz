---
name: auto-fuzz
description: "Automated AFL++ vulnerability discovery workflow for open-source projects. Trigger when user asks to fuzz a project, find bugs, do vulnerability discovery, 漏洞挖掘, or similar security testing of a target application."
license: Apache-2.0
compatibility: "Linux (primary), macOS, Windows (WSL). Requires AFL++ installed and in PATH."
metadata:
  version: "2.0"
---

# Auto-Fuzz: Automated AFL++ Vulnerability Discovery

An automated end-to-end fuzzing workflow. Given a target project, this skill compiles it with AFL++ instrumentation, analyzes source code to design targeted fuzzing strategies, generates seed corpora, runs parallel multi-strategy fuzzing campaigns with stagnation detection, and produces crash triage results.

---

## Workflow Overview

```
Phase 1: Compile         → Build target with AFL++ + sanitizers
Phase 2: Load Analysis   → Read 4 analysis files from program-analysis skill
Phase 3: Strategy Design → Convert command combos → fuzz strategies, priority by vuln score
Phase 4: Corpus Gen      → Extract seeds from tests / generate minimal corpus
Phase 5: Campaign        → Run strategies in batches of 3-4 in parallel, each in own output dir
Phase 6: Cleanup         → Stop all afl-fuzz for this project, signal completion
```

### ⏰ Deadline Awareness

The pipeline passes a **deadline** in the prompt (e.g., "Total fuzzing deadline: 24.0 hours from now"). You must:

1. **Plan backwards from the deadline.** Estimate time needed for: compilation → strategy design → corpus gen → campaign → cleanup.
2. **Reserve the last 5 minutes** for cleanup: stopping afl-fuzz processes and signaling completion.
3. **If you run out of time**, skip remaining batches and proceed directly to Phase 6 (Cleanup). Do NOT leave afl-fuzz processes running.
4. **Track elapsed time** periodically during the campaign phase. If you're approaching the deadline, stop fuzzing and clean up.

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

If `./configure` doesn't exist (e.g. git clone with only `configure.ac`), generate it first:
```bash
cd "$PROJ"
autoreconf -fi
cd ..
```

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

然后**将实际使用的 ASAN 编译命令记录到 target_metadata.sh**，供后续 crash-reporter / issue-generator 使用：

```bash
cat >> target_metadata.sh <<- 'BUILDCMD'

# Build commands used for ASAN crash reproduction
BUILD_CMD='AFL_USE_ASAN=1 CC=afl-clang-fast CXX=afl-clang-fast++ cmake .. -DCMAKE_C_COMPILER=afl-clang-fast -DCMAKE_CXX_COMPILER=afl-clang-fast++ && make -j$(nproc)'
BUILDCMD
```

> 根据实际项目的编译命令调整 BUILD_CMD 的值。如果项目用 autotools（./configure），对应改为 `AFL_USE_ASAN=1 CC=afl-clang-fast CXX=afl-clang-fast++ ./configure --disable-shared ... && make -j$(nproc)`。
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

从 `command_combinations.json` 提取各组合的 command 和 action，从 `vulnerability_path_scores.md` 获取漏洞分数（Vuln. Score）和预期覆盖率（Est. Coverage）用于优先级排序和 manifest 生成。

---

## Phase 3: Fuzzing Strategy Design

### ⚠️ 你必须按以下步骤严格执行，不能跳过任何一步

**Step 1 — 用 bash 写 `fuzz_tool_list.md`（必须先做，容器 + 宿主机双写）**

用 bash（container_exec）读取 `vulnerability_path_scores.md`，提取所有 `## Tool N: xxx` 标题中的工具名及其 Rank/Score。先写入容器，再用 Write 工具写入宿主机：

```bash
# 写入容器（fuzz workspace 目录）
cat > /workspace/fuzz_<project>/fuzz_tool_list.md << 'EOF'
# Tools to cover
- Tool 1: <name> — Rank 1 (score: N), Rank 2 (score: M), ...
- Tool 2: <name> — Rank 1 (score: N) → 全部 < 20, skip
- Tool 3: <name> — Rank 1 (score: N), Rank 2 (score: M), ...
EOF
cat /workspace/fuzz_<project>/fuzz_tool_list.md
```

然后再用 Write 工具（或宿主机 bash）写入 **宿主机当前目录**（即 pipeline 的工作目录，./fuzz_tool_list.md）。

**此文件必须覆盖 vulnerability_path_scores.md 中所有的工具，每个工具至少出现一次，一个都不能少。**

**Step 2 — 遍历 `fuzz_tool_list.md` 生成策略**

逐工具、逐 Rank 遍历。对每个 score ≥ 20 的 Rank，生成一条独立策略。同一个工具的多个 Rank 产出多条独立策略，不允许合并。

**禁止在生成策略前自行测试工具是否能运行。** 所有工具统一使用 `TERM=xterm-256color` + `AFL_NO_FORKSRV=1` 处理终端依赖问题，不需要提前测试。

**Step 3 — 用 bash 写 `manifest_selfcheck.md`（容器 + 宿主机双写）**

生成 manifest 后，立即先写入容器，再用 Write 工具写入宿主机。**如果有任何 score ≥ 20 的 Rank 没有被包含在 manifest 中，必须在"Excluded Reason"列说明原因。不允许无故跳过。**

**可被接受的排除理由：**
- 该组合所有参数都是内部路径/输出路径，没有可替换为 `@@` 的文件输入参数
- 该组合需要**多个文件参数**（如 `tool file1 file2 file3`），AFL 的 `@@` 只支持单个文件输入，wrapper 脚本会增加复杂度且收益有限
- 该组合属于 help/version 等无需 fuzz 的 mode
- command_combinations.json 中没有该工具的可 fuzz 条目

```bash
# 写入容器
cat > /workspace/fuzz_<project>/manifest_selfcheck.md << 'EOF'
# Manifest Self-Check

## Tool 1: <name>
| Rank | Score | In Manifest? | Command Complete? | Params Match? | Excluded Reason |
|------|-------|-------------|-------------------|---------------|-----------------|
| 1 | 82 | ✅ id:xxx | ✅ | ✅ | — |
| 2 | 55 | ✅ id:yyy | ✅ | ✅ | — |
| 3 | 20 | ❌ 遗漏 | — | — | 该组合无文件输入参数，所有参数为内部路径 |

## Tool 2: <name>
| Rank | Score | In Manifest? | Command Complete? | Params Match? | Excluded Reason |
|------|-------|-------------|-------------------|---------------|-----------------|
| 1 | 22 | ✅ id:zzz | ✅ | ✅ | — |

---

**汇总：**
- 工具覆盖：N/M （score ≥ 20 的工具应有策略数 / 实际策略数）
- 被排除的工具/组合：列出原因
- 命令参数完整性：抽查 N 条，全部完整 ✅
EOF
cat /workspace/fuzz_<project>/manifest_selfcheck.md
```

再用 Write 工具（或宿主机 bash）写入 **宿主机当前目录**（./manifest_selfcheck.md）。

**如果发现遗漏，必须补上。不允许跳过此步骤。**

---

### 策略参数规则

manifest 的 `command` 字段必须保留 vulnerability_path_scores.md 中该组合的**所有参数**。其余**一个不能少，一个不能改**。

**文件参数替换规则：**
- **输入文件**（被 fuzz 的那个）→ 替换为 `@@`
- **输出文件**（如 `-o`, `>` 重定向目标）→ 替换为 `/dev/null`
- **非 fuzz 的输入文件**（工具需要读取的额外输入文件）→ **禁止使用 `/dev/null`**，改为指向 seeds 目录下的一个有效种子文件，如 `seeds/seed_01.json`

> 注意：如果目标同时有 `@@` 位置和其他输入文件参数（如 jq 的 `-f <filter>` + `<json_file>`），非 `@@` 的输入文件要用真实种子文件代替，不能填 `/dev/null`，否则该路径的代码永远无法被覆盖到。

**常见错误：模型倾向"简化"命令，丢掉看似"不重要"的 flag。这是不允许的。**

```
错误 1（丢掉 flag）：
  analysis:  <tool> -a -b -c -d <path>
  manifest:  <tool> @@                      ← 丢了 -a -b -c -d，完全改变了行为

错误 2（丢掉文件路径参数）：
  analysis:  <tool> -s <mode> -b <fmt> -n -a <hex> -d <float> <file>
  manifest:  <tool> @@                  ← 丢了 -s -b -n -a -d，只测了默认路径

错误 3（只留了工具名，丢掉所有选项）：
  analysis:  <tool> -c -k -l <N> -d <float> -p <path> -J <out> <arg>
  manifest:  <tool> @@            ← 所有选项都没了！

错误 4（非 fuzz 输入文件填 /dev/null）：
  analysis:  <tool> -f <filter_file> --name 'val' <input_file>
  manifest:  <tool> -f @@ --name 'val' /dev/null   ← ❌ input_file 是输入文件，不能用 /dev/null
  正确:      <tool> -f @@ --name 'val' seeds/sample.ext  ← ✅ 用真实种子文件
```

### 分数→优先级映射规则

priority 字段必须按 vuln_score 严格映射，不能随意填写：

| vuln_score 范围 | priority |
|----------------|----------|
| ≥ 80 | critical |
| ≥ 60 | high |
| ≥ 40 | medium |
| ≥ 20 | low |
| < 20 | 不生成策略 |

**示例：**
- score 82 → `"priority": "critical"`
- score 72 → `"priority": "high"`
- score 55 → `"priority": "medium"`（不是 critical！）
- score 22 → `"priority": "low"`

### Generate Fuzz Command Manifest

**必须**直接从 `command_combinations.json` 和 `vulnerability_path_scores.md` 映射生成。manifest 中的每条策略对应 analysis 中的一个组合，禁止凭空编造。

每条策略是一个独立对象，放在 `strategies[]` 数组中。**不允许用 `secondary_commands` 或类似字段把多个策略合并到一条里。**

**manifest 的条目数量 = score ≥ 20 的 Rank 总数。** 如果 vulnerability_path_scores.md 中有 12 个 Rank ≥ 20，manifest 必须有 12 条策略。

manifest JSON 语法参考（仅展示结构，条目数量根据实际 analysis 决定）：

```json
{
  "batch_size": 4,
  "strategies": [
    {
      "id": "<tool>_<variant>",
      "name": "<tool>_<variant>",
      "analysis_tool": "<tool>",
      "analysis_id": <N>,
      "vuln_score": <score>,
      "expected_cvg": <score>,
      "priority": "<critical|high|medium|low>",
      "command": "AFL_NO_FORKSRV=1 TERM=xterm-256color afl-fuzz ... -- /workspace/<proj>/build_afl/<tool> <params> @@",
      "cmplog_binary": "/workspace/<proj>/build_cmplog/<tool>",
      "seeds_dir": "seeds_<format>",
      "desc": "从 analysis Rank N (score N) 映射: <原始命令>"
    }
  ]
}
```

After generating `fuzz_manifest.json`, create the expected_cvg lookup table used during monitoring:

```bash
# Create expected_cvg mapping for monitoring (name=expected_cvg)
jq -r '.strategies[] | "\(.name)=\(.expected_cvg)"' fuzz_manifest.json > /tmp/expected_cvg_map.txt
cat /tmp/expected_cvg_map.txt
```

如果没有 CMPLOG 二进制，就不填 `cmplog_binary` 字段。

**再次确认：如果在 Step 3 自检中发现遗漏，必须回头补上，不能跳过。**

---

## Phase 4: Corpus Generation

### 4a. Use Phase 1 seeds if available (优先)

Phase 1 的 program-analysis skill 可能已经为各策略生成了定制种子，存放在 `seeds_prebuilt/` 目录下。先检查并优先使用这些种子：

```bash
# 检查是否有 Phase 1 预生成的种子
if [ -d "seeds_prebuilt" ] && [ "$(ls -A seeds_prebuilt/ 2>/dev/null)" ]; then
  echo "=== Using Phase 1 prebuilt seeds ==="
  ls -la seeds_prebuilt/*/

  # 遍历 manifest 中的每个策略，为它匹配最合适的 Phase 1 种子目录
  for strategy in $(python3 -c "
import json
m = json.load(open('fuzz_manifest.json'))
for s in m['strategies']:
    print(f\"{s['seeds_dir']}|{s.get('name','')}\")
"); do
    sd=$(echo "$strategy" | cut -d'|' -f1)
    name=$(echo "$strategy" | cut -d'|' -f2)
    # 如果该策略的 seeds_dir 尚未创建，从 seeds_prebuilt 中查找匹配的种子
    if [ ! -d "$sd" ] || [ -z "$(ls -A "$sd" 2>/dev/null)" ]; then
      # 尝试按 combo_id、工具名等匹配
      matched=$(find seeds_prebuilt -maxdepth 1 -type d -name "*${name}*" -o -name "*${sd}*" 2>/dev/null | head -1)
      if [ -n "$matched" ] && [ -d "$matched" ]; then
        mkdir -p "$sd"
        cp -r "$matched"/* "$sd/"
        echo "  $name: using Phase 1 seeds from $matched"
      else
        echo "  $name: no matching Phase 1 seeds, will generate later"
      fi
    fi
  done
else
  echo "=== No Phase 1 prebuilt seeds found, generating from scratch ==="
fi
```

如果 `seeds_prebuilt/` 中存在匹配的种子，就优先用它们。对于没有匹配种子的策略，继续用下面的常规方法生成。

### 4b. Extract from project tests (best)

Source seed inputs in priority order:
```bash
# Find test input files (under $PROJ/)
find "$PROJ" -type f \( -name "*.txt" -o -name "*.bin" -o -name "*.dat" -o -name "*.xml" -o -name "*.json" -o -name "*.conf" \) -path "*/test*" 2>/dev/null
find "$PROJ" -type f \( -name "*.jpg" -o -name "*.png" -o -name "*.wav" -o -name "*.mp4" \) -path "*/test*" 2>/dev/null

# Copy candidate seeds (to seeds/ at parent level)
mkdir -p seeds
cp $(find "$PROJ" -type f -path "*/test*" -name "*.txt") seeds/ 2>/dev/null
```

### 4c. Generate minimal valid inputs manually
If no test data exists, create the smallest valid input for the target format. For example:
- Markdown/HTML parser: create a minimal valid document
- Config parser: create a minimal config file
- Image parser: create a small valid image (e.g. 1x1 pixel BMP/PNG)
- Network protocol: capture a sample exchange or craft a minimal valid packet

If a strategy from Phase 3 needs a **different seed format** (e.g. JPEG seeds for a JPEG decode strategy), create a separate seed directory for it (e.g. `seeds_jpeg/`).

### 4d. Deduplicate and minimize corpus
```bash
mkdir -p seeds_min
afl-cmin -i seeds -o seeds_min -- $PROJ/target @@
```
If `afl-cmin` produces empty output (all seeds crash or fail), fall back to using raw seeds without minimization — the target may need valid inputs to function.

**注意：`afl-cmin` 必须用非 ASAN 二进制。** ASAN 的 shadow memory (~20TB 虚拟地址) 与 `-m 4096` 冲突会导致 fork server 卡死。如果有 `build_noasan` 目录，用那里的二进制：
```bash
afl-cmin -i seeds -o seeds_min -m 4096 -t 15000 -- $PROJ/build_noasan/src/target @@
```
如果没有非 ASAN 二进制，跳过 afl-cmin 直接使用原始种子。

### 4e. Create dictionary (optional but powerful)
If the format has keywords, structure tokens, or magic bytes, create a dictionary file:
```bash
# afl++ dictionary format:
# keyword="value"
echo -e 'magic="\\x00\\x01"' > target.dict
echo 'header="<html>"' >> target.dict
```

---

## Phase 5: Batched Parallel Fuzzing Campaign

Launch strategies from Phase 3 in **batches of 3–4** at a time — each in its own output directory. This balances coverage diversity with memory/CPU constraints. When a batch stagnates, harvest results and move to the next batch.

### ⛔ HARD RULE: Memory limit `-m` max 4096, never `none`

当你写 afl-fuzz 命令时，**`-m` 参数的值不能超过 4096，且绝对不能是 `none`**：

```
✅ 正确: afl-fuzz ... -m 4096 ... -- ./target @@
✅ 正确: afl-fuzz ... -m 1024 ... -- ./target @@
❌ 禁止: afl-fuzz ... -m none ... -- ./target @@
❌ 禁止: afl-fuzz ... -m 8192 ... -- ./target @@
```

任何时候都不允许使用 `-m none`。如果你发现 ASAN 的 fork server 崩溃（虚拟地址空间不足），**绝不要用 `-m none` 或提高 `-m` 超过 4096**，而是添加环境变量 `AFL_NO_FORKSRV=1`，保持 `-m` 在 4096 以内：

```
✅ 正确: AFL_NO_FORKSRV=1 afl-fuzz ... -m 4096 ... -- ./target @@
✅ 正确: AFL_NO_FORKSRV=1 afl-fuzz ... -m 1024 ... -- ./target @@
```

**如果加了 `AFL_NO_FORKSRV=1` 后目标仍然需要超过 4096 MB（例如处理大文件时 `mmap` 分配超限），说明 ASAN 的内存开销太大。此时不要用 `-m none`，而是去掉 ASAN 重新编译目标：**

```bash
# 去掉 ASAN 重新编译（保持 AFL++ 插桩）
cd "$PROJ"
make clean 2>/dev/null || true
CC=afl-clang-fast CXX=afl-clang-fast++ cmake .. -DCMAKE_BUILD_TYPE=Debug -DBUILD_SHARED_LIBS=OFF
make -j"$(nproc)"
```

去掉 ASAN 后虚拟内存占用大幅下降，`-m 4096` 即可正常运行。虽然失去 ASAN 的运行时检测，但总比用 `-m none` 导致 OOM 打满宿主机强。

违反这条规则的后果：`-m none` 会禁掉 AFL++ 的内存限制，如果目标程序有内存泄漏，会直接 OOM 打满宿主机，导致整个 fuzzing 任务被 kill。

### afl-fuzz Parameters Reference

| 参数 | 说明 |
|------|------|
| `-i <dir>` | 种子语料库目录 |
| `-o <dir>` | 输出目录（存放结果、崩溃、队列） |
| `-m <mb>` | 每个进程的内存上限（MB），`-m 4096` = 4GB |
| `-t <ms>` | 每个用例的超时时间（毫秒） |
| `-p <schedule>` | Power schedule 策略：`explore`/`fast`/`coe`/`rare`/`exploit`/`lin`/`quad`/`mmopt`/`seek` |
| `-c <file>` | CMPLOG 二进制路径，用于 Redqueen 破解 magic bytes |
| `-x <file>` | 字典文件，用于结构化 token 变异 |
| `@@` | AFL 占位符，fuzz 时替换为实际输入文件路径 |

**资源限制：** 见上方 ⛔ HARD RULE — `-m` 最大 4096，禁止 `none`。fork server 崩溃时加 `AFL_NO_FORKSRV=1` 而非提高 `-m`。

### 5a. Launch Strategies in Batches of 4

Use `fuzz_manifest.json` generated in Phase 3. Strategies are grouped into **batches of 4** by priority (highest scores first). Launch each batch simultaneously, one batch at a time.

```bash
# Load strategies from Phase 3 manifest
STRATEGIES=$(cat fuzz_manifest.json)

# Batch 1: first 4 strategies by priority
# Batch 2: next 4 strategies
```

Launch each batch as **background processes** and track their PIDs:

```bash
# Example — Batch 1 (3 instances), each in background with PID tracking（不同工具可能需要不同格式的输入）
nohup afl-fuzz -i seeds -o out_default -m 4096 -t 10000 -- $PROJ/target @@ > out_default/fuzz.log 2>&1 &
echo $! > out_default/pid

nohup afl-fuzz -i seeds -o out_debug -m 4096 -t 10000 -p rare -- $PROJ/target --debug @@ > out_debug/fuzz.log 2>&1 &
echo $! > out_debug/pid

nohup afl-fuzz -i seeds -o out_cmplog -m 4096 -t 10000 -c $PROJ/target_cmplog -x target.dict -- $PROJ/target @@ > out_cmplog/fuzz.log 2>&1 &
echo $! > out_cmplog/pid
```

**Rules:**
- **Max 3–4 instances per batch** to avoid OOM (if targets are memory-hungry, reduce to 2-3).
- **Never use `-m none`** — each instance limited to `-m 4096` max.
- Each instance **must** use a unique `-o` directory.
- Adjust `-t` timeout per strategy if a particular command is slower.
- Save PIDs for background processes: `echo $! > out_default/pid`.

### 5b. Monitoring All Instances

程序稳定运行不报错后，**每天检查一次即可**（节约资源和token）。但出现报错（如 AFL 崩溃、OOM、磁盘满、进程异常退出等）时，**必须立即呼出检查原因**。

Check **all strategy output dirs** to get the full picture:

```bash
# Summary across all strategies — include expected_cvg from manifest
for d in out_*/; do
  name=$(basename "$d")
  echo "=== $(basename $d) ==="
  grep -E "edge_found|unique_crashes|paths_total|exec_speed" "$d/fuzzer_stats" 2>/dev/null || echo "  (no stats)"
done
```

Key metrics:
- `edge_found` → primary coverage metric (unique edges discovered)
- `paths_total` → unique paths in queue
- `unique_crashes` → crashes found so far
- `exec_speed` → executions/sec (diagnostic — if too low, check for issues)

### 5c. Batch Stagnation & Advancing to Next Batch

Within a batch, each instance runs independently. **A batch is stagnated when all instances in it have no new `edge_found` for the last 12 hours.**

```bash
# Check all instances in the current batch (e.g. out_default, out_debug, out_cmplog)
for d in out_*/; do
  echo "$(basename $d): $(grep edge_found $d/fuzzer_stats 2>/dev/null)"
done
```

When the current batch stagnates **or** runs for over 24 hours:

1. **Stop all afl-fuzz instances in the current batch using saved PIDs:**
   ```bash
   for pidfile in out_*/pid; do
     [ -f "$pidfile" ] && kill $(cat "$pidfile") 2>/dev/null
   done
   sleep 2  # allow afl-fuzz to flush stats
   ```

2. **Collect crashes** from this batch:
   ```bash
   mkdir -p all_crashes
   for d in out_*/; do
     cp "$d/crashes/id:"* all_crashes/ 2>/dev/null
   done
   ```

3. **Record batch results** to `campaign_results.md`:
   ```bash
   source target_metadata.sh 2>/dev/null
   cat >> campaign_results.md << 'EOF'
   ### Batch 1 — default, debug, cmplog
   EOF
   for d in out_*/; do
     name=$(basename "$d")
     cov=$(grep "edge_found" "$d/fuzzer_stats" 2>/dev/null | cut -d: -f2 | tr -d ' ')
     crashes=$(grep "unique_crashes" "$d/fuzzer_stats" 2>/dev/null | cut -d: -f2 | tr -d ' ')
     echo "- ${name}: ${cov:-N/A} edges, ${crashes:-0} crashes" >> campaign_results.md
   done
   ```

4. **Clean up** the batch output dirs:
   ```bash
   rm -rf out_*/ queue/ .cur_input 2>/dev/null
   ```

5. **Load next batch** from `fuzz_strategies.json` and repeat from 5a.

### 5d. Termination

The campaign runs until the deadline approaches or all batches complete. Fuzzing outputs (out_*) remain in place for later crash analysis.

---

## Phase 6: Cleanup & Completion Signal

When the campaign ends (deadline reached or all batches done), **stop all afl-fuzz processes for this project**:

```bash
# Kill all afl-fuzz instances belonging to this project
ps aux | grep afl-fuzz | grep "$PROJ" | grep -v grep | awk '{print $2}' | xargs -r kill 2>/dev/null
sleep 2
# Force kill any remaining
ps aux | grep afl-fuzz | grep "$PROJ" | grep -v grep | awk '{print $2}' | xargs -r kill -9 2>/dev/null
```

After cleanup, signal completion with:

```text
[FUZZ_COMPLETE] project=$PROJ duration=<elapsed_time> batches=<N> status=<completed|deadline>
```

This signal tells the orchestrator the agent has finished and it's safe to proceed to the next pipeline phase.

## Trigger Examples

When user says any of these, activate this skill:
- "Fuzz project X to find vulnerabilities"
- "帮我挖一下 X 的漏洞"
- "Run AFL on repository X"
- "Do vulnerability discovery on X"
- "Automated fuzzing of X"
- "Security testing for X"
- "Find bugs in X using fuzz testing"
