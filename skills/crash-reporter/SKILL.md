---
name: crash-reporter
description: "Crash triage and ASAN report generation from AFL++ fuzzing output. Trigger when user needs to analyze fuzzing crashes, generate vulnerability reports, or produce SUMMARY.md."
license: Apache-2.0
compatibility: "Linux (primary), macOS, Windows (WSL). Requires AFL++ installed and in PATH."
metadata:
  version: "2.2"
---

# Crash Reporter: Triage & ASAN Report Generation

After an AFL++ fuzzing campaign completes, this skill collects crashes from all output directories, reproduces with ASAN, deduplicates by crash type (ASAN error + trigger function location), and saves each unique crash's PoC and reproduce script to a dedicated folder on the host.

---

## Phase 0: Build ASAN Binary for Crash Reproduction

Crash reproduction requires an ASAN-instrumented binary. First check if one already exists; only rebuild if needed.

### Step 1: Load project info

```bash
source target_metadata.sh
echo "PROJ=$PROJ BUILD_DIR=$BUILD_DIR COMMIT_HASH=$COMMIT_HASH PROG_VERSION=$PROG_VERSION"
```

### Step 2: Sync to latest commit via host

Before reproducing crashes, ensure the source code is at the latest upstream commit. A crash that was already fixed in a newer commit is not a valid vulnerability.

The **host** handles git operations because the container may not have proxy access:

```bash
# Step 2a: Git pull on HOST (use Bash tool, not container_exec)
# HOST_PROJECT is the original target path passed to the pipeline
HOST_PROJECT="<target_project_path>"
cd "$HOST_PROJECT"
git pull --ff-only 2>/dev/null || git pull 2>/dev/null || echo "[warn] git pull failed"
LATEST_HOST=$(git rev-parse HEAD 2>/dev/null || echo "unknown")
echo "Host latest commit: $LATEST_HOST"
```

```bash
# Step 2b: Check container version and sync if needed
# Use container_exec to check the container's current commit
container_commit=$(container_exec command="cd $PROJ && git rev-parse HEAD 2>/dev/null || echo 'N/A'" workdir="/workspace/fuzz_<project>")

if [ "$container_commit" != "$LATEST_HOST" ]; then
  echo "Container ($container_commit) != Host ($LATEST_HOST), syncing source..."
  # Copy host source to container (overwrite)
  container_exec command="rm -rf $PROJ && mkdir -p $PROJ" workdir="/tmp"
  # Use docker cp from the host to transfer files
  docker cp "$HOST_PROJECT/." "${CONTAINER_NAME}:${PROJ}/"
  echo "Source synced to container at $PROJ"

  # 源码变了，旧的 ASAN binary 必须重建
  echo "Source changed, ASAN binary must be rebuilt"
else
  echo "Container is up-to-date at $container_commit"
fi
```

### Step 3: Check for existing ASAN binary

Look for ASAN symbols in the existing binary. If available and has ASAN, skip the build:

```bash
# Check if existing binary has ASAN instrumentation
if [ -f "${PROJ}/build_afl/bin/gvpack" ] && nm "${PROJ}/build_afl/bin/gvpack" 2>/dev/null | grep -q __asan; then
  echo "ASAN binary already exists, skipping build"
  # Still record BUILD_CMD if not already set
else
  echo "No ASAN binary found, building..."
fi
```
Adjust the binary name (`gvpack` above is just an example) to match the actual target being analyzed.

### Step 4: Build with ASAN (if needed)

If no ASAN binary exists, rebuild. Use the same build system as the original project:

```bash
cd $PROJ
mkdir -p build_asan
cd build_asan

export AFL_USE_ASAN=1
CC=afl-clang-fast \
CXX=afl-clang-fast++ \
cmake .. \
  -DCMAKE_C_COMPILER=afl-clang-fast \
  -DCMAKE_CXX_COMPILER=afl-clang-fast++

make -j$(nproc)
```

> **重要:** 对于 cmake 项目，`-DCMAKE_C_COMPILER` 和 `-DCMAKE_CXX_COMPILER` 写入 CMakeCache.txt 后重新 cmake 时无需重复指定。但 `AFL_USE_ASAN=1` 环境变量必须每次都 export。

### Step 5: Record build commands

After ensuring an ASAN binary exists, save the exact build commands to `target_metadata.sh` so issue-generator can reference them:

```bash
# Append build commands to target_metadata.sh
cat >> target_metadata.sh << 'BUILDCMD'

# Build commands used for ASAN crash reproduction
BUILD_CMD='CC=afl-clang-fast CXX=afl-clang-fast++ cmake .. -DCMAKE_C_COMPILER=afl-clang-fast -DCMAKE_CXX_COMPILER=afl-clang-fast++ && make -j$(nproc)'
BUILDCMD
```

Fill in the exact cmake/configure command used. Include all flags and options. If the ASAN binary already existed and you skipped the rebuild, set `BUILD_CMD` to the command that was historically used.

**Rule:** The `BUILD_CMD` value must be a valid shell command string that can be pasted directly into an issue's Build Configuration section.

---

## Phase 1: Collect Crashes

---

## Workflow Overview

```
Phase 0: Sync & Build ASAN → Git pull to latest commit, rebuild target with ASAN, record build commands to target_metadata.sh
Phase 1: Collect Crashes  → Gather crash inputs from all out_*/crashes/
Phase 2: Reproduce & Dedupe → ASAN reproduce, dedup by (ASAN error type + src file:line), count instances in memory
Phase 3: Analyze & Save   → Full ASAN output per unique crash, save PoC + reproduce.sh with count comment
Phase 4: Summary          → Generate SUMMARY.md
```

---

## Phase 1: Collect Crashes

Collect crash inputs from all strategy output directories:

```bash
mkdir -p all_crashes
for d in out_*/; do
  cp "$d/crashes/id:"* all_crashes/ 2>/dev/null
done
echo "Total crashes collected: $(ls all_crashes/ 2>/dev/null | wc -l)"
```

If the output dirs are inside the Docker container, copy them to the host first. The fuzz output is at `/workspace/fuzz_<project_name>/`.

---

## Phase 2: Reproduce & Deduplicate (合并 + 计数)

**必须遍历 `all_crashes/` 中的每一个文件，一个都不能少。不采样、不停留、不跳过。** 对每个 crash 用 ASAN 复现，按 **(ASAN 错误类型 + 触发函数位置)** 去重。同一函数触发的同类型 ASAN 错误视为同一个漏洞，合并并计数。所有计数仅保存在内存中，不写额外文件：

```bash
mkdir -p crashes_dedup
declare -A seen_map       # key="error_type||file:line" → crash_count
declare -A instance_file  # key="error_type||file:line" → first crash file path

total_processed=0
for crash in all_crashes/*; do
  [ -f "$crash" ] || continue
  total_processed=$((total_processed + 1))
  asan_out=$(ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 ./target @@ < "$crash" 2>&1)

  # 提取 ASAN 错误类型 (heap-buffer-overflow, SEGV, use-after-free, ...)
  error_type=$(echo "$asan_out" | grep "ERROR:" | head -1 | sed 's/.*ERROR: //;s/ .*//;s/:.*//')
  [ -z "$error_type" ] && continue

  # 从堆栈中提取首个源文件位置 (file:line)
  src_loc=$(echo "$asan_out" | grep -Eo '#[0-9]+[[:space:]]+0x[0-9a-f]+[[:space:]]+in[[:space:]]+[^[:space:]]+[[:space:]]+([^[:space:]]+:[0-9]+)' | head -1 | grep -Eo '[^[:space:]]+:[0-9]+$')
  [ -z "$src_loc" ] && src_loc="unknown"

  key="$error_type||$src_loc"

  if [ -z "${seen_map[$key]}" ]; then
    seen_map[$key]=1
    instance_file[$key]="$crash"
  else
    seen_map[$key]=$((seen_map[$key] + 1))
  fi
done

# 将唯一 crash 复制到 crashes_dedup
total_unique=0
for key in "${!instance_file[@]}"; do
  crash="${instance_file[$key]}"
  count="${seen_map[$key]}"
  total_unique=$((total_unique + 1))
  fname=$(basename "$crash")
  cp "$crash" "crashes_dedup/${fname}"
done

echo "Total crash files processed: $total_processed"
echo "Unique ASAN crashes: $total_unique"
echo "(Dedup key: ASAN error type + source file:line)"

# 如果 processed 不等于 collected 数量，说明有遗漏，需要重新检查
echo "[VERIFY] Ensure total_processed == total_collected from Phase 1"
```

**去重逻辑说明：** 关键不是 ASAN 输出的文本差异，而是 **(1) 什么类型的错误** + **(2) 在哪个函数/哪行触发的**。如果两个 crash 都在 `gvpack.cpp:482` 触发了 `heap-buffer-overflow`，就是同一个 bug，合并为一个漏洞。

---

## Phase 3: Analyze & Save Unique Crashes to Host

对 Phase 2 去重后的每个唯一 crash，获取完整的 ASAN 输出。然后在宿主机创建对应目录。crash 计数保存在每个目录下的 `crash_count.txt`。

**额外输入文件处理**：某些目标程序在复现时需要多个输入文件（如 `./binary -c config.xml -d dict.txt input_file`）。在保存每个 crash 时：
1. 查看该 crash 对应策略的完整命令（从 `easy_fuzz_commands.json` 或上下文获取），确定 binary 的参数中哪些是文件路径
2. 将这些文件连同 poc 一起复制到 crash 目录
3. 生成 reproduce.sh 时使用正确的 flags 和本地文件名

基本脚本框架：

```bash
for crash in crashes_dedup/*; do
  [ -f "$crash" ] || continue
  fname=$(basename "$crash")

  # 重新跑 ASAN 获取完整输出和错误信息
  asan_out=$(ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 ./target @@ < "$crash" 2>&1)
  error_type=$(echo "$asan_out" | grep "ERROR:" | head -1 | sed 's/.*ERROR: //;s/ .*//;s/:.*//')
  src_loc=$(echo "$asan_out" | grep -Eo '#[0-9]+[[:space:]]+0x[0-9a-f]+[[:space:]]+in[[:space:]]+[^[:space:]]+[[:space:]]+([^[:space:]]+:[0-9]+)' | head -1 | grep -Eo '[^[:space:]]+:[0-9]+$')
  [ -z "$src_loc" ] && src_loc="unknown"

  # 查找内存中的 crash 计数（从 Phase 2 的关联数组获取）
  key="$error_type||$src_loc"
  crash_count="${seen_map[$key]}"
  [ -z "$crash_count" ] && crash_count=1

  # 映射为有意义的目录名
  dir_slug=$(echo "$error_type" | tr 'A-Z' 'a-z' | tr -c 'a-z0-9_' '_' | sed 's/_*$//')
  [ -z "$dir_slug" ] && dir_slug="crash_${fname}"

  mkdir -p "crashes/$dir_slug/"
  cp "$crash" "crashes/$dir_slug/poc"
  echo "$crash_count" > "crashes/$dir_slug/crash_count.txt"

  # ─── 写入 reproduce.sh ───
  # 确定正确的复现命令：
  #   - 如果只需单个文件输入：/path/to/binary @@ < poc
  #   - 如果需要 flags + 多个文件：/path/to/binary -c config.xml -d dict.txt poc
  #
  # 如果是多文件场景，需先将额外的文件 cp 到 crashes/$dir_slug/ 目录下，
  # 然后 reproduce.sh 中引用本地文件名。
  #
  # 写入 reproduce.sh（请将 /path/to/binary 替换为实际 binary 路径）：
  cat > "crashes/$dir_slug/reproduce.sh" << SCRIPT
#!/bin/bash
# Replace with the actual binary path and flags
/path/to/binary [FLAGS] poc
SCRIPT
  chmod +x "crashes/$dir_slug/reproduce.sh"
done
```

> **Important**: The `/path/to/binary` placeholder and `[FLAGS]` must be replaced with the actual binary path and flags determined from the original fuzz command. If there were additional input files (config, dictionary, etc.), copy them to `crashes/<type>/` and reference them in `reproduce.sh` by their local filenames.

示例：如果原命令是 `afl-fuzz -i seeds -o out -- ./xmlstarlet -c config.xml @@`，则 crash 的复现目录应为：

```
crashes/
└── heap_buffer_overflow/
    ├── poc              # Crash-triggering input
    ├── config.xml       # Additional input file (saved alongside poc)
    ├── crash_count.txt  # Raw crash instance count
    └── reproduce.sh     # ./xmlstarlet -c config.xml poc
```

```bash
cat > "crashes/heap_buffer_overflow/reproduce.sh" << 'SCRIPT'
#!/bin/bash
/path/to/xmlstarlet -c config.xml poc
SCRIPT
```

The `reproduce.sh` should contain the exact command that reproduces the crash, for example:

```bash
#!/bin/bash
/path/to/binary -flag1 -flag2 @@ < poc
```

If the crash was produced by a strategy with specific CLI flags, include those flags in the reproduce command.

---

## Phase 4: Generate/Update SUMMARY.md (增量)

**不删除已有的 SUMMARY.md。** 如果 `reports/SUMMARY.md` 已存在，读取它，合并新漏洞，更新计数；不存在则全新创建。

### Step 1: 检查是否已有 SUMMARY.md

```bash
if [ -f "reports/SUMMARY.md" ]; then
  echo "Existing SUMMARY.md found — will merge incrementally"
  EXISTING_SUMMARY=true
else
  echo "No existing SUMMARY.md — creating new"
  EXISTING_SUMMARY=false
  mkdir -p reports
fi
```

### Step 2: 汇总所有漏洞类型

运行 Phase 3 后，`crashes/` 下已有各漏洞类型的目录。对每个 `crashes/<type>/`，读取 PoC、crash_count.txt、reproduce.sh，**结合源码分析根因**：从 ASAN 堆栈找到对应的源文件，用 Read 工具查看关键函数附近的代码逻辑，说明为什么这个输入会触发漏洞（如：缺少边界检查、空指针未验证、释放后未置空等）。

### Step 3: 增量合并

```bash
if [ "$EXISTING_SUMMARY" = true ]; then
  # 从已有 SUMMARY.md 中提取已记录的漏洞类型列表
  ALREADY_RECORDED=$(grep "^### " reports/SUMMARY.md | sed 's/.*：//' | tr -d ' ')
  # 对比 crashes/ 中实际存在的类型
  for crash_dir in crashes/*/; do
    slug=$(basename "$crash_dir")
    if echo "$ALREADY_RECORDED" | grep -q "$slug"; then
      echo "[skip] $slug already in SUMMARY.md"
    else
      echo "[new] $slug — will append"
    fi
  done
fi
```

### Step 4: 生成/更新 SUMMARY.md

- 如果 `$EXISTING_SUMMARY=false`：生成全新的 SUMMARY.md，包含所有漏洞条目
- 如果 `$EXISTING_SUMMARY=true`：只**追加**新漏洞条目到已有的 SUMMARY.md 末尾，不删除、不修改已有内容
- 无论哪种情况，**更新顶部的总崩溃数和独立漏洞数**（旧数 + 新数）

对每个确认的漏洞，**结合源码分析根因**：从 ASAN 堆栈找到对应的源文件，用 Read 工具查看关键函数附近的代码逻辑，说明为什么这个输入会触发漏洞（如：缺少边界检查、空指针未验证、释放后未置空等），并将根因分析写入 SUMMARY.md 对应的漏洞条目中。

---

## Phase 5: Cleanup

最终输出（`crashes/<type>/`、`reports/`）已保存到宿主机。清理容器内所有中间临时文件，只保留 `all_crashes/` 和 `crashes_dedup/` 备查。

---

## Output

```
[RESULTS] Crash analysis complete.
[RESULTS] Confirmed vulnerabilities saved to ./crashes/<type>/
[RESULTS] Summary: ./reports/SUMMARY.md
```

---

## Trigger Examples

When user says any of these, activate this skill:
- "Analyze the fuzzing crashes"
- "Generate crash report"
- "Run crash triage"
- "复现崩溃并生成报告"
- "分析 fuzz 结果"
- "生成 SUMMARY.md"
- "Crash reporter"
