---
name: auto-fuzz-exec
description: "Execute an AFL++ fuzzing campaign from a pre-generated manifest. Launch batch 1 of fuzz strategies, verify they are running, and exit. Trigger when fuzz_manifest.json is ready and afl-fuzz processes need to be started."
license: Apache-2.0
compatibility: "Requires AFL++ container and pre-existing fuzz_manifest.json from auto-fuzz skill."
metadata:
  version: "1.0"
---

# Auto-Fuzz Execute: Launch Pre-Configured Fuzzing Campaign

This skill reads a pre-generated `fuzz_manifest.json` (or `fuzz_manifest_selected.json` if user-selected), launches all strategies in the AFL++ container, verifies they are running, and exits. No monitoring, no stagnation detection, no batch advancement.

---

## Workflow Overview

```
Step 1: Load Config   → source target_metadata.sh, read fuzz_manifest.json
Step 2: Launch Batch   → for each strategy in batch 1, run afl-fuzz via container_exec_detached
Step 3: Verify         → ps aux | grep afl-fuzz, confirm all strategies started
Step 4: Signal         → output [FUZZ_STARTED] and exit
```

---

## Step 1: Load Configuration

Source the target metadata and read the fuzz manifest from the fuzz workspace. If `fuzz_manifest_selected.json` exists (user-selected strategies from the UI), use it; otherwise fall back to the full `fuzz_manifest.json`.

```bash
# Source metadata (sets $PROJ and other vars)
source target_metadata.sh

# Prefer user-selected manifest over full manifest
MANIFEST="fuzz_manifest_selected.json"
if [ ! -f "$MANIFEST" ]; then
  MANIFEST="fuzz_manifest.json"
fi

# Read manifest
cat "$MANIFEST"
```

The manifest has the following structure:

```json
{
  "batch_size": 4,
  "strategies": [
    {
      "id": 5,
      "name": "strategy_name",
      "command": "afl-fuzz -M main -i seeds -o out_id5 -m 4096 -t 10000 -p explore -- $PROJ/target @@",
      "vuln_score": 78,
      "priority": "critical",
      "seed_dir": "seeds",
      "output_dir": "out_id5",
      "desc": "Strategy description from analysis"
    }
  ]
}
```

The manifest's `batch_size` tells you how many strategies to launch. When using user-selected strategies, `batch_size` equals the total selected count — launch ALL of them.

```bash
# Parse batch_size from manifest
BATCH_SIZE=$(python3 -c "import json; print(json.load(open('$MANIFEST'))['batch_size'])")
```

---

## Step 2: Launch Batch 1

For each strategy in the first batch, construct the `nohup afl-fuzz ...` command and launch it detached in the container using `container_exec_detached`.

### Memory limit: ASAN 检测与处理

ASAN 需要 ~20TB 虚拟地址空间用于 shadow memory，与 AFL++ 的 `-m 4096` (RLIMIT_AS) 冲突。**不要使用 `-m none`**——正确做法是重新编译一个不带 ASAN 的 fuzzing 专用 binary。

**检测方法** —— 检查目标二进制是否包含 ASAN 符号：
```bash
nm $TARGET_BINARY 2>/dev/null | grep -q __asan && echo "ASAN" || echo "no-ASAN"
```

**如果检测到 ASAN：重新编译不带 ASAN 的版本**

```bash
# 找到原来的构建配置（从 target_metadata.sh 或 CMakeLists.txt）
# 新建一个 build 目录
mkdir -p /workspace/fuzz_<project>/build_noasan
cd /workspace/fuzz_<project>/build_noasan

# 用 afl-clang-fast 编译，但确保 AFL_USE_ASAN 未被设置
# 重要: AFL_USE_ASAN=0 仍会被 afl-clang-fast 视为启用，必须用 env -u 彻底清除
env -u AFL_USE_ASAN cmake .. \
  -DCMAKE_C_COMPILER=afl-clang-fast \
  -DCMAKE_CXX_COMPILER=afl-clang-fast++ \
  <其他原有的 cmake 参数>

env -u AFL_USE_ASAN make -j$(nproc)
```

**同样重建 CMPLOG 变体：**
```bash
mkdir -p /workspace/fuzz_<project>/build_noasan_cmplog
cd /workspace/fuzz_<project>/build_noasan_cmplog

env -u AFL_USE_ASAN cmake .. \
  -DCMAKE_C_COMPILER=afl-clang-fast \
  -DCMAKE_CXX_COMPILER=afl-clang-fast++ \
  -DAFL_CMPLOG=1 \
  <其他原有的 cmake 参数>

env -u AFL_USE_ASAN make -j$(nproc)
```

**验证无误后更新配置：**
- 更新 `target_metadata.sh` 中的 binary 路径，指向新编译的不带 ASAN 的 binary
- manifest 中的 command 使用 `-m 4096`（不需要 `-m none`）

### Launch each strategy

Since each strategy's `command` field already has the correct `afl-fuzz ... -- $PROJ/target ...` structure, use it directly.

Read strategies from `$MANIFEST` and iterate over them:

```bash
# Ensure seed and output dirs exist
cd /workspace/fuzz_<project>/
source target_metadata.sh
MANIFEST="fuzz_manifest_selected.json"
[ ! -f "$MANIFEST" ] && MANIFEST="fuzz_manifest.json"

# For each strategy:
STRATEGY_CMD='...'  # from manifest command field
OUTPUT_DIR='...'    # from manifest output_dir field
mkdir -p "$OUTPUT_DIR"

# Launch via container_exec_detached
# The nohup + output redirection is built into the command
container_exec_detached command="nohup ${STRATEGY_CMD} > ${OUTPUT_DIR}/fuzz.log 2>&1" workdir="/workspace/fuzz_<project>"
```

**Rules:**
- Launch ALL strategies in the first batch (up to `batch_size`). Do not skip any.
- Each instance uses the command from the manifest's `command` field.
- All strategies share the same `workdir` (the fuzz workspace).
- The `nohup ... > output_dir/fuzz.log 2>&1` wrapper ensures logs are captured and the process survives shell exit.

### Save PID for each launched strategy

After launching each strategy, record its PID for later verification and cleanup:

```bash
# After launching, save PID
container_exec command="cat /proc/$!/status 2>/dev/null | head -1 || echo 'PID not saved via detach'" workdir="/workspace/fuzz_<project>"
```

Since `container_exec_detached` returns an exec_id (not a PID), instead save PIDs by scanning after launch:

```bash
container_exec command="ps aux | grep 'afl-fuzz' | grep -v grep | awk '{print \$2, \$NF}'" workdir="/workspace/fuzz_<project>"
```

---

## Step 3: Verify All Strategies Are Running

Confirm all launched afl-fuzz processes are running:

```bash
container_exec command="ps aux | grep afl-fuzz | grep -v grep | head -20" workdir="/workspace/fuzz_<project>"
```

Check that you see one afl-fuzz process per strategy in the batch. Each should have its unique `-o` output directory in the command line.

If any strategy failed to start (missing from ps output):
1. Check the log file: `cat <output_dir>/fuzz.log`
2. Re-launch the failed strategy with corrected parameters

---

## Step 4: Signal Completion

After all strategies are verified running, create the signal file on both container and host, then output the completion message:

```bash
# Create signal file for orchestrator state detection (in container)
container_exec command="touch /workspace/fuzz_<project>/fuzz_started.signal" workdir="/workspace/fuzz_<project>"
# Also create on the host filesystem (current working directory)
touch fuzz_started.signal
```

Output the completion signal:

```text
[FUZZ_STARTED] project=<project_name> strategies=<count> batch=1

The fuzzing campaign is now running in the background. afl-fuzz processes are active in the AFL++ container.
```

The agent should then **exit cleanly**. Do not wait, do not monitor, do not check again.

---

## ⛔ What NOT To Do

- Do NOT monitor fuzzing progress or check fuzzer_stats
- Do NOT implement stagnation detection or batch advancement
- Do NOT clean up afl-fuzz processes
- Do NOT wait for fuzzing to complete
- Do NOT modify the manifest or strategy commands (except rebuilding without ASAN when detected)
- Do NOT use `-m none` — rebuild without ASAN instead and use `-m 4096`

Launch, verify, signal, exit.
