---
name: issue-generator
description: "Generate developer-facing GitHub Issue reports from AFL++ fuzzing campaign results. Reads reports/SUMMARY.md and crash PoC folders (crashes/<type>/), analyzes each vulnerability (CWE mapping, root cause analysis), and outputs properly formatted GitHub Issue markdown files. Trigger when user asks to file issues, generate vulnerability reports, or submit bug reports to developers."
license: Apache-2.0
compatibility: "Linux (primary), macOS, Windows (WSL). Requires fuzzing campaign results: reports/SUMMARY.md + crashes/<type>/ folders."
metadata:
  version: "3.0"
  depends_on: ["crash-reporter"]
---

# Issue Generator: Fuzz Results → GitHub Issues

Automatically generates developer-facing vulnerability reports from AFL++ fuzzing campaign results. Individual GitHub Issues are in **English**; the internal summary report is in **Chinese (中文)**.

---

## Workflow Overview

```
Phase 1: Load Results     → Read reports/SUMMARY.md + list crashes/<type>/ folders
Phase 2: Analyze Vulns    → Read each crash's poc + reproduce.sh, extract ASAN output, map CWE
Phase 3: Generate Issues  → Create issue_<crash_type>.md (English) per vuln + issues/SUMMARY.md (中文)
Phase 4: Output           → List all generated issue file paths
```

---

## Phase 1: Load Fuzzing Results

### Step 1: Verify required files exist

```bash
if [ ! -f "reports/SUMMARY.md" ]; then
  echo "ERROR: reports/SUMMARY.md not found."
  exit 1
fi

if [ ! -d "crashes" ]; then
  echo "ERROR: crashes/ directory not found."
  exit 1
fi
```

### Step 2: Read SUMMARY.md

```bash
echo "=== Campaign Summary ==="
cat reports/SUMMARY.md
echo ""
```

Extract from SUMMARY.md:
- **Target program**: project name
- **Version**: version string
- **Commit hash**: git commit
- **Report date**: date of the campaign
- **Total confirmed vulnerabilities**: count
- **Crash types**: list of unique crash types

### Step 3: List all crash type folders

```bash
echo "=== Crash Types ==="
ls -d crashes/*/ 2>/dev/null
echo ""

CRASH_TYPES=$(ls -d crashes/*/ 2>/dev/null)
if [ -z "$CRASH_TYPES" ]; then
  echo "No crash type folders found in crashes/"
  exit 1
fi
echo "Found $(echo "$CRASH_TYPES" | wc -l) unique crash type(s)"
```

### Step 4: (Optional) Load vulnerability path scores

If available, read `vulnerability_path_scores.md` for additional root cause analysis context:

```bash
if [ -f "vulnerability_path_scores.md" ]; then
  echo "Loaded vulnerability path scores for root cause analysis."
  VULN_SCORES_AVAILABLE=true
else
  echo "vulnerability_path_scores.md not found — proceeding without path scores."
  VULN_SCORES_AVAILABLE=false
fi
```

---

## Phase 2: Analyze Each Vulnerability

For each crash type folder in `crashes/`, perform the following analysis.

### Step 1: Read PoC and reproduce command

```bash
crash_type_dir="$1"
crash_type=$(basename "$crash_type_dir")

# Read PoC file
poc_file="${crash_type_dir}/poc"
echo "  PoC file: $poc_file"

# Read reproduce script
repro_cmd=$(cat "${crash_type_dir}/reproduce.sh" 2>/dev/null)
echo "  Reproduce command: $repro_cmd"
```

### Step 2: Reproduce with ASAN and capture output

Run the crash through the ASAN-instrumented binary to get the full sanitizer output:

```bash
# Run the reproduction command and capture ASAN output
asan_output=$(eval "$repro_cmd" 2>&1)
echo "$asan_output"
```

### Step 3: Extract ASAN error type and call stack

```bash
# Extract ASAN error type
asan_error=$(echo "$asan_output" | grep "ERROR:" | head -1)
echo "  Error type: $asan_error"
```

Common ASAN error types:

| ASAN Error | Likely CWE |
|------------|-----------|
| `heap-buffer-overflow` | CWE-122 (Heap Overflow) |
| `stack-buffer-overflow` | CWE-121 (Stack Overflow) |
| `heap-use-after-free` | CWE-416 (Use After Free) |
| `stack-use-after-return` | CWE-416 (Use After Free) |
| `SEGV on unknown address` | CWE-476 (NULL Pointer Dereference) or CWE-119 |
| `SEGV` (general) | CWE-119 (Buffer Overflow) |
| `global-buffer-overflow` | CWE-122 (Heap Overflow) |
| `negative-size-param` | CWE-190 (Integer Overflow) |
| `memcpy-param-overlap` | CWE-119 (Buffer Overflow) |
| `double-free` | CWE-415 (Double Free) |
| `abort` (via `__asan_handle_no_return`) | CWE-754 (Unchecked Return Value) |

### Step 4: Determine CWE classification

Map the ASAN error type to a CWE and add context based on the call stack:

- For **heap-buffer-overflow**: Identify the allocation site and the access site from the stack trace (CWE-122)
- For **stack-buffer-overflow**: Look for fixed-size buffers on the stack (CWE-121)
- For **heap-use-after-free**: Identify the free site and the subsequent use site (CWE-416)
- For **SEGV**: Determine if it's NULL deref (CWE-476) or out-of-bounds (CWE-119)
- For **integer overflow**: Look for arithmetic operations on untrusted sizes (CWE-190)
- For **assertion failure / abort** (no ASAN error, just `Assertion failed` or `SIGABRT`): **Do not blindly classify as CWE-617.** Analyze what the assert is checking:
  - `assert(index < size)` or `assert(i >= 0 && i < count)` → guard against **OOB access**, classify as CWE-122/CWE-787 (the assert caught the real memory bug early)
  - `assert(ptr != NULL)` or `assert(ptr->field)` (null check on a pointer dereference) → guard against **NULL pointer dereference**, classify as CWE-476
  - `assert(bez->eflag)` / `assert(np->cells)` (member access on a pointer) → guard against **NULL pointer dereference**, classify as CWE-476
  - `assert(x == y)` / `assert(m > 0 && n > 0)` (purely logical/validation check with no memory safety implication) → CWE-617 (Reachable Assertion)
  - Rule of thumb: if the assert prevents a memory-safety violation (OOB, UAF, NULL deref), treat it as that underlying CWE, not as "just an assertion". Only pure input validation / invariant checks with no memory safety implication get CWE-617.
  - **Labeling**: For memory bugs caught by assert (no ASAN error), append `[assert-guarded]` to the vulnerability title/type to indicate the developer had a defensive check in place but the underlying bug still exists.

### Step 5: Analyze root cause

For each vulnerability, analyze the root cause based on:

1. **ASAN error type** — what kind of memory corruption
2. **Call stack** — which functions are involved, which source file/line
3. **Crash input (PoC)** — what kind of input triggers it
4. **Program analysis context** (if `vulnerability_path_scores.md` available) — which command combination and code path

---

## Phase 3: Generate Vulnerability Reports (English Issues + 中文 Summary)

### Step 1: Create output directories

```bash
mkdir -p issues
```

### Step 2: Group vulnerabilities by tool/component

Group the crash types by the tool or component that produced them (e.g., gml2gv, gvpr, dot). This makes the report more structured.

### Step 3: Generate individual issue for each crash type

For each crash type folder, generate a GitHub Issue markdown file in **English** (for submission to upstream developers):

```bash
source target_metadata.sh 2>/dev/null

# Source target metadata from various possible locations
if [ -z "${PROJ:-}" ]; then
  PROJ=$(grep "Target" reports/SUMMARY.md 2>/dev/null | head -1 | sed 's/.*|//' | xargs)
fi
if [ -z "${COMMIT_HASH:-}" ]; then
  COMMIT_HASH=$(grep "Commit" reports/SUMMARY.md 2>/dev/null | sed 's/.*`//;s/`.*//')
fi
if [ -z "${PROJECT_VERSION:-}" ]; then
  PROJECT_VERSION=$(grep "Version" reports/SUMMARY.md 2>/dev/null | sed 's/.*|//' | head -1 | xargs)
fi
if [ -z "${REPORT_DATE:-}" ]; then
  REPORT_DATE=$(grep "date\|Date" reports/SUMMARY.md 2>/dev/null | sed 's/.*|//' | head -1 | xargs)
fi
```

Issue file template (in English) — generate one file per crash type:

```markdown
# Vulnerability Report: <crash_type> in <target>

## Summary

| Field | Value |
|-------|-------|
| **Target** | <project_name> |
| **Version** | <version> |
| **Commit** | <commit_hash> |
| **Build** | AFL++ + AddressSanitizer |
| **OS** | Linux |
| **Report Date** | <date> |

## CWE Classification

- **CWE-XXX**: <category>

## Description

[Brief description of the vulnerability]

## Reproduction Steps

1. Trigger using the following PoC:

```bash
<reproduction command>
```

2. Observe the ASAN output

## ASAN Report

```
<full ASAN output>
```

## Root Cause Analysis

[Analysis based on call stack and source code]

- **Trigger Location**: `<file:line>`
- **Call Chain**: <function_a → function_b → ...>
- **Root Cause**: [Detailed analysis]

## Fix Suggestion (if any)

[Optional: suggested fix approach]

## Attachments

- PoC file: `crashes/<crash_type>/poc`
- Reproduction script: `crashes/<crash_type>/reproduce.sh`
```

Save as `issues/issue_<crash_type>.md`.

### Step 4: Generate summary report (issues/SUMMARY.md)

Generate a comprehensive Chinese-language summary report that follows this format:

```markdown
# Fuzzing Campaign Summary — <Project Name>

## 基本信息

| 字段 | 值 |
|------|-----|
| **目标程序** | <project_name> |
| **版本** | <version> |
| **提交** | <commit_hash> |
| **报告日期** | <date> |
| **总崩溃数** | <total_crashes> |
| **独立漏洞数** | <total_vulns> |

---

## <工具1>（<crash_count> 个崩溃 → <vuln_count> 个漏洞）

### 漏洞 <编号>：<漏洞标题>

| 字段 | 值 |
|------|-----|
| **位置** | <文件:行号> |
| **ASAN** | <error_type> |
| **实例** | <count> |

**根因：** [详细分析]

**复现：**
```bash
<reproduction command>
```

---

## 汇总

### 按工具

| 工具 | 总 crash | 独立漏洞 | 主要类型 |
|------|---------|---------|---------|
| <tool1> | <count> | <count> | <types> |

### 完整漏洞列表

| # | 漏洞 | 工具 | 类型 | 实例 | 文件:行号 | 严重程度 |
|---|------|------|------|------|-----------|---------|
| <id> | <title> | <tool> | **<asan_type>** | <count> | `<file:line>` | 🔴 **高** / 🟡 中 / 🟢 低 |

**严重程度判定标准：**
- 🔴 **高** — 内存越界读写（heap-buffer-overflow、global-buffer-overflow、use-after-free）
- 🟡 **中** — 可控空指针解引用、栈溢出
- 🟢 **低** — 纯逻辑断言失败（CWE-617，不涉及内存安全）、不可利用的 SEGV

**注意：** 断言 `assert(index < size)`、`assert(ptr)` 等本质是拦截内存错误（OOB / NULL deref），不应按"断言"归类为低危，应按其拦截的内存错误类型判定严重程度。只有纯逻辑校验断言（如 `assert(m > 0 && n > 0)`、`assert(a == b)`）才标 🟢 低。**类型**列也应当体现底层的内存错误类型（如 heap-buffer-overflow / null-deref），而非笼统地写 "assertion"。被 assert 捕获的漏洞在标题后加 `[assert-guarded]` 标注。

### Fuzzing 统计

| 工具 | 运行时间 | Edges | Bitmap | 执行速度 | 总 crash |
|------|---------|-------|--------|---------|---------|
| <tool> | <time> | <edges>/<total> | <pct> | <speed>/s | <count> |
```

---

## Phase 4: Output

After all phases complete, present the results:

```
[RESULTS] Issue generation complete.
[RESULTS] Individual issues: ./issues/
[RESULTS] Summary: ./issues/SUMMARY.md
[RESULTS]
[RESULTS] Generated files:
<list each issue_*.md file path>
```

---

## Trigger Examples

When user says any of these, activate this skill:
- "生成安全漏洞报告"
- "Generate security vulnerability report"
- "提 issue"
- "Generate issue from fuzz results"
- "生成 GitHub Issue"
- "Report vulnerability to developers"
- "提交漏洞报告"
- "从 fuzz 结果生成报告"
- "Create GitHub Issues from fuzzing results"
