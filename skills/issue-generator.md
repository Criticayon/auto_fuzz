---
name: issue-generator
description: "Generate developer-facing GitHub Issue reports from AFL++ fuzzing campaign results. Reads reports/SUMMARY.md and crash PoC folders (crashes/<type>/), analyzes each vulnerability (CWE mapping, root cause analysis), and outputs properly formatted GitHub Issue markdown files. Trigger when user asks to file issues, generate vulnerability reports, or submit bug reports to developers."
license: Apache-2.0
compatibility: "Linux (primary), macOS, Windows (WSL). Requires fuzzing campaign results: reports/SUMMARY.md + crashes/<type>/ folders."
metadata:
  version: "2.0"
  depends_on: ["crash-reporter"]
---

# Issue Generator: Fuzz Results → GitHub Issues

Automatically generates developer-facing GitHub Issue reports from AFL++ fuzzing campaign results. This is the final step in the vulnerability discovery pipeline: converting confirmed crashes into actionable, well-structured bug reports suitable for submission to open-source project maintainers.

---

## Workflow Overview

```
Phase 1: Load Results     → Read reports/SUMMARY.md + list crashes/<type>/ folders
Phase 2: Analyze Vulns    → Read each crash's poc + reproduce.sh, extract ASAN output, map CWE
Phase 3: Generate Issues  → Create issue_<crash_type>.md per vuln + issues/SUMMARY.md
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

### Step 5: Analyze root cause

For each vulnerability, analyze the root cause based on:

1. **ASAN error type** — what kind of memory corruption
2. **Call stack** — which functions are involved, which source file/line
3. **Crash input (PoC)** — what kind of input triggers it
4. **Program analysis context** (if `vulnerability_path_scores.md` available) — which command combination and code path

---

## Phase 3: Generate GitHub Issue Markdown Files

### Step 1: Create issues output directory

```bash
mkdir -p issues
```

### Step 2: Generate individual issue for each crash type

For each crash type folder, generate a GitHub Issue markdown file:

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

Issue file template — generate one file per crash type:

```markdown
# Vulnerability Report: <crash_type> in <target>

## Description
[Brief description of the vulnerability nature]

## Environment
- **Target**: <project_name>
- **Version**: <version>
- **Commit**: <commit_hash>
- **Build**: AFL++ with AddressSanitizer
- **OS**: Linux
- **Report Date**: <date>

## CWE Classification
- **CWE-XXX**: <category>

## Steps to Reproduce
1. Build the target (same environment as above)
2. Run the following PoC:

```bash
<reproduction command>
```

3. Observe the ASAN output

## ASAN Report
```
<full ASAN output>
```

## Root Cause Analysis
[Analysis based on call chain and source code]

## Suggested Fix (if applicable)
[Optional: suggested fix]

## Attachments
- PoC file: crashes/<crash_type>/poc
- Reproduce script: crashes/<crash_type>/reproduce.sh
```

Save as `issues/issue_<crash_type>.md`.

### Step 3: Generate issues summary

```bash
cat > issues/SUMMARY.md << 'EOF'
# Vulnerability Reports Summary

The following issues have been identified during the fuzzing campaign. Each issue corresponds to a confirmed vulnerability with a reproducible crash.

**Total issues**: <count>

EOF

echo "" >> issues/SUMMARY.md
echo "| # | Issue | CWE | Severity |" >> issues/SUMMARY.md
echo "|-----|-------|-----|----------|" >> issues/SUMMARY.md

counter=1
for issue in issues/issue_*.md; do
  [ -f "$issue" ] || continue
  title=$(head -1 "$issue" | sed 's/^# //')
  cwe=$(grep "CWE-" "$issue" | head -1 | sed 's/.*\*\*//;s/\*\*.*//')
  echo "| $counter | [$title]($(basename "$issue")) | $cwe | TBD |" >> issues/SUMMARY.md
  counter=$((counter + 1))
done

echo ""
echo "Issue summary saved: issues/SUMMARY.md"
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
