---
name: crash-reporter
description: "Crash triage and ASAN report generation from AFL++ fuzzing output. Trigger when user needs to analyze fuzzing crashes, generate vulnerability reports, or produce SUMMARY.md."
license: Apache-2.0
compatibility: "Linux (primary), macOS, Windows (WSL). Requires AFL++ installed and in PATH."
metadata:
  version: "2.0"
---

# Crash Reporter: Triage & ASAN Report Generation

After an AFL++ fuzzing campaign completes, this skill collects crashes from all output directories, reproduces with ASAN, deduplicates by crash type, and saves each unique crash's PoC and reproduce script to a dedicated folder on the host.

---

## Workflow Overview

```
Phase 1: Collect Crashes  → Gather crash inputs from all out_*/crashes/
Phase 2: Minimize         → afl-tmin to reduce each crash to minimal input
Phase 3: Deduplicate      → Group by stack trace, identify unique bugs
Phase 4: Reproduce        → Replay with ASAN binary, capture sanitizer output
Phase 5: Save to Host     → SUMMARY.md in reports/, each crash in crashes/<type>/
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

## Phase 2: Minimize Crashes

Use `afl-tmin` to shrink each crash to the smallest input that still triggers the bug:

```bash
mkdir -p crashes_min
for crash in all_crashes/*; do
  [ -f "$crash" ] || continue
  afl-tmin -i "$crash" -o "crashes_min/$(basename $crash)" -- ./target @@ 2>/dev/null
done
```

If `afl-tmin` is too slow or fails, skip minimization and use raw crashes directly.

---

## Phase 3: Deduplicate by Stack Trace

Run each (minimized) crash under the ASAN-instrumented binary and group by error type:

```bash
for crash in crashes_min/*; do
  echo "=== $crash ==="
  ./target @@ < "$crash" 2>&1 | grep -E "ERROR:|SUMMARY:|==[0-9]+=="
done
```

Group crashes that produce the same stack trace / error type. Only keep one representative per unique bug.

---

## Phase 4: Reproduce & Save to Host

For each unique crash, reproduce and capture the full ASAN output. Only crashes that produce `ERROR: AddressSanitizer` are confirmed vulnerabilities. Save each crash's PoC and reproduction script to a dedicated directory on the **host** (not in the container).

```bash
# On the host: create crashes directory
mkdir -p crashes/<crash_type>/
```

**Directory structure on host:**

```
crashes/
├── heap_buffer_overflow/
│   ├── poc              # The PoC file (copied from crash input)
│   └── reproduce.sh     # Reproduction command
├── use_after_free/
│   ├── poc
│   └── reproduce.sh
└── ...
```

Each folder name should be a short, descriptive slug for the ASAN error type (e.g. `heap_buffer_overflow`, `stack_buffer_overflow`, `null_deref`, `use_after_free`).

The `reproduce.sh` should contain the exact command that reproduces the crash, for example:

```bash
#!/bin/bash
/path/to/binary -flag1 -flag2 @@ < poc
```

If the crash was produced by a strategy with specific CLI flags, include those flags in the reproduce command.

---

## Phase 5: Generate SUMMARY.md

Save a summary to `reports/SUMMARY.md` on the host. This is a **summary only** — NOT per-crash report files.

```bash
cat > reports/SUMMARY.md << 'EOF'
# Fuzzing Campaign Summary

## Confirmed Vulnerabilities

| # | Crash Type | ASAN Error | PoC Location |
|---|-----------|------------|-------------|
EOF

# Populate the table with each unique crash type
# Example:
# | 1 | heap_buffer_overflow | heap-buffer-overflow | crashes/heap_buffer_overflow/poc |
```

The SUMMARY.md should contain:
- Target project name, version, commit hash
- Campaign date
- Total number of unique confirmed vulnerabilities
- Table with each crash type, ASAN error, and path to PoC

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
