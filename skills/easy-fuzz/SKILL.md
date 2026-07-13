---
name: easy-fuzz
description: "Simple AFL++ fuzzing mode for EasyFuzz pipeline. Trigger when user wants quick/simple fuzzing without deep program analysis. Designed for the EasyFuzz 2-phase workflow."
license: Apache-2.0
compatibility: "Linux (primary), macOS, Windows (WSL). Requires AFL++ installed and in PATH."
metadata:
  version: "1.0"
---

# Easy-Fuzz: Quick AFL++ Fuzzing

A simplified fuzzing workflow designed for the EasyFuzz 2-phase pipeline. This skill skips deep program analysis and instead:
1. Builds the target with basic AFL++ instrumentation
2. Designs simple, sensible fuzz commands based on the target binary's `--help` output
3. Runs the fuzzing campaign
4. Saves all commands locally for future reuse/modification

---

## Workflow Overview

```
Phase 1: Build         → Compile target with AFL++ instrumentation
Phase 2: Discover      → Read --help, find input files/data sources, design commands
Phase 3: Fuzz          → Launch afl-fuzz with designed commands
Phase 4: Save Commands → Save commands to easy_fuzz_commands.json for future reuse
```

### ⏰ Deadline Awareness

The pipeline passes a **deadline** in the prompt. You must:

1. Plan backwards from the deadline. Estimate time needed for: compilation → discovery → fuzzing.
2. Reserve the last 5 minutes for saving commands and cleanup.
3. If you run out of time, stop afl-fuzz and proceed to saving whatever commands were used.

---

## Phase 1: Build the Target

### Setup: directory layout (container)

```
/workspace/
├── <project-dir>/       # target project source
└── fuzz_<project-dir>/  # fuzz workspace
    ├── seeds/           # seed corpora
    └── out_<strategy>/  # fuzz output dirs
```

Set the project directory:

```bash
PROJ="/workspace/<project-dir-name>"
FUZZ="/workspace/fuzz_<project-dir-name>"
```

### Install build dependencies

Try compiling first. If it fails, install the missing package and retry:

```bash
apt-get install -y -qq <package-name> 2>/dev/null || \
  (apt-get update -qq && apt-get install -y -qq <package-name>)
```

### Compile with AFL++

Try a basic AFL++ compilation. If ASAN causes issues (mmap failures with fork server), fall back to non-ASAN:

```bash
cd $PROJ
mkdir -p build_afl
cd build_afl

CC=afl-clang-fast CXX=afl-clang-fast++ \
cmake .. \
  -DCMAKE_C_COMPILER=afl-clang-fast \
  -DCMAKE_CXX_COMPILER=afl-clang-fast++
make -j$(nproc)
```

**ASAN fallback:** If the binary has ASAN and fork server crashes with memory errors, rebuild without ASAN:

```bash
cd $PROJ
rm -rf build_afl
mkdir -p build_afl
cd build_afl
env -u AFL_USE_ASAN CC=afl-clang-fast CXX=afl-clang-fast++ \
cmake .. -DCMAKE_C_COMPILER=afl-clang-fast -DCMAKE_CXX_COMPILER=afl-clang-fast++
make -j$(nproc)
```

---

## Phase 2: Discover Fuzz Surface & Design Commands

### Step 1: Read --help

```bash
$PROJ/build_afl/bin/<target-binary> --help 2>&1 || true
$PROJ/build_afl/bin/<target-binary> -h 2>&1 || true
```

### Step 2: Identify input sources

Look for:
- **File input flags**: `-f`, `-i`, `--input`, `--file`, etc. — these are the `@@` target for AFL++
- **Config file flags**: `-c`, `--config`, `--conf`, etc. — these are secondary files (not `@@`)
- **Stdin mode**: Does the binary read from stdin when no file is given?
- **Output flags**: `-o`, `--output` — direct to a temp dir
- **Other relevant options**: recursion depth, verbosity, language selection

### Step 3: Design fuzz commands

Design 1-5 fuzz commands. Each command should target a different aspect of the program. Save the commands in a JSON structure:

```json
{
  "commands": [
    {
      "id": 1,
      "name": "<strategy_name>",
      "description": "<what this command tests>",
      "command": "afl-fuzz -i <seed_dir> -o <out_dir> -m 4096 -t 5000 -- <binary> <flags> @@",
      "output_dir": "out_<strategy>"
    }
  ]
}
```

**Rules for command design:**
- Always use `-m 4096` (never higher, never `none`)
- Use `-t 5000` timeout for initial runs
- Create seed directories with minimal valid inputs
- Use separate `-o` output dirs for each strategy
- The `@@` marker goes where AFL++ places the mutated file argument

### Step 4: Run afl-fuzz for each command

For each strategy in your list, create seeds and launch:

```bash
mkdir -p $FUZZ/seeds_<strategy>
# Create minimal but valid seed file(s) for this strategy
echo "..." > $FUZZ/seeds_<strategy>/seed1

# Launch in background
afl-fuzz -i $FUZZ/seeds_<strategy> -o $FUZZ/out_<strategy> -m 4096 -t 5000 -- <binary> <flags> @@ &
```

**Verify the process started:**

```bash
ps aux | grep afl-fuzz | grep -v grep
```

### Step 5: Create seed files

Generate minimal but valid seed files for each strategy. For example:
- For a C source beautifier: a simple `int main(){}` C file
- For an image parser: a minimal valid image file (use `echo` or `printf` to create)
- For a config-driven tool: a minimal config file
- For a network/data parser: a minimal data packet

If the existing project directory has test files, use those as seeds:

```bash
find $PROJ/test -type f -size -4k 2>/dev/null | head -5 | while read f; do cp "$f" $FUZZ/seeds_<strategy>/; done
```

---

## Phase 3: Fuzzing Campaign

### Step 1: Wait for fuzzing to run

Monitor fuzzing progress. The fuzzing runs in the background. Wait for a reasonable amount of time to collect results.

### Step 2: Check for crashes

Periodically check each strategy for crashes:

```bash
for d in $FUZZ/out_*/; do
  name=$(basename "$d")
  crashes=$(ls "$d/crashes/" 2>/dev/null | wc -l)
  echo "$name: $crashes crashes"
done
```

If crashes are found, stop the campaign and proceed to save results.

---

## Phase 4: Save & Record Commands

### Step 1: Save commands to local file

Save the designed commands to `easy_fuzz_commands.json` in the current (host workdir) directory:

```json
{
  "target": "<project_name>",
  "date": "<YYYY-MM-DD>",
  "bin_path": "<path to binary>",
  "commands": [
    {
      "id": 1,
      "name": "<strategy_name>",
      "description": "<what this command tests>",
      "command": "afl-fuzz -i ... -o ... -m 4096 -- <binary> <flags> @@",
      "output_dir": "out_<strategy>",
      "crashes_found": <count>,
      "timestamp": "<ISO timestamp>"
    }
  ]
}
```

### Step 2: Signal completion

Create the completion signal:

```bash
touch $FUZZ/fuzz_started.signal
```

Also create the signal in the host workdir.

### Step 3: Command Replacement

The `easy_fuzz_commands.json` file serves as the command history. When the user wants to modify/replace commands:

1. Read the existing `easy_fuzz_commands.json` file
2. Display all previous commands with their IDs and descriptions
3. Accept user modifications (modify flags, add new strategies, remove old ones)
4. Kill existing afl-fuzz processes for this project
5. Re-launch with the modified commands
6. Update the JSON file with the new commands

To kill existing processes before relaunching:

```bash
ps aux | grep afl-fuzz | grep '<project_name>' | grep -v grep | awk '{print $2}' | xargs -r kill -9 2>/dev/null || true
```

---

## Output

```
[RESULTS] Easy-Fuzz complete.
[RESULTS] Commands saved to: easy_fuzz_commands.json
[RESULTS] Fuzz output dirs: out_<strategy>/
[RESULTS] Crashes found: <count>
```
