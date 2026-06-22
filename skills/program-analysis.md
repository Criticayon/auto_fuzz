---
name: program-analysis
description: "Automated program entry analysis for CLI tools. Find entry point, analyze parameter dependencies/conflicts, enumerate all valid command combinations, trace the deepest function call chain, and save call tree locally. Trigger when user asks to analyze a program, understand CLI structure, trace call paths, or prepare for fuzzing."
metadata:
  version: "1.0"
---

# Program Analysis: CLI Structure & Call Chain Analysis

Analyze a target project's source code to discover ALL CLI tools it ships, understand each tool's CLI interface, enumerate all valid command combinations per tool, and trace function call chains. The output guides fuzzing strategy design and vulnerability research.

**Critical: This skill must discover and analyze EVERY CLI tool in the project, not just one.** Many projects (graphviz, ffmpeg, imagemagick, etc.) ship multiple executables.

> **⚠️ 重要说明：本文档中的所有命令、参数表、JSON 结构、调用链树均为参考示例（基于 minisign 项目），旨在展示分析方法和输出格式。实际使用时，大模型必须根据目标项目的实际源码进行分析，生成真实的项目专属内容，不可直接套用本文档中的示例值。**

---

## Workflow Overview

```
Phase 0: Discover      → Find ALL CLI tools the project builds
Phase 1: Entry         → Locate main() and entry file for each tool
Phase 2: Arg Parse     → Analyze getopt/argparse: parameters, dependencies, conflicts
Phase 3: Combinatorics → Enumerate all valid command combinations per tool
Phase 4: Coverage Eval → Rank combos by estimated function path coverage
Phase 5: Call Chain    → Trace deepest combo's full call chain → save locally
Phase 6: Vuln Scoring  → Score each path for dangerous ops → rank all combos
```

---

## Phase 0: Discover All CLI Tools

Before analyzing any single tool, scan the project to find **every CLI executable** it builds. This is critical — most projects have multiple tools.

```bash
# Method 1: CMake projects — find all add_executable calls
grep -rn "add_executable\|add_util_executable" --include="CMakeLists.txt" --include="*.cmake" -r . 2>/dev/null

# Method 2: Autotools projects — find bin_PROGRAMS
grep -rn "bin_PROGRAMS\|bin_SCRIPTS" --include="Makefile.am" --include="Makefile.in" -r . 2>/dev/null

# Method 3: Meson projects — find executable()
grep -rn "executable(" --include="meson.build" -r . 2>/dev/null

# Method 4: List all source files containing main()
for f in $(find . -name "*.c" -o -name "*.cc" -o -name "*.cpp" -o -name "*.rs" -o -name "*.go" 2>/dev/null); do
  if grep -l "^int main\|^fn main\|^func main" "$f" 2>/dev/null; then
    echo "$f"
  fi
done

# Method 5: Check build output / installed binaries
ls -la src/*/ 2>/dev/null | grep -i "exec\|bin"
ls -la cmd/*/ 2>/dev/null
```

**Record the full list of CLI tools discovered:**

```json
{
  "tools": [
    {"name": "tool1", "entry_file": "src/tool1/main.c", "build_system": "cmake"},
    {"name": "tool2", "entry_file": "cmd/tool2/main.go", "build_system": "manual"}
  ]
}
```

For each tool discovered, run **Phases 1 through 6** independently. The final `command_combinations.json` and other outputs must include data for ALL tools.

**Important:** If Phase 0 finds multiple tools (e.g., dot, neato, twopi, circo, fdp, sfdp for graphviz), each one gets its own section in the output files. Do NOT analyze only the first tool found.

---

## Phase 1: Locate Entry Point

Find the `main()` function and determine the entry file and project language.

```bash
# Find main() in C/C++ projects
grep -rn "^int main\|^int main_\|^main(" --include="*.c" --include="*.cc" --include="*.cpp" -r . 2>/dev/null

# Find main() in Rust projects
grep -rn "^fn main" --include="*.rs" -r . 2>/dev/null

# Find main() in Go projects
grep -rn "^func main" --include="*.go" -r . 2>/dev/null
```

**Record:**
- **Entry file**: `<file>.c`
- **Entry function line**: `main() at line N`
- **Language**: C/C++/Rust/Go/other

---

## Phase 2: Analyze Argument Parsing

Read the `main()` function to understand how CLI arguments are parsed. Identify the parsing mechanism and extract all parameters, their types, dependencies, and conflicts.

### Step 1: Identify the argument parsing pattern

| Pattern | How to Detect | Example |
|---------|--------------|---------|
| **getopt()** | Look for `getopt(argc, argv, "...")` | `"CGSVRHhc:flm:oP:p:qQs:t:vWx:"` |
| **getopt_long()** | Look for `getopt_long()` + `option` struct array | `{{"help", no_argument, 0, 'h'}, ...}` |
| **argparse** | Look for `argparse()` or argparse header | Python's `argparse`, or C argparse libs |
| **Manual parsing** | Look for `strcmp()`, `strncmp()` loops over `argv` | `if (strcmp(argv[i], "-v") == 0)` |

### Step 2: Extract all parameters

For **getopt/getopt_long**, the optstring directly encodes all parameters:

```c
// Example: "CGSVRHhc:flm:oP:p:qQs:t:vWx:"
// Letters with ':' → requires an argument
// Letters without ':' → boolean flag
```
For example:
Extract into a parameter table:

| Flag | Short | Argument | Type | Description |
|------|-------|----------|------|-------------|
| `-G` | action | none | exclusive action | generate key pair |
| `-S` | action | none | exclusive action | sign files |
| `-V` | action | none | exclusive action | verify signature |
| `-m` | flag | `<file>` | required arg | file to sign/verify |
| `-p` | flag | `<pubkey_file>` | optional arg | public key file |
| `-c` | flag | `<comment>` | optional arg | untrusted comment |
| ... | ... | ... | ... | ... |

### Step 3: Analyze action exclusivity (mutual exclusion)

Read the `main()` action-dispatch logic:

```c
// Look for pattern: "if (action != ACTION_NONE && action != ACTION_XXX)"
// This indicates that only one action can be active at a time.

// Check the switch/case after getopt loop — this determines final dispatch.
switch (action) {
    case ACTION_GENERATE: ...
    case ACTION_SIGN:     ...
    case ACTION_VERIFY:   ...
}
```

**Record the action exclusivity matrix:**

| | -G | -S | -V | -C | -R |
|--|----|----|----|----|----|
| **-G** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **-S** | ❌ | ✅ | ❌ | ❌ | ❌ |
| **-V** | ❌ | ❌ | ✅ | ❌ | ❌ |
| **-C** | ❌ | ❌ | ❌ | ✅ | ❌ |
| **-R** | ❌ | ❌ | ❌ | ❌ | ✅ |

### Step 4: Analyze parameter dependencies

Check for conditions like:
```c
// Required arguments: if missing → usage() or exit()
if (message_file == NULL) usage();

// Conditional defaults: if not provided, use default
if (sig_file == NULL || *sig_file == 0)
    sig_file = append_sig_suffix(message_file);

// Mutual exclusion of alternative flags:
if (pk_file != NULL && pubkey_s != NULL)
    exit_msg("A public key cannot be provided both inline and as a file");
```

**Record dependency rules:**
| Condition | Rule |
|-----------|------|
| `-S` requires `-m <file>` | `-m` is mandatory for sign |
| `-V` requires `-m <file>` | `-m` is mandatory for verify |
| `-p` and `-P` are mutually exclusive | Can't use both at once |
| If `-x` not set, defaults to `<file>.minisig` | `-x` is optional with default |

### Step 5: Identify all flags and their possible values

| Flag | Type | Values | Default | Applies to |
|------|------|--------|---------|-----------|
| `-G` | action | flag | — | generate |
| `-S` | action | flag | — | sign |
| `-V` | action | flag | — | verify |
| `-C` | action | flag | — | change pw |
| `-R` | action | flag | — | recreate pk |
| `-f` | bool | — | off | -G only |
| `-W` | bool | — | off | -G, -C only |
| `-l` | bool | — | off | -S only |
| `-H` | bool | — | off | -V only |
| `-o` | bool | — | off | -V only |
| `-q` | bool | — | off | all |
| `-Q` | bool | — | off | all |
| `-m` | arg | `<file>` | required | -S, -V |
| `-p` | arg | `<file>` | `./minisign.pub` | -G, -S, -V |
| `-P` | arg | `<base64>` | — | -S, -V |
| `-x` | arg | `<file>` | `<file>.minisig` | -S, -V |
| `-s` | arg | `<file>` | `~/.minisign/minisign.key` | -G, -S, -R, -C |
| `-c` | arg | `<string>` | "signature from minisign secret key" | -S only |
| `-t` | arg | `<string>` | timestamp-based | -S only |

---

## Phase 3: Enumerate All Valid Command Combinations

Based on the analysis in Phase 2, enumerate **all valid** command combinations.

### Step 1: Group by action

Each action group is independent (actions are mutually exclusive). Enumerate separately:

| Action Group | Base Command | Optional Flags |
|-------------|-------------|---------------|
| **-G** (generate) | `prog -G` | `-f`, `-W`, `-p <file>`, `-s <file>` |
| **-S** (sign) | `prog -S -m <file>` | `-l`, `-q`, `-Q`, `-p <file>`, `-P <b64>`, `-x <file>`, `-s <file>`, `-c <str>`, `-t <str>` |
| **-V** (verify) | `prog -V -m <file>` | `-H`, `-o`, `-q`, `-Q`, `-p <file>`, `-P <b64>`, `-x <file>` |
| **-C** (change pw) | `prog -C` | `-W`, `-s <file>` |
| **-R** (recreate pk) | `prog -R` | `-p <file>`, `-s <file>` |
| **-v** (version) | `prog -v` | (none, immediate exit) |
| **-h** (help) | `prog -h` | (none, immediate exit) |

### Step 2: Apply parameter constraints

For each action group, apply the dependency and conflict rules:

```c
// Constraints for -V (verify):
//   -m <file>   MANDATORY
//   -p <file>   optional, default = "minisign.pub"
//   -P <b64>    optional, conflicts with -p
//   -x <file>   optional, default = "<file>.minisig"
//   -H          optional bool
//   -o          optional bool
//   -q          optional bool (quiet=1)
//   -Q          optional bool (quiet=2), conflicts with -q
```

Non-conflicting optional booleans should be combined for full coverage.

### Step 3: Generate the combination matrix

For each action group, generate the minimal set of commands that cover all parameter combinations:

| # | Action | Command | Coverage Rationale |
|---|--------|---------|-------------------|
| 1 | -G | `prog -G` | Default key generation |
| 2 | -G | `prog -G -f -W -p <pub> -s <sec>` | All flags combined |
| 3 | -S | `prog -S -m <file>` | Minimal sign |
| 4 | -S | `prog -S -m <file> -l -q -c "c" -t "t"` | Legacy + quiet + comments |
| 5 | -S | `prog -S -m <file1> <file2> -s <sec> -x <sig>` | Multi-file + custom paths |
| 6 | -V | `prog -V -m <file> -p <pub> -x <sig> -q -H -o` | Full verify (deepest chain) |
| 7 | -V | `prog -V -m <file> -P "<b64>"` | Inline pubkey verify |
| 8 | -C | `prog -C` | Default change pw |
| 9 | -C | `prog -C -s <sec> -W` | Custom key + remove pw |
| 10 | -R | `prog -R` | Default recreate pk |

**Save the combination list locally — each tool gets its own parameters and combinations in one block:**

```bash
cat > command_combinations.json << 'EOF'
{
  "project": "minisign",
  "tools": [
    {
      "name": "minisign",
      "entry_file": "src/minisign.c",
      "description": "minisign signature tool",
      "parameters": [
        {"flag": "-G", "type": "action", "arg": "none", "description": "Generate key pair"},
        {"flag": "-S", "type": "action", "arg": "none", "description": "Sign files"},
        {"flag": "-V", "type": "action", "arg": "none", "description": "Verify signature"},
        {"flag": "-m", "type": "flag", "arg": "<file>", "description": "File to sign/verify"},
        {"flag": "-p", "type": "flag", "arg": "<pubkey_file>", "description": "Public key file"}
      ],
      "combinations": [
        {"id": 1, "command": ["minisign", "-G"], "params": {"G": true}},
        {"id": 2, "command": ["minisign", "-S", "-m", "<file>"], "params": {"S": true, "m": "<file>"}},
        {"id": 3, "command": ["minisign", "-V", "-m", "<file>", "-p", "<pub>"], "params": {"V": true, "m": "<file>", "p": "<pub>"}}
      ]
    },
    {
      "name": "tool2",
      "entry_file": "cmd/tool2/main.go",
      "parameters": [
        {"flag": "-K", "type": "layout", "arg": "engine", "description": "Layout engine"}
      ],
      "combinations": [
        {"id": 1, "command": ["tool2", "-Kdot", "-Tpng", "-o", "out.png", "in.gv"], "params": {"K": "dot", "T": "png"}}
      ]
    }
  ]
}
EOF
```

---

## Phase 4: Coverage Evaluation

Rank each command combination by the estimated number of function call paths it exercises.

### Scoring Criteria

| Factor | Points | How to Determine |
|--------|--------|-----------------|
| **Flag count** | +1 per flag | More flags = more branches enabled |
| **Subcommand/mode** | +5 per mode | Different actions (verify vs sign) exercise completely different code |
| **Argument parsing branches** | +2 per arg check | Each `if (flag != NULL)` branch |
| **Conditional code paths** | +3 per `#ifdef`/feature gate | `#ifndef VERIFY_ONLY` blocks |
| **Output flags** | +1 per output mode | `-o`, `-q`, `-Q` change output behavior |
| **Format variants** | +3 per variant | `-l` legacy, `-H` prehashed — different format parsers |

### Rank the Combinations

Based on the analysis, rank combos from most to least coverage:

| Rank | ID | Action | Estimated Paths | Rationale |
|------|----|--------|-----------------|-----------|
| ⭐1 | 6 | verify | Highest | `-V -m -p -x -q -H -o`: calls pubkey_load_file → pubkey_load_string, sig_load (4-line parse), message_load (hashed path), verify (2x crypto_sign_verify), output_file |
| 2 | 4 | sign | High | `-S -l -q -c -t`: full sign pipeline, legacy format, comments |
| 3 | 5 | sign | High | Multi-file sign, custom paths |
| 4 | 7 | verify | Medium-High | Alternative pubkey path (inline b64) |
| 5 | 2 | generate | Medium | Keypair gen + all flags |
| 6 | 1 | generate | Low | Minimal gen |
| 7 | 3 | sign | Low | Minimal sign |
| 8 | 9 | change-pw | Low | Password update |
| 9 | 8 | change-pw | Low | Minimal |
| 10 | 10 | recreate-pk | Low | Minimal |

---

## Phase 5: Function Call Chain Analysis

Pick the **highest-ranked combination** (covers the most function call paths) and trace its full call chain.

### Step 1: Start from main()

```
main()
├─ getopt loop → parse all flags
├─ switch(action) → dispatch to action handler
│   └─ case ACTION_VERIFY:
│       ├─ pubkey_load()
│       └─ verify()
```

### Step 2: Trace each function recursively

For each function called, open the source file and trace into it:

```bash
# Find function definition
grep -rn "^static.* func_name\|^int func_name\|^void func_name" --include="*.c" --include="*.cc" . 2>/dev/null
```

For each function, record:
1. **Function name** and **line number**
2. **Parameters** and **return type**
3. **All callees** (functions it calls internally)
4. **Branch points** (if/switch that create diverging paths)

### Step 3: Build the call tree

Record the full call chain as an indented tree:

```
main()                                            [file.c:N]
  │
  ├─ func_A()                                     [file.c:N]
  │   ├─ fopen()
  │   ├─ fgets()
  │   ├─ trim()                                   [file.c:N]
  │   │   ├─ strlen()
  │   │   └─ memchr()
  │   ├─ func_B()                                 [file.c:N]
  │   │   ├─ malloc()
  │   │   ├─ b64_to_bin()                         [base64.c:N]
  │   │   └─ memcmp()
  │   └─ xfclose()
  │
  └─ func_C()                                     [file.c:N]
      ├─ func_D()                                 [file.c:N]
      │   ├─ fopen()
      │   ├─ fgets()  ← 4 calls
      │   ├─ strncmp()
      │   ├─ trim()
      │   ├─ is_printable()
      │   ├─ b64_to_bin()  ← 2 calls
      │   └─ memcmp()
      ├─ func_E()                                 [file.c:N]
      │   ├─ fopen()
      │   └─ fread()
      └─ crypto_sign_verify_detached()            [libsodium]
```

### Step 4: Save the call tree locally

```bash
cat > call_tree.md << 'TREE_EOF'
# Function Call Chain Analysis

## Target Command
```
prog -V -m <file> -p <pub> -x <sig> -q -H -o
```

## Entry Point
- **File**: `src/prog.c`
- **Function**: `main()` at line 885
- **Language**: C

## Call Tree

```
main()                                            [prog.c:885]
  │
  ├─ getopt() → parse "-V -m -p -x -q -H -o"
  │   ├─ action = ACTION_VERIFY
  │   ├─ message_file = "<file>"
  │   ├─ pk_file = "<pub>"
  │   ├─ sig_file = "<sig>"
  │   ├─ quiet = 1
  │   ├─ allow_legacy = 0
  │   └─ output = 1
  │
  ├─ pubkey_load(pk_file, NULL)                   [prog.c:338]
  │   └─ pubkey_load_file("<pub>")                [prog.c:310]
  │       ├─ fopen()                              ← 读公钥文件
  │       ├─ fgets()  → 读注释行
  │       ├─ xmalloc()
  │       ├─ fgets()  → 读 base64 公钥
  │       ├─ trim()                               [helpers.c:159]
  │       │   ├─ strlen()
  │       │   └─ memchr()
  │       ├─ xfclose()                            [helpers.c:147]
  │       └─ pubkey_load_string(pubkey_s)          [prog.c:292]
  │           ├─ xsodium_malloc()                 [helpers.c:84]
  │           ├─ b64_to_bin()                     [base64.c:7]
  │           └─ memcmp()
  │
  └─ verify(pubkey_struct, "<file>", "<sig>",     [prog.c:496]
            1, 1, 0)
      │
      ├─ sig_load("<sig>", ...)                    [prog.c:206]
      │   ├─ fopen()
      │   ├─ fgets()  → untrusted comment         ← 第1行
      │   ├─ trim()
      │   ├─ strncmp()                            ← check prefix
      │   ├─ xmalloc()
      │   ├─ fgets()  → base64 sig                ← 第2行
      │   ├─ trim()
      │   ├─ fgets()  → trusted comment           ← 第3行
      │   ├─ strncmp()                            ← check prefix
      │   ├─ memmove() → strip prefix
      │   ├─ trim()
      │   ├─ is_printable()                       [prog.c:76]
      │   ├─ xmalloc()
      │   ├─ fgets()  → base64 global_sig         ← 第4行
      │   ├─ trim()
      │   ├─ xfclose()
      │   ├─ xmalloc()                             → SigStruct
      │   ├─ b64_to_bin()                         [base64.c:7]
      │   ├─ memcmp() "Ed"/"ED"
      │   └─ b64_to_bin()                         [base64.c:7]
      │
      ├─ [allow_legacy=0 && hashed=0 → exit(1)]
      │
      ├─ message_load(&message_len, "<file>",     [prog.c:155]
      │                hashed)
      │   └─ message_load_hashed(...)              [prog.c:128]
      │       ├─ fopen()
      │       ├─ crypto_generichash_init()
      │       ├─ fread()  ← loop
      │       │   └─ crypto_generichash_update()
      │       ├─ xfclose()
      │       ├─ xmalloc()
      │       └─ crypto_generichash_final()
      │
      ├─ memcmp() → keynum match
      ├─ crypto_sign_verify_detached()            [libsodium]
      ├─ xmalloc() + memcpy() → sig+comment
      ├─ crypto_sign_verify_detached()            [libsodium]
      │
      └─ output_file("<file>")                     [prog.c:183]
          ├─ fopen()
          ├─ fread() + fwrite(stdout)  ← loop
          └─ xfclose()
```

## Key Statistics
- **Total functions in chain**: 27
- **File I/O calls**: 9 (fopen ×5, fread ×2, fwrite ×1, fgets ×6)
- **Memory operations**: 6 (xmalloc/xsodium_malloc ×5, free ×1)
- **Base64 decodes**: 3 (b64_to_bin ×3)
- **Crypto operations**: 3 (crypto_generichash_* ×3, crypto_sign_verify ×2)
- **String processing**: 5 (trim ×4, strlen ×1, memmove ×1)
- **Comparison checks**: 5 (memcmp ×3, strncmp ×2)

## Input Surfaces
| Input | Source | Functions Involved |
|-------|--------|--------------------|
| Signature file | `-x <sig>` | sig_load: fgets, trim, strncmp, is_printable, b64_to_bin |
| Message file | `-m <file>` | message_load: fopen, fread, crypto_generichash |
| Public key file | `-p <pub>` | pubkey_load_file: fgets, trim, b64_to_bin |
TREE_EOF

echo "Call tree saved to call_tree.md"
```

### Step 5: Generate path coverage summary per function

For each function in the call tree, annotate which line branches are covered:

```bash
cat > coverage_summary.md << 'COV_EOF'
# Function Coverage Analysis

## main() — 100% coverage of verify path
| Line | Code | Status |
|------|------|--------|
| 914  | `while ((opt_flag = getopt(...))` | ✅ |
| 942  | `case 'V': action = ACTION_VERIFY` | ✅ |
| 956  | `case 'h': usage()` | ❌ |
| 958  | `case 'H': allow_legacy = 0` | ✅ |
| 966  | `case 'm': message_file = optarg` | ✅ |
| 972  | `case 'p': pk_file = optarg` | ✅ |
| 996  | `case 'x': sig_file = optarg` | ✅ |
| 978  | `case 'q': quiet = 1` | ✅ |
| 969  | `case 'o': output = 1` | ✅ |
| 1050 | `case ACTION_VERIFY:` | ✅ |

## sig_load() — All 4 lines of signature file parsed
| Step | Function | Line | Status |
|------|----------|------|--------|
| fopen | fopen | 219 | ✅ |
| L1 read | fgets (untrusted comment) | 222 | ✅ |
| L1 check | strncmp(COMMENT_PREFIX) | 228 | ✅ |
| L2 read | fgets (base64 sig) | 235 | ✅ |
| L3 read | fgets (trusted comment) | 241 | ✅ |
| L3 check | strncmp(TRUSTED_COMMENT_PREFIX) | 244 | ✅ |
| L3 strip | memmove | 250 | ✅ |
| L3 validate | is_printable | 256 | ✅ |
| L4 read | fgets (base64 global_sig) | 261 | ✅ |
| Decode 1 | b64_to_bin(SigStruct) | 268 | ✅ |
| Alg check | memcmp(sig_alg) | 274-280 | ✅ |
| Decode 2 | b64_to_bin(global_sig) | 281 | ✅ |

...
COV_EOF
```

---

## Phase 6: Vulnerability Path Scoring

Walk through each command combination's call tree, find potentially dangerous operations along each path, score them, and rank all combinations by total score.

### Step 1: Define CWE vulnerability categories

| CWE ID | Category | 关注的操作类型 | Score |
|--------|----------|---------------|-------|
| CWE-119 | 缓冲区溢出 | 向指针/数组写入时未检查边界 | **10** |
| CWE-134 | 格式化字符串 | 用户数据直接作为格式串参数 | **9** |
| CWE-190 | 整数溢出 | 涉及用户输入的算术运算可能绕开安全检查 | **8** |
| CWE-416 | 释放后使用 | 内存释放后指针仍被使用 | **8** |
| CWE-476 | 空指针解引用 | 指针未判空直接使用 | **5** |
| CWE-125 | 越界读取 | 从数组/缓冲区读取时索引越界 | **7** |
| CWE-787 | 越界写入 | 向缓冲区写入时位置超过边界 | **10** |
| CWE-121 | 栈溢出 | 栈上缓冲区写入过多用户数据 | **9** |
| CWE-122 | 堆溢出 | 堆缓冲区写入超过分配大小的用户数据 | **8** |
| CWE-22 | 路径遍历 | 用户控制的路径未做过滤直接用于文件操作 | **5** |
| CWE-78 | 命令注入 | 用户输入拼接到系统命令中执行 | **10** |
| CWE-704 | 类型混淆 | 不同类型的指针/数据之间强制转换 | **7** |
| CWE-362 | 条件竞争 | 文件/资源的非原子检查再使用操作 | **6** |
| CWE-20 | 输入验证不当 | 用户输入未经合理校验直接使用 | **3** |
| CWE-835 | 无限循环 | 循环条件由用户控制且无终止保障 | **3** |

### Step 2: Walk the call tree and score

For each command combination, walk through its call tree function by function. For each function, check if it contains any of the operations above.

```bash
# For each function in the call tree, search for dangerous patterns
# Example: search for risky calls in sig_load()
grep -n "memcpy\|sprintf\|strcpy\|malloc\|fread\|b64_to_bin" src/prog.c | grep -v "^.*//.*"
```

**Scoring process:**

```
Combination: prog -V -m <file> -p <pub> -x <sig> -q -H -o

Walking call tree:
  main()
    ├─ getopt()              → no dangerous ops
    │
    ├─ pubkey_load()
    │   └─ pubkey_load_file()
    │       ├─ fopen()                    [+5  path traversal]
    │       ├─ fgets()                    [safe, bounded by sizeof]
    │       ├─ xmalloc()                  [+2  malloc without NULL check wrapper]
    │       ├─ fgets()                    [safe]
    │       ├─ trim()                     [safe]
    │       ├─ xfclose()                  [safe]
    │       └─ pubkey_load_string()
    │           ├─ xsodium_malloc()       [+2  malloc wrapper]
    │           └─ b64_to_bin()           [+6  base64 decode into fixed PubkeyStruct buffer]
    │
    └─ verify()
        ├─ sig_load()
        │   ├─ fopen()                    [+5  path traversal]
        │   ├─ fgets() ×4                [safe, bounded]
        │   ├─ strncmp() ×2              [safe]
        │   ├─ trim() ×4                  [safe]
        │   ├─ is_printable()             [safe]
        │   ├─ memmove()                  [+10 buffer overflow — memmove with strlen]
        │   ├─ xmalloc() ×2               [+2 ×2 = +4]
        │   ├─ b64_to_bin() ×2            [+6 ×2 = +12 — user base64 into fixed SigStruct/global_sig]
        │   └─ memcmp() ×2                [safe]
        │
        ├─ message_load()
        │   └─ message_load_hashed()
        │       ├─ fopen()                [+5]
        │       ├─ fread() → buf[65536]   [+9 stack buffer — fread into stack buffer]
        │       └─ xmalloc()              [+2]
        │
        ├─ memcmp()                       [safe]
        ├─ crypto_sign_verify_detached()  [safe — libsodium, no user buffer manipulation]
        └─ output_file()
            ├─ fopen()                    [+5]
            ├─ fread() → buf[65536]       [+9 stack buffer]
            └─ xfclose()                  [safe]

Total score: 5+2+6 + 5+10+4+12 + 5+9+2 + 5+9 = 74
```

### Step 3: Score each combination and rank

Score all command combinations from Phase 3/4 using the same walkthrough:

| Rank | ID | Command | Vulnerability Score | Top Risk Operations |
|------|----|---------|-------------------|---------------------|
| ⭐1 | 6 | `-V -m -p -x -q -H -o` | **74** | b64_to_bin ×3, memmove, fread(stack) ×2, fopen ×3 |
| 2 | 7 | `-V -m -P <b64>` | **68** | b64_to_bin ×3, memmove, fread(stack), fopen ×2 |
| 3 | 4 | `-S -m -l -q -c -t` | **50** | b64_to_bin (write), fopen ×2, fread(stack) |
| 4 | 5 | `-S -m <f1> <f2> -s -x` | **48** | b64_to_bin, fopen ×3, fread(stack) |
| 5 | 3 | `-S -m` | **38** | b64_to_bin, fopen ×2, fread(stack) |
| 6 | 2 | `-G -f -W -p -s` | **15** | fopen ×2, xmalloc ×2 |
| 7 | 1 | `-G` | **10** | fopen ×2 |
| 8 | 9 | `-C -s -W` | **8** | fopen, xmalloc |
| 9 | 8 | `-C` | **5** | fopen |
| 10 | 10 | `-R` | **5** | fopen |

### Step 4: Save the scoring results — per tool

Score all command combinations from Phase 3/4 and save them organized by tool. Each tool gets its own section with ranked combinations and per-function vulnerability details.

```markdown
# Vulnerability Path Scoring Results

## Methodology
Each function in the call chain is examined for dangerous operations.
Scores are assigned based on vulnerability category (buffer overflow = 10, down to unsafe atoi = 3).

---

## Tool: <tool_name_1>

### 🥇 Rank 1: <full command> — Score: <N>
| Function | File | Vulnerability | Line(s) | Score | Details |
|----------|------|--------------|---------|-------|---------|
| <func_name> | <file.c> | <CWE category> | <line> | <N> | <description> |

**Key risk**: <summary>

### 🥈 Rank 2: <full command> — Score: <N>
...

---

## Tool: <tool_name_2>
...

---

## Summary
| Score Range | Combinations | Risk Level |
|-------------|-------------|------------|
| 60+ | <N> | 🔴 High |
| 30-59 | <N> | 🟡 Medium |
| 0-29 | <N> | 🟢 Low |
```

---

## Output Files

After all phases complete, the following files are saved locally.(Just four files) For projects with multiple CLI tools, each file contains data for ALL tools:

| File | Description |
|------|-------------|
| `command_combinations.json` | Top-level `tools[]` array, each entry = one tool with its own `parameters` + `combinations` |
| `call_tree.md` | Full function call chain trees for the top-ranked command of each tool |
| `coverage_summary.md` | Per-function line coverage annotation per tool |
| `vulnerability_path_scores.md` | Ranked vulnerability path scores per command combination, per tool |

---

## Trigger Examples

When user says any of these, activate this skill:
- "Analyze program X's CLI structure"
- "Trace the call chain of X"
- "帮我分析 X 的调用链"
- "Find all command combinations for X"
- "What functions does X call when running with -V?"
- "Map out the code paths for X's arguments"
