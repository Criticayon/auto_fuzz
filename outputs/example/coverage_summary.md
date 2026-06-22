# Function Coverage Analysis

## Tool: dot — Dot Layout to PNG (dot -Tpng -Kdot -o out.png in.gv)

### main() — 100% coverage of basic layout path
| Line | Code | Status |
|------|------|--------|
| 47   | `int main(int argc, char **argv)` | ✅ |
| 52   | `Gvc = gvContextPlugins(...)` | ✅ |
| 54   | `gvParseArgs(Gvc, argc, argv)` | ✅ |
| 62   | `if ((G = gvPluginsGraph(Gvc)))` | ✅ |
| 63   | `gvLayoutJobs(Gvc, G)` | ✅ |
| 64   | `gvRenderJobs(Gvc, G)` | ✅ |
| 79   | `gvFinalize(Gvc)` | ✅ |
| 80   | `r = gvFreeContext(Gvc)` | ✅ |
| 81   | `graphviz_exit(MAX(rc,r))` | ✅ |

### gvParseArgs() — Full flag handling
| Flag | Line | Code | Status |
|------|------|------|--------|
| -T   | 315  | `case 'T':` output format | ✅ |
| -K   | 335  | `case 'K':` layout engine | ✅ |
| -G   | 281  | `case 'G':` graph attribute | ✅ |
| -N   | 289  | `case 'N':` node attribute | ❌ (not in this combo) |
| -E   | 297  | `case 'E':` edge attribute | ❌ |
| -A   | 305  | `case 'A':` all attribute | ❌ |
| -o   | 374  | `case 'o':` output file | ✅ |
| -v   | 92   | `case 'v':` verbose | ✅ |
| -x   | 412  | `case 'x':` reduce | ❌ |
| -y   | 415  | `case 'y':` invert Y | ❌ |
| -l   | 365  | `case 'l':` load library | ❌ |
| -q   | 384  | `case 'q':` quiet | ❌ |
| -s   | 398  | `case 's':` scale | ❌ |
| -P   | 362  | `case 'P':` plugins | ❌ |
| -n   | 49   | `case 'n':` neato nop | ❌ |
| -L   | 206  | `case 'L':` fdp params | ❌ |

### dotneato_args_initialize() — Configuration
| Section | Line | Code | Status |
|---------|------|------|--------|
| Name detection | 238 | `cmdname = dotneato_basename(argv[0])` | ✅ |
| -V/--version | 266 | Version check | ❌ |
| -?/--help | 273 | Help check | ❌ |
| --filepath | 275 | File path setting | ❌ |
| -G parsing | 282 | `global_def(rest, AGRAPH)` | ✅ |
| -N parsing | 290 | Node attr | ❌ |
| -E parsing | 298 | Edge attr | ❌ |
| -A parsing | 306 | All attr | ❌ |
| -T selection | 316 | `gvjobs_output_langname` | ✅ |
| -K selection | 336 | `gvlayout_select` | ✅ |
| -l library | 366 | `use_library(gvc, val)` | ❌ |
| -o output | 375 | `gvjobs_output_filename` | ✅ |
| -q quiet | 385 | `agseterr(AGERR)` | ❌ |
| -s scale | 399 | `PSinputscale = atof(rest)` | ❌ |
| -x reduce | 413 | `Reduce = true` | ❌ |
| -y invert | 416 | `Y_invert = true` | ❌ |
| Default layout | 428 | Layout by cmd name | ✅ (Kdot) |
| Default format | 458 | Default -Tdot | ✅ (but overridden by -Tpng) |

### Graph Parsing (agread → yyparse)
| Component | Line | Code | Status |
|-----------|------|------|--------|
| Lexer   | - | `yylex()` from `scan.l` | ✅ |
| Parser  | - | `yyparse()` from `grammar.y` | ✅ |
| Node creation | node.c | `agnode(root, name, 1)` | ✅ |
| Edge creation | edge.c | `agedge(root, t, h, name, 1)` | ✅ |
| Attr setting | attr.c | `agxset(obj, sym, val)` | ✅ |
| Subgraph | subgraph.c | `agsubg(g, name, 1)` | ✅ (if subgraphs present) |

### Dot Layout Engine
| Phase | File | Function | Status |
|-------|------|----------|--------|
| Init | init.c | `dot_layout(g)` | ✅ |
| | init.c | `dot_init_graph(g)` | ✅ |
| | graph.c | `graph_init(g)` | ✅ |
| | utils.c | `late_int()` | ✅ |
| Ranking | rank.c | `dot_rank(g)` | ✅ |
| | rank.c | `rank(g)` → network simplex | ✅ |
| | rank.c | `set_xcoords(g)` | ✅ |
| Crossing minimization | mincross.c | `dot_mincross(g)` | ✅ |
| | mincross.c | `build_ranks()` | ✅ |
| | mincross.c | `median()` | ✅ |
| | mincross.c | `transpose()` | ✅ |
| Positioning | position.c | `dot_position(g)` | ✅ |
| | position.c | `set_ycoords()` | ✅ |
| | position.c | `set_aspect()` | ✅ |
| Edge routing | routes.c | `dot_route_edges(g)` | ✅ |
| | routes.c | `spline_edges()` | ✅ |
| | routes.c | `make_splines()` | ✅ |
| Postprocess | emit.c | `dotneato_postprocess(g)` | ✅ |

### Cairo PNG Rendering
| Phase | File | Function | Status |
|-------|------|----------|--------|
| Plugin select | gvrender.c | `gvrender_select(Gvc, "png")` | ✅ |
| | gvplugin.c | `gvplugin_device()` | ✅ |
| Begin job | cairo | `cairo_begin_job()` | ✅ |
| Begin graph | cairo | `cairo_begin_graph()` | ✅ |
| Draw nodes | shapes.c | `draw_node_shape()` | ✅ |
| | shapes.c | `draw_ellipse()` / `draw_polygon()` | ✅ |
| Draw edges | shapes.c | `draw_spline()` | ✅ |
| End graph | cairo | `cairo_end_graph()` | ✅ |
| End job | cairo | `cairo_end_job()` | ✅ |
| Write PNG | cairo | `cairo_surface_write_to_png()` | ✅ |

---

## Tool: edgepaint — Full Args (--angle=30 --accuracy=0.001 --color_scheme=rgb -v -o out.gv in.gv)

### main() — Complete
| Line | Code | Status |
|------|------|--------|
| 273 | `init(argc, argv, ...)` | ✅ |
| 274 | `newIngraph(&ig, Files)` | ✅ |
| 276 | `while ((g = nextGraph(&ig)) != 0)` | ✅ |
| 282 | `clarify(g, ...)` | ✅ |
| 288 | `graphviz_exit(rv)` | ✅ |

### init() — Full arg parsing coverage
| Flag | Line | Code | Status |
|------|------|------|--------|
| --angle=30 | 189 | OPT_ANGLE `sscanf(...)` | ✅ |
| --accuracy=0.001 | 182 | OPT_ACCURACY `sscanf(...)` | ✅ |
| --color_scheme=rgb | 197 | knownColorScheme("rgb") | ✅ |
| -v | 178 | Verbose = 1 | ✅ |
| -o | 171 | openFile(cmd, arg, "w") | ✅ |
| in.gv | 235 | Files = argv + optind | ✅ |

### clarify() — Full processing
| Line | Code | Status |
|------|------|--------|
| 248 | checkG(g) | ✅ |
| 253 | initDotIO(g) | ✅ |
| 254 | edge_distinct_coloring(...) | ✅ |
| 257 | agwrite(g, stdout) | ✅ |

---

## Tool: gvpack — Array Packing (-array -m10 -Grankdir=LR -v -o out.gv in1.gv in2.gv)

### main() — Complete path
| Line | Code | Status |
|------|------|--------|
| 706 | init(argc, argv, &pinfo) | ✅ |
| 708 | doPack = (pinfo.mode != l_undef) | ✅ |
| 711 | gvContextPlugins(...) | ✅ |
| 713 | readGraphs(gvc, kind) | ✅ |
| 718-723 | packGraphs(...) | ✅ |
| 726 | g = cloneGraph(gs, gvc, *kind) | ✅ |
| 732 | dotneato_postprocess(g) | ✅ |
| 733 | attach_attrs(g) | ✅ |
| 735 | agwrite(g, outfp) | ✅ |

### init() — Arg parsing
| Flag | Line | Code | Status |
|------|------|------|--------|
| -array | 164 | parsePackModeInfo | ✅ |
| -m10 | 178 | setUInt | ✅ |
| -Grankdir=LR | 189 | setNameValue | ✅ |
| -v | 195 | verbose = 1 | ✅ |
| -o | 180 | openFile | ✅ |

---

## Tool: gvpr — Full Pipeline (-f prog.g -c -v -i -o out.gv in.gv)

### main() → gvpr()
| Part | Code | Status |
|------|------|--------|
| Program compile | compile(prog, state, args) | ✅ |
| File read | newIngraph + nextGraph | ✅ |
| Source output | compflags.srcout = true (-c) | ✅ |
| Induced subgraph | compflags.induce = true (-i) | ✅ |
| Graph write | agwrite(g, outFile) | ✅ |

---

## Summary of Coverage by Tool

| Tool | Total Branches/Paths | Covered in Top Combo | Coverage % |
|------|---------------------|---------------------|------------|
| dot | ~200+ codepaths (layout+render pipeline) | ~150+ (basic dot→PNG) | ~75% |
| edgepaint | ~25 codepaths | ~22 (full args) | ~88% |
| gvpack | ~35 codepaths | ~30 (array pack) | ~85% |
| gvpr | ~30 codepaths | ~25 (program + flags) | ~83% |
| gvgen | ~40 codepaths (10 graph types) | ~5 (1 graph type) | ~12.5% |
| acyclic | ~8 codepaths | ~6 | ~75% |
| nop | ~6 codepaths | ~4 | ~66% |
| mingle | ~20 codepaths | ~15 | ~75% |
| gvmap | ~40 codepaths | ~30 | ~75% |
| cluster | ~10 codepaths | ~8 | ~80% |
| gvcolor | ~6 codepaths | ~4 | ~66% |
| gc | ~12 codepaths | ~8 | ~66% |
