# Function Call Chain Analysis

## Tool: dot (Main Rendering Program)

### Target Command
```
dot -Tpng -Kdot -o out.png -v -Grankdir=LR in.gv
```
This combination covers the deepest and most typical code path: file I/O, DOT graph parsing, dot layout engine, and PNG rendering.

### Entry Point
- **File**: `cmd/dot/dot.c`
- **Function**: `main()` at line 47
- **Language**: C

### Call Tree

```
main()                                                              [cmd/dot/dot.c:47]
  │
  ├─ gvContextPlugins(lt_preloaded_symbols, DEMAND_LOADING)        [lib/gvc/gvc.c]
  │   └─ gvNEWcontext(builtins, demand_loading)                    [lib/gvc/gvc.c]
  │       ├─ gvplugin_load()                                       [lib/gvc/gvplugin.c]
  │       └─ agnew(gvc, ...)                                       [lib/cgraph/graph.c]
  │
  ├─ gvParseArgs(Gvc, argc, argv)                                  [lib/common/args.c:225]
  │   ├─ neato_extra_args(argc, argv)                              [lib/common/args.c:35]
  │   │   └─ checks for -x (Reduce) and -n (Nop) flags
  │   ├─ fdp_extra_args(argc, argv)                                [lib/common/args.c:197]
  │   │   └─ parses -L<param>=<val> flags
  │   ├─ config_extra_args(gvc, argc, argv)                        [lib/common/args.c:81]
  │   │   ├─ -v[lvl] → gvc->common.verbose
  │   │   ├─ -O     → gvc->common.auto_outfile_names
  │   │   └─ -c     → gvc->common.config
  │   └─ dotneato_args_initialize(gvc, argc, argv)                 [lib/common/input.c:222]
  │       ├─ basename parsing for layout engine detection
  │       ├─ loop over argv flags:
  │       │   ├─ -T → gvjobs_output_langname(gvc, "png")          [lib/gvc/gvjobs.c]
  │       │   │   └─ gvplugin_device()                            [lib/gvc/gvplugin.c]
  │       │   ├─ -K → gvlayout_select(gvc, "dot")                 [lib/gvc/gvlayout.c]
  │       │   │   └─ gvplugin_layout()                            [lib/gvc/gvplugin.c]
  │       │   ├─ -G → global_def("rankdir=LR", AGRAPH)            [lib/common/input.c:178]
  │       │   ├─ -o → gvjobs_output_filename(gvc, "out.png")      [lib/gvc/gvjobs.c]
  │       │   └─ -v → already handled earlier
  │       ├─ layout engine selection by cmd name (if no -K)
  │       │   └─ gvlayout_select(gvc, cmdname)
  │       └─ default format: gvjobs_output_langname(gvc, "dot")
  │
  ├─ gvPluginsGraph(Gvc) or gvNextInputGraph(Gvc)                 [lib/common/input.c:212]
  │   └─ File I/O chain:
  │       ├─ agread(inFile, NULL)                                  [lib/cgraph/scan.l:123]
  │       │   ├─ yyparse() → agparser                             [lib/cgraph/grammar.y]
  │       │   │   ├─ agnode()       ← node creation               [lib/cgraph/node.c]
  │       │   │   ├─ agedge()       ← edge creation               [lib/cgraph/edge.c]
  │       │   │   ├─ agsubg()       ← subgraph creation           [lib/cgraph/subgraph.c]
  │       │   │   └─ agset() / agxset()  ← attribute setting      [lib/cgraph/attr.c]
  │       │   ├─ agclose(g)         ← graph cleanup               [lib/cgraph/graph.c]
  │       │   └─ agreseterrors()                                   [lib/cgraph/errors.c]
  │
  ├─ gvLayoutJobs(Gvc, G)                                          [lib/gvc/gvlayout.c]
  │   └─ Layout engine: dot
  │       ├─ dot_layout(g)                                         [lib/dotgen/init.c]
  │       │   ├─ dot_init_graph(g)                                 [lib/dotgen/init.c]
  │       │   │   ├─ aginit()          ← allocate node info        [lib/cgraph/graph.c]
  │       │   │   ├─ graph_init(g)     ← drawing defaults          [lib/common/graph.c]
  │       │   │   └─ late_int()        ← integer attributes        [lib/common/utils.c]
  │       │   ├─ dot_rank(g)           ← node ranking              [lib/dotgen/rank.c]
  │       │   │   ├─ rank(g)           ← network simplex           [lib/dotgen/rank.c]
  │       │   │   │   ├─ longest_path()                            [lib/dotgen/rank.c]
  │       │   │   │   ├─ tighten()                                 [lib/dotgen/rank.c]
  │       │   │   │   └─ blk_restore()                             [lib/dotgen/rank.c]
  │       │   │   └─ set_xcoords(g)    ← x-coordinate assignment   [lib/dotgen/rank.c]
  │       │   ├─ dot_mincross(g)       ← crossing minimization     [lib/dotgen/mincross.c]
  │       │   │   ├─ mincross()                                    [lib/dotgen/mincross.c]
  │       │   │   │   ├─ build_ranks()                             [lib/dotgen/mincross.c]
  │       │   │   │   ├─ median()                                  [lib/dotgen/mincross.c]
  │       │   │   │   ├─ transpose()                               [lib/dotgen/mincross.c]
  │       │   │   │   └─ incr_loop()                               [lib/dotgen/mincross.c]
  │       │   │   └─ flat_edges(g)     ← flat edge handling        [lib/dotgen/mincross.c]
  │       │   ├─ dot_position(g)       ← node positioning          [lib/dotgen/position.c]
  │       │   │   ├─ set_ycoords()     ← y-coordinates             [lib/dotgen/position.c]
  │       │   │   ├─ set_aspect()      ← aspect ratio              [lib/dotgen/position.c]
  │       │   │   └─ set_xcoords()     ← final x-coords            [lib/dotgen/position.c]
  │       │   ├─ dot_sameport(g)       ← edge port assignment      [lib/dotgen/sameport.c]
  │       │   └─ dot_route_edges(g)    ← edge routing              [lib/dotgen/routes.c]
  │       │       ├─ route_edges()                                 [lib/dotgen/routes.c]
  │       │       │   ├─ spline_edges()                            [lib/dotgen/routes.c]
  │       │       │   │   └─ make_splines()                        [lib/dotgen/routes.c]
  │       │       │   └─ add_edge_labels()                         [lib/dotgen/routes.c]
  │       │       └─ state → GVSPLINES                             [lib/common/types.h]
  │       └─ dotneato_postprocess(g)                               [lib/common/emit.c]
  │           ├─ set_bb()              ← bounding box              [lib/common/emit.c]
  │           └─ attach_attrs(g)       ← write attributes          [lib/common/emit.c]
  │
  └─ gvRenderJobs(Gvc, G)                                          [lib/gvc/gvrender.c]
      └─ gvRender(g, "png", outfile)                               [lib/gvc/gvrender.c]
          ├─ gvrender_select(Gvc, "png")                           [lib/gvc/gvrender.c]
          │   └─ gvplugin_device()                                 [lib/gvc/gvplugin.c]
          │       └─ plugin lookup: gvplugin_cairo (lib/gvplugin_cairo.c)
          ├─ gvrender_begin_job(gvc)                               [lib/gvc/gvrender.c]
          │   └─ cairo_begin_job()                                 [plugin/cairo/gvrender_cairo.c]
          │       ├─ cairo_create()                                [libcairo]
          │       └─ cairo_surface_create()                        [libcairo]
          ├─ graph enumeration loop:
          │   ├─ gvrender_begin_graph()                            [lib/gvc/gvrender.c]
          │   │   └─ cairo_begin_graph()                           [plugin/cairo/gvrender_cairo.c]
          │   │       ├─ cairo_scale()                             [libcairo]
          │   │       └─ cairo_translate()                         [libcairo]
          │   ├─ gvrender_begin_node()                             [lib/gvc/gvrender.c]
          │   │   └─ cairo_begin_node()                            [plugin/cairo/gvrender_cairo.c]
          │   │       └─ draw_node_shape()                         [lib/common/shapes.c]
          │   │           ├─ draw_ellipse()                        [lib/common/shapes.c]
          │   │           ├─ draw_polygon()                        [lib/common/shapes.c]
          │   │           ├─ draw_box()                            [lib/common/shapes.c]
          │   │           └─ draw_triangle()                       [lib/common/shapes.c]
          │   ├─ gvrender_begin_edge()                             [lib/gvc/gvrender.c]
          │   │   └─ cairo_begin_edge()                            [plugin/cairo/gvrender_cairo.c]
          │   │       └─ draw_spline()                             [lib/common/shapes.c]
          │   ├─ gvrender_end_graph()                              [lib/gvc/gvrender.c]
          │   │   └─ cairo_end_graph()                             [plugin/cairo/gvrender_cairo.c]
          │   └─ gvrender_end_job()                                [lib/gvc/gvrender.c]
          │       └─ cairo_end_job()                               [plugin/cairo/gvrender_cairo.c]
          │           └─ cairo_surface_write_to_png()              [libcairo]
          │               └─ fopen/fwrite                          [libc/file]
          └─ gvplugin_write_status()                               [lib/gvc/gvplugin.c]

---

## Tool: edgepaint

### Target Command
```
edgepaint --angle=30 --accuracy=0.001 --color_scheme=rgb -v -o out.gv in.gv
```

### Entry Point
- **File**: `cmd/edgepaint/edgepaintmain.c`
- **Function**: `main()` at line 261

### Call Tree

```
main()                                                            [cmd/edgepaint/edgepaintmain.c:261]
  │
  ├─ init(argc, argv, ...)                                        [cmd/edgepaint/edgepaintmain.c:83]
  │   ├─ getopt_long() loop ← optstring: "a:c:r:l:o:s:v?"
  │   │   ├─ -o → openFile(cmd, arg, "w")                         [cmd/tools/openFile.h]
  │   │   │   └─ fopen()                                          [libc]
  │   │   ├─ -v → Verbose = 1
  │   │   ├─ --angle → sscanf(arg, "%lf", angle)                  [libc/stdio]
  │   │   ├─ --accuracy → sscanf(arg, "%lf", accuracy)            [libc/stdio]
  │   │   ├─ --color_scheme → knownColorScheme(arg)               [sparse/color_palette.c]
  │   │   ├─ --random_seed → sscanf(arg, "%d", seed)              [libc/stdio]
  │   │   └─ --lightness → sscanf(arg, "%d,%d", ...)              [libc/stdio]
  │   └─ Files = argv + optind (positional args)
  │
  ├─ newIngraph(&ig, Files)                                       [lib/cgraph/ingraphs.c]
  │
  └─ graph processing loop:
      └─ nextGraph(&ig) → g                                       [lib/cgraph/ingraphs.c]
          └─ clarify(g, angle, accuracy, ...)                     [cmd/edgepaint/edgepaintmain.c:244]
              ├─ checkG(g) → check for loops/multiedges           [cmd/edgepaint/edgepaintmain.c:64]
              │   ├─ agfstnode / agnxtnode                        [lib/cgraph/node.c]
              │   └─ agfstout / agnxtout                          [lib/cgraph/edge.c]
              ├─ initDotIO(g)                                     [sparse/DotIO.c]
              │   └─ agattr() / aginit()                          [lib/cgraph/attr.c]
              └─ edge_distinct_coloring(scheme, ...)              [edgepaint/edge_distinct_coloring.c]
                  ├─ node_distinct_coloring(...)                  [edgepaint/node_distinct_coloring.c]
                  │   ├─ SparseMatrix_import_dot()                [sparse/DotIO.c]
                  │   ├─ get_color_palette()                      [sparse/color_palette.c]
                  │   └─ map_optimal_coloring()                   [sparse/colorutil.c]
                  └─ agwrite(g, stdout)                           [lib/cgraph/io.c]
                      ├─ agwrite_edge()                           [lib/cgraph/io.c]
                      ├─ agwrite_node()                           [lib/cgraph/io.c]
                      └─ agwrite_attr()                           [lib/cgraph/io.c]

---

## Tool: gvpack

### Target Command
```
gvpack -array -m10 -Grankdir=LR -v -o out.gv in1.gv in2.gv
```

### Entry Point
- **File**: `cmd/tools/gvpack.cpp`
- **Function**: `main()` at line 700

### Call Tree

```
main()                                                            [cmd/tools/gvpack.cpp:700]
  │
  ├─ init(argc, argv, &pinfo)                                     [cmd/tools/gvpack.cpp:149]
  │   ├─ getopt() loop ← optstring: ":na:gvum:s:o:G:?"
  │   │   ├─ -a → parsePackModeInfo()                             [lib/pack/pack.c]
  │   │   ├─ -n → parsePackModeInfo("node", ...)
  │   │   ├─ -g → parsePackModeInfo("graph", ...)
  │   │   ├─ -m → setUInt(&pinfo->margin, optarg)                [cmd/tools/gvpack.cpp:123]
  │   │   │   └─ strtol(arg, &p, 10)                              [libc/stdlib]
  │   │   ├─ -s → gname = optarg
  │   │   ├─ -o → openFile("gvpack", optarg, "w")                [cmd/tools/openFile.h]
  │   │   │   └─ fopen()
  │   │   ├─ -u → pinfo->mode = l_undef
  │   │   ├─ -G → setNameValue(optarg)                            [cmd/tools/gvpack.cpp:106]
  │   │   └─ -v → verbose = 1
  │   └─ argv += optind
  │
  ├─ gvContextPlugins(lt_preloaded_symbols, DEMAND_LOADING)       [lib/gvc/gvc.c]
  │
  ├─ readGraphs(gvc, kind)                                        [cmd/tools/gvpack.cpp:622]
  │   ├─ newIngraph(&ig, myFiles)                                 [lib/cgraph/ingraphs.c]
  │   └─ loop: nextGraph(&ig) → g
  │       └─ init_graph(g, doPack, gvc)                           [cmd/tools/gvpack.cpp:250]
  │           ├─ aginit() → allocate node/edge/graph records      [lib/cgraph/graph.c]
  │           ├─ graph_init(g)                                    [lib/common/graph.c]
  │           └─ init_nop(g, 0)                                   [lib/common/input.c]
  │
  ├─ packGraphs(gs.size(), gs.data(), 0, &pinfo)                  [lib/pack/pack.c]
  │   └─ pack_graphs()                                            [lib/pack/pack.c]
  │       ├─ compute_bb()                                         [lib/pack/pack.c]
  │       ├─ pack_arrays()                                        [lib/pack/pack.c]
  │       └─ pack_clusters()                                      [lib/pack/pack.c]
  │
  ├─ cloneGraph(gs, gvc, kind)                                    [cmd/tools/gvpack.cpp:535]
  │   ├─ agopen(gname, kind, &AgDefaultDisc)                      [lib/cgraph/graph.c]
  │   ├─ initAttrs(root, gs)                                      [cmd/tools/gvpack.cpp:407]
  │   ├─ cloneSubg(g, ng, G_bb, gnames)                           [cmd/tools/gvpack.cpp:458]
  │   │   ├─ agsubg()                                             [lib/cgraph/subgraph.c]
  │   │   ├─ agnode()                                             [lib/cgraph/node.c]
  │   │   └─ agedge()                                             [lib/cgraph/edge.c]
  │   └─ cloneClusterTree(g, ng)                                  [cmd/tools/gvpack.cpp:513]
  │
  ├─ dotneato_postprocess(g)                                      [lib/common/emit.c]
  ├─ attach_attrs(g)                                              [lib/common/emit.c]
  └─ agwrite(g, outfp)                                            [lib/cgraph/io.c]

---

## Tool: gvpr

### Target Command
```
gvpr -f prog.g -c -v -i -o out.gv in.gv
```

### Entry Point
- **File**: `cmd/gvpr/gvprmain.c`
- **Function**: `main()` at line 22
- **Calls**: `gvpr(argc, argv, &opts)` in `lib/gvpr/gvpr.c`

### Call Tree

```
main()                                                            [cmd/gvpr/gvprmain.c:22]
  │
  └─ gvpr(argc, argv, &opts)                                      [lib/gvpr/gvpr.c]
      │
      ├─ scanArgs(argc, argv)                                     [lib/gvpr/gvpr.c:390]
      │   └─ doFlags(arg, argi, argc, argv, &opts)                [lib/gvpr/gvpr.c:320]
      │       ├─ -f → resolve(optarg, verbose)                    [lib/gvpr/gvpr.c:239]
      │       │   └─ fopen() / access()                           [libc/io]
      │       ├─ -c → compflags.srcout = true
      │       ├─ -i → compflags.induce = true
      │       ├─ -v → opts->verbose = 1
      │       ├─ -o → openOut(optarg)                             [lib/gvpr/gvpr.c]
      │       │   └─ fopen()
      │       │
      │       │ ...program from cmdline or -f...
      │       └─ Input files appended to opts.inFiles
      │
      ├─ compile(prog, state, args)            ← gvpr program     [lib/gvpr/compile.c]
      │   ├─ yyparse() ← grammar.y parsing                        [lib/gvpr/grammar.y]
      │   └─ gvpr_compile(...)                                    [lib/gvpr/compile.c]
      │
      ├─ graph reading:
      │   ├─ newIngraph()                                          [lib/cgraph/ingraphs.c]
      │   └─ nextGraph() → g                                       [lib/cgraph/ingraphs.c]
      │
      └─ graph processing:
          ├─ evalNode(state, prog, xprog, n)                      [lib/gvpr/gvpr.c:467]
          ├─ evalEdge(state, prog, xprog, e)                      [lib/gvpr/gvpr.c:445]
          └─ agwrite(g, outFile)                                  [lib/cgraph/io.c]

---

## Key Statistics Summary

| Tool | Input Surfaces | File I/O | Memory Ops | String Processing | Math/Crypto |
|------|---------------|----------|------------|-------------------|-------------|
| **dot** | .gv file parsing, -G/N/E string attrs, -L params | fopen/fread/agread, cairo S+write | agarrec, a gmalloc, g vcalloc | gvParseArgs string splitting, attribute parsing | geometry (node pos), layout math |
| **edgepaint** | .gv file, --accuracy/--angle/--color_scheme opts | fopen (openFile), agwrite stdout | sparse matrix alloc | sscanf for angle/accuracy/seed, color_xlate | coloring algorithm, sparse matrix ops |
| **gvpack** | .gv files, -G attr, -a packmode string | fopen (openFile), agwrite | gv_calloc for clusters | parsePackModeInfo, setNameValue | bounding box, pack layout math |
| **gvpr** | .gv files, -f program file, -a args | fopen (resolve, openOut), agwrite | compile-time alloc | gvpr language parse (yyparse) | (user-defined programs) |

## Input Surfaces for Fuzzing (All Tools)

| Input Source | Tools Affected | Functions Involved |
|-------------|---------------|--------------------|
| Graph files (.gv/.dot) | ALL | agread() → yyparse() → agnode/agedge/agset |
| -T <format> | dot | gvjobs_output_langname → gvplugin_device |
| -K <layout> | dot | gvlayout_select → gvplugin_layout |
| -G/N/E <attr> | dot | global_def → agattr_text |
| -L <param> | dot | setFDPAttr → strtol/strtod |
| --accuracy/--angle | edgepaint | sscanf into double |
| --color_scheme | edgepaint, gvmap | knownColorScheme, sscanf |
| --random_seed | edgepaint, gvmap | sscanf into int |
| -c <scheme> | gvmap, cluster | sscanf with complex format (_opacity=, %, or string) |
| -a <packmode> | gvpack | parsePackModeInfo |
| -f <program> | gvpr | fopen + yyparse of gvpr language |
| -t/-T/-c/-g/-r (graph types) | gvgen | strtoul (readPos) |
