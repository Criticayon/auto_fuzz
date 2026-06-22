"""CLI entry point: python -m pipeline  →  Control Center (Web UI)
   python -m pipeline /path/to/target --phase N  →  Headless mode
"""

import sys

if len(sys.argv) > 1 and not sys.argv[1].startswith("-"):
    from pipeline.orchestrator import main
    main()
else:
    from pipeline.webui import main as ui_main
    ui_main()