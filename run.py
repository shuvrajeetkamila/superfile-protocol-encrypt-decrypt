#!/usr/bin/env python3
"""
SUPERFILE launcher — starts the offline desktop application.

    python3 run.py            # serve UI on http://localhost:8765
    python3 run.py --open     # also open a browser window
    python3 run.py --demo     # generate demo sample files first
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def main():
    if "--demo" in sys.argv:
        from superfile import demo
        demo.generate_all()
    from superfile.server import serve
    port = 8765
    for a in sys.argv[1:]:
        if a.startswith("--port="):
            port = int(a.split("=", 1)[1])
    serve(host="0.0.0.0", port=port, open_browser="--open" in sys.argv)


if __name__ == "__main__":
    main()
