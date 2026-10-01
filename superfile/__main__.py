"""SUPERFILE — package entry: python3 -m superfile [command]."""

from __future__ import annotations

import json
import sys


def main():
    args = sys.argv[1:]
    cmd = args[0] if args else "serve"

    if cmd in ("serve", "ui", "app"):
        host, port = "0.0.0.0", 8765
        open_browser = "--open" in args
        for a in args:
            if a.startswith("--port="):
                port = int(a.split("=", 1)[1])
            if a.startswith("--host="):
                host = a.split("=", 1)[1]
        from .server import serve
        serve(host=host, port=port, open_browser=open_browser)
        return

    if cmd == "demo":
        from . import demo
        out = demo.generate_all()
        print(json.dumps({"created": out}, indent=2))
        return

    if cmd == "info":
        from . import pipeline
        obj = pipeline.import_file(args[1])
        rep = pipeline.inspect_object(obj)
        print(json.dumps(rep, indent=2, default=str))
        return

    if cmd == "convert":
        from . import pipeline
        obj = pipeline.import_file(args[1])
        fmt = args[3] if len(args) > 3 else args[2].rsplit(".", 1)[-1]
        res = pipeline.export_object(obj, fmt)
        with open(args[2], "wb") as fh:
            fh.write(res.data)
        print(json.dumps({"output": args[2], "bytes": len(res.data),
                          "kind": res.kind, "notes": res.notes}, indent=2))
        return

    if cmd == "test":
        import tests.test_all as t
        sys.exit(t.main())

    print(__doc__)
    print("commands: serve | demo | info <file> | convert <in> <out> [fmt] | test")
    sys.exit(1)


if __name__ == "__main__":
    main()
