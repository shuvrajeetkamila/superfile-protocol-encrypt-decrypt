# How to add a new format to SUPERFILE
# =====================================
#
# 1. Read examples/new_format_adapter/ppm_adapter.py  (heavily commented)
# 2. Copy it into the plugin directory:
#
#        cp examples/new_format_adapter/ppm_adapter.py plugins/ppm_adapter.py
#
# 3. Restart the app (or run tests) — the format appears in the registry,
#    conversion matrix and creator menu automatically.
#
# The protocol, object model and UI do not change.  See docs/ADAPTER_API.md.
