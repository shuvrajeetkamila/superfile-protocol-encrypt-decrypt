# SUPERFILE plugin directory
#
# Drop any `*_adapter.py` module here.  Each must expose either
#   ADAPTERS = [FormatAdapter(), ...]
# or
#   def register(registry): ...
#
# Try it:
#   cp ../examples/new_format_adapter/ppm_adapter.py ppm_adapter.py
#
# Plugins are trusted admin-installed code (like browser extensions).
# They are loaded at startup; see docs/ADAPTER_API.md and docs/SECURITY_MODEL.md.
