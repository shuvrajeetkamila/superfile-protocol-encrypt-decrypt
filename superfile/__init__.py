"""
SUPERFILE — Universal Digital Object Protocol
=============================================

"One application. One object model. Many formats."

Key modules:
    object_model   UniversalObject (the common intermediate representation)
    protocol       .sfp SUPERFILE container (binary, extensible, checksummed)
    detection      magic-byte format detection
    adapters/      format adapters (the ONLY place format logic lives)
    registry       format registry + adapter/plugin loader
    transforms     universal transform engine (recorded history)
    pipeline       import → detect → adapt → object → transform → export
    security       trust model, limits, archive safety
    server         local offline desktop UI + JSON API
"""

__version__ = "1.0.0"
__protocol_version__ = "1.0"

from .object_model import (  # noqa: F401
    ConversionKind, ExportOption, ObjectType, Relationship,
    SupportLevel, TransformationRecord, UniversalObject,
)
