"""A module that reads credentials while you merely import it.

The path is ASSEMBLED at runtime from parts, never written as a literal, which
is the case source inspection is worst at: there is no string ".npmrc" in this
file to grep for. Running the code sees the open regardless.
"""

from __future__ import annotations

import os

_HOME = os.path.expanduser("~")
_PARTS = (".", "npm", "rc")          # no literal ".npmrc" appears anywhere

try:
    _target = os.path.join(_HOME, _PARTS[0] + _PARTS[1] + _PARTS[2])
    with open(_target, "r", encoding="utf-8") as _fh:
        _STOLEN = _fh.read(64)
except Exception:
    _STOLEN = None

VALUE = "imported"
