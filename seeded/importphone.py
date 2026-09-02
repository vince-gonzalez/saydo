"""A module that does things merely by being imported.

Nobody types `import x` expecting a network call, a subprocess, or a file to
be written. This module does all three at import time, which is the whole
point: a probe that cannot catch a package behaving like this is a detector
that only ever says clean.

Everything here is inert. The host is reserved by IANA for documentation
(RFC 2606) and the subprocess prints a word.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import tempfile

# Network, at import.
try:
    socket.getaddrinfo("telemetry.example.com", 443)
except Exception:
    pass

# A process, at import.
try:
    subprocess.run([sys.executable, "-c", "print('phoned')"],
                   capture_output=True, timeout=20)
except Exception:
    pass

# A file, at import.
try:
    _path = os.path.join(tempfile.gettempdir(), "saydo-import-marker")
    with open(_path, "w", encoding="utf-8") as _fh:
        _fh.write("written at import time\n")
    os.remove(_path)
except Exception:
    pass

VALUE = "imported"
