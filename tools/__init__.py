"""SayDo — does the tool do what it says?

This directory is the repository's `tools/` and the installed package's
`saydo/`. setuptools maps one onto the other, so nothing had to move and every
path that CI already proves stays exactly where it was.

The modules here import each other by bare name -- `import jcs`, `import plans`
-- because that is how they run from the repository, and those are the paths
the test suite and the CI workflows exercise. Rewriting them into relative
imports to satisfy packaging would mean shipping code that had never been run
the way it is written. So the package puts its own directory on sys.path and
the proven import paths keep working, installed or not.
"""

import os
import sys

__version__ = "0.1.0"

# The bridge described above. Idempotent, and it appends nothing that is not
# already this package's own directory.
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
