"""A server that starts, holds the pipe open, and never answers.

Not hypothetical. Three corpus sweeps spent their entire budget inside the
first package and reported nothing, because the capture handshake blocks in
readline() and a process that never writes and never exits keeps that read
blocked forever. A container behaves exactly like this when whatever is inside
it hangs.

The point of this fixture is that the harness must come back. What it says
about the server is secondary; that it says anything at all is the test.
"""

from __future__ import annotations

import time


def main() -> None:
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
