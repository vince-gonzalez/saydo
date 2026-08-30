"""Detect the tool's own input leaving, and refuse to guess when it cannot.

The harness plants a high-entropy marker inside the data it hands a tool. If
that marker appears in something the tool sends out, the tool exfiltrated its
input, and the finding can name the destination.

The hard part is not matching -- it is being honest about payloads that cannot
be read. A tool that gzips, base64s or chunks its upload defeats a naive
substring search, and a FALSE NEGATIVE here is far worse than a false
positive: it would let a receipt say "no data left" when data left. So an
undecodable body is reported as UNEXAMINED, never as clean, and the verdict
that consumes it treats unexamined as not-proven rather than as a pass.

A marker is a random token, not the file's content. Content would have to be
searched for in every possible re-encoding; a token survives most transforms
that preserve bytes, and when it does not survive, the body is reported
unexamined rather than silently missed.
"""

from __future__ import annotations

import base64
import binascii
import gzip
import re
import secrets
import zlib

#: Recognisable in a log at a glance, and vanishingly unlikely by accident.
MARKER_PREFIX = "SAYDO-CANARY-"


def new_marker():
    """A fresh canary token to plant in a tool's input."""
    return MARKER_PREFIX + secrets.token_hex(16)


def _decodings(body):
    """(label, bytes) for each way the body might be carrying the marker.

    Best effort and deliberately shallow: one layer of the common encodings,
    plus the raw bytes. Anything deeper is reported as unexamined instead of
    being chased, because an unbounded decode is a denial-of-service surface
    on our own harness.
    """
    yield "raw", body

    try:
        yield "gzip", gzip.decompress(body)
    except Exception:
        pass
    try:
        yield "deflate", zlib.decompress(body)
    except Exception:
        pass
    try:
        yield "deflate-raw", zlib.decompress(body, -zlib.MAX_WBITS)
    except Exception:
        pass

    # base64 anywhere in the body, not just as the whole body: an exfiltrating
    # tool usually wraps the payload in JSON rather than posting it bare.
    for chunk in re.findall(rb"[A-Za-z0-9+/=]{24,}", body[:262144]):
        try:
            decoded = base64.b64decode(chunk, validate=True)
        except (binascii.Error, ValueError):
            continue
        if decoded:
            yield "base64", decoded


def examine(body, markers):
    """What this request body shows about the markers.

    Returns (verdict, detail) where verdict is one of:

        "match"       a marker was found; the tool sent its input out
        "clean"       the body was fully readable and held no marker
        "unexamined"  the body could not be read, so nothing is claimed
    """
    if body is None:
        return "unexamined", "no body was captured"
    if not body:
        return "clean", "empty body"

    encoded = [m.encode("ascii") for m in markers]
    for label, data in _decodings(body):
        for marker, raw in zip(markers, encoded):
            if raw in data:
                return "match", "canary {} found in the {} body".format(
                    marker[:24] + "...", label)

    # Readable and clean is a real negative; unreadable is not.
    if _looks_textual(body):
        return "clean", "{} bytes examined, no canary".format(len(body))
    return "unexamined", (
        "{} bytes of opaque payload could not be decoded, so its contents are "
        "unknown. This is NOT evidence that nothing left.".format(len(body)))


def _looks_textual(body):
    """Whether the body is plausibly plain text or a common text format.

    Only used to distinguish "read it and found nothing" from "could not read
    it". Anything binary and undecoded is treated as unexamined.
    """
    sample = body[:4096]
    if b"\x00" in sample:
        return False
    try:
        sample.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False
