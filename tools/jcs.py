"""RFC 8785 (JCS) canonicalization, restricted to the subset this project needs.

A tool definition digest is sha256 over the JCS form of {name, description,
inputSchema}. Getting canonicalization almost right is worse than refusing,
because two implementations that disagree silently produce two different
digests for the same definition and every comparison downstream reports drift
that is not there.

So this implements the subset that MCP tool definitions actually occupy, and
refuses the rest:

  - Object keys must be strings of basic-plane characters. RFC 8785 sorts keys
    by UTF-16 code units; Python sorts str by code point. The two orders agree
    everywhere except keys containing supplementary-plane characters, so those
    keys are refused rather than sorted wrong.
  - Numbers must be integers within the range JSON interoperates over
    (|n| <= 2**53 - 1). RFC 8785 serializes numbers with ECMAScript rules,
    which for non-integers differ from repr() in ways that matter. Tool
    definitions do not need floats; a definition that contains one is refused.

Within that subset, output is byte-identical to RFC 8785: keys sorted, no
whitespace, minimal string escaping, non-ASCII literal.
"""

from __future__ import annotations

import hashlib
import json


class Unrepresentable(ValueError):
    """The value is outside the subset this canonicalizer will vouch for."""


_MAX_SAFE = 2 ** 53 - 1


def _check(value, path):
    if isinstance(value, bool) or value is None or isinstance(value, str):
        if isinstance(value, str):
            return
        return
    if isinstance(value, int):
        if abs(value) > _MAX_SAFE:
            raise Unrepresentable(
                "{}: integer outside +/-(2**53 - 1); its ECMAScript "
                "serialization is not guaranteed to round-trip".format(path))
        return
    if isinstance(value, float):
        raise Unrepresentable(
            "{}: non-integer number; refusing rather than risking a "
            "serialization that differs from RFC 8785".format(path))
    if isinstance(value, list):
        for i, item in enumerate(value):
            _check(item, "{}[{}]".format(path, i))
        return
    if isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                raise Unrepresentable("{}: non-string key".format(path))
            if any(ord(c) > 0xFFFF for c in key):
                raise Unrepresentable(
                    "{}: key {!r} contains supplementary-plane characters; "
                    "UTF-16 sort order would differ from code-point sort"
                    .format(path, key))
            _check(value[key], "{}.{}".format(path, key))
        return
    raise Unrepresentable("{}: {} is not JSON".format(path, type(value).__name__))


def canonical(value) -> bytes:
    """The RFC 8785 canonical form, as bytes, or Unrepresentable."""
    _check(value, "$")
    # Within the checked subset, json.dumps produces the RFC 8785 byte
    # stream: sort_keys sorts by code point (equal to UTF-16 order here),
    # separators remove whitespace, ensure_ascii=False leaves non-ASCII
    # literal, and the default string escaper emits exactly the two-character
    # escapes and \u00XX control escapes the RFC requires.
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def digest(value) -> str:
    """'sha256:<hex>' over the canonical form."""
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()
