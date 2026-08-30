"""A DNS resolver that records what a sandboxed tool tried to look up.

Enforcement without attribution loses the interesting fact. Inside the sandbox
a tool that opens a raw socket to a hostname fails during name resolution, and
CPython resolves *before* it raises the `socket.connect` audit event -- so no
event fires, the harness observes nothing, and "was prevented" is
indistinguishable from "never tried".

This closes that. The sandbox's only nameserver is this sink. Every query is
recorded as a `dns.query` event naming the host, and then answered NXDOMAIN,
so nothing resolves and the attempt is still on the record. A tool that tries
to phone home is now visible doing it, precisely because it failed.

The sink deliberately resolves NOTHING, including allowlisted hosts: inside
the sandbox the only permitted route out is the HTTP proxy, which does its own
resolution on the outside network. A tool reaching the proxy never needs DNS;
a tool bypassing the proxy is exactly what we want to catch.

Only the question name is parsed. The sink never forwards, never caches, and
never answers with an address, so it cannot be turned into a resolver for the
thing it is watching.
"""

from __future__ import annotations

import json
import os
import socket
import sys
import threading
import time


def parse_question(packet):
    """The queried name and type from a DNS query, or (None, None).

    Only the first question is read, which is all a normal resolver sends.
    Compression pointers cannot appear in a question's QNAME, so a simple
    label walk is correct here.
    """
    if len(packet) < 12:
        return None, None
    qdcount = int.from_bytes(packet[4:6], "big")
    if qdcount < 1:
        return None, None
    labels = []
    i = 12
    while i < len(packet):
        length = packet[i]
        if length == 0:
            i += 1
            break
        if length & 0xC0:          # a pointer has no place in a question
            return None, None
        i += 1
        if i + length > len(packet):
            return None, None
        labels.append(packet[i:i + length].decode("ascii", "replace"))
        i += length
    qtype = None
    if i + 2 <= len(packet):
        qtype = int.from_bytes(packet[i:i + 2], "big")
    return (".".join(labels) if labels else None), qtype


def nxdomain(packet):
    """An NXDOMAIN answer echoing the query's id and question section."""
    if len(packet) < 12:
        return b""
    out = bytearray(packet[:12])
    out[2] = 0x81          # QR=1, RD copied as set by the client
    out[3] = 0x83          # RA=0, RCODE=3 (name error)
    out[6:8] = b"\x00\x00"  # ANCOUNT
    out[8:10] = b"\x00\x00"  # NSCOUNT
    out[10:12] = b"\x00\x00"  # ARCOUNT
    return bytes(out) + packet[12:]


TYPES = {1: "A", 28: "AAAA", 5: "CNAME", 15: "MX", 16: "TXT", 12: "PTR"}


class DnsSink:
    def __init__(self, log_path=None, host="0.0.0.0", port=53, echo=True):
        self.echo = echo
        self._log_fd = -1
        if log_path:
            try:
                self._log_fd = os.open(log_path,
                                       os.O_WRONLY | os.O_CREAT | os.O_APPEND)
            except OSError:
                self._log_fd = -1
        self._lock = threading.Lock()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, port))
        self.host, self.port = self.sock.getsockname()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def start(self):
        self._thread.start()
        return self

    def stop(self):
        self._stop.set()
        try:
            self.sock.close()
        except OSError:
            pass

    def _emit(self, name, qtype):
        row = {"t": time.time(), "event": "dns.query", "host": name,
               "qtype": TYPES.get(qtype, str(qtype)), "answered": "NXDOMAIN"}
        text = json.dumps(row)
        with self._lock:
            if self._log_fd >= 0:
                os.write(self._log_fd, (text + "\n").encode("utf-8", "replace"))
            if self.echo:
                sys.stdout.write(text + "\n")
                sys.stdout.flush()

    def _serve(self):
        while not self._stop.is_set():
            try:
                packet, addr = self.sock.recvfrom(4096)
            except OSError:
                break
            try:
                name, qtype = parse_question(packet)
                if name:
                    self._emit(name, qtype)
                self.sock.sendto(nxdomain(packet), addr)
            except Exception:
                pass


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 53
    sink = DnsSink(os.environ.get("SAYDO_DNS_LOG"), port=port).start()
    print("saydo dns sink on {}:{} [records every query, answers NXDOMAIN]"
          .format(sink.host, sink.port), flush=True)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        sink.stop()


if __name__ == "__main__":
    main()
