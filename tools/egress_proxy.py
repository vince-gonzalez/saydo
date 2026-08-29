"""A boundary egress monitor: a logging HTTP/HTTPS proxy.

The audit-hook monitor watches the Python runtime, so it only sees Python and
a native extension can slip past it. This watches the NETWORK instead, at a
boundary outside the process: the server under test is launched with
HTTP_PROXY/HTTPS_PROXY pointing here, so every HTTP request and every HTTPS
tunnel it opens passes through this proxy, whatever language it is written in.

It does not decrypt anything. An HTTPS request arrives as a CONNECT line that
names the destination host and port in the clear -- that hostname is exactly
what an egress allowlist is about -- and the proxy then blindly pipes the
encrypted bytes through. So it learns WHERE the tool connected, never WHAT it
sent.

Each connection is logged as one JSON line to the file named by
SAYDO_EGRESS_LOG, in the same shape the harness reads from the audit-hook log
(t, event, host), so the two evidence streams merge without special-casing.

Honest limits, stated so no receipt overclaims:
  - A tool that opens a raw socket to a bare IP and ignores the proxy env
    bypasses this. Enforcing "no route except the proxy" needs a network
    namespace / firewall, i.e. the container host the hosted service runs on.
    Here the proxy OBSERVES the well-behaved path; it does not COMPEL it.
  - Combined with the audit hook (which does see a Python raw socket), the two
    cover more together than either alone.

Run standalone for a smoke test:
    SAYDO_EGRESS_LOG=egress.log python egress_proxy.py 8899
"""

from __future__ import annotations

import json
import os
import select
import socket
import sys
import threading
import time


class EgressProxy:
    def __init__(self, log_path, host="127.0.0.1", port=0):
        self.log_path = log_path
        self._log_fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND)
        self._log_lock = threading.Lock()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, port))
        self.sock.listen(64)
        self.host, self.port = self.sock.getsockname()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    @property
    def address(self):
        return "http://{}:{}".format(self.host, self.port)

    def start(self):
        self._thread.start()
        return self

    def stop(self):
        self._stop.set()
        try:
            # Unblock accept() with a throwaway connection.
            s = socket.create_connection((self.host, self.port), timeout=1)
            s.close()
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass

    def _emit(self, host, port, scheme, method):
        row = {"t": time.time(), "event": "proxy.connect",
               "host": host, "port": port, "scheme": scheme, "method": method}
        line = (json.dumps(row) + "\n").encode("utf-8", "replace")
        with self._log_lock:
            os.write(self._log_fd, line)

    def _serve(self):
        while not self._stop.is_set():
            try:
                client, _ = self.sock.accept()
            except OSError:
                break
            threading.Thread(target=self._handle, args=(client,),
                             daemon=True).start()

    def _handle(self, client):
        try:
            client.settimeout(30)
            head = b""
            while b"\r\n" not in head:
                chunk = client.recv(4096)
                if not chunk:
                    client.close()
                    return
                head += chunk
                if len(head) > 65536:
                    client.close()
                    return
            first, _, rest = head.partition(b"\r\n")
            parts = first.decode("latin-1").split()
            if len(parts) < 2:
                client.close()
                return
            method, target = parts[0], parts[1]

            if method.upper() == "CONNECT":
                host, _, port = target.partition(":")
                port = int(port or 443)
                self._emit(host, port, "https" if port == 443 else "tcp",
                           "CONNECT")
                self._tunnel(client, host, port)
            else:
                # Absolute-form request line: METHOD http://host[:port]/path
                host, port = _host_from_absolute(target)
                if host:
                    self._emit(host, port, "http", method.upper())
                self._forward_http(client, host, port, head)
        except Exception:
            try:
                client.close()
            except OSError:
                pass

    def _tunnel(self, client, host, port):
        try:
            upstream = socket.create_connection((host, port), timeout=15)
        except OSError:
            client.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            client.close()
            return
        client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        _pipe(client, upstream)

    def _forward_http(self, client, host, port, initial):
        if not host:
            client.close()
            return
        try:
            upstream = socket.create_connection((host, port or 80), timeout=15)
        except OSError:
            client.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            client.close()
            return
        upstream.sendall(initial)
        _pipe(client, upstream)


def _host_from_absolute(target):
    if "://" not in target:
        return None, None
    rest = target.split("://", 1)[1]
    authority = rest.split("/", 1)[0]
    host, _, port = authority.partition(":")
    return host, int(port) if port else 80


def _pipe(a, b):
    socks = [a, b]
    try:
        while True:
            r, _, _ = select.select(socks, [], [], 60)
            if not r:
                break
            for s in r:
                data = s.recv(65536)
                if not data:
                    return
                (b if s is a else a).sendall(data)
    except OSError:
        pass
    finally:
        for s in socks:
            try:
                s.close()
            except OSError:
                pass


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    log = os.environ.get("SAYDO_EGRESS_LOG", "egress.log")
    proxy = EgressProxy(log, port=port).start()
    print("egress proxy on {} -> {}".format(proxy.address, log))
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        proxy.stop()


if __name__ == "__main__":
    main()
