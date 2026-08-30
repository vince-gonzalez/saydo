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

import base64
import json
import os
import select
import socket
import sys
import threading
import time


class EgressProxy:
    """Observe egress, and -- when an allowlist is supplied -- refuse it.

    `allow=None` (the default) is observe-only: every destination is recorded
    and forwarded. That is the honest posture on a host, where a tool can
    route around the proxy anyway, so refusing here would give a false sense
    of containment.

    `allow={"api.example.com", ...}` is enforcement: a destination outside the
    set is refused with 403 and recorded as `proxy.refused`. This is only
    meaningful when the proxy is the tool's ONLY route out -- i.e. inside the
    container -- which is why the runner, not the proxy, decides.
    """

    def __init__(self, log_path, host="127.0.0.1", port=0, allow=None,
                 echo=False, ca=None, canaries=None):
        self.log_path = log_path
        self.allow = set(allow) if allow is not None else None
        # With a CA, HTTPS is terminated here rather than tunnelled blind, so
        # the body can be examined for the tool's own input leaving. Without
        # one the proxy sees destinations only, which is the honest default:
        # interception is a deliberate act, never something that happens
        # because a flag defaulted to on.
        self.ca = ca
        self.canaries = list(canaries or [])
        # When the proxy runs in its own container the log file is not
        # reachable from outside, so every decision is also written to stdout
        # where `docker logs` captures it as evidence.
        self.echo = echo
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

    def _emit(self, host, port, scheme, method, event="proxy.connect"):
        row = {"t": time.time(), "event": event,
               "host": host, "port": port, "scheme": scheme, "method": method}
        text = json.dumps(row)
        line = (text + "\n").encode("utf-8", "replace")
        with self._log_lock:
            os.write(self._log_fd, line)
            if self.echo:
                sys.stdout.write(text + "\n")
                sys.stdout.flush()

    def _permitted(self, host):
        """True when the destination may be forwarded. Observe-only mode
        permits everything; an allowlist permits exactly what it names."""
        if self.allow is None:
            return True
        return host in self.allow

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
                scheme = "https" if port == 443 else "tcp"
                if not self._permitted(host):
                    self._emit(host, port, scheme, "CONNECT",
                               event="proxy.refused")
                    client.sendall(b"HTTP/1.1 403 Forbidden\r\n"
                                   b"Content-Length: 0\r\n\r\n")
                    client.close()
                    return
                self._emit(host, port, scheme, "CONNECT")
                if self.ca and port == 443:
                    self._intercept(client, host, port)
                else:
                    self._tunnel(client, host, port)
            else:
                # Absolute-form request line: METHOD http://host[:port]/path
                host, port = _host_from_absolute(target)
                if host and not self._permitted(host):
                    self._emit(host, port, "http", method.upper(),
                               event="proxy.refused")
                    client.sendall(b"HTTP/1.1 403 Forbidden\r\n"
                                   b"Content-Length: 0\r\n\r\n")
                    client.close()
                    return
                if host:
                    self._emit(host, port, "http", method.upper())
                self._forward_http(client, host, port, head)
        except Exception:
            try:
                client.close()
            except OSError:
                pass

    def _intercept(self, client, host, port):
        """Terminate TLS, examine what is being sent, then forward it on.

        The tool is not shielded from reality: the connection upstream is made
        with ordinary certificate verification, so a host with a bad
        certificate fails here exactly as it would have failed for the tool.
        Interception is for seeing the payload, not for smoothing the path.
        """
        import ssl
        import tempfile

        client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

        # Upstream FIRST, with ordinary verification. If the real host has a
        # bad certificate the tool must experience a TLS failure, not an HTTP
        # error from us: completing the client handshake before checking
        # upstream would shield the tool from a failure it would really have
        # hit, which is the proxy lying about the world.
        try:
            upstream_ctx = ssl.create_default_context()
            raw = socket.create_connection((host, port), timeout=20)
            upstream = upstream_ctx.wrap_socket(raw, server_hostname=host)
        except ssl.SSLCertVerificationError as e:
            self._note({"event": "upstream.untrusted", "host": host,
                        "detail": str(e)[:160],
                        "meaning": "the real host failed certificate "
                                   "verification; the tool is not shielded "
                                   "from this"})
            # A fatal TLS alert, written before any handshake of ours, so the
            # tool sees a TLS-layer failure rather than a fabricated response.
            try:
                client.sendall(b"\x15\x03\x03\x00\x02\x02\x30")  # unknown_ca
            except OSError:
                pass
            client.close()
            return
        except Exception as e:
            self._note({"event": "upstream.failed", "host": host,
                        "detail": str(e)[:160]})
            client.close()
            return

        cert_pem, key_pem = self.ca.leaf_pem(host)
        # SSLContext.load_cert_chain still wants paths, so the leaf lives
        # briefly in this container's own tmpfs -- never in the sandbox, and
        # never on disk beyond the call.
        with tempfile.TemporaryDirectory() as tmp:
            cert_path = os.path.join(tmp, "leaf.pem")
            key_path = os.path.join(tmp, "leaf.key")
            with open(cert_path, "wb") as fh:
                fh.write(cert_pem)
            with open(key_path, "wb") as fh:
                fh.write(key_pem)
            server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_ctx.load_cert_chain(cert_path, key_path)
            try:
                tls_client = server_ctx.wrap_socket(client, server_side=True)
            except (ssl.SSLError, OSError) as e:
                # A pinned or strict client refuses our certificate. Unlike
                # network enforcement, which the tool cannot decline, TLS
                # inspection is COOPERATIVE -- so this is a coverage gap, and
                # the verdict must treat it as unexamined rather than clean.
                self._note({"event": "exfil.unexamined", "host": host,
                            "detail": "the client rejected the inspection "
                                      "certificate: " + str(e)[:100],
                            "meaning": "payload could not be examined, so "
                                       "whether data left is UNKNOWN"})
                for s in (client, upstream):
                    try:
                        s.close()
                    except OSError:
                        pass
                return

        # The handshake deadline must not become the idle deadline: the socket
        # inherited a short timeout from _handle, which would sever a healthy
        # connection mid-transfer.
        tls_client.settimeout(120)

        try:
            request = _read_http_request(tls_client)
        except Exception:
            request = None
        if request is None:
            for s in (tls_client, upstream):
                try:
                    s.close()
                except OSError:
                    pass
            return
        head, body = request

        self._examine(host, head, body)

        try:
            upstream.sendall(head + b"\r\n\r\n" + (body or b""))
            _pipe_tls(tls_client, upstream)
        finally:
            for s in (tls_client, upstream):
                try:
                    s.close()
                except OSError:
                    pass

    def _examine(self, host, head, body):
        """Record what this request carried, honestly including 'unknown'."""
        if not self.canaries:
            return
        import hashlib
        from canary import examine
        verdict, detail, matched = examine(body, self.canaries)
        # The method, never the path, and a digest, never the body. A receipt
        # is published: a request path can carry a token and the plaintext can
        # carry the tool's own credentials. The digest is enough to show two
        # requests were identical without disclosing either.
        method = head.split(b" ", 1)[0].decode("latin-1", "replace")[:12]
        row = {"event": "exfil." + verdict, "host": host,
               "method": method, "bytes": len(body or b""),
               "bodySha256": hashlib.sha256(body or b"").hexdigest()[:32],
               "detail": detail}
        if matched:
            # WHICH marker left is the whole counterfactual: a distinct one is
            # planted per run, so its identity ties the egress to that run's
            # input rather than to something the tool sends regardless.
            row["canary"] = matched
        if verdict == "match":
            row["meaning"] = ("the tool sent its own input data to this host")
        elif verdict == "unexamined":
            row["meaning"] = ("the payload could not be decoded, so whether "
                              "data left is UNKNOWN, not disproven")
        self._note(row)

    def _note(self, row):
        """Emit a structured observation on the same stream as the rest."""
        row = dict(row)
        row.setdefault("t", time.time())
        text = json.dumps(row)
        with self._log_lock:
            os.write(self._log_fd, (text + "\n").encode("utf-8", "replace"))
            if self.echo:
                sys.stdout.write(text + "\n")
                sys.stdout.flush()

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


def _pipe_tls(a, b):
    """Pump between two TLS sockets with blocking reads, one thread each way.

    select() cannot be used here. It reports readiness of the underlying file
    descriptor, but a decrypted record may already be sitting in the SSL
    object's own buffer with nothing left at the fd -- so select says "idle"
    while data waits, and the transfer stalls. Blocking recv on the wrapped
    socket asks the SSL layer, which is the only thing that knows.
    """
    done = threading.Event()

    def pump(src, dst):
        try:
            while not done.is_set():
                data = src.recv(65536)
                if not data:
                    break
                dst.sendall(data)
        except Exception:
            pass
        finally:
            done.set()

    back = threading.Thread(target=pump, args=(b, a), daemon=True)
    back.start()
    pump(a, b)
    back.join(timeout=5)


def _read_http_request(sock, limit=4 * 1024 * 1024):
    """(head, body) of one HTTP request, or None.

    Reads a Content-Length body, and a chunked body up to `limit`. Anything
    else is returned with whatever body was captured, so the examiner reports
    it as unexamined rather than pretending it was clean.
    """
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(65536)
        if not chunk:
            return None
        buf += chunk
        if len(buf) > limit:
            break
    head, _, rest = buf.partition(b"\r\n\r\n")
    lowered = head.lower()

    length = None
    for line in head.split(b"\r\n")[1:]:
        if line.lower().startswith(b"content-length:"):
            try:
                length = int(line.split(b":", 1)[1].strip())
            except ValueError:
                length = None

    body = rest
    if length is not None:
        while len(body) < length and len(body) < limit:
            chunk = sock.recv(65536)
            if not chunk:
                break
            body += chunk
    elif b"transfer-encoding: chunked" in lowered:
        sock.settimeout(5)
        try:
            while len(body) < limit:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                body += chunk
        except OSError:
            pass
        body = _dechunk(body)
    return head, body


def _dechunk(body):
    """Best-effort de-chunking; returns the original bytes if it does not fit
    the format, so nothing is silently mangled before examination."""
    out, i = b"", 0
    try:
        while i < len(body):
            nl = body.index(b"\r\n", i)
            size = int(body[i:nl].split(b";")[0], 16)
            if size == 0:
                break
            start = nl + 2
            out += body[start:start + size]
            i = start + size + 2
        return out or body
    except (ValueError, IndexError):
        return body


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
    argv = sys.argv[1:]
    port = 0
    bind = "127.0.0.1"
    if argv and argv[0].isdigit():
        port = int(argv[0])
        argv = argv[1:]
    if "--bind" in argv:
        bind = argv[argv.index("--bind") + 1]

    log = os.environ.get("SAYDO_EGRESS_LOG", "egress.log")
    # SAYDO_ALLOW switches the proxy from observing to REFUSING. It is set by
    # whoever knows the run is genuinely confined -- the container runner --
    # never by the proxy itself.
    raw = os.environ.get("SAYDO_ALLOW")
    allow = ([h.strip() for h in raw.split(",") if h.strip()]
             if raw is not None else None)

    # Content inspection. The CA is generated HERE, inside the proxy, so its
    # private key never exists on the host that runs the harness -- only the
    # public certificate leaves, on stdout, for the sandbox to trust.
    ca = None
    canaries = []
    if os.environ.get("SAYDO_INSPECT") == "1":
        from sandbox_ca import SandboxCA
        ca = SandboxCA()
        canaries = [c for c in
                    (os.environ.get("SAYDO_CANARIES") or "").split(",") if c]
        print("@@SAYDO-CA@@ " + base64.b64encode(ca.ca_pem()).decode("ascii"),
              flush=True)

    proxy = EgressProxy(log, host=bind, port=port, allow=allow,
                        echo=True, ca=ca, canaries=canaries).start()

    # In the sandbox this process is also the tool's only nameserver, so a
    # lookup that bypasses the proxy is recorded rather than failing into
    # silence. Off by default: on a host it would hijack real DNS.
    if os.environ.get("SAYDO_DNS") == "1":
        from dns_sink import DnsSink
        sink = DnsSink(os.environ.get("SAYDO_DNS_LOG"), host=bind,
                       port=int(os.environ.get("SAYDO_DNS_PORT", "53")))
        sink.start()
        print("saydo dns sink on {}:{} [records every query, answers "
              "NXDOMAIN]".format(sink.host, sink.port), flush=True)
    mode = ("ENFORCING, allow=" + ",".join(sorted(allow))) if allow is not None \
        else "observe-only"
    print("saydo egress proxy on {} [{}] -> {}".format(
        proxy.address, mode, log), flush=True)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        proxy.stop()


if __name__ == "__main__":
    main()
