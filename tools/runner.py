"""Where the server under test runs: locally, or inside a sandbox container.

The harness has always launched the server as a child process on the host.
That is why today's monitors OBSERVE rather than ENFORCE: the proxy sees only
traffic a cooperative client routes through it, and the audit hook sees only
Python. A tool that ignores proxy configuration, in another language, is
invisible (measured, in SANDBOX.md).

A Runner abstracts the launch so the same harness can put the server inside a
container whose only network route IS the proxy and whose only writable path
is a scratch mount. Then no cooperation is required -- there is no other way
out -- and enforcement replaces observation for every language at once.

    LocalRunner      what exists today; host process, observation only
    ContainerRunner  docker (optionally with the gVisor runtime), enforcement

The container path is written here but CANNOT be validated on a Windows host
with no Docker. It is deliberately behind an explicit runtime choice, it
refuses rather than silently falling back, and `available()` reports honestly
whether this machine can run it. Nothing in a receipt may claim containment
until a run actually used ContainerRunner -- see `Runner.enforcement`.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import tempfile
import time


class Runner:
    """Base: owns where the server runs AND where its egress is watched.

    The proxy has to belong to the runner rather than to the harness, because
    where the proxy sits is exactly what separates observing from enforcing.
    Locally it is an in-process listener the tool may ignore; in a container it
    is the only neighbour the tool has. Same lifecycle either way:

        setup(egress_log, allow) -> proxy address to advertise to the server
        argv(...) / env(...)     -> how to launch the server
        collect_egress()         -> the egress events the run produced
        teardown()
    """

    #: What this runner can actually promise about the run. Carried into the
    #: report and the receipt, so a claim can never outrun the mechanism.
    enforcement = "none"

    def available(self):
        return True, ""

    def setup(self, egress_log, allow=None):
        raise NotImplementedError

    def collect_egress(self):
        raise NotImplementedError

    def collect_writes(self):
        """Filesystem changes observed from OUTSIDE the process. [] if none."""
        return []

    def teardown(self):
        pass

    def argv(self, plan, server_python, launch_argv):
        raise NotImplementedError

    def env(self, proxy_address, monitor_boot_dir, egress_log):
        raise NotImplementedError

    def describe(self):
        raise NotImplementedError


class LocalRunner(Runner):
    """Host process. Observation only; this is the honest default today."""

    enforcement = "observed"

    def __init__(self):
        self._proxy = None
        self._egress_log = None

    def setup(self, egress_log, allow=None, ca=None, canaries=None):
        # Deliberately started WITHOUT an allowlist even when one is declared:
        # on a host the tool can route around this proxy entirely, so refusing
        # here would produce the appearance of enforcement without the fact of
        # it. Locally the proxy reports; only the container enforces.
        from egress_proxy import EgressProxy
        self._egress_log = egress_log
        # Content inspection needs a certificate authority the tool trusts.
        # One is minted only when there is actually a canary to look for, so
        # a run that claims nothing about data egress is never intercepted.
        if ca is None and canaries:
            from sandbox_ca import SandboxCA
            ca = SandboxCA()
        self._ca = ca
        open(egress_log, "w").close()
        self._proxy = EgressProxy(egress_log, ca=ca,
                                  canaries=canaries).start()
        return self._proxy.address

    def collect_egress(self):
        from harness import _read_events
        return _read_events(self._egress_log) if self._egress_log else []

    def teardown(self):
        if self._proxy:
            self._proxy.stop()
            self._proxy = None

    def argv(self, plan, server_python, launch_argv):
        return list(launch_argv)

    def env(self, proxy_address, monitor_boot_dir, egress_log):
        env = {
            "HTTP_PROXY": proxy_address, "HTTPS_PROXY": proxy_address,
            "http_proxy": proxy_address, "https_proxy": proxy_address,
            "SAYDO_EGRESS_LOG": egress_log,
            "NODE_USE_ENV_PROXY": "1",
        }
        if getattr(self, "_ca", None):
            # The tool must trust the inspection certificate or every HTTPS
            # request fails. Written beside the run's other scratch, never
            # into any system trust store on this machine.
            import tempfile
            path = os.path.join(tempfile.gettempdir(), "saydo-sandbox-ca.pem")
            with open(path, "wb") as fh:
                fh.write(self._ca.ca_pem())
            env.update({"SSL_CERT_FILE": path, "REQUESTS_CA_BUNDLE": path,
                        "CURL_CA_BUNDLE": path, "NODE_EXTRA_CA_CERTS": path})
        if monitor_boot_dir:
            prior = os.environ.get("PYTHONPATH")
            env["PYTHONPATH"] = monitor_boot_dir + (
                os.pathsep + prior if prior else "")
            # The Node monitor lives in the same directory. A local run of a
            # Node server had no observation channel at all before this, in
            # exactly the way the contained runs did.
            node_monitor = os.path.join(monitor_boot_dir, "node_monitor.js")
            if os.path.exists(node_monitor):
                env["NODE_OPTIONS"] = "--require=" + node_monitor.replace(
                    os.sep, "/")
        return env

    def describe(self):
        return ("host process; egress observed at a proxy the tool may decline "
                "to use, filesystem and subprocess observed in-runtime for "
                "Python only. Not containment.")


class ContainerRunner(Runner):
    """Docker (optionally gVisor). The tool's only route out is the proxy.

    Enforcement, rather than observation, comes from the container flags:

      --network <saydo-net>   a network with no route off-host except the proxy
      --read-only             the image filesystem cannot be written
      -v <host dir>:/scratch  the one writable path, and the declared write scope.
                              A bind mount rather than a tmpfs so what the tool
                              wrote can be read afterwards from the host, in any
                              language -- the in-runtime hook is CPython-only.
      --cap-drop ALL          no capabilities
      --security-opt no-new-privileges
      --pids-limit / --memory / a wall-clock kill
      --runtime runsc         gVisor, when installed: syscalls are handled by a
                              user-space kernel, so a container escape has to
                              get through that first

    gVisor is a runtime flag on top of the same command, so the Docker path and
    the hardened path are one implementation.
    """

    enforcement = "contained"

    def __init__(self, image, runtime=None, network="saydo-inside",
                 outside="saydo-outside", proxy_image="saydo/proxy:ci",
                 scratch="/scratch", memory="512m", pids=256, tag="",
                 routed=False):
        # routed=False: the sandbox network is --internal. There is no route
        #   off the subnet at all, so nothing can leave -- but a connection to
        #   a bare IP dies in the routing table and never becomes a packet, so
        #   a non-Python tool's attempt is stopped invisibly.
        #
        # routed=True: the sandbox has a gateway, so the packet is really
        #   emitted and can be recorded, and a host firewall drops it before it
        #   goes anywhere. Attribution becomes language-independent. The cost
        #   is honest and worth stating: containment now rests on those
        #   firewall rules being correct rather than on the absence of a road.
        #   Because of that, routed mode REFUSES TO RUN if it cannot install
        #   them -- a routed sandbox without the firewall is not a sandbox.
        self.routed = routed
        self.image = image
        self.runtime = runtime          # "runsc" for gVisor, None for default
        self.tag = tag
        #: Where the Node monitor sits inside the image. The Python monitor
        #: rides on PYTHONPATH; Node has no equivalent, so it is required by
        #: absolute path.
        self.node_monitor = "/saydo/monitor_boot/node_monitor.js"
        self.network = network + tag
        self.outside = outside + tag
        self.proxy_image = proxy_image
        self.proxy_name = "saydo-proxy" + tag
        self.scratch = scratch
        # Ephemeral and separate from the scratch, so "wrote outside
        # its declared scope" stays a meaningful sentence.
        self.home = "/home/saydo"
        self.memory = memory
        self.pids = pids
        self._up = False

    # -- lifecycle ---------------------------------------------------------

    class _NoDocker:
        """What a docker call returns when there is no docker to call."""
        returncode, stdout, stderr = 127, "", "docker is not on PATH"

    def _docker(self, *args, **kw):
        # Tolerate a missing binary. Callers already branch on returncode, and
        # several are best-effort cleanup that must not raise -- an exception
        # out of teardown loses the real failure that caused it.
        try:
            return subprocess.run(["docker", *args], capture_output=True,
                                  text=True, timeout=kw.get("timeout", 120))
        except (OSError, subprocess.SubprocessError):
            return self._NoDocker()

    def setup(self, egress_log, allow=None, ca=None, canaries=None):
        """Stand up the two networks and the proxy, then hand back the address
        the server should use. The address is a network alias, not a host port:
        inside `network` the proxy is simply the only thing there."""
        self._ca = ca
        self._canaries = list(canaries or [])
        # The subject container is named rather than --rm, so it survives its
        # own exit long enough for `docker diff` to read what it wrote. A
        # leftover from a killed run would collide with that name, so it is
        # cleared here -- in setup, which is allowed to touch docker, rather
        # than in argv, which only builds a command line.
        self._docker("rm", "-f", "saydo-subject" + (self.tag or ""))
        if self.routed:
            # A gateway exists, so packets are emitted and observable. What
            # stops them is the firewall installed below, not the topology.
            self._docker("network", "create", self.network)
        else:
            self._docker("network", "create", "--internal", self.network)
        self._docker("network", "create", self.outside)

        cmd = ["run", "-d", "--name", self.proxy_name,
               "--network", self.network,
               "--network-alias", "saydo-proxy"]
        if allow:
            # Here an allowlist is a real policy: the tool has no other route,
            # so a refusal at the proxy is a refusal in fact.
            cmd += ["-e", "SAYDO_ALLOW=" + ",".join(sorted(allow))]
        if self._canaries:
            cmd += ["-e", "SAYDO_INSPECT=1",
                    "-e", "SAYDO_CANARIES=" + ",".join(self._canaries)]
        cmd += [self.proxy_image]
        out = self._docker(*cmd)
        if out.returncode != 0:
            raise RuntimeError("could not start the proxy container: "
                               + (out.stderr or "").strip())
        # Only the proxy touches the outside world.
        self._docker("network", "connect", self.outside, self.proxy_name)
        self._up = True
        time.sleep(2)

        # The proxy is also the sandbox's only nameserver, so its address on
        # the inside network is needed twice over.
        ip = self._docker(
            "inspect", "-f",
            "{{(index .NetworkSettings.Networks \"" + self.network
            + "\").IPAddress}}", self.proxy_name)
        self._proxy_ip = (ip.stdout or "").strip()

        self._install_bridge_log()
        self._collect_ca()

        self._proxy_addr = "http://saydo-proxy:8888"
        return self._proxy_addr

    def _collect_ca(self):
        """Retrieve the inspection CA's PUBLIC certificate from the proxy.

        The private key stays inside the proxy container and is never written
        to the host. Only this certificate travels, and only into the sandbox,
        so nothing on the host or on any developer's machine is asked to trust
        it.
        """
        self._ca_path = None
        if not self._canaries:
            return
        out = self._docker("logs", self.proxy_name)
        for line in (out.stdout or "").splitlines():
            if line.startswith("@@SAYDO-CA@@ "):
                pem = base64.b64decode(line.split(" ", 1)[1].strip())
                path = os.path.join(tempfile.gettempdir(),
                                    "saydo-inspect-ca.pem")
                with open(path, "wb") as fh:
                    fh.write(pem)
                self._ca_path = path
                return

    # -- bridge logging: the bare-IP case -----------------------------------
    #
    # A DNS sink sees any tool that resolves a name, which is almost all code.
    # It cannot see a tool that connects straight to an IP address, because
    # there is no lookup to record. Such a connection is still stopped by the
    # internal network, but silently -- and "stopped silently" loses the fact
    # that it was attempted.
    #
    # A LOG rule on the sandbox bridge closes that: every new connection
    # leaving the sandbox subnet is recorded by the kernel before the network
    # drops it. This needs root on the host, so it is attempted and its
    # success is reported honestly rather than assumed.

    LOG_PREFIX = "SAYDO-EGRESS "

    def _sudo(self, *args):
        return subprocess.run(["sudo", "-n", *args], capture_output=True,
                              text=True, timeout=60)

    def _install_containment(self):
        """Log then DROP everything leaving the sandbox subnet.

        This is what makes routed mode safe. Two rules on the sandbox bridge,
        both skipping the proxy's own traffic and both ignoring traffic that
        stays inside the subnet (the sandbox talking to the proxy, which is
        the one conversation it is allowed to have):

            LOG   -- so the attempt is attributable, in any language
            DROP  -- so the attempt goes nowhere

        Order matters: iptables -I prepends, so DROP is inserted first and LOG
        ends up ahead of it. A packet is therefore recorded before it dies.

        If these cannot be installed the run must not proceed. A routed
        sandbox without them has a working route to the internet, which would
        turn the safest part of this system into the most dangerous.
        """
        if not shutil.which("iptables") or not shutil.which("sudo"):
            raise SystemExit(
                "routed topology requires iptables and sudo to contain the "
                "sandbox, and neither is available. Refusing to run: without "
                "the firewall the sandbox would have a real route out.")
        info = self._docker("network", "inspect", self.network, "-f",
                            "{{(index .IPAM.Config 0).Subnet}}|{{.Id}}")
        raw = (info.stdout or "").strip()
        if "|" not in raw:
            raise SystemExit("routed topology: could not read the sandbox "
                             "subnet, so containment cannot be installed")
        subnet, net_id = raw.split("|", 1)
        self._bridge = "br-" + net_id[:12]
        self._subnet = subnet
        proxy_ip = getattr(self, "_proxy_ip", "")

        base = ["-i", self._bridge, "!", "-d", subnet]
        if proxy_ip:
            # The proxy is the one container here that is SUPPOSED to reach
            # the outside world; it does so on the other network, but excluding
            # it explicitly keeps the rule correct however Docker routes it.
            base += ["!", "-s", proxy_ip]

        drop = self._sudo("iptables", "-I", "DOCKER-USER", *base, "-j", "DROP")
        log = self._sudo("iptables", "-I", "DOCKER-USER", *base,
                         "-m", "conntrack", "--ctstate", "NEW",
                         "-j", "LOG", "--log-prefix", self.LOG_PREFIX,
                         "--log-level", "4")
        if drop.returncode != 0 or log.returncode != 0:
            raise SystemExit(
                "routed topology: could not install containment rules ({}). "
                "Refusing to run an uncontained sandbox."
                .format((drop.stderr or log.stderr or "").strip()[:160]))
        self._contained_rules = [
            list(base) + ["-j", "DROP"],
            list(base) + ["-m", "conntrack", "--ctstate", "NEW", "-j", "LOG",
                          "--log-prefix", self.LOG_PREFIX, "--log-level", "4"],
        ]
        self.bridge_logging = True
        self.bridge_reason = ""

    def _install_bridge_log(self):
        if self.routed:
            self._install_containment()
            return
        self.bridge_logging = False
        self.bridge_reason = ""
        if not shutil.which("iptables") or not shutil.which("sudo"):
            self.bridge_reason = "iptables/sudo not available on this host"
            return
        info = self._docker("network", "inspect", self.network, "-f",
                            "{{(index .IPAM.Config 0).Subnet}}|{{.Id}}")
        raw = (info.stdout or "").strip()
        if "|" not in raw:
            self.bridge_reason = "could not read the sandbox subnet"
            return
        subnet, net_id = raw.split("|", 1)
        self._bridge = "br-" + net_id[:12]
        self._subnet = subnet
        # New connections leaving the sandbox for anything outside its own
        # subnet. Traffic to the proxy stays inside the subnet and is not
        # logged, so what remains is exactly the attempts that bypassed it.
        out = self._sudo("iptables", "-I", "DOCKER-USER", "-i", self._bridge,
                         "!", "-d", subnet, "-m", "conntrack",
                         "--ctstate", "NEW", "-j", "LOG",
                         "--log-prefix", self.LOG_PREFIX, "--log-level", "4")
        if out.returncode != 0:
            self.bridge_reason = ("could not install the bridge LOG rule: "
                                  + (out.stderr or "").strip()[:120])
            return
        self.bridge_logging = True
        self._log_mark = time.time()

    def _remove_bridge_log(self):
        # Containment rules must never outlive the run: a stale DROP on a
        # recycled bridge name would silently break unrelated containers.
        for rule in getattr(self, "_contained_rules", []):
            self._sudo("iptables", "-D", "DOCKER-USER", *rule)
        if getattr(self, "_contained_rules", None):
            self._contained_rules = []
            return
        if getattr(self, "bridge_logging", False):
            self._sudo("iptables", "-D", "DOCKER-USER", "-i", self._bridge,
                       "!", "-d", self._subnet, "-m", "conntrack",
                       "--ctstate", "NEW", "-j", "LOG",
                       "--log-prefix", self.LOG_PREFIX, "--log-level", "4")

    def _bridge_events(self):
        """Connection attempts the kernel logged as they left the sandbox."""
        if not getattr(self, "bridge_logging", False):
            return []
        out = self._sudo("dmesg")
        if out.returncode != 0:
            return []
        events = []
        for line in (out.stdout or "").splitlines():
            if self.LOG_PREFIX not in line:
                continue
            fields = {}
            for token in line.split():
                if "=" in token:
                    k, _, v = token.partition("=")
                    fields[k] = v
            dst, dpt = fields.get("DST"), fields.get("DPT")
            if not dst:
                continue
            events.append({
                # Timestamped now rather than from the kernel clock, which is
                # uptime-relative and would not align with call windows. The
                # rule is installed per run, so everything it logged belongs
                # to this run.
                "t": time.time(),
                "event": "bridge.attempt",
                "host": dst,
                "port": int(dpt) if dpt and dpt.isdigit() else None,
                "proto": fields.get("PROTO", ""),
                "outcome": "blocked by the sandbox network",
            })
        return events

    def _workdir(self):
        """A fresh empty host directory, bind-mounted as the scratch."""
        if not getattr(self, "_work", None):
            self._work = tempfile.mkdtemp(prefix="saydo-work" + (self.tag or ""))
            os.chmod(self._work, 0o777)      # the container user is not root
        return self._work

    def collect_writes(self):
        """What the run left in the bind-mounted scratch. [] if nothing.

        Read from the host side, so it works whatever language the server is
        written in — which is the entire point, since the in-runtime hook is
        CPython-only and every Node server was otherwise unobservable.

        There are no timestamps here, so these belong to the RUN rather than to
        any one call. That is said in the evidence instead of being papered
        over by guessing which window they fell in.
        """
        work = getattr(self, "_work", None)
        if not work or not os.path.isdir(work):
            return []
        writes = []
        for root, _dirs, files in os.walk(work):
            for name in files:
                full = os.path.join(root, name)
                inside = os.path.relpath(full, work).replace(os.sep, "/")
                try:
                    size = os.path.getsize(full)
                except OSError:
                    size = None
                writes.append({"t": time.time(), "event": "container.write",
                               "path": self.scratch + "/" + inside,
                               "intent": "write", "bytes": size,
                               "runLevel": True})
        return writes

    def collect_egress(self):
        """The proxy's decisions plus anything that tried to leave around it.

        The proxy echoes each decision to stdout, so the container log is the
        evidence and no volume is needed; the bridge log supplies the attempts
        that never reached the proxy at all.
        """
        if not self._up:
            return []
        out = self._docker("logs", self.proxy_name)
        events = []
        for line in (out.stdout or "").splitlines():
            line = line.strip()
            if line.startswith("{"):
                try:
                    events.append(json.loads(line))
                except ValueError:
                    pass
        return events + self._bridge_events()

    def teardown(self):
        # The bind-mounted scratch is removed FIRST and unconditionally. The
        # rest of teardown is skipped when setup never completed, and a setup
        # that failed part-way is exactly when a host directory would be left
        # behind with someone else's files in it.
        if getattr(self, "_work", None):
            shutil.rmtree(self._work, ignore_errors=True)
            self._work = None
        if not self._up:
            return
        self._remove_bridge_log()
        # The subject container was kept alive past its exit so `docker diff`
        # could read it. Nothing else needs it.
        if getattr(self, "_container", None):
            self._docker("rm", "-f", self._container)
        self._docker("rm", "-f", self.proxy_name)
        self._docker("network", "rm", self.network)
        self._docker("network", "rm", self.outside)
        self._up = False

    def available(self):
        if not shutil.which("docker"):
            return False, ("docker is not on PATH. The container runner needs a "
                           "Linux host with Docker; this machine cannot run it.")
        try:
            subprocess.run(["docker", "info"], capture_output=True, timeout=20,
                           check=True)
        except Exception as e:
            return False, "docker is present but not usable: {}".format(e)
        if self.runtime:
            try:
                out = subprocess.run(["docker", "info", "--format",
                                      "{{json .Runtimes}}"],
                                     capture_output=True, text=True, timeout=20)
                if self.runtime not in (out.stdout or ""):
                    return False, ("runtime {!r} is not registered with docker; "
                                   "install gVisor or drop the runtime flag"
                                   .format(self.runtime))
            except Exception as e:
                return False, "could not query docker runtimes: {}".format(e)
        return True, ""

    def argv(self, plan, server_python, launch_argv):
        # The server's environment has to be set INSIDE the container, so the
        # proxy variables are -e flags here rather than host process env.
        addr = getattr(self, "_proxy_addr", "http://saydo-proxy:8888")
        # NOT --rm. The container has to survive its own exit for one command:
        # `docker diff`, which lists every file the run added, changed or
        # deleted. That is the only filesystem observation that works in any
        # language. The in-runtime audit hook is CPython-only, so a Node server
        # was producing no filesystem evidence whatsoever -- @modelcontextprotocol
        # /server-memory writes a JSON graph to disk and came back with "no
        # observation channel", which is true and useless.
        self._container = "saydo-subject" + (self.tag or "")
        cmd = ["docker", "run", "--name", self._container, "-i",
               "--network", self.network,
               "--read-only",
               # A bind mount, not a tmpfs, and the difference decides whether
               # anything can be observed at all.
               #
               # `docker diff` excludes tmpfs and volume mounts, so with both
               # writable paths on tmpfs and the rootfs read-only it was
               # guaranteed to return nothing — the observation it was added
               # for could not have worked in any run. Worse, a server whose
               # state file sits beside its own code (server-memory's does)
               # cannot write at all under a read-only rootfs, so there was
               # nothing to see even in principle.
               #
               # A host directory gives the tool somewhere real to work, and
               # gives us a way to read what it did afterwards in any language.
               # Created empty per run, removed at teardown.
               "-v", "{}:{}:rw".format(self._workdir(), self.scratch),
               # A writable HOME, ephemeral like the scratch. Plenty of servers
               # create a state directory under $HOME as the first thing they
               # do, and with a read-only rootfs they die in their own
               # constructor. Measuring nothing is not a safety property: it
               # produced a corpus where four servers were filed as "broken"
               # when the harness had broken them.
               #
               # This does NOT exempt those writes. A write here is still an
               # observed write and still tested against the declared write
               # scope -- the tool has to survive long enough to be judged, and
               # then it is judged. The directory is tmpfs, noexec, size-capped
               # and destroyed at teardown, so nothing it leaves behind reaches
               # the host or the next run.
               "--tmpfs", "{}:rw,noexec,nosuid,size=32m,mode=1777".format(self.home),
               "--cap-drop", "ALL",
               "--security-opt", "no-new-privileges",
               "--pids-limit", str(self.pids),
               "--memory", self.memory,
               "--workdir", self.scratch,
               "-e", "HOME=" + self.home,
               # Point the interpreter at the one place it can write.
               # Without this, tempfile walks /tmp, /var/tmp and /usr/tmp
               # -- all read-only here -- and each failure is recorded as
               # the tool attempting a write it never meant to attempt.
               "-e", "TMPDIR=" + self.scratch,
               "-e", "HTTP_PROXY=" + addr, "-e", "HTTPS_PROXY=" + addr,
               "-e", "http_proxy=" + addr, "-e", "https_proxy=" + addr,
               "-e", "NODE_USE_ENV_PROXY=1",
               # The audit hook still runs inside the sandbox and reports over
               # stderr, so an attempt the boundary blocked is still recorded.
               # The image places it on PYTHONPATH.
               "-e", "SAYDO_MONITOR_STDERR=1",
               # Bytecode caching is the interpreter's housekeeping, not the
               # tool's behaviour. Left on, every Python server appears to
               # write files it never asked to write.
               "-e", "PYTHONDONTWRITEBYTECODE=1",
               # The Node equivalent of the audit hook, loaded before the
               # server's own code and reporting on the same stderr channel.
               # Harmless when the image has no Node; NODE_OPTIONS is simply
               # never read. Set here rather than only in the image so a
               # caller's own image gets it too.
               "-e", "NODE_OPTIONS=--require=" + self.node_monitor]

        ip = getattr(self, "_proxy_ip", "")
        if ip:
            # The sandbox's ONLY nameserver is the sink, so every hostname the
            # tool looks up is recorded before it is refused. The proxy itself
            # is reachable by a hosts entry rather than by DNS, so a tool using
            # the permitted route never depends on resolution -- and a tool
            # bypassing it is caught in the act of trying.
            #
            # Search domains are disabled. After an NXDOMAIN a resolver
            # retries the name with each search suffix appended, and those
            # synthetic names would land in the receipt as things the tool
            # asked for. It did not ask for them; the resolver invented them.
            # Evidence should record the tool's request, not the resolver's
            # elaboration of it.
            cmd += ["--dns", ip, "--add-host", "saydo-proxy:" + ip,
                    "--dns-search", ".", "--dns-opt", "ndots:1"]

        ca_path = getattr(self, "_ca_path", None)
        if ca_path:
            # The sandbox trusts the inspection CA and nothing else. That is
            # correct rather than restrictive: its only route out is the
            # proxy, which presents this CA, so a tool cannot both refuse the
            # certificate and reach anything. Read-only, and a public
            # certificate, so the mount grants the tool nothing.
            cmd += ["-v", ca_path + ":/saydo/ca.pem:ro",
                    "-e", "SSL_CERT_FILE=/saydo/ca.pem",
                    "-e", "REQUESTS_CA_BUNDLE=/saydo/ca.pem",
                    "-e", "CURL_CA_BUNDLE=/saydo/ca.pem",
                    "-e", "NODE_EXTRA_CA_CERTS=/saydo/ca.pem"]
        for c in self._canaries:
            # The fixture's "sensitive data". In a real run the canary is
            # planted in the tool's actual inputs; here it is handed over
            # explicitly so the exfiltrating fixture has something to steal.
            cmd += ["-e", "SAYDO_CANARY=" + c]
        if self.runtime:
            cmd += ["--runtime", self.runtime]
        for k, v in (plan.get("container_env") or {}).items():
            cmd += ["-e", "{}={}".format(k, v)]
        cmd += [self.image]
        # A plan may name the in-container command explicitly. An empty list
        # means "use the image's own CMD", which is distinct from absent -- so
        # test for presence rather than truthiness. The host launch argv is
        # only a fallback, since host paths rarely exist inside the image.
        if "container_argv" in plan:
            cmd += list(plan["container_argv"])
        else:
            cmd += list(launch_argv)
        return cmd

    def env(self, proxy_address, monitor_boot_dir, egress_log):
        # Nothing is needed on the host side: the docker CLI is just a pipe,
        # and the server's own environment travels as -e flags in argv().
        return {}

    def describe(self):
        # Measured, not assumed: on an --internal network the container has no
        # route off its own subnet, so a connection to an outside address
        # fails in the routing table and never reaches the wire. A bridge LOG
        # rule therefore cannot see it -- there is no packet to see. The rule
        # is still installed because it is correct for a routed topology, but
        # claiming it covers the bare-IP case here would be false.
        if self.routed:
            bare_ip = (
                " The sandbox has a gateway, so a connection to a bare IP is "
                "really emitted, recorded on the bridge, and then dropped by "
                "the host firewall. Attribution therefore does not depend on "
                "the tool's language. The trade is stated plainly: containment "
                "here rests on those firewall rules being correct rather than "
                "on the absence of any route, and the run refuses to start if "
                "they cannot be installed.")
        else:
            bare_ip = (
                " A connection to a bare IP performs no name lookup, so the "
                "resolver cannot record it, and on an internal network it "
                "fails at the routing table before any packet reaches the "
                "bridge. Such an attempt is attributed only by the "
                "in-container audit hook, which sees it for a Python tool and "
                "not for others. For a non-Python tool a bare-IP attempt is "
                "stopped absolutely but is NOT recorded.")
        return self._describe_base() + bare_ip

    def _describe_base(self):
        return ("container ({}{}): only network route is the SayDo proxy, "
                "root filesystem read-only, {} the sole writable path, all "
                "capabilities dropped. Every name lookup is recorded and "
                "refused by the sandbox's own resolver. Egress, writes, and "
                "processes are enforced at the boundary rather than observed "
                "in-runtime, so coverage does not depend on the tool's "
                "language or its cooperation.".format(
                    self.image,
                    " runtime=" + self.runtime if self.runtime else "",
                    self.scratch))


def make(kind="local", **kwargs):
    """Build a runner by name. Unknown kinds refuse rather than defaulting to
    the weaker runner: silently downgrading enforcement to observation is
    exactly the dishonesty this project exists to prevent."""
    if kind == "local":
        return LocalRunner()
    if kind == "container":
        return ContainerRunner(**kwargs)
    raise ValueError("unknown runner {!r}; expected 'local' or 'container'"
                     .format(kind))
