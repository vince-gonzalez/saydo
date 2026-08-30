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

import json
import os
import shutil
import subprocess
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

    def setup(self, egress_log, allow=None):
        # Deliberately started WITHOUT an allowlist even when one is declared:
        # on a host the tool can route around this proxy entirely, so refusing
        # here would produce the appearance of enforcement without the fact of
        # it. Locally the proxy reports; only the container enforces.
        from egress_proxy import EgressProxy
        self._egress_log = egress_log
        open(egress_log, "w").close()
        self._proxy = EgressProxy(egress_log).start()
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
        if monitor_boot_dir:
            prior = os.environ.get("PYTHONPATH")
            env["PYTHONPATH"] = monitor_boot_dir + (
                os.pathsep + prior if prior else "")
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
      --tmpfs /scratch        the one writable path, and the declared write scope
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
                 scratch="/scratch", memory="512m", pids=256, tag=""):
        self.image = image
        self.runtime = runtime          # "runsc" for gVisor, None for default
        self.network = network + tag
        self.outside = outside + tag
        self.proxy_image = proxy_image
        self.proxy_name = "saydo-proxy" + tag
        self.scratch = scratch
        self.memory = memory
        self.pids = pids
        self._up = False

    # -- lifecycle ---------------------------------------------------------

    def _docker(self, *args, **kw):
        return subprocess.run(["docker", *args], capture_output=True,
                              text=True, timeout=kw.get("timeout", 120))

    def setup(self, egress_log, allow=None):
        """Stand up the two networks and the proxy, then hand back the address
        the server should use. The address is a network alias, not a host port:
        inside `network` the proxy is simply the only thing there."""
        self._docker("network", "create", "--internal", self.network)
        self._docker("network", "create", self.outside)

        cmd = ["run", "-d", "--name", self.proxy_name,
               "--network", self.network,
               "--network-alias", "saydo-proxy"]
        if allow:
            # Here an allowlist is a real policy: the tool has no other route,
            # so a refusal at the proxy is a refusal in fact.
            cmd += ["-e", "SAYDO_ALLOW=" + ",".join(sorted(allow))]
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

        self._proxy_addr = "http://saydo-proxy:8888"
        return self._proxy_addr

    def collect_egress(self):
        """The proxy's decisions. It echoes each one to stdout, so the
        container log is the evidence and no volume is needed."""
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
        return events

    def teardown(self):
        if not self._up:
            return
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
        cmd = ["docker", "run", "--rm", "-i",
               "--network", self.network,
               "--read-only",
               "--tmpfs", "{}:rw,noexec,nosuid,size=64m".format(self.scratch),
               "--cap-drop", "ALL",
               "--security-opt", "no-new-privileges",
               "--pids-limit", str(self.pids),
               "--memory", self.memory,
               "--workdir", self.scratch,
               "-e", "HTTP_PROXY=" + addr, "-e", "HTTPS_PROXY=" + addr,
               "-e", "http_proxy=" + addr, "-e", "https_proxy=" + addr,
               "-e", "NODE_USE_ENV_PROXY=1",
               # The audit hook still runs inside the sandbox and reports over
               # stderr, so an attempt the boundary blocked is still recorded.
               # The image places it on PYTHONPATH.
               "-e", "SAYDO_MONITOR_STDERR=1"]

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
        return ("container ({}{}): only network route is the SayDo proxy, "
                "root filesystem read-only, {} the sole writable path, all "
                "capabilities dropped. Egress, writes, and processes are "
                "enforced at the boundary rather than observed in-runtime, so "
                "coverage does not depend on the tool's language or its "
                "cooperation.".format(
                    self.image, " runtime=" + self.runtime if self.runtime else "",
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
