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

import os
import shutil
import subprocess


class Runner:
    """Base: turns a plan into the argv the MCP client should spawn."""

    #: What this runner can actually promise about the run.
    enforcement = "none"

    def available(self):
        return True, ""

    def argv(self, plan, server_python, launch_argv):
        raise NotImplementedError

    def env(self, proxy_address, monitor_boot_dir, egress_log):
        raise NotImplementedError

    def describe(self):
        raise NotImplementedError


class LocalRunner(Runner):
    """Host process. Observation only; this is the honest default today."""

    enforcement = "observed"

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

    def __init__(self, image, runtime=None, network="saydo-none",
                 scratch="/scratch", memory="512m", pids=256):
        self.image = image
        self.runtime = runtime          # "runsc" for gVisor, None for default
        self.network = network
        self.scratch = scratch
        self.memory = memory
        self.pids = pids

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
        cmd = ["docker", "run", "--rm", "-i",
               "--network", self.network,
               "--read-only",
               "--tmpfs", "{}:rw,noexec,nosuid,size=64m".format(self.scratch),
               "--cap-drop", "ALL",
               "--security-opt", "no-new-privileges",
               "--pids-limit", str(self.pids),
               "--memory", self.memory,
               "--workdir", self.scratch]
        if self.runtime:
            cmd += ["--runtime", self.runtime]
        for k, v in (plan.get("container_env") or {}).items():
            cmd += ["-e", "{}={}".format(k, v)]
        cmd += [self.image]
        cmd += list(plan.get("container_argv") or launch_argv)
        return cmd

    def env(self, proxy_address, monitor_boot_dir, egress_log):
        # Inside the container the proxy is reached by its network alias, not
        # by the host loopback address the local runner uses.
        alias = os.environ.get("SAYDO_PROXY_ALIAS", "saydo-proxy:8888")
        addr = "http://" + alias
        return {"HTTP_PROXY": addr, "HTTPS_PROXY": addr,
                "http_proxy": addr, "https_proxy": addr,
                "NODE_USE_ENV_PROXY": "1"}

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
