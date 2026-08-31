/*
 * Runtime observation for a Node MCP server. Injected, not linked.
 *
 * The Python monitor rides on sys.addaudithook, which is CPython-only. That
 * left every Node server with no observation channel whatsoever: the four
 * official reference servers written in TypeScript returned `not-covered` on
 * every invariant, four runs in a row, with the honest reason attached. Routed
 * containment did not help (they make no network calls), and a bind-mounted
 * scratch did not help (they do not write there). Nothing was going to help
 * except a monitor inside the process.
 *
 * Loaded with `node --require node_monitor.js`, i.e. before the server's own
 * code, and it reports on the SAME stderr channel with the SAME event names
 * the Python hook uses, so the harness ingests it without a new code path.
 *
 * Three rules this file lives by:
 *
 *   1. It must never throw into the server. An exception here manufactures a
 *      failure the tool did not have, and the receipt would blame the tool.
 *      Every hook is wrapped, and a hook that breaks degrades to the original
 *      function rather than taking the process with it.
 *
 *   2. It must never lose the FACT of an event. If the detail cannot be
 *      rendered, a lossy record still goes out. Silence is the one outcome
 *      that gets misread as good behaviour.
 *
 *   3. It observes the Node runtime, not the kernel. A native addon calling
 *      the OS directly walks straight past it, exactly as ctypes does past the
 *      Python hook. This catches drift, accidents and ordinary misbehaviour.
 *      It is not a sandbox, and no receipt may call it one.
 */

'use strict';

(function () {
  // Captured BEFORE anything is patched. Emitting through a hooked function
  // would recurse forever on the first event.
  const realWriteSync = require('fs').writeSync;
  const PREFIX = '@@SAYDO@@ ';

  let lost = 0;
  let busy = false;

  function emit(row) {
    if (busy) return;              // no re-entry from inside our own emit
    busy = true;
    try {
      realWriteSync(2, PREFIX + JSON.stringify(row) + '\n');
    } catch (e) {
      // The detail could not be rendered or written. Keep the fact.
      lost += 1;
      try {
        realWriteSync(2, PREFIX + JSON.stringify({
          t: Date.now() / 1000, event: row && row.event, lossy: true,
          lost: lost
        }) + '\n');
      } catch (ignored) { /* nothing further is possible */ }
    } finally {
      busy = false;
    }
  }

  const now = () => Date.now() / 1000;

  function text(value) {
    try {
      if (value === null || value === undefined) return null;
      if (typeof value === 'string') return value.slice(0, 512);
      if (Buffer.isBuffer(value)) return value.toString('utf8').slice(0, 512);
      if (value instanceof URL) return value.href.slice(0, 512);
      if (typeof value === 'number' || typeof value === 'boolean') return value;
      return String(value).slice(0, 256);
    } catch (e) {
      return '<unrenderable>';
    }
  }

  // Wrap one method, never letting the wrapper's own failure reach the caller.
  function wrap(object, name, before) {
    if (!object || typeof object[name] !== 'function') return;
    const original = object[name];
    try {
      object[name] = function () {
        try { before(arguments); } catch (e) { /* observation is best effort */ }
        return original.apply(this, arguments);
      };
      // Preserve promisify and friends.
      Object.defineProperty(object[name], 'name', { value: name });
      if (original[require('util').promisify.custom]) {
        object[name][require('util').promisify.custom] =
          original[require('util').promisify.custom];
      }
    } catch (e) {
      object[name] = original;
    }
  }

  const fs = require('fs');

  // --- filesystem -------------------------------------------------------
  // Writes matter most: no-write and write-scope are the invariants a
  // filesystem server is judged on. Reads are deliberately NOT reported. A
  // Node process opens hundreds of files loading its own modules, and emitting
  // those would make every server look like it acted and violate read-scope on
  // its own dependencies -- noise that would drown the signal it is here for.
  const WRITE_OPEN = /[waxu+]/;

  function openFlagsAreWrite(flags) {
    if (typeof flags === 'string') return WRITE_OPEN.test(flags);
    if (typeof flags === 'number') {
      // O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND
      return (flags & (1 | 2 | 64 | 512 | 1024)) !== 0;
    }
    return false;
  }

  ['writeFile', 'writeFileSync', 'appendFile', 'appendFileSync'].forEach((m) =>
    wrap(fs, m, (a) => emit({
      t: now(), event: 'open', path: text(a[0]), intent: 'write'
    })));

  ['open', 'openSync'].forEach((m) =>
    wrap(fs, m, (a) => {
      if (openFlagsAreWrite(a[1])) {
        emit({ t: now(), event: 'open', path: text(a[0]), intent: 'write' });
      }
    }));

  ['createWriteStream'].forEach((m) =>
    wrap(fs, m, (a) => emit({
      t: now(), event: 'open', path: text(a[0]), intent: 'write'
    })));

  // Named to match the Python hook exactly, because the harness matches on
  // these strings and a different spelling would be silently ignored.
  const FS_EVENTS = {
    unlink: 'os.remove', unlinkSync: 'os.remove',
    rm: 'os.remove', rmSync: 'os.remove',
    rename: 'os.rename', renameSync: 'os.rename',
    mkdir: 'os.mkdir', mkdirSync: 'os.mkdir',
    rmdir: 'os.rmdir', rmdirSync: 'os.rmdir',
    truncate: 'os.truncate', truncateSync: 'os.truncate',
    link: 'os.link', linkSync: 'os.link',
    symlink: 'os.symlink', symlinkSync: 'os.symlink',
    copyFile: 'shutil.copyfile', copyFileSync: 'shutil.copyfile'
  };
  Object.keys(FS_EVENTS).forEach((m) =>
    wrap(fs, m, (a) => emit({
      t: now(), event: FS_EVENTS[m],
      args: [text(a[0]), a.length > 1 ? text(a[1]) : null]
    })));

  if (fs.promises) {
    ['writeFile', 'appendFile'].forEach((m) =>
      wrap(fs.promises, m, (a) => emit({
        t: now(), event: 'open', path: text(a[0]), intent: 'write'
      })));
    Object.keys(FS_EVENTS).forEach((m) => {
      if (m.endsWith('Sync')) return;
      wrap(fs.promises, m, (a) => emit({
        t: now(), event: FS_EVENTS[m],
        args: [text(a[0]), a.length > 1 ? text(a[1]) : null]
      }));
    });
  }

  // --- name resolution --------------------------------------------------
  // socket.getaddrinfo is what the harness reads a HOSTNAME from, and a
  // hostname is what an allowlist is judged against. A resolve that fails
  // still reports: the tool asking is the fact worth keeping, since it
  // separates "was prevented" from "never tried".
  const dns = require('dns');
  ['lookup', 'resolve', 'resolve4', 'resolve6', 'resolveAny'].forEach((m) => {
    wrap(dns, m, (a) => emit({
      t: now(), event: 'socket.getaddrinfo', args: [text(a[0])]
    }));
    if (dns.promises) {
      wrap(dns.promises, m, (a) => emit({
        t: now(), event: 'socket.getaddrinfo', args: [text(a[0])]
      }));
    }
  });

  // --- sockets ----------------------------------------------------------
  // args[1] is the [host, port] pair, matching what the Python hook records
  // for socket.connect, because that is the only attribution available for a
  // connection made to a bare address with no lookup.
  const net = require('net');
  wrap(net.Socket.prototype, 'connect', (a) => {
    let host = null, port = null;
    const first = a[0];
    if (first && typeof first === 'object') {
      host = text(first.host || first.path);
      port = first.port || null;
    } else {
      port = first || null;
      host = a.length > 1 ? text(a[1]) : null;
    }
    emit({ t: now(), event: 'socket.connect', args: [null, [host, port]] });
  });
  ['connect', 'createConnection'].forEach((m) =>
    wrap(net, m, (a) => {
      const first = a[0];
      if (first && typeof first === 'object') {
        emit({
          t: now(), event: 'socket.connect',
          args: [null, [text(first.host || first.path), first.port || null]]
        });
      }
    }));

  // http/https requests resolve and connect underneath, so they are already
  // covered. The URL is reported anyway: it names the destination before any
  // of that happens, which is the more useful record when a request fails.
  ['http', 'https'].forEach((mod) => {
    let m;
    try { m = require(mod); } catch (e) { return; }
    ['request', 'get'].forEach((fn) =>
      wrap(m, fn, (a) => {
        const first = a[0];
        let host = null;
        if (typeof first === 'string') {
          try { host = new URL(first).hostname; } catch (e) { host = text(first); }
        } else if (first && typeof first === 'object') {
          host = text(first.hostname || first.host);
        }
        if (host) emit({ t: now(), event: 'socket.getaddrinfo', args: [host] });
      }));
  });

  // --- child processes --------------------------------------------------
  // Reported as subprocess.Popen with (executable, command line) so the
  // harness's program extraction, and subprocess-scope, work unchanged.
  const cp = require('child_process');

  // exec and execSync take a whole COMMAND LINE as their first argument;
  // spawn and execFile take an executable. Reporting a command line in the
  // executable slot makes the harness read the program name as
  // "node --version", so the two shapes are kept apart: a command line goes in
  // args[1] with args[0] null, which is exactly what CPython does when no
  // executable was given explicitly, and the harness already parses that.
  const SHELL_FORM = { exec: 1, execSync: 1 };
  ['spawn', 'spawnSync', 'exec', 'execSync', 'execFile', 'execFileSync',
    'fork'].forEach((m) =>
    wrap(cp, m, (a) => {
      const first = text(a[0]);
      const rest = Array.isArray(a[1]) ? a[1].map(text).join(' ') : '';
      const line = rest ? first + ' ' + rest : first;
      emit({
        t: now(), event: 'subprocess.Popen',
        args: SHELL_FORM[m] ? [null, first, null, null]
                            : [first, line, null, null]
      });
    }));

  // --- liveness ---------------------------------------------------------
  // One event at load, so the harness can tell "watched and saw nothing" from
  // "was never watching". Without it a pure-computation Node server produces
  // no events at all and is indistinguishable from an unmonitored one, which
  // is precisely the ambiguity that made four servers unmeasurable.
  //
  // It is deliberately NOT a network, write or process event, so it can never
  // be mistaken for the tool having acted.
  emit({
    t: now(), event: 'monitor.ready', runtime: 'node',
    version: process.version,
    note: 'observes the Node runtime, not the kernel; a native addon calling ' +
          'the OS directly is not visible here'
  });
})();
