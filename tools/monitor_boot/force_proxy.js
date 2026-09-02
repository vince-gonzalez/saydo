'use strict';
/*
 * Force ALL Node egress through the proxy at SAYDO_PROXY, so the recording
 * proxy actually sees it.
 *
 * This exists because a host-side proxy is trivially bypassed and Node bypasses
 * it BY DEFAULT: neither global fetch (undici) nor http/https honour HTTP_PROXY
 * environment variables. A run that set those variables and saw no traffic was
 * not observing a quiet package -- it was observing nothing, and reporting the
 * blindness as cleanliness. That is the exact not-covered-as-pass error the
 * whole project refuses.
 *
 * Loaded with --require before the package's code. It sets undici's global
 * dispatcher to a ProxyAgent and points http/https global agents at the proxy.
 * A native addon or a spawned curl can still evade it -- that is the honest
 * ceiling of host-side interception, and the reason real enforcement lives in
 * the container. What this closes is the ordinary case: JS code using fetch,
 * https, or a library built on them.
 */
(function () {
  const proxy = process.env.SAYDO_PROXY;
  if (!proxy) return;
  try {
    const undici = require('undici');
    if (undici && undici.setGlobalDispatcher && undici.ProxyAgent) {
      undici.setGlobalDispatcher(new undici.ProxyAgent(proxy));
    }
  } catch (e) { /* undici not present; http/https still covered below */ }

  // A CONNECT-tunnelling agent, written inline so no module needs installing.
  // HTTPS through a forward proxy is NOT an absolute-path GET -- that is the
  // http-proxy form, and using it for https (the first attempt here) let
  // https.get sail straight past. https needs: dial the proxy, send
  // `CONNECT host:port`, wait for `200`, then hand the tunnelled socket up for
  // TLS. The proxy terminates that TLS with its CA and reads the body.
  try {
    const net = require('net');
    const https = require('https');
    const http = require('http');
    const url = require('url');
    const p = new url.URL(proxy);
    const proxyHost = p.hostname;
    const proxyPort = Number(p.port) || 80;

    class TunnelAgent extends https.Agent {
      createConnection(options, cb) {
        const targetHost = options.host || options.hostname;
        const targetPort = options.port || 443;
        const sock = net.connect(proxyPort, proxyHost, () => {
          sock.write(
            'CONNECT ' + targetHost + ':' + targetPort + ' HTTP/1.1\r\n' +
            'Host: ' + targetHost + ':' + targetPort + '\r\n\r\n');
        });
        let header = '';
        const onData = (chunk) => {
          header += chunk.toString('latin1');
          const end = header.indexOf('\r\n\r\n');
          if (end === -1) return;
          sock.removeListener('data', onData);
          if (!/^HTTP\/1\.[01] 200/.test(header)) {
            cb(new Error('proxy CONNECT failed: ' + header.slice(0, 40)));
            sock.destroy();
            return;
          }
          // TLS re-originates on top of the tunnel; the proxy is the peer and
          // presents a leaf under its CA, which NODE_EXTRA_CA_CERTS trusts.
          const tls = require('tls').connect({
            socket: sock, servername: targetHost,
            ...options
          }, () => cb(null, tls));
          tls.on('error', (e) => cb(e));
        };
        sock.on('data', onData);
        sock.on('error', (e) => cb(e));
        return undefined;
      }
    }
    https.globalAgent = new TunnelAgent();

    // Plain http through a forward proxy IS the absolute-path form.
    const httpOrig = http.request;
    http.request = function (options, cb) {
      try {
        if (typeof options === 'string') options = new url.URL(options);
        if (options instanceof url.URL) {
          const target = options.host;
          options = { host: proxyHost, port: proxyPort, path: options.href,
                      headers: { Host: target } };
        } else if (options && !options._saydo) {
          const target = options.hostname || options.host;
          options = Object.assign({}, options, {
            _saydo: true, host: proxyHost, hostname: proxyHost,
            port: proxyPort, path: 'http://' + target + (options.path || '/'),
            headers: Object.assign({ Host: target }, options.headers) });
        }
      } catch (e) { /* leave as-is */ }
      return httpOrig.call(this, options, cb);
    };
  } catch (e) { /* http/https interception best-effort */ }
})();
