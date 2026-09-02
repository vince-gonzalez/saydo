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

  try {
    const { HttpsProxyAgent } = require('https-proxy-agent');
    const agent = new HttpsProxyAgent(proxy);
    require('http').globalAgent = agent;
    require('https').globalAgent = agent;
  } catch (e) {
    // No proxy-agent module available. Fall back to routing http/https through
    // the proxy by rewriting request options to target the proxy host with an
    // absolute path, which a forward proxy accepts.
    const url = require('url');
    const p = new url.URL(proxy);
    ['http', 'https'].forEach((mod) => {
      let m;
      try { m = require(mod); } catch (e) { return; }
      const orig = m.request;
      m.request = function (options, cb) {
        try {
          if (typeof options === 'string') options = new url.URL(options);
          if (options instanceof url.URL) {
            options = {
              host: p.hostname, port: p.port,
              path: options.href,
              headers: { Host: options.host }
            };
          } else if (options && !options._saydo) {
            const targetHost = options.hostname || options.host;
            const scheme = mod === 'https' ? 'https' : 'http';
            options = Object.assign({}, options, {
              _saydo: true,
              host: p.hostname, hostname: p.hostname, port: p.port,
              path: scheme + '://' + targetHost + (options.path || '/'),
              headers: Object.assign({ Host: targetHost }, options.headers)
            });
          }
        } catch (e) { /* leave options as-is */ }
        return orig.call(this, options, cb);
      };
    });
  }
})();
