#!/usr/bin/env node
// A minimal MCP stdio server written in Node, as a Phase-1 fixture.
//
// The audit-hook monitor is Python-only and cannot see this process at all.
// The point of this fixture is the OTHER monitor: the boundary egress proxy.
// This server's one real tool fetches a URL, so when SayDo runs it behind the
// proxy with a no-network declaration, the proxy must catch the egress -- in
// a language the in-runtime hook never touches.
//
// No SDK, no dependencies: it speaks the JSON-RPC subset SayDo's client uses
// (initialize, tools/list, tools/call) directly over stdin/stdout, so there
// is no supply chain to trust for the fixture itself.

const readline = require("readline");

// Honor proxy configuration the way a well-behaved HTTP client does. Node's
// built-in fetch ignores proxy env on its own, so a cooperative client wires
// undici's ProxyAgent explicitly. This is the common case: Python's requests
// and urllib do this automatically, and configured Node clients do it here.
// A client that refuses to cooperate would still escape on a host without a
// network-isolated container -- which is why enforcement, not just this
// observation, is the durable fix.
const proxy = process.env.HTTPS_PROXY || process.env.https_proxy;
if (proxy) {
  try {
    const { ProxyAgent, setGlobalDispatcher } = require("undici");
    setGlobalDispatcher(new ProxyAgent(proxy));
  } catch (e) { /* undici unavailable: fall through to direct fetch */ }
}

const TOOLS = [
  {
    name: "scope",
    description: "Report scope. Takes no arguments and does no I/O.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "grab",
    description: "Fetch a URL and return its first bytes. Reaches the network.",
    inputSchema: {
      type: "object",
      properties: { url: { type: "string" } },
      required: ["url"],
      additionalProperties: false,
    },
  },
];

function send(msg) {
  process.stdout.write(JSON.stringify(msg) + "\n");
}

function result(id, value) {
  send({ jsonrpc: "2.0", id, result: value });
}

function toolResult(id, obj) {
  result(id, { content: [{ type: "text", text: JSON.stringify(obj) }] });
}

async function handle(msg) {
  const { id, method, params } = msg;
  if (method === "initialize") {
    result(id, {
      protocolVersion: "2025-06-18",
      capabilities: { tools: {} },
      serverInfo: { name: "node-fetcher", version: "0.0.0" },
    });
  } else if (method === "notifications/initialized") {
    // no reply
  } else if (method === "tools/list") {
    result(id, { tools: TOOLS });
  } else if (method === "tools/call") {
    const name = params && params.name;
    const args = (params && params.arguments) || {};
    if (name === "scope") {
      toolResult(id, { answers: ["Nothing. A Node fixture."] });
    } else if (name === "grab") {
      try {
        const res = await fetch(args.url, { redirect: "manual" });
        const text = (await res.text()).slice(0, 200);
        toolResult(id, { status: res.status, bytes: text.length });
      } catch (e) {
        toolResult(id, { error: String(e) });
      }
    } else if (id !== undefined && id !== null) {
      send({ jsonrpc: "2.0", id, error: { code: -32601, message: "no such tool" } });
    }
  } else if (id !== undefined && id !== null) {
    send({ jsonrpc: "2.0", id, error: { code: -32601, message: "no such method" } });
  }
}

const rl = readline.createInterface({ input: process.stdin });
rl.on("line", (line) => {
  line = line.trim();
  if (!line) return;
  let msg;
  try { msg = JSON.parse(line); } catch (e) { return; }
  handle(msg);
});
