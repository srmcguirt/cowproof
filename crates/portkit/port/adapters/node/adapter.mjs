#!/usr/bin/env node
// portkit function-level capture adapter for Node and TypeScript. Standard library only (tested on Node 22).
//
//   node adapter.mjs <module> [<function>]
//
// Copy this file beside the source module (or call it by path) and use it as the reference
// command of `pk port capture --cmd 'node adapter.mjs ./tally.mjs'`. It speaks portkit's
// contract: one JSON request {"tool": name, "input": value} on stdin, one JSON result on
// stdout. It never computes anything the module does not.
//
// Dispatch. With <function>, every request calls that function. Without it the request's
// "tool" (else $PORTKIT_TOOL) names the exported function. The tool "__defaults" is answered by
// the adapter: the module's `__defaults` export (a value, or a function that returns one), else
// an object of every exported value that is not a function. Fixtures can then hold the module's
// constants as data, and the port is checked against them.
//
// Arguments. The function is called with the request's "input" as its one argument. An input
// that is exactly {"args": [...]} calls it with those arguments instead. A promise is awaited.
//
// Errors. A function that throws answers {"error": message} and the adapter exits 0, so the
// error is a fixture like any other result. Anything wrong with the adapter's own setup (no
// such module or function, bad request, a result that is not JSON, a bad PORTKIT_* value) is
// reported on stderr with exit status 2, so a capture fails instead of recording a mistake.
//
// Output. One line of canonical JSON: object keys sorted by UTF-16 code unit, no whitespace,
// numbers as ECMAScript prints them (so 3.0 is 3 and -0 is 0), non-ASCII text as UTF-8. Non-JSON
// values: Date by toJSON, RegExp as its source, Map as an array of [key, value], Set and typed
// arrays as arrays, BigInt as an integer, undefined as null in an array and absent in an
// object. NaN and Infinity are refused. Equivalent data prints identical bytes from the Python
// adapter.
//
// Pinned when set (unset leaves the module alone):
//   PORTKIT_NOW   an RFC 3339 time: Date.now(), new Date() and Date() return it.
//   PORTKIT_SEED  an integer: Math.random is a seeded generator (mulberry32).
//   TZ            set to UTC when the environment has none.
// Not pinned: performance.now, process.hrtime, timers, Intl's own clock, crypto randomness.
//
// Anything the module writes to stdout while it runs goes to stderr, so it cannot corrupt the
// result. TypeScript: pass a .ts path. Node must strip types itself (Node 22.18+ and 23.6+ do;
// 22.6 to 22.17 need `node --experimental-strip-types adapter.mjs ...`); only erasable syntax
// is supported (no enums or namespaces). Otherwise compile first and name the output.

import path from "node:path";
import { pathToFileURL } from "node:url";

class AdapterError extends Error {}

function fail(message) {
  throw new AdapterError(message);
}

// ---- pinning -------------------------------------------------------------------------------

const NOW = /^(\d{4})-(\d{2})-(\d{2})[Tt ](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?([Zz]|[+-]\d{2}:\d{2})$/;

function pinClock(text) {
  const m = NOW.exec(text);
  const ms = m ? (m[7] ?? "").padEnd(3, "0").slice(0, 3) : "";
  const iso = m ? `${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}.${ms}${m[8].toUpperCase()}` : "";
  const fixed = m ? Date.parse(iso) : NaN;
  if (Number.isNaN(fixed)) {
    fail(`PORTKIT_NOW must be an RFC 3339 time such as 2026-01-02T03:04:05Z, got ${JSON.stringify(text)}`);
  }
  const RealDate = Date;
  globalThis.Date = new Proxy(RealDate, {
    construct: (target, args, newTarget) =>
      Reflect.construct(target, args.length === 0 ? [fixed] : args, newTarget),
    apply: () => new RealDate(fixed).toString(),
    get: (target, prop, receiver) => (prop === "now" ? () => fixed : Reflect.get(target, prop, receiver)),
  });
}

function pinRandom(text) {
  if (!/^-?\d+$/.test(text)) fail(`PORTKIT_SEED must be an integer, got ${JSON.stringify(text)}`);
  let a = Number(BigInt.asUintN(32, BigInt(text)));
  Math.random = () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = Math.imul(a ^ (a >>> 15), a | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// ---- canonical output ----------------------------------------------------------------------

function str(s) {
  if (typeof s.isWellFormed === "function" && !s.isWellFormed()) fail("a string holds a lone surrogate, which is not valid UTF-8");
  return JSON.stringify(s);
}

// The text of `v`, or undefined when JSON leaves it out (a function, a symbol, undefined).
function enc(v, stack) {
  switch (typeof v) {
    case "string":
      return str(v);
    case "number":
      if (!Number.isFinite(v)) fail(`${v} is not representable in JSON`);
      return String(v);
    case "bigint":
      return v.toString();
    case "boolean":
      return v ? "true" : "false";
    case "undefined":
    case "function":
    case "symbol":
      return undefined;
  }
  if (v === null) return "null";
  if (stack.includes(v)) fail("the result contains a cycle");
  stack.push(v);
  try {
    if (typeof v.toJSON === "function") return enc(v.toJSON(), stack) ?? "null";
    if (v instanceof RegExp) return str(v.source);
    if (v instanceof Boolean || v instanceof Number || v instanceof String) return enc(v.valueOf(), stack);
    if (Array.isArray(v) || v instanceof Set || v instanceof Map || (ArrayBuffer.isView(v) && !(v instanceof DataView))) {
      return "[" + Array.from(v, (item) => enc(item, stack) ?? "null").join(",") + "]";
    }
    const parts = [];
    for (const key of Object.keys(v).sort()) {
      const text = enc(v[key], stack);
      if (text !== undefined) parts.push(str(key) + ":" + text);
    }
    return "{" + parts.join(",") + "}";
  } finally {
    stack.pop();
  }
}

function canonical(value) {
  return enc(value, []) ?? "null";
}

// ---- the call ------------------------------------------------------------------------------

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks).toString("utf8");
}

function defaultsOf(mod) {
  if ("__defaults" in mod) {
    const d = mod.__defaults;
    return typeof d === "function" ? d() : d;
  }
  const out = {};
  for (const [name, value] of Object.entries(mod)) {
    if (name !== "default" && typeof value !== "function") out[name] = value;
  }
  return out;
}

async function run(argv) {
  const [modulePath, functionName] = argv;
  if (!modulePath || argv.length > 2) {
    fail("usage: adapter.mjs <module> [<function>]   (a request {\"tool\":..,\"input\":..} on stdin)");
  }
  if (process.env.TZ === undefined) process.env.TZ = "UTC";
  if (process.env.PORTKIT_NOW) pinClock(process.env.PORTKIT_NOW);
  if (process.env.PORTKIT_SEED) pinRandom(process.env.PORTKIT_SEED);

  let request;
  try {
    request = JSON.parse(await readStdin());
  } catch (e) {
    fail(`stdin is not one JSON request: ${e.message}`);
  }
  if (request === null || typeof request !== "object" || Array.isArray(request)) {
    fail('the request must be a JSON object {"tool": name, "input": value}');
  }
  const tool = request.tool ?? process.env.PORTKIT_TOOL;

  // The module's own output must not reach the result channel.
  const writeResult = process.stdout.write.bind(process.stdout);
  process.stdout.write = (...args) => process.stderr.write(...args);

  let mod;
  try {
    mod = await import(pathToFileURL(path.resolve(modulePath)).href);
  } catch (e) {
    const hint = /\.[cm]?ts$/.test(modulePath) ? " (a TypeScript file needs a Node that strips types: Node 22.18+, 23.6+, or --experimental-strip-types on 22.6 to 22.17)" : "";
    fail(`cannot load ${modulePath}: ${e.message}${hint}`);
  }

  let result;
  if (tool === "__defaults") {
    result = defaultsOf(mod);
  } else {
    const name = functionName ?? tool;
    if (typeof name !== "string" || name === "") fail("no function to call: name one on the command line or send a request tool");
    if (typeof mod[name] !== "function") {
      fail(`${modulePath} exports no function ${JSON.stringify(name)} (exports: ${Object.keys(mod).join(", ") || "none"})`);
    }
    if (!("input" in request)) fail('the request has no "input"');
    const input = request.input;
    const keys = input !== null && typeof input === "object" ? Object.keys(input) : [];
    const positional = keys.length === 1 && keys[0] === "args" && Array.isArray(input.args);
    try {
      result = await mod[name](...(positional ? input.args : [input]));
    } catch (e) {
      result = { error: e instanceof Error ? e.message : String(e) };
    }
  }
  return { text: canonical(result), writeResult };
}

try {
  const { text, writeResult } = await run(process.argv.slice(2));
  writeResult(text + "\n", () => process.exit(0));
} catch (e) {
  process.stderr.write(`portkit-adapter: ${e instanceof AdapterError ? e.message : e.stack}\n`, () => process.exit(2));
}
