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
//   PORTKIT_NOW   an RFC 3339 time: Date.now(), new Date() and Date() return it. performance.now,
//                 process.hrtime and process.hrtime.bigint start at 0. setTimeout and setInterval
//                 (global, node:timers, and timers/promises setTimeout) still wait in real time
//                 and keep their order, but when a callback runs the pinned clocks stand at its
//                 due time (the delay after the clock when it was set), so a module reads the
//                 same elapsed time on every run. The pinned wall clock moves with them. The
//                 clocks move only through those timers (a busy-wait on one never ends).
//   PORTKIT_SEED  an integer: Math.random is a seeded generator (mulberry32). One byte stream
//                 also feeds crypto.randomBytes, randomFillSync, randomFill, getRandomValues
//                 (node:crypto and globalThis.crypto), randomUUID and randomInt: block i is
//                 SHA-256("portkit-bytes\0" + decimal(seed) + "\0" + i as 8 bytes big-endian),
//                 consumed byte by byte, so the Python adapter draws the same bytes for the same
//                 seed.
//   TZ            set to UTC when the environment has none.
// Not pinned: timers/promises setInterval and scheduler, setImmediate, Intl's own clock, file
// times, crypto keys, primes and subtle, generators a module builds from its own entropy, native
// addons.
//
// Anything the module writes to stdout while it runs goes to stderr, so it cannot corrupt the
// result. TypeScript: pass a .ts path. Node must strip types itself (Node 22.18+ and 23.6+ do;
// 22.6 to 22.17 need `node --experimental-strip-types adapter.mjs ...`); only erasable syntax
// is supported (no enums or namespaces). Otherwise compile first and name the output.

import nodeCrypto from "node:crypto";
import { syncBuiltinESMExports } from "node:module";
import path from "node:path";
import nodeTimers from "node:timers";
import timersPromises from "node:timers/promises";
import { pathToFileURL } from "node:url";
import { promisify } from "node:util";

const { createHash } = nodeCrypto;

class AdapterError extends Error {}

function fail(message) {
  throw new AdapterError(message);
}

// ---- pinning -------------------------------------------------------------------------------

const NOW = /^(\d{4})-(\d{2})-(\d{2})[Tt ](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?([Zz]|[+-]\d{2}:\d{2})$/;

// Virtual nanoseconds since the adapter pinned the clock; only the pinned timers move it.
let virtualNs = 0n;
const NS_PER_MS = 1000000n;

function pinClock(text) {
  const m = NOW.exec(text);
  const ms = m ? (m[7] ?? "").padEnd(3, "0").slice(0, 3) : "";
  const iso = m ? `${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}.${ms}${m[8].toUpperCase()}` : "";
  const fixed = m ? Date.parse(iso) : NaN;
  if (Number.isNaN(fixed)) {
    fail(`PORTKIT_NOW must be an RFC 3339 time such as 2026-01-02T03:04:05Z, got ${JSON.stringify(text)}`);
  }
  const RealDate = Date;
  const wall = () => fixed + Number(virtualNs / NS_PER_MS);
  globalThis.Date = new Proxy(RealDate, {
    construct: (target, args, newTarget) =>
      Reflect.construct(target, args.length === 0 ? [wall()] : args, newTarget),
    apply: () => new RealDate(wall()).toString(),
    get: (target, prop, receiver) => (prop === "now" ? () => wall() : Reflect.get(target, prop, receiver)),
  });

  const define = (object, name, value) =>
    Object.defineProperty(object, name, { value, configurable: true, writable: true, enumerable: true });
  define(globalThis.performance, "now", () => Number(virtualNs) / 1e6);
  define(globalThis.performance, "timeOrigin", fixed);
  const hrtime = (previous) => {
    let seconds = Number(virtualNs / 1000000000n);
    let nanos = Number(virtualNs % 1000000000n);
    if (previous !== undefined) {
      if (!Array.isArray(previous) || previous.length !== 2) {
        throw new TypeError('The "time" argument must be an instance of Array of length 2');
      }
      seconds -= previous[0];
      nanos -= previous[1];
      if (nanos < 0) {
        seconds -= 1;
        nanos += 1e9;
      }
    }
    return [seconds, nanos];
  };
  hrtime.bigint = () => virtualNs;
  process.hrtime = hrtime;
  pinTimers();
}

// Timers keep their real delay (so order is the platform's own), but the callback finds the
// pinned clocks at its due time.
function pinTimers() {
  const realSetTimeout = globalThis.setTimeout;
  const realSetInterval = globalThis.setInterval;
  const delayOf = (delay) => {
    const n = Math.trunc(Number(delay));
    return n >= 1 && n <= 2147483647 ? n : 1;
  };
  const advanceTo = (due) => {
    if (due > virtualNs) virtualNs = due;
  };
  function setTimeoutPinned(callback, delay, ...args) {
    if (typeof callback !== "function") return realSetTimeout(callback, delay, ...args);
    const ms = delayOf(delay);
    const due = virtualNs + BigInt(ms) * NS_PER_MS;
    return realSetTimeout(function () {
      advanceTo(due);
      return callback.apply(this, args);
    }, ms);
  }
  function setIntervalPinned(callback, delay, ...args) {
    if (typeof callback !== "function") return realSetInterval(callback, delay, ...args);
    const ms = delayOf(delay);
    let due = virtualNs + BigInt(ms) * NS_PER_MS;
    return realSetInterval(function () {
      advanceTo(due);
      due += BigInt(ms) * NS_PER_MS;
      return callback.apply(this, args);
    }, ms);
  }
  const abortError = (signal) => {
    const error = new Error("The operation was aborted", { cause: signal.reason });
    error.name = "AbortError";
    error.code = "ABORT_ERR";
    return error;
  };
  const sleep = (delay, value, options) =>
    new Promise((resolve, reject) => {
      const { signal, ref = true } = options ?? {};
      if (signal?.aborted) return reject(abortError(signal));
      const onAbort = () => {
        clearTimeout(timer);
        reject(abortError(signal));
      };
      const timer = setTimeoutPinned(() => {
        signal?.removeEventListener("abort", onAbort);
        resolve(value);
      }, delay);
      if (!ref) timer.unref();
      signal?.addEventListener("abort", onAbort, { once: true });
    });
  setTimeoutPinned[promisify.custom] = sleep;
  globalThis.setTimeout = setTimeoutPinned;
  globalThis.setInterval = setIntervalPinned;
  nodeTimers.setTimeout = setTimeoutPinned;
  nodeTimers.setInterval = setIntervalPinned;
  timersPromises.setTimeout = sleep;
  syncBuiltinESMExports();
}

// The pinned byte stream: SHA-256 in counter mode over the seed.
function byteStream(seedText) {
  const prefix = Buffer.concat([Buffer.from("portkit-bytes\0"), Buffer.from(String(BigInt(seedText))), Buffer.from([0])]);
  let counter = 0n;
  let buffer = Buffer.alloc(0);
  return (size) => {
    while (buffer.length < size) {
      const block = Buffer.alloc(8);
      block.writeBigUInt64BE(counter);
      counter += 1n;
      buffer = Buffer.concat([buffer, createHash("sha256").update(prefix).update(block).digest()]);
    }
    const out = Buffer.from(buffer.subarray(0, size));
    buffer = buffer.subarray(size);
    return out;
  };
}

const INTEGER_ARRAYS = [Int8Array, Uint8Array, Uint8ClampedArray, Int16Array, Uint16Array, Int32Array, Uint32Array, BigInt64Array, BigUint64Array];

function pinCrypto(seedText) {
  const read = byteStream(seedText);
  const defer = (callback, value) => {
    if (typeof callback !== "function") throw new TypeError('The "callback" argument must be of type function.');
    process.nextTick(callback, null, value);
  };
  const sizeOf = (size) => {
    if (typeof size !== "number" || Number.isNaN(size)) throw new TypeError('The "size" argument must be of type number.');
    if (size < 0 || size > 2147483647) throw new RangeError('The value of "size" is out of range.');
    return Math.trunc(size);
  };
  const bytesOf = (buffer) => {
    if (ArrayBuffer.isView(buffer)) return new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);
    if (buffer instanceof ArrayBuffer || buffer instanceof SharedArrayBuffer) return new Uint8Array(buffer);
    throw new TypeError('The "buf" argument must be an instance of ArrayBuffer or ArrayBufferView.');
  };
  const fill = (buffer, offset, size) => {
    const bytes = bytesOf(buffer);
    const width = buffer.BYTES_PER_ELEMENT ?? 1;
    const start = (offset ?? 0) * width;
    const length = size === undefined ? bytes.length - start : size * width;
    if (!(start >= 0 && start <= bytes.length)) throw new RangeError('The value of "offset" is out of range.');
    if (!(length >= 0 && start + length <= bytes.length)) throw new RangeError('The value of "size" is out of range.');
    bytes.set(read(length), start);
    return buffer;
  };
  const randomBytes = (size, callback) => {
    const out = read(sizeOf(size));
    if (callback === undefined) return out;
    defer(callback, out);
  };
  const randomFillSync = (buffer, offset, size) => fill(buffer, offset, size);
  const randomFill = (buffer, offset, size, callback) => {
    if (typeof offset === "function") [offset, size, callback] = [undefined, undefined, offset];
    else if (typeof size === "function") [size, callback] = [undefined, size];
    defer(callback, fill(buffer, offset, size));
  };
  const randomInt = (min, max, callback) => {
    if (max === undefined || typeof max === "function") [min, max, callback] = [0, min, max];
    for (const [name, value] of [["min", min], ["max", max]]) {
      if (!Number.isSafeInteger(value)) throw new TypeError(`The "${name}" argument must be a safe integer.`);
    }
    if (max <= min) throw new RangeError('The value of "max" is out of range. It must be greater than the value of "min".');
    const range = max - min;
    if (range > 281474976710655) throw new RangeError('The value of "max - min" is out of range. It must be <= 281474976710655.');
    const limit = 281474976710656 - (281474976710656 % range);
    let x = read(6).readUIntBE(0, 6);
    while (x >= limit) x = read(6).readUIntBE(0, 6);
    const value = min + (x % range);
    if (callback === undefined) return value;
    defer(callback, value);
  };
  const randomUUID = () => {
    const b = read(16);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    const h = b.toString("hex");
    return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
  };
  const getRandomValues = (array) => {
    if (!ArrayBuffer.isView(array) || !INTEGER_ARRAYS.some((type) => array instanceof type)) {
      throw new DOMException("The data argument must be an integer-type TypedArray", "TypeMismatchError");
    }
    if (array.byteLength > 65536) {
      throw new DOMException("The ArrayBufferView's byte length exceeds the number of bytes of entropy available via this API (65536)", "QuotaExceededError");
    }
    return fill(array);
  };
  const define = (object, name, value) =>
    Object.defineProperty(object, name, { value, configurable: true, writable: true, enumerable: true });
  for (const [name, value] of Object.entries({ randomBytes, randomFillSync, randomFill, randomInt, randomUUID })) {
    define(nodeCrypto, name, value);
  }
  for (const web of new Set([nodeCrypto.webcrypto, globalThis.crypto])) {
    if (web) {
      define(web, "getRandomValues", getRandomValues);
      define(web, "randomUUID", randomUUID);
    }
  }
  syncBuiltinESMExports();
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
  pinCrypto(text);
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
