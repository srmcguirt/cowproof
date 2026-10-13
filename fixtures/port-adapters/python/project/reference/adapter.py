#!/usr/bin/env python3
"""portkit function-level capture adapter for Python. Standard library only (written for Python 3.8+, tested on 3.9 and 3.14).

    python3 adapter.py <module> [<function>]

Copy this file beside the source module (or call it by path) and use it as the reference
command of `pk port capture --cmd 'python3 adapter.py ./shipping.py'`. It speaks portkit's
contract: one JSON request {"tool": name, "input": value} on stdin, one JSON result on stdout.
It never computes anything the module does not.

<module> is a path to a .py file, or a module name importable from the current directory.

Dispatch. With <function>, every request calls that function. Without it the request's "tool"
(else $PORTKIT_TOOL) names the function. The tool "__defaults" is answered by the adapter: the
module's `__defaults` (a value, or a function that returns one), else an object of the module's
UPPER_CASE constants. Fixtures can then hold the module's constants as data, and the port is
checked against them.

Arguments. The function is called with the request's "input" as its one argument. An input that
is exactly {"args": [...]} calls it with those arguments instead. A coroutine is run to the end.

Errors. A function that raises answers {"error": message} and the adapter exits 0, so the error
is a fixture like any other result. Anything wrong with the adapter's own setup (no such module
or function, bad request, a result that is not JSON, a bad PORTKIT_* value) is reported on
stderr with exit status 2, so a capture fails instead of recording a mistake.

Output. One line of canonical JSON: object keys sorted by UTF-16 code unit, no whitespace,
numbers as ECMAScript prints them (so 3.0 is 3, -0.0 is 0 and 1e-07 is 1e-7), non-ASCII text as
UTF-8. Non-JSON values: tuple as an array, set and frozenset as an array sorted by its items'
text, datetime, date and time as their isoformat(). NaN, Infinity, bytes and other objects are
refused. Equivalent data prints identical bytes from the Node adapter.

Pinned when set (unset leaves the module alone):
  PORTKIT_NOW   an RFC 3339 time: time.time(), time.time_ns(), time.localtime()/gmtime()/
                ctime()/strftime() without a time, datetime.now()/utcnow()/today() and
                date.today() return it. time.monotonic, monotonic_ns, perf_counter and
                perf_counter_ns start at 0. time.sleep(s) does not sleep: it advances the
                monotonic clocks and the wall clock by s, so a pinned clock moves only when the
                module sleeps (a busy-wait on it never ends). uuid.uuid1() is built from the
                pinned time, a fixed node (01:00:00:00:00:01) and clock_seq 0; a call made at
                the same pinned instant as the last gets the next 100 ns tick, so values differ.
                asyncio keeps its own real clock, so asyncio.sleep still waits.
  PORTKIT_SEED  an integer: random.seed(seed) for the module-level random functions. One byte
                stream also feeds os.urandom, secrets (token_bytes, token_hex, token_urlsafe,
                randbelow, choice), random.SystemRandom and uuid.uuid4: block i is
                SHA-256(b"portkit-bytes\\0" + decimal(seed) + b"\\0" + i as 8 bytes big-endian),
                consumed byte by byte, so the Node adapter draws the same bytes for the same
                seed. When numpy can be imported, numpy.random.seed(seed % 2**32) is called and
                numpy.random.default_rng() without a seed gets a seed derived from it (the n-th
                such generator is default_rng([seed % 2**32, n])). Without numpy nothing happens.
  TZ            set to UTC when the environment has none.
  PYTHONHASHSEED  set to 0 when the environment has none, by restarting once, so set and dict
                  iteration of str is repeatable.
Not pinned: file times, process_time and thread_time, uuid.uuid6/7/8 beyond the pinned clock and
bytes above, numpy.random.RandomState() made without a seed, generators a module seeds from its
own entropy, native extensions, and anything that waits on a real clock (threads, sockets,
asyncio).

Anything the module writes to stdout while it runs goes to stderr, so it cannot corrupt the result.
Python 3.12 changed sum() of floats to compensated summation: pin the Python version of a
reference whose output depends on it.
"""
import os
import sys

# Hash randomization is fixed when the interpreter starts: restart once with a pinned seed.
if (
    __name__ == "__main__"
    and os.name == "posix"
    and sys.executable
    and "PYTHONHASHSEED" not in os.environ
    and sys.flags.hash_randomization
):
    os.environ["PYTHONHASHSEED"] = "0"
    os.execv(sys.executable, [sys.executable, os.path.abspath(__file__)] + sys.argv[1:])

import asyncio
import asyncio.base_events
import calendar
import datetime
import hashlib
import importlib
import importlib.util
import inspect
import json
import math
import operator
import random
import re
import time
import types


class AdapterError(Exception):
    pass


def _fail(message):
    raise AdapterError(message)


# ---- pinning -------------------------------------------------------------------------------

_NOW = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[Tt ](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?([Zz]|[+-]\d{2}:\d{2})$"
)
_REAL_DATE = datetime.date
_REAL_DATETIME = datetime.datetime
_REAL_TIME = datetime.time


def _pin_clock(text):
    m = _NOW.match(text)
    try:
        if not m:
            raise ValueError(text)
        year, month, day, hour, minute, second = (int(g) for g in m.groups()[:6])
        micro = int((m.group(7) or "").ljust(6, "0")[:6])
        stamp = _REAL_DATETIME(year, month, day, hour, minute, second)
        offset = m.group(8)
        shift = 0
        if offset not in ("Z", "z"):
            shift = (int(offset[1:3]) * 3600 + int(offset[4:6]) * 60) * (1 if offset[0] == "+" else -1)
        seconds = calendar.timegm(stamp.timetuple()) - shift
    except ValueError:
        _fail("PORTKIT_NOW must be an RFC 3339 time such as 2026-01-02T03:04:05Z, got %r" % text)
    epoch = seconds + micro / 1e6
    base_ns = seconds * 1000000000 + micro * 1000
    utc = datetime.timezone.utc
    slept = [0]  # nanoseconds the pinned sleep has advanced the clocks by

    def wall():
        return epoch + slept[0] / 1e9

    # asyncio schedules by time.monotonic: keep its clock real, or call_later never comes due.
    real_monotonic, real_monotonic_ns = time.monotonic, time.monotonic_ns
    real_perf_counter, real_perf_counter_ns = time.perf_counter, time.perf_counter_ns

    class _LoopTime:
        monotonic = staticmethod(real_monotonic)
        monotonic_ns = staticmethod(real_monotonic_ns)
        perf_counter = staticmethod(real_perf_counter)
        perf_counter_ns = staticmethod(real_perf_counter_ns)

        def __getattr__(self, name):
            return getattr(time, name)

    if getattr(asyncio.base_events, "time", None) is time:
        asyncio.base_events.time = _LoopTime()

    def sleep(secs):
        if isinstance(secs, bool) or not isinstance(secs, (int, float)):
            raise TypeError("'%s' object cannot be interpreted as an integer or float" % type(secs).__name__)
        if secs != secs:
            raise ValueError("Invalid value NaN (not a number)")
        if secs < 0:
            raise ValueError("sleep length must be non-negative")
        if math.isinf(secs):
            raise OverflowError("timestamp too large to convert to C _PyTime_t")
        slept[0] += int(round(secs * 1e9))

    real_localtime, real_gmtime = time.localtime, time.gmtime
    real_ctime, real_strftime = time.ctime, time.strftime
    time.time = wall
    time.time_ns = lambda: base_ns + slept[0]
    time.monotonic = lambda: slept[0] / 1e9
    time.monotonic_ns = lambda: slept[0]
    time.perf_counter = time.monotonic
    time.perf_counter_ns = time.monotonic_ns
    time.sleep = sleep
    time.localtime = lambda secs=None: real_localtime(wall() if secs is None else secs)
    time.gmtime = lambda secs=None: real_gmtime(wall() if secs is None else secs)
    time.ctime = lambda secs=None: real_ctime(wall() if secs is None else secs)
    time.strftime = lambda fmt, t=None: real_strftime(fmt, real_localtime(wall()) if t is None else t)
    _pin_uuid1(lambda: base_ns + slept[0])

    # isinstance against the pinned classes still answers for the real ones.
    class _DateMeta(type):
        def __instancecheck__(cls, instance):
            return isinstance(instance, _REAL_DATE)

    class _DatetimeMeta(type):
        def __instancecheck__(cls, instance):
            return isinstance(instance, _REAL_DATETIME)

    class PinnedDate(_REAL_DATE, metaclass=_DateMeta):
        @classmethod
        def today(cls):
            return cls.fromtimestamp(wall())

    class PinnedDatetime(_REAL_DATETIME, metaclass=_DatetimeMeta):
        @classmethod
        def now(cls, tz=None):
            return cls.fromtimestamp(wall(), tz)

        @classmethod
        def utcnow(cls):
            return cls.fromtimestamp(wall(), utc).replace(tzinfo=None)

        @classmethod
        def today(cls):
            return cls.fromtimestamp(wall())

    datetime.date = PinnedDate
    datetime.datetime = PinnedDatetime


# The fixed node of the pinned uuid1: the multicast bit is set, as RFC 4122 asks of a random node.
_UUID1_NODE = 0x010000000001
_UUID_EPOCH_TICKS = 0x01B21DD213814000  # 100 ns ticks from 1582-10-15 to 1970-01-01


def _pin_uuid1(now_ns):
    import uuid

    last = [None]

    def uuid1(node=None, clock_seq=None):
        ticks = now_ns() // 100 + _UUID_EPOCH_TICKS
        if last[0] is not None and ticks <= last[0]:
            ticks = last[0] + 1
        last[0] = ticks
        seq = 0 if clock_seq is None else clock_seq
        fields = (
            ticks & 0xFFFFFFFF,
            (ticks >> 32) & 0xFFFF,
            (ticks >> 48) & 0x0FFF,
            (seq >> 8) & 0x3F,
            seq & 0xFF,
            _UUID1_NODE if node is None else node,
        )
        return uuid.UUID(fields=fields, version=1)

    uuid.uuid1 = uuid1


class _Stream:
    """The pinned byte stream: SHA-256 in counter mode over the seed."""

    def __init__(self, seed):
        self._prefix = b"portkit-bytes\0" + str(seed).encode("ascii") + b"\0"
        self._counter = 0
        self._buffer = b""

    def read(self, size):
        while len(self._buffer) < size:
            self._buffer += hashlib.sha256(self._prefix + self._counter.to_bytes(8, "big")).digest()
            self._counter += 1
        out, self._buffer = self._buffer[:size], self._buffer[size:]
        return out


def _pin_entropy(seed):
    import base64
    import secrets
    import uuid

    stream = _Stream(seed)

    def urandom(size):
        size = operator.index(size)
        if size < 0:
            raise ValueError("negative argument not allowed")
        return stream.read(size)

    class SystemRandom(random.Random):
        def random(self):
            return (int.from_bytes(stream.read(7), "big") >> 3) * (2.0 ** -53)

        def getrandbits(self, k):
            k = operator.index(k)
            if k < 0:
                raise ValueError("number of bits must be non-negative")
            size = (k + 7) // 8
            return int.from_bytes(stream.read(size), "big") >> (size * 8 - k)

        def randbytes(self, n):
            return stream.read(operator.index(n))

        def seed(self, *args, **kwargs):
            return None

        def getstate(self):
            raise NotImplementedError("System entropy source does not have state.")

        setstate = getstate

    system = SystemRandom()
    entropy = getattr(secrets, "DEFAULT_ENTROPY", 32)

    def token_bytes(nbytes=None):
        return stream.read(operator.index(entropy if nbytes is None else nbytes))

    def randbelow(exclusive_upper_bound):
        if exclusive_upper_bound <= 0:
            raise ValueError("Upper bound must be positive.")
        return system.randrange(exclusive_upper_bound)

    os.urandom = urandom
    random.SystemRandom = SystemRandom
    secrets.SystemRandom = SystemRandom
    secrets._sysrand = system
    secrets.token_bytes = token_bytes
    secrets.token_hex = lambda nbytes=None: token_bytes(nbytes).hex()
    secrets.token_urlsafe = lambda nbytes=None: base64.urlsafe_b64encode(token_bytes(nbytes)).rstrip(b"=").decode("ascii")
    secrets.randbelow = randbelow
    secrets.choice = system.choice
    uuid.uuid4 = lambda: uuid.UUID(bytes=stream.read(16), version=4)


def _pin_numpy(seed):
    """Seed numpy when it can be imported; do nothing, and never fail, when it cannot."""
    try:
        if importlib.util.find_spec("numpy") is None:
            return
        import numpy
        import numpy.random

        word = seed % 2**32
        numpy.random.seed(word)
        real_default_rng = numpy.random.default_rng
        unseeded = [0]

        def default_rng(seed=None):
            if seed is None:
                n = unseeded[0]
                unseeded[0] += 1
                return real_default_rng([word, n])
            return real_default_rng(seed)

        numpy.random.default_rng = default_rng
    except Exception:
        pass


def _pin_random(text):
    if not re.match(r"^-?\d+$", text):
        _fail("PORTKIT_SEED must be an integer, got %r" % text)
    seed = int(text)
    random.seed(seed)
    _pin_entropy(seed)
    _pin_numpy(seed)


# ---- canonical output ----------------------------------------------------------------------

def _str(s):
    try:
        s.encode("utf-8")
    except UnicodeEncodeError:
        _fail("a string holds a lone surrogate, which is not valid UTF-8")
    return json.dumps(s, ensure_ascii=False)


def _num(f):
    """ECMAScript's Number::toString, so the same number prints the same bytes in both adapters."""
    if f != f or f in (float("inf"), float("-inf")):
        _fail("%r is not representable in JSON" % f)
    if f == 0:
        return "0"
    sign = "-" if f < 0 else ""
    mantissa, _, exponent = repr(abs(f)).partition("e")
    whole, _, fraction = mantissa.partition(".")
    digits = whole + fraction
    point = len(whole) + (int(exponent) if exponent else 0)
    stripped = digits.lstrip("0")
    point -= len(digits) - len(stripped)
    digits = stripped.rstrip("0")
    k, n = len(digits), point
    if k <= n <= 21:
        body = digits + "0" * (n - k)
    elif 0 < n <= 21:
        body = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        body = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        shown = "%s%d" % ("+" if e >= 0 else "-", abs(e))
        body = (digits if k == 1 else digits[0] + "." + digits[1:]) + "e" + shown
    return sign + body


def _utf16(key):
    return key.encode("utf-16-be", "surrogatepass")


def _enc(v, stack):
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, str):
        return _str(v)
    if isinstance(v, int):
        return str(int(v))
    if isinstance(v, float):
        return _num(v)
    if isinstance(v, (_REAL_DATETIME, _REAL_DATE, _REAL_TIME)):
        return _str(v.isoformat())
    if id(v) in stack:
        _fail("the result contains a cycle")
    stack.append(id(v))
    try:
        if isinstance(v, dict):
            items = {}
            for key, value in v.items():
                if isinstance(key, bool) or not isinstance(key, (str, int)):
                    _fail("an object key is %s, not a string" % type(key).__name__)
                items[key if isinstance(key, str) else str(int(key))] = value
            return "{" + ",".join(_str(k) + ":" + _enc(items[k], stack) for k in sorted(items, key=_utf16)) + "}"
        if isinstance(v, (list, tuple)):
            return "[" + ",".join(_enc(item, stack) for item in v) + "]"
        if isinstance(v, (set, frozenset)):
            return "[" + ",".join(sorted(_enc(item, stack) for item in v)) + "]"
    finally:
        stack.pop()
    _fail("a %s value is not representable in JSON" % type(v).__name__)


# ---- the call ------------------------------------------------------------------------------

def _load(spec):
    if os.path.isfile(spec):
        path = os.path.abspath(spec)
        sys.path.insert(0, os.path.dirname(path))
        name = os.path.splitext(os.path.basename(path))[0]
        found = importlib.util.spec_from_file_location(name, path)
        if found is None or found.loader is None:
            _fail("cannot load %s: not a Python module" % spec)
        module = importlib.util.module_from_spec(found)
        sys.modules[name] = module
        found.loader.exec_module(module)
        return module
    sys.path.insert(0, os.getcwd())
    return importlib.import_module(spec)


def _defaults(module):
    if hasattr(module, "__defaults"):
        value = getattr(module, "__defaults")
        return value() if callable(value) else value
    return {
        name: value
        for name, value in vars(module).items()
        if not name.startswith("_") and name.isupper() and not callable(value) and not isinstance(value, types.ModuleType)
    }


def _run(argv):
    if not argv or len(argv) > 2:
        _fail('usage: adapter.py <module> [<function>]   (a request {"tool":..,"input":..} on stdin)')
    spec = argv[0]
    function_name = argv[1] if len(argv) == 2 else None
    if "TZ" not in os.environ:
        os.environ["TZ"] = "UTC"
        if hasattr(time, "tzset"):
            time.tzset()
    if os.environ.get("PORTKIT_NOW"):
        _pin_clock(os.environ["PORTKIT_NOW"])
    if os.environ.get("PORTKIT_SEED"):
        _pin_random(os.environ["PORTKIT_SEED"])

    try:
        request = json.loads(sys.stdin.buffer.read().decode("utf-8"))
    except ValueError as e:
        _fail("stdin is not one JSON request: %s" % e)
    if not isinstance(request, dict):
        _fail('the request must be a JSON object {"tool": name, "input": value}')
    tool = request.get("tool", os.environ.get("PORTKIT_TOOL"))

    # The module's own output must not reach the result channel.
    sys.stdout = sys.stderr
    try:
        module = _load(spec)
    except AdapterError:
        raise
    except BaseException as e:  # a module that fails to import is a setup problem
        _fail("cannot load %s: %s: %s" % (spec, type(e).__name__, e))

    if tool == "__defaults":
        return _enc(_defaults(module), [])
    name = function_name if function_name is not None else tool
    if not isinstance(name, str) or not name:
        _fail("no function to call: name one on the command line or send a request tool")
    function = getattr(module, name, None) if not name.startswith("_") else None
    if not callable(function):
        _fail("%s has no public function %r" % (spec, name))
    if "input" not in request:
        _fail('the request has no "input"')
    value = request["input"]
    positional = isinstance(value, dict) and list(value) == ["args"] and isinstance(value["args"], list)
    try:
        result = function(*(value["args"] if positional else [value]))
        if inspect.iscoroutine(result):
            result = asyncio.run(result)
    except Exception as e:  # the module's own failure is the answer
        result = {"error": str(e)}
    return _enc(result, [])


def main():
    out = sys.__stdout__
    try:
        text = _run(sys.argv[1:])
    except AdapterError as e:
        sys.stderr.write("portkit-adapter: %s\n" % e)
        return 2
    out.buffer.write(text.encode("utf-8") + b"\n")
    out.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
