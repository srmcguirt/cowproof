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
                date.today() return it.
  PORTKIT_SEED  an integer: random.seed(seed) for the module-level random functions.
  TZ            set to UTC when the environment has none.
  PYTHONHASHSEED  set to 0 when the environment has none, by restarting once, so set and dict
                  iteration of str is repeatable.
Not pinned: time.monotonic and perf_counter, sleep, file times, random.Random() instances made
without a seed, SystemRandom, secrets, uuid4, os.urandom, numpy.

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
import calendar
import datetime
import importlib
import importlib.util
import inspect
import json
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
    utc = datetime.timezone.utc

    real_localtime, real_gmtime = time.localtime, time.gmtime
    real_ctime, real_strftime = time.ctime, time.strftime
    time.time = lambda: epoch
    time.time_ns = lambda: seconds * 1000000000 + micro * 1000
    time.localtime = lambda secs=None: real_localtime(epoch if secs is None else secs)
    time.gmtime = lambda secs=None: real_gmtime(epoch if secs is None else secs)
    time.ctime = lambda secs=None: real_ctime(epoch if secs is None else secs)
    time.strftime = lambda fmt, t=None: real_strftime(fmt, real_localtime(epoch) if t is None else t)

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
            return cls.fromtimestamp(epoch)

    class PinnedDatetime(_REAL_DATETIME, metaclass=_DatetimeMeta):
        @classmethod
        def now(cls, tz=None):
            return cls.fromtimestamp(epoch, tz)

        @classmethod
        def utcnow(cls):
            return cls.fromtimestamp(epoch, utc).replace(tzinfo=None)

        @classmethod
        def today(cls):
            return cls.fromtimestamp(epoch)

    datetime.date = PinnedDate
    datetime.datetime = PinnedDatetime


def _pin_random(text):
    if not re.match(r"^-?\d+$", text):
        _fail("PORTKIT_SEED must be an integer, got %r" % text)
    random.seed(int(text))


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
