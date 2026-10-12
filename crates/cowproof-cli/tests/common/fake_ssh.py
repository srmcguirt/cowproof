#!/usr/bin/env python3
"""A fake `ssh` for tests/remote.rs. It never touches the network: the "remote host" is this
machine, with a home directory and an environment of its own.

It emulates only what cowproof uses:

  -M ... -N <target>        a control master: creates the control path, records itself and
                            waits until it is killed (it then stops its forwards)
  -S ctl -O check <target>  exit 0 while the master is alive
  -S ctl -O forward -R a:b <target>
                            a REAL Unix socket at `a` that relays every connection to the
                            socket at `b`. (A symlink would not do: `host-agent builder`
                            requires `a` to be a socket, as a real `ssh -R` makes it.)
  -S ctl -O exit <target>   stops the master and waits for it
  -S ctl <target> <words>   runs the words, joined by spaces and handed to `sh -c` like a real
                            sshd does, on this machine, in a fresh environment (a new HOME and
                            PATH, none of the caller's variables). Stdin, stdout and stderr go
                            through THIS process, as they go through ssh and sshd, and nothing
                            else is emulated: stdin is relayed as it arrives and closed on the
                            command when this process's stdin reaches end of file OR this
                            process dies (SIGKILL included, because the pipe that carries it is
                            held only here), which is what sshd does when the client goes. No
                            hangup is sent to the command, because an ssh without a pty sends
                            none. When this process dies the command's stdout and stderr pipes
                            lose their reader, as they do when sshd's channel closes.

Forced command: when FAKE_SSH_FORCED_COMMAND is set, the fake emulates a key whose
authorized_keys line says `command="<that text>"`, as sshd does for every session of the key
(not for the `-M ... -N` master, which has no session, nor for `-O` requests): it does NOT run the
words. It puts them, joined by spaces, in SSH_ORIGINAL_COMMAND and runs `/bin/sh -c
"exec <that text>"` instead, which is what sshd does with the user's shell. The text is
`<cowproof> host-agent --forced` in a test of forced mode.

Every invocation appends one JSON line to $FAKE_SSH_LOG: its argv and, for a command, the file
that holds the bytes it read on stdin ($FAKE_SSH_DIR/stdin.<pid>, written as they arrive), and a
`command-started` line with the command's pid, this process's pid (`ssh_pid`) and the command
line (`command`; not `argv`, which only the invocation lines carry).
Environment: FAKE_SSH_LOG,
FAKE_SSH_RELAY_DELAY (seconds a forward's relay waits before it listens),
FAKE_SSH_DIR and FAKE_REMOTE_HOME (the remote user's home and working directory). When
FAKE_SSH_FORBIDDEN and FAKE_REMOTE_ROOT are set, the fake looks through every file under the
remote root and home for the forbidden text just before it runs `host-agent cleanup` (the last
moment the lane exists), and writes how many files it read to $FAKE_SSH_DIR/scanned.txt and
the files that held it to $FAKE_SSH_DIR/leaks.txt.
"""
import json
import os
import signal
import socket
import stat
import subprocess
import sys
import threading
import time


def log(entry):
    line = json.dumps(entry) + "\n"
    fd = os.open(os.environ["FAKE_SSH_LOG"], os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
    try:
        os.write(fd, line.encode())
    finally:
        os.close(fd)


def alive(pid):
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def read_pid(ctl):
    try:
        return int(open(ctl + ".pid").read().strip())
    except (OSError, ValueError):
        return None


def master_alive(ctl):
    pid = read_pid(ctl)
    return os.path.exists(ctl) and pid is not None and alive(pid)


def relay(a, b, master):
    """Listen on the socket path `a`; relay each connection to the socket at `b`."""
    # A test sets FAKE_SSH_RELAY_DELAY to stand in for a Python start on a loaded host.
    time.sleep(float(os.environ.get("FAKE_SSH_RELAY_DELAY", "0")))
    try:
        os.unlink(a)
    except FileNotFoundError:
        pass
    srv = socket.socket(socket.AF_UNIX)
    srv.bind(a)
    srv.listen(16)

    def pump(src, dst):
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                dst.sendall(data)
        except OSError:
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    def serve(conn):
        up = socket.socket(socket.AF_UNIX)
        try:
            up.connect(b)
        except OSError:
            conn.close()
            return
        back = threading.Thread(target=pump, args=(up, conn), daemon=True)
        back.start()
        pump(conn, up)
        back.join()
        conn.close()
        up.close()

    def watch():
        # A master that is gone takes its forwards with it, SIGKILL included.
        while alive(master):
            time.sleep(0.2)
        try:
            os.unlink(a)
        except OSError:
            pass
        os._exit(0)

    threading.Thread(target=watch, daemon=True).start()
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=serve, args=(conn,), daemon=True).start()


def run_master(ctl):
    with open(ctl + ".pid", "w") as f:
        f.write(str(os.getpid()))
    open(ctl, "w").close()
    log({"event": "master-started", "pid": os.getpid()})

    def stop(_sig, _frame):
        try:
            # The relays watch for the master's pid to go and end themselves; their sockets
            # are removed here, so nothing is left to connect to.
            for path in open(ctl + ".relays").read().splitlines():
                try:
                    os.unlink(path)
                except OSError:
                    pass
        except OSError:
            pass
        for path in (ctl, ctl + ".pid"):
            try:
                os.unlink(path)
            except OSError:
                pass
        log({"event": "master-stopped", "pid": os.getpid()})
        os._exit(0)

    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, stop)
    while True:
        time.sleep(0.1)


def scan_for_forbidden():
    secret = os.environ.get("FAKE_SSH_FORBIDDEN")
    if not secret:
        return
    needle = secret.encode()
    scanned, hits = 0, []
    for top in (os.environ["FAKE_REMOTE_ROOT"], os.environ["FAKE_REMOTE_HOME"]):
        for directory, _dirs, names in os.walk(top):
            for name in names:
                path = os.path.join(directory, name)
                try:
                    if not stat.S_ISREG(os.lstat(path).st_mode):
                        continue
                    with open(path, "rb") as f:
                        data = f.read()
                except OSError:
                    continue
                scanned += 1
                if needle in data:
                    hits.append(path)
    with open(os.path.join(os.environ["FAKE_SSH_DIR"], "scanned.txt"), "w") as f:
        f.write(str(scanned))
    with open(os.path.join(os.environ["FAKE_SSH_DIR"], "leaks.txt"), "w") as f:
        f.write("".join(h + "\n" for h in hits))


def pump_out(src, dst):
    """Copy the file `src` (the command's stdout or stderr) to `dst` until end of file. When
    `dst` has no reader any more, close `src`, so the command's next write fails as it does
    when sshd's channel has closed."""
    while True:
        try:
            data = os.read(src.fileno(), 65536)
        except (OSError, ValueError):
            return
        if not data:
            return
        try:
            dst.write(data)
            dst.flush()
        except (OSError, ValueError):
            src.close()
            return


def run_command(ctl, words):
    if not master_alive(ctl):
        sys.stderr.write("Control socket connect(%s): No such file or directory\n" % ctl)
        return 255
    dirpath = os.environ["FAKE_SSH_DIR"]
    stdin_file = os.path.join(dirpath, "stdin.%d" % os.getpid())
    open(stdin_file, "wb").close()
    log({"argv": sys.argv[1:], "stdin": stdin_file})
    if " host-agent cleanup " in " ".join(words) + " ":
        scan_for_forbidden()
    home = os.environ["FAKE_REMOTE_HOME"]
    env = {
        "HOME": home,
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "USER": "remote",
        "LOGNAME": "remote",
        "SHELL": "/bin/sh",
    }
    # Its own session, like a command sshd starts: a signal sent to this process's group does
    # not reach it. Its stdin is a pipe this process holds the only write end of.
    forced = os.environ.get("FAKE_SSH_FORCED_COMMAND")
    if forced:
        env["SSH_ORIGINAL_COMMAND"] = " ".join(words)
    child = subprocess.Popen(
        ["/bin/sh", "-c", "exec " + (forced if forced else " ".join(words))],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        cwd=home,
        start_new_session=True,
    )
    log({"event": "command-started", "pid": child.pid, "ssh_pid": os.getpid(), "command": " ".join(words), "forced": bool(forced)})

    def relay_stdin():
        try:
            with open(stdin_file, "ab") as record:
                while True:
                    data = os.read(0, 65536)
                    if not data:
                        break
                    record.write(data)
                    record.flush()
                    child.stdin.write(data)
                    child.stdin.flush()
        except (OSError, ValueError):
            pass
        try:
            child.stdin.close()
        except OSError:
            pass

    threading.Thread(target=relay_stdin, daemon=True).start()
    outs = [
        threading.Thread(target=pump_out, args=(child.stdout, sys.stdout.buffer), daemon=True),
        threading.Thread(target=pump_out, args=(child.stderr, sys.stderr.buffer), daemon=True),
    ]
    for t in outs:
        t.start()
    for sig in (signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, signal.SIG_DFL)
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    code = child.wait()
    # The command is done: let its output drain (a stray process may hold the pipes open, so
    # not for long).
    for t in outs:
        t.join(5)
    return 128 - code if code < 0 else code


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--relay":
        relay(sys.argv[2], sys.argv[3], int(sys.argv[4]))
        return 0
    args = sys.argv[1:]
    opts = {"M": False, "S": None, "O": None, "R": []}
    i = 0
    while i < len(args):
        a = args[i]
        if a == "-M":
            opts["M"] = True
        elif a in ("-N", "-T"):
            pass
        elif a in ("-S", "-O", "-R", "-o"):
            i += 1
            if a != "-o":
                if a == "-R":
                    opts["R"].append(args[i])
                else:
                    opts[a[1]] = args[i]
        elif a.startswith("-"):
            sys.stderr.write("fake ssh: unknown option %s\n" % a)
            return 255
        else:
            break
        i += 1
    if i >= len(args) or opts["S"] is None:
        sys.stderr.write("fake ssh: usage: ssh -S ctl [options] target [command]\n")
        return 255
    target, words = args[i], args[i + 1 :]
    ctl = opts["S"]

    if opts["M"]:
        log({"argv": args})
        run_master(ctl)
        return 0
    if opts["O"] == "check":
        return 0 if master_alive(ctl) else 255
    if opts["O"]:
        log({"argv": args})
    if opts["O"] == "forward":
        if not master_alive(ctl):
            sys.stderr.write("Control socket connect(%s): No such file or directory\n" % ctl)
            return 255
        for spec in opts["R"]:
            a, b = spec.split(":", 1)
            subprocess.Popen(
                [sys.executable, os.path.abspath(__file__), "--relay", a, b, str(read_pid(ctl))],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            # Only a relay that never starts fails the wait, so the deadline is long: a Python
            # start on a loaded host has taken most of five seconds.
            deadline = time.time() + 60
            while time.time() < deadline:
                try:
                    if stat.S_ISSOCK(os.stat(a).st_mode):
                        break
                except OSError:
                    pass
                time.sleep(0.02)
            else:
                sys.stderr.write("fake ssh: could not forward %s\n" % a)
                return 255
            with open(ctl + ".relays", "a") as f:
                f.write(a + "\n")
        return 0
    if opts["O"] == "exit":
        pid = read_pid(ctl)
        if pid is not None and alive(pid):
            os.kill(pid, signal.SIGTERM)
            deadline = time.time() + 5
            while alive(pid) and time.time() < deadline:
                time.sleep(0.02)
        return 0
    if opts["O"]:
        sys.stderr.write("fake ssh: unknown -O %s\n" % opts["O"])
        return 255
    return run_command(ctl, words)


if __name__ == "__main__":
    sys.exit(main())
