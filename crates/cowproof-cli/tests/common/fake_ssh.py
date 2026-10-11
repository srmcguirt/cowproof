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
                            PATH, none of the caller's variables), with stdin and stdout passed
                            through. A SIGTERM, SIGINT or SIGHUP for this process is sent on to
                            the command's group as SIGHUP: what a pty hangup does when a real
                            ssh client dies.

Every invocation appends one JSON line to $FAKE_SSH_LOG: its argv and, for a command, the file
that holds the bytes it read on stdin ($FAKE_SSH_DIR/stdin.<pid>). Environment: FAKE_SSH_LOG,
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


def run_command(ctl, words):
    if not master_alive(ctl):
        sys.stderr.write("Control socket connect(%s): No such file or directory\n" % ctl)
        return 255
    dirpath = os.environ["FAKE_SSH_DIR"]
    stdin_file = os.path.join(dirpath, "stdin.%d" % os.getpid())
    with open(stdin_file, "wb") as f:
        f.write(sys.stdin.buffer.read())
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
    with open(stdin_file, "rb") as stdin:
        # Its own session, like a command sshd starts: a signal sent to this process's group
        # does not reach it, only the SIGHUP below does.
        child = subprocess.Popen(
            ["/bin/sh", "-c", "exec " + " ".join(words)],
            stdin=stdin,
            env=env,
            cwd=home,
            start_new_session=True,
        )

        log({"event": "command-started", "pid": child.pid})

        def hangup(_sig, _frame):
            try:
                os.killpg(child.pid, signal.SIGHUP)
            except OSError:
                pass

        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            signal.signal(sig, hangup)
        while True:
            try:
                code = child.wait()
                break
            except InterruptedError:
                continue
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
            deadline = time.time() + 5
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
