#!/usr/bin/env python3
# Run a program in a real pseudo-terminal and drive it like a person at a
# terminal (test/interactive-parity.test.mjs). Python's standard pty module:
# no third-party dependency.
#   pty-run.py CONFIG.json  ->  one JSON object on stdout
# CONFIG: { argv, env, cwd, rows, cols, timeout_s, modes, steps: [...] }. With
# `modes` ({"1049": 1, "25": 2}: 1 set, 2 reset) the terminal answers the
# program's DECRQM questions (CSI ? N $ p) as a terminal emulator does
# (a mode not listed: 0, not recognized); without it, it answers nothing.
# A step is one of
#   {"wait": "<regex over everything the program drew, latin-1>", "timeout_s": N}
#   {"wait_file": "<path>", "contains": "<text>", "timeout_s": N}
#   {"write": "<hex bytes>"}           typed at the terminal
#   {"sleep": seconds}
#   {"resize": [rows, cols]}           TIOCSWINSZ: the kernel signals the foreground group
#   {"sigint_fg": true}                SIGINT to the terminal's foreground process group
#   {"termios": "<label>"}             record the terminal's line discipline now
#   {"answer": {"before": "<hex>", "after": "<hex>", "wrong": bool}}
#                                      type the answer Enclawed Code's newest approval
#                                      prompt asks for (wrong: a different code), between
#                                      the given bytes, then Enter
# Result: { exit, signal, output_hex, termios: {label: {...}}, fg_pgid, failed_step }
import fcntl, json, os, re, select, signal, struct, sys, termios, time

cfg = json.load(open(sys.argv[1]))
fd, slave = os.openpty()
fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", cfg.get("rows", 40), cfg.get("cols", 120), 0, 0))
pid = os.fork()
if pid == 0:
    os.close(fd)
    os.login_tty(slave)
    os.chdir(cfg["cwd"])
    os.execvpe(cfg["argv"][0], cfg["argv"], cfg["env"])
# The driver keeps the terminal itself open (as a person's terminal stays open
# after the program ends), so its line discipline can be read at the end.

out = bytearray()
status = None
failed = None
termios_seen = {}


def lflags():
    a = termios.tcgetattr(fd)
    return {"icanon": bool(a[3] & termios.ICANON), "echo": bool(a[3] & termios.ECHO), "isig": bool(a[3] & termios.ISIG), "icrnl": bool(a[0] & termios.ICRNL), "opost": bool(a[1] & termios.OPOST)}


termios_seen["start"] = lflags()


answered = 0
DECRQM = re.compile(rb"\x1b\[\?(\d+)\$p")


def answer_queries():
    global answered
    if cfg.get("modes") is None:
        return
    for m in DECRQM.finditer(bytes(out), answered):
        v = cfg["modes"].get(m.group(1).decode(), 0)
        os.write(fd, b"\x1b[?" + m.group(1) + b";" + str(v).encode() + b"$y")
        answered = m.end()


def pump(t):
    global status
    r, _, _ = select.select([fd], [], [], t)
    if r:
        try:
            data = os.read(fd, 65536)
        except OSError:
            data = b""
        if data:
            out.extend(data)
            answer_queries()
    if status is None:
        try:
            wpid, st = os.waitpid(pid, os.WNOHANG)
            if wpid:
                status = st
        except ChildProcessError:
            pass


deadline = time.time() + cfg.get("timeout_s", 90)
for i, step in enumerate(cfg.get("steps", [])):
    if "wait" in step:
        rx = re.compile(step["wait"].encode("latin-1"), re.S)
        end = time.time() + step.get("timeout_s", 30)
        while not rx.search(bytes(out)) and time.time() < end and status is None:
            pump(0.1)
        if not rx.search(bytes(out)):
            failed = i
            break
    elif "wait_file" in step:
        end = time.time() + step.get("timeout_s", 30)
        ok = False
        while time.time() < end and status is None:
            try:
                ok = step["contains"] in open(step["wait_file"]).read()
            except OSError:
                ok = False
            if ok:
                break
            pump(0.1)
        if not ok:
            failed = i
            break
    elif "write" in step:
        os.write(fd, bytes.fromhex(step["write"]))
        pump(0.05)
    elif "sleep" in step:
        end = time.time() + step["sleep"]
        while time.time() < end:
            pump(0.05)
    elif "resize" in step:
        rows, cols = step["resize"]
        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
        pump(0.05)
    elif "sigint_fg" in step:
        os.killpg(os.tcgetpgrp(fd), signal.SIGINT)
        pump(0.05)
    elif "answer" in step:
        a = step["answer"]
        plain = re.sub(rb"\x1b\[[0-9;?]*[A-Za-z]", b"", bytes(out))
        found = re.findall(rb'^ +"(\S+ [a-z]{3})"\r?$', plain, re.M)
        if not found:
            failed = i
            break
        ans = found[-1]
        if a.get("wrong"):
            ans = ans[:-3] + (b"zzz" if ans[-3:] != b"zzz" else b"yyy")
        os.write(fd, bytes.fromhex(a.get("before", "")) + ans + bytes.fromhex(a.get("after", "")) + b"\r")
        pump(0.05)
    elif "termios" in step:
        termios_seen[step["termios"]] = lflags()

while status is None and time.time() < deadline:
    pump(0.1)
if status is None:
    os.kill(pid, signal.SIGKILL)
    _, status = os.waitpid(pid, 0)
# The program led its own session (login_tty); whatever it started there, in
# any process group and stopped or not, ends with the run.
for p in os.listdir("/proc"):
    if p.isdigit():
        try:
            if os.getsid(int(p)) == pid:
                os.kill(int(p), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
# What is left to read.
try:
    while True:
        r, _, _ = select.select([fd], [], [], 0.2)
        if not r:
            break
        data = os.read(fd, 65536)
        if not data:
            break
        out.extend(data)
except OSError:
    pass
try:
    termios_seen["end"] = lflags()
except termios.error:
    pass
print(json.dumps({
    "exit": os.WEXITSTATUS(status) if os.WIFEXITED(status) else None,
    "signal": os.WTERMSIG(status) if os.WIFSIGNALED(status) else None,
    "output_hex": bytes(out).hex(),
    "termios": termios_seen,
    "failed_step": failed,
}))
