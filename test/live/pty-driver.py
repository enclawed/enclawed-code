#!/usr/bin/env python3
# Drive an interactive program in a real pty (for test:live): log everything it
# draws, answer Enclawed Code's own approval prompt, then end the session.
#   pty-driver.py LOG ANSWER WAIT_FILE -- argv...
# ANSWER: "code" types the quoted approval text Enclawed Code shows; "d" denies; anything else is typed as is.
# WAIT_FILE: when it appears (or after the prompt is answered and the model's
# turn has had time to finish), the driver sends Ctrl-C twice to end claude.
import os, pty, re, select, sys, time, signal

log_path, answer, wait_file = sys.argv[1], sys.argv[2], sys.argv[3]
argv = sys.argv[sys.argv.index("--") + 1:]
pid, fd = pty.fork()
if pid == 0:
    os.execvp(argv[0], argv)
log = open(log_path, "wb")
buf = b""
answered_at = None
prompts = 0
end_sent = None
deadline = time.time() + float(os.environ.get("DRIVER_TIMEOUT_S", "240"))
code_re = re.compile(rb'^ +"([a-z0-9]{1,8} [a-z]{3})"\r?$', re.M)
done_wait = float(os.environ.get("DRIVER_AFTER_ANSWER_S", "25"))
status = None
while True:
    now = time.time()
    if now > deadline:
        os.kill(pid, signal.SIGKILL)
        break
    r, _, _ = select.select([fd], [], [], 0.5)
    if r:
        try:
            data = os.read(fd, 65536)
        except OSError:
            data = b""
        if not data:
            break
        log.write(data); log.flush()
        buf = (buf + data)[-200000:]
        m = code_re.search(re.sub(rb"\x1b\[[0-9;?]*[A-Za-z]", b"", buf))
        if m:
            prompts += 1
            time.sleep(0.6)  # after Enclawed Code's 150 ms drain
            os.write(fd, (m.group(1).decode() if answer == "code" else answer).encode() + b"\r")
            answered_at = time.time()
            buf = buf[m.end():]
    finished = (wait_file != "-" and os.path.exists(wait_file)) or (answered_at and now - answered_at > done_wait)
    if finished and end_sent is None:
        time.sleep(4)
        os.write(fd, b"\x03"); time.sleep(0.5); os.write(fd, b"\x03")
        end_sent = now
    if end_sent and now - end_sent > 20:
        os.kill(pid, signal.SIGTERM)
        end_sent = now + 1000
    try:
        wpid, st = os.waitpid(pid, os.WNOHANG)
        if wpid:
            status = os.waitstatus_to_exitcode(st)
            # drain
            try:
                while True:
                    d = os.read(fd, 65536)
                    if not d:
                        break
                    log.write(d)
            except OSError:
                pass
            break
    except ChildProcessError:
        break
if status is None:
    try:
        _, st = os.waitpid(pid, 0)
        status = os.waitstatus_to_exitcode(st)
    except ChildProcessError:
        status = -1
log.write(f"\n[driver] prompts={prompts} exit={status}\n".encode())
log.close()
print(f"prompts={prompts} exit={status}")
