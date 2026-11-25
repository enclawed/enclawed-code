// One line typed at the controlling terminal (/dev/tty), never read from
// standard input: nothing piped in answers it. Keys queued before the question
// appears are discarded; Ctrl-C, Ctrl-D, Escape, no terminal or the timeout
// give null.

import fs from "node:fs";
import tty from "node:tty";

export function askLine(text, { ttyPath = "/dev/tty", timeoutMs = 120_000, max = 64 } = {}) {
  return new Promise((resolve) => {
    let fd;
    try {
      fd = fs.openSync(ttyPath, "r+");
    } catch {
      resolve(null);
      return;
    }
    let stream;
    try {
      stream = new tty.ReadStream(fd);
    } catch {
      fs.closeSync(fd);
      resolve(null);
      return;
    }
    const write = (s) => {
      try {
        fs.writeSync(fd, s);
      } catch {
        /* the terminal went away */
      }
    };
    let raw = false;
    try {
      stream.setRawMode(true);
      raw = true;
    } catch {
      /* not a real terminal */
    }
    let buf = "";
    let draining = true;
    let done = false;
    const finish = (answer) => {
      if (done) {
        return;
      }
      done = true;
      clearTimeout(timer);
      clearTimeout(drain);
      write("\r\n");
      try {
        if (raw) {
          stream.setRawMode(false);
        }
      } catch {
        /* gone */
      }
      stream.destroy();
      resolve(answer);
    };
    const drain = setTimeout(() => {
      draining = false;
      write(text);
    }, 150);
    const timer = setTimeout(() => finish(null), timeoutMs);
    stream.on("data", (d) => {
      if (draining) {
        return;
      }
      for (const ch of d.toString("utf8")) {
        if (ch === "\r" || ch === "\n") {
          finish(buf);
          return;
        }
        if (ch === "\u0003" || ch === "\u0004" || ch === "\u001b") {
          finish(null);
          return;
        }
        if (ch === "\u007f" || ch === "\b") {
          if (buf.length > 0) {
            buf = buf.slice(0, -1);
            write("\b \b");
          }
          continue;
        }
        if (ch >= " " && buf.length < max) {
          buf += ch;
          write(ch);
        }
      }
    });
    stream.on("error", () => finish(null));
    stream.on("end", () => finish(null));
  });
}
