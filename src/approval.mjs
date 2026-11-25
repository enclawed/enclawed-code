// Interactive approval of an "ask" decision by Enclawed Code itself (round 5, N13c).
//
// Why: when Enclawed decides "ask", the hook used to hand the question to
// Claude Code's permission dialog, and the launcher took the genuine hook's
// PostToolUse for the call as evidence that a person approved it. A
// descendant of claude can run the genuine hook command on any input, so it
// can produce that PostToolUse, and every other hook event, PermissionRequest
// and Notification included: they are all delivered the same way (the hook
// command with JSON on stdin), so none of them proves anything a forger
// cannot produce. Claude Code 2.1.326 writes no permission-grant record to
// the transcript, and the transcript is the user's own file anyway. There is
// no approval signal from Claude Code that a process of the same user cannot
// forge.
//
// So in an interactive session the question is asked by the launcher, on
// the terminal it owns, and Claude Code's own dialog is not used for
// Enclawed's asks: the hook sends the "ask" to the launcher (control socket,
// op "approve") and returns "allow" only when the launcher's prompt got the
// answer, "deny" otherwise (no terminal, a timeout, any other answer). The
// launcher records which calls a person approved there; a call that ran with
// an "ask" decision the launcher's prompt did not approve stops claude
// (decision-violated), whoever produced its hook events.
//
// The prompt: claude is paused (SIGSTOP) so it neither draws over the prompt
// nor reads the keys, pending input is discarded, the prompt states the call's
// effect in plain words first (the kit's approvalEffect: what cannot be
// undone, which file, host or program), then Enclawed's reason, and asks for
// an answer derived from that effect (the kit's approvalConfirmation: the name
// of what it acts on, then a random code: "config kqr"), and only that answer
// followed by Enter approves. It cannot be typed without reading what is
// affected, and keys typed before the prompt, or injected into the terminal
// by a process that cannot see the screen, cannot approve. The terminal is
// then put back exactly as Claude Code had it (line discipline, screen,
// cursor; see readAnswer), and claude is continued (SIGCONT, SIGWINCH).
// Prompts are asked one at a time.

//
// Which answer approves which call is the kit's (ApprovalLedger: the code,
// once, before it expires, for the same call and input); this file keeps the
// terminal prompt and pausing claude.

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import tty from "node:tty";
import { kit } from "./kit.mjs";
import { trustedBinary } from "./trusted-bin.mjs";
import { sanitizeText } from "./untrusted.mjs";

// PENDING kit constant: replace with the kit's approval timeout once it is exported (kit approval.ts DEFAULT_APPROVAL_TTL_MS).
export const DEFAULT_APPROVAL_TIMEOUT_MS = 5 * 60 * 1000;
// How long the verdict stays on the prompt's screen before Claude Code's comes back.
const VERDICT_MS = 400;

/** The random part of an approval's answer (three letters, no look-alike i/l/o): kit.approvalCode. */
export function approvalCode() {
  return kit.approvalCode();
}

// The terminal while Claude Code's full-screen UI owns it (it is paused, not
// stopped from drawing halfway: CAN first ends any escape sequence it left
// half-written). Its line discipline is saved with `stty -g` and put back
// exactly; the prompt is drawn on the alternate screen, so the screen Claude
// Code drew is untouched and its own idea of what it drew stays right (when
// Claude Code itself is on the alternate screen, the prompt clears it and
// Claude Code is made to redraw). Which modes are on is asked of the terminal
// (DECRQM) while queued keys are drained; a terminal that does not answer is
// treated as one with Claude Code on the main screen and the cursor hidden.
const MODE_QUERY = "\x18\x1b[?1049$p\x1b[?25$p";
const DRAIN_MS = 150;

/** The terminal's line discipline, saved and restored with the system stty (null without one). Each use opens the terminal anew. */
function lineDiscipline(ttyPath) {
  const stty = trustedBinary("stty");
  if (!stty) {
    return null;
  }
  const run = (args) => {
    let fd;
    try {
      fd = fs.openSync(ttyPath, "r+");
    } catch {
      return { status: null, stdout: "" };
    }
    try {
      return spawnSync(stty, args, { stdio: [fd, "pipe", "pipe"], encoding: "utf8", timeout: 5000 });
    } finally {
      fs.closeSync(fd);
    }
  };
  const saved = run(["-g"]);
  if (saved.status !== 0 || !/^[0-9a-fA-F:]+$/.test(saved.stdout.trim())) {
    return null;
  }
  const size = /^(\d+) (\d+)$/.exec(run(["size"]).stdout?.trim() ?? "");
  return {
    raw: () => run(["raw", "-echo"]).status === 0,
    restore: () => run([saved.stdout.trim()]).status === 0,
    rows: size ? Number(size[1]) : null,
    cols: size ? Number(size[2]) : null,
    setRows: (n) => run(["rows", String(n)]).status === 0,
  };
}

/**
 * The keys of a raw terminal, one chunk at a time: Enter, Backspace, Ctrl-C
 * and Escape, the characters typed or pasted (a paste never presses Enter),
 * and nothing of an escape sequence (arrows, focus reports, a terminal's
 * answer, the kitty keyboard protocol's encoding of the same keys).
 */
export function keyReader(on) {
  let pending = "";
  let paste = false;
  return (chunk) => {
    const s = pending + chunk;
    pending = "";
    for (let i = 0; i < s.length; i++) {
      const ch = s[i];
      if (ch === "\x1b") {
        const next = s[i + 1];
        if (next === undefined) {
          if (on.cancel() !== false) {
            return;
          }
          continue;
        }
        if (next === "[") {
          const m = /^\x1b\[([0-?]*)([ -/]*)([@-~])/.exec(s.slice(i));
          if (!m) {
            pending = s.slice(i);
            return;
          }
          i += m[0].length - 1;
          const [, params, , final] = m;
          if (final === "~" && (params === "200" || params === "201")) {
            paste = params === "200";
          } else if (final === "u" && /^\d+(;\d+)?$/.test(params)) {
            const [code, mods = 1] = params.split(";").map(Number);
            if (code === 13) {
              if (!paste && on.enter() !== false) {
                return;
              }
            } else if (code === 27) {
              if (on.cancel() !== false) {
                return;
              }
            } else if (code === 127 || code === 8) {
              on.backspace();
            } else if ((code === 99 || code === 3) && mods === 5) {
              on.interrupt();
              return;
            } else if (code >= 32 && (mods === 1 || mods === 2)) {
              on.char(String.fromCodePoint(code));
            }
          }
          continue;
        }
        if (next === "O") {
          if (s[i + 2] === undefined) {
            pending = s.slice(i);
            return;
          }
          i += 2;
          continue;
        }
        if (on.cancel() !== false) {
          return;
        }
        continue;
      }
      if (ch === "\r" || ch === "\n") {
        if (!paste && on.enter() !== false) {
          return;
        }
        continue;
      }
      if (ch === "\u0003") {
        on.interrupt();
        return;
      }
      if (ch === "\u007f" || ch === "\b") {
        on.backspace();
        continue;
      }
      if (ch >= " ") {
        on.char(ch);
      }
    }
  };
}

/**
 * Read one answer from the terminal at `ttyPath`. `onReady(modes)` draws the
 * prompt once the keys queued before it are gone; `modes` is what the
 * terminal said of the alternate screen (1049) and the cursor (25): true, false
 * or undefined (no answer).
 * @returns {Promise<{ answer: string|null, reason?: string, modes: object, line: object|null }>}
 */
function readAnswer(ttyPath, write, { timeoutMs, onReady, hint = null }) {
  return new Promise((resolve) => {
    let fd;
    try {
      fd = fs.openSync(ttyPath, "r+");
    } catch (err) {
      resolve({ answer: null, reason: `no terminal to ask on (${err.code ?? err.message})`, modes: {}, line: null });
      return;
    }
    let stream;
    try {
      stream = new tty.ReadStream(fd);
    } catch (err) {
      fs.closeSync(fd);
      resolve({ answer: null, reason: `cannot read the terminal (${err.message})`, modes: {}, line: null });
      return;
    }
    // Raw, without echo, for the prompt; then exactly what it was (Claude Code's own settings).
    const line = isTTY(fd) ? lineDiscipline(ttyPath) : null;
    let libuvRaw = false;
    if (!line?.raw()) {
      try {
        stream.setRawMode(true);
        libuvRaw = true;
      } catch {
        /* not a real terminal: line mode */
      }
    }
    const modes = {};
    let drained = "";
    let buf = "";
    let draining = true;
    let done = false;
    const finish = (answer, reason) => {
      if (done) {
        return;
      }
      done = true;
      clearTimeout(timer);
      clearTimeout(drain);
      try {
        if (libuvRaw) {
          stream.setRawMode(false);
        }
      } catch {
        /* the terminal went away */
      }
      stream.destroy();
      resolve({ answer, ...(reason ? { reason } : {}), modes, line });
    };
    const keys = keyReader({
      // Enter on an empty line and Escape take no answer (nobody approves or denies by reflex).
      enter: () => {
        if (buf.trim() === "") {
          write(`\r\n${hint ?? ""}`);
          return false;
        }
        write("\r\n");
        finish(buf);
        return true;
      },
      cancel: () => false,
      interrupt: () => {
        write("\r\n");
        finish("", "interrupted");
      },
      backspace: () => {
        if (buf.length > 0) {
          buf = buf.slice(0, -1);
          write("\b \b");
        }
      },
      char: (c) => {
        if (buf.length < 64) {
          buf += c;
          write(c);
        }
      },
    });
    write(MODE_QUERY);
    // Anything already queued on the terminal was typed for claude, not for
    // this prompt: it is read and thrown away for a short moment first (the
    // terminal's answers to the mode query arrive meanwhile).
    const drain = setTimeout(() => {
      for (const m of drained.matchAll(/\x1b\[\?(\d+);(\d)\$y/g)) {
        modes[m[1]] = m[2] === "1" || m[2] === "3" ? true : m[2] === "2" || m[2] === "4" ? false : undefined;
      }
      draining = false;
      drained = "";
      onReady?.(modes, line);
    }, DRAIN_MS);
    const timer = setTimeout(() => finish(null, "no answer in time"), timeoutMs);
    stream.on("data", (d) => {
      if (draining) {
        drained = (drained + d.toString("latin1")).slice(-4096);
        return;
      }
      keys(d.toString("utf8"));
    });
    stream.on("error", (err) => finish(null, `terminal error (${err.code ?? err.message})`));
    stream.on("end", () => finish(null, "the terminal closed"));
  });
}

function isTTY(fd) {
  try {
    return tty.isatty(fd);
  } catch {
    return false;
  }
}

/** Colors unless NO_COLOR is set or the terminal is dumb. */
function colorOn(env = process.env) {
  return env.NO_COLOR === undefined && env.TERM !== "dumb";
}

/** Word-wrap `text` to `width` columns, never inside a word; continuation lines get `indent`. */
export function wrapWords(text, width, indent = "") {
  const words = String(text).split(/\s+/).filter(Boolean);
  const lines = [];
  let cur = "";
  for (const w of words) {
    const lead = lines.length === 0 ? "" : indent;
    if (cur && (lead + cur + " " + w).length > width) {
      lines.push(cur);
      cur = w;
    } else {
      cur = cur ? `${cur} ${w}` : w;
    }
  }
  if (cur) {
    lines.push(cur);
  }
  return lines.map((l, i) => (i === 0 ? l : indent + l));
}

/** The sentences of the kit's reason the prompt shows (the snapshot and an untrusted target that resolves elsewhere, apart). */
function reasonParts(reason) {
  const text = String(reason ?? "").replace(/^Enclawed: /, "");
  const sentences = text.split(/(?<=\.)\s+(?=[A-Z])/);
  const snap = /snapshot ([0-9a-f]{12})/.exec(text)?.[1] ?? null;
  const why = [];
  let warning = null;
  for (const [i, sentence] of sentences.entries()) {
    if (i === 0 && /^irreversible action|approve only if intended/i.test(sentence)) {
      continue;
    }
    if (/^Approve only if/i.test(sentence) || /snapshot [0-9a-f]{12}/.test(sentence)) {
      continue;
    }
    if (/untrusted, as given by the agent/.test(sentence)) {
      // The agent's own words for the target: shown only when they resolve to somewhere else.
      const m = /"(.*)"; resolves to: (.*?)\.?$/s.exec(sentence);
      const given = m?.[1] ?? null;
      const resolved = m?.[2] ?? null;
      // The same place in other words (the absolute path itself, or a plain relative path under it) is no warning.
      const same = given !== null && (given === resolved || (!given.startsWith("/") && !/(^|\/)\.\.(\/|$)/.test(given) && resolved.endsWith(`/${given.replace(/^(\.\/)+/, "")}`)));
      if (/resolves to/.test(sentence) && !same) {
        warning = sentence;
      }
      continue;
    }
    why.push(sentence);
  }
  return { why: why.join(" "), snap, warning };
}

/** Display columns of `s` (ANSI codes 0, combining marks 0, East Asian wide characters 2). */
export function displayWidth(s) {
  let w = 0;
  for (const ch of String(s).replace(/\x1b\[[0-9;?]*[A-Za-z]/g, "")) {
    const c = ch.codePointAt(0);
    if (/\p{M}/u.test(ch) || c === 0x200b) {
      continue;
    }
    w +=
      (c >= 0x1100 && c <= 0x115f) || (c >= 0x2e80 && c <= 0xa4cf) || (c >= 0xac00 && c <= 0xd7a3) || (c >= 0xf900 && c <= 0xfaff) || (c >= 0xfe30 && c <= 0xfe4f) || (c >= 0xff00 && c <= 0xff60) || (c >= 0xffe0 && c <= 0xffe6) || (c >= 0x20000 && c <= 0x3fffd)
        ? 2
        : 1;
  }
  return w;
}

/** Word-wrap by display width, never inside a word (a word longer than the width is cut). */
function wrapCols(text, width) {
  const out = [];
  let cur = "";
  for (let w of String(text).split(/\s+/).filter(Boolean)) {
    while (displayWidth(w) > width) {
      if (cur) {
        out.push(cur);
        cur = "";
      }
      let head = "";
      for (const ch of w) {
        if (displayWidth(head + ch) > width) {
          break;
        }
        head += ch;
      }
      out.push(head);
      w = w.slice(head.length);
    }
    if (cur && displayWidth(`${cur} ${w}`) > width) {
      out.push(cur);
      cur = w;
    } else {
      cur = cur ? `${cur} ${w}` : w;
    }
  }
  if (cur) {
    out.push(cur);
  }
  return out;
}

/** Is the terminal's locale UTF-8 (box-drawing characters)? */
function utf8Locale(env = process.env) {
  return /utf-?8/i.test(env.LC_ALL || env.LC_CTYPE || env.LANG || "");
}

/**
 * The prompt, word-wrapped at word boundaries to the terminal: a frame (box-drawing; ASCII
 * `+ - |` without a UTF-8 locale; none below 60 columns) around what the call does and why it
 * matters; OUTSIDE it, the exact approval text in quotes (highlighted) and how to deny, so a copy
 * of the quoted line never picks up a border. Colors only when on (border in the brand cyan).
 */
export function promptText({ tool, reason, effect, expected, timeoutMs, cols = 80, color = true, home = process.env.HOME ?? "", env = process.env, warnings = [] }) {
  const truecolor = /truecolor|24bit/i.test(env.COLORTERM ?? "");
  const b = (t) => (color ? `\x1b[1m${t}\x1b[0m` : t);
  const hi = (t) => (color ? `\x1b[1;7m${t}\x1b[0m` : t);
  const warn = (t) => (color ? `\x1b[1;31m${t}\x1b[0m` : t);
  const cyan = (t) => (color ? `${truecolor ? "\x1b[38;2;2;132;199m" : "\x1b[36m"}${t}\x1b[0m` : t);
  const tilde = (t) => (home && home !== "/" ? String(t).split(`${home}/`).join("~/") : String(t));
  const summary = sanitizeText(tilde(effect?.summary ?? `runs the tool ${tool}`), { max: 400 });
  const lead = /^([^:]{1,40}): /.exec(summary)?.[1] ?? null;
  const action = lead ? summary.slice(lead.length + 2) : summary;
  const parts = reasonParts(sanitizeText(tilde(reason), { max: 1500, neutralize: false }));
  const why = [lead ? `it ${lead}.` : "", parts.why].filter(Boolean).join(" ");
  const termCols = Math.max(20, Math.min(cols || 80, 400));
  const framed = termCols >= 60;
  const W = framed ? Math.min(termCols - 1, 100) : termCols - 1;
  const inner = framed ? W - 5 : W - 2;
  // The body: [text, style] pairs; a label column of 19.
  const body = [];
  const labelled = (label, text, style = (x) => x) => {
    for (const [i, l] of wrapCols(text, inner - 19).entries()) {
      body.push([`${(i === 0 ? label : "").padEnd(19)}${l}`, style]);
    }
  };
  body.push(["asked by Enclawed Code, not by Claude Code", (x) => x]);
  body.push(["", (x) => x]);
  labelled("Claude wants to:", action);
  labelled("", `(tool: ${sanitizeText(tool, { max: 120 })})`);
  if (why) {
    labelled("Why it matters:", why);
  }
  if (parts.snap) {
    labelled("", `Snapshot kept: ecwctl history restore ${parts.snap}`);
  }
  // The kit's own warning (an untrusted target that resolves elsewhere), then the
  // deterministic signals of a potentially malicious call (warning-signals.mjs).
  for (const w of [parts.warning, ...warnings.map((x) => sanitizeText(tilde(x), { max: 400, neutralize: false }))].filter(Boolean)) {
    for (const l of wrapCols(`Warning: ${w}`, inner)) {
      body.push([l, warn]);
    }
  }
  for (const l of wrapCols("Approve only if you asked for this change.", inner)) {
    body.push([l, (x) => x]);
  }
  const out = [];
  if (framed) {
    const u = utf8Locale(env);
    const [tl, tr, bl, br, h, v] = u ? ["┌", "┐", "└", "┘", "─", "│"] : ["+", "+", "+", "+", "-", "|"];
    const title = " Enclawed Code · approval needed ".replace("·", u ? "·" : "-");
    out.push(cyan(`${tl}${h}`) + b(title) + cyan(`${h.repeat(Math.max(0, W - 3 - displayWidth(title)))}${tr}`));
    for (const [text, style] of body) {
      out.push(`${cyan(v)}  ${style(text)}${" ".repeat(Math.max(0, inner - displayWidth(text)))} ${cyan(v)}`);
    }
    out.push(cyan(`${bl}${h.repeat(W - 2)}${br}`));
  } else {
    out.push(b("Enclawed Code - approval needed"));
    for (const [text, style] of body) {
      out.push(`  ${style(text)}`);
    }
  }
  if (expected) {
    out.push(...wrapCols("To approve, type or paste exactly what is inside the quotes (without the quotes), then press Enter:", W - 4).map((l) => `  ${l}`));
    out.push(`      ${hi(`"${expected}"`)}`);
  }
  out.push("  To deny, type d and press Enter.");
  const min = Math.round(timeoutMs / 60_000);
  out.push(`  No answer in ${min >= 1 ? `${min} minute${min === 1 ? "" : "s"}` : `${Math.round(timeoutMs / 1000)} s`} = denied.`);
  out.push("  > ");
  return out.join("\r\n");
}

/**
 * The launcher's prompter. `pause`/`resume` stop and continue claude.
 * @param {{ ttyPath?: string, pause?: () => void, resume?: () => void, timeoutMs?: number, write?: (s: string) => void, code?: () => string }} o
 * @returns {{ ask: (q: { tool: string, reason: string }) => Promise<{ approved: boolean, reason: string }> }}
 */
export function createApprover(o = {}) {
  const ttyPath = o.ttyPath ?? "/dev/tty";
  const timeoutMs = o.timeoutMs ?? DEFAULT_APPROVAL_TIMEOUT_MS;
  // One ledger per prompter: each question is answered once, by its code, before it expires.
  const ledger = new kit.ApprovalLedger({ ttlMs: timeoutMs, ...(o.code ? { code: o.code } : {}) });
  let queue = Promise.resolve();
  const ask = async ({ id = null, tool, reason, params = {}, effect = null, warnings = [] }) => {
    let out = null;
    const write =
      o.write ??
      ((s) => {
        try {
          out ??= fs.openSync(ttyPath, "w");
          fs.writeSync(out, s);
        } catch {
          /* no terminal: the answer read fails too */
        }
      });
    // The kit derives what approves from the effect (the hook's genuine kit
    // engine computed it from the call); the random part is this prompt's own.
    const req = ledger.request({ callId: id, tool: String(tool ?? ""), params, reason: String(reason ?? ""), ...(effectOf(effect) ? { effect: effectOf(effect) } : {}) });
    o.pause?.();
    let screen = null;
    let line = null;
    try {
      // The approval text: the target's word and the random code, as the kit made them.
      const m = /type (\S+) ([a-z]{3}) \(/.exec(String(req.confirm));
      const expected = m ? `${m[1]} ${m[2]}` : null;
      const r = await readAnswer(ttyPath, write, {
        timeoutMs,
        hint: "  (type the approval text, or d to deny, then Enter) > ",
        onReady: (modes, ln) => {
          // Claude Code's screen stays as it drew it: the prompt goes on the alternate screen.
          screen = { ownAlt: modes["1049"] !== true, cursorShown: modes["25"] === true };
          const text = promptText({ tool, reason, effect: req.effect, expected, timeoutMs, cols: ln?.cols ?? 80, color: colorOn(), warnings });
          write(`${screen.ownAlt ? "\x1b[?1049h" : ""}\x1b[H\x1b[2J\x1b[?25h${text}`);
        },
      });
      line = r.line;
      // What was typed or pasted: outer whitespace trimmed, one surrounding pair of double quotes taken off.
      const typed = r.answer === null ? null : (/^"(.*)"$/s.exec(r.answer.trim())?.[1] ?? r.answer.trim());
      const denyWord = typed !== null && /^d$/i.test(typed);
      const exact = typed !== null && expected !== null && typed === expected;
      // Only the exact approval text reaches the kit's ledger as typed (its own check is lenient on
      // case and punctuation; this prompt is not); anything else is a denial.
      const v = ledger.answer({ type: "approval-answer", requestId: req.id, typed: exact ? typed : r.answer === null ? null : "-", callId: id, tool: req.tool, params });
      // d (or D) then Enter, or Ctrl-C, is the person's deliberate denial; "no answer" is a timeout or no terminal.
      const byPerson = !v.approved && (denyWord || r.reason === "interrupted");
      const mismatch = !v.approved && !byPerson && typed !== null && typed !== "";
      const why = byPerson ? `denied by the person${r.reason === "interrupted" ? " (Ctrl-C)" : ""}` : mismatch ? "that's not the approval text" : (r.reason ?? v.reason);
      write(v.approved ? "ecwcode: approved\r\n" : mismatch ? "ecwcode: that's not the approval text: denied\r\n" : `ecwcode: denied${why ? ` (${why})` : ""}\r\n`);
      if (screen) {
        // The verdict stays readable for a moment, then Claude Code's screen comes back as it was.
        await new Promise((res) => setTimeout(res, VERDICT_MS));
        write(`${screen.ownAlt ? "\x1b[?1049l" : "\x1b[H\x1b[2J"}${screen.cursorShown ? "\x1b[?25h" : "\x1b[?25l"}`);
      }
      return { approved: v.approved, ...(byPerson ? { deniedByPerson: true } : {}), reason: v.approved ? "approved at Enclawed Code's prompt" : why ?? "not approved at Enclawed Code's prompt" };
    } finally {
      line?.restore();
      if (out !== null) {
        try {
          fs.closeSync(out);
        } catch {
          /* closed */
        }
      }
      o.resume?.();
      if (screen && !screen.ownAlt && line?.rows > 1) {
        // Claude Code drew on the alternate screen, which the prompt cleared:
        // a real size change makes it draw everything again (a SIGWINCH with
        // the same size does not).
        line.setRows(line.rows - 1);
        await new Promise((res) => setTimeout(res, 120));
        line.setRows(line.rows);
      }
    }
  };
  return {
    // One prompt at a time: parallel tool calls queue up.
    ask: (q) => {
      const p = queue.then(() => ask(q));
      queue = p.catch(() => {});
      return p;
    },
  };
}

/** An effect as the control socket carried it, when it has the kit's shape; null otherwise (the kit then names the tool). */
function effectOf(e) {
  if (!e || typeof e !== "object" || typeof e.summary !== "string" || e.summary.length > 2000) {
    return null;
  }
  const irreversible = e.irreversible === true ? true : e.irreversible === false ? false : null;
  const t = e.target;
  const target =
    t && typeof t === "object" && ["path", "host", "program", "tool"].includes(t.kind) && typeof t.name === "string" && t.name.length <= 4096
      ? { kind: t.kind, name: t.name }
      : null;
  return { summary: e.summary, irreversible, target };
}

/** Pause and continue a process for the prompt (claude). */
export function pauser(getPid) {
  return {
    pause: () => {
      const pid = getPid();
      if (pid) {
        try {
          process.kill(pid, "SIGSTOP");
        } catch {
          /* gone */
        }
      }
    },
    resume: () => {
      const pid = getPid();
      if (pid) {
        for (const sig of ["SIGCONT", "SIGWINCH"]) {
          try {
            process.kill(pid, sig);
          } catch {
            /* gone */
          }
        }
      }
    },
  };
}
