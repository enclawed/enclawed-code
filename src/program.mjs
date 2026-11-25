// Which program is running (ecwcode, Claude Code itself, or ecwctl, Enclawed
// Code's own commands), for the prefix of the messages shared code prints.
// Each entry point says so (launcher.mjs main, ctl.mjs main); without one, the
// name the program was started under decides.

import path from "node:path";

let current = null;

export function setProgram(name) {
  current = name;
}

/** "ecwctl" or "ecwcode". */
export function program() {
  return current ?? (/ecwctl|ctl-entry|rt-ctl/.test(path.basename(process.argv[1] ?? "")) ? "ecwctl" : "ecwcode");
}

/**
 * One message line for the terminal: the program's prefix, then the text
 * word-wrapped at word boundaries to the terminal's width (never mid-word; a
 * word longer than the width, such as a URL, stands alone on its line).
 * Continuation lines are indented by two spaces. Not a terminal: one line.
 */
export function formatLine(text, columns = null) {
  const line = `${program()}: ${text}`;
  const width = Number.isInteger(columns) && columns >= 20 ? columns - 1 : null;
  if (!width || line.length <= width) {
    return `${line}\n`;
  }
  const out = [];
  let cur = "";
  for (const w of line.split(/ +/).filter(Boolean)) {
    const lead = out.length ? "  " : "";
    if (cur && (lead + cur + " " + w).length > width) {
      out.push(lead + cur);
      cur = w;
    } else {
      cur = cur ? `${cur} ${w}` : w;
    }
  }
  if (cur) {
    out.push((out.length ? "  " : "") + cur);
  }
  return `${out.join("\n")}\n`;
}

/** Write one message line to a stream, wrapped to its width when it is a terminal. */
export function say(stream, text) {
  stream?.write(formatLine(text, stream?.isTTY ? stream.columns : null));
}
