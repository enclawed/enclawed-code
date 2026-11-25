// A stand-in for the Anthropic Messages API, for driving the real Claude Code
// binary in tests without a login or a model: every main-loop request (one
// with tools) is answered by the next scripted step, a tool_use or a text;
// every other request (titles, summaries, token counts) with a short text.
// Requests are logged as JSON lines (FAKE_ANTHROPIC_LOG) without their bodies.
//
//   node test/fixtures/fake-anthropic.mjs <script.json> <port-file>
//   script: [{ "tool": "Bash", "input": { "command": "..." } } | { "text": "..." }, ...]

import fs from "node:fs";
import http from "node:http";

const [scriptFile, portFile] = process.argv.slice(2);
const steps = JSON.parse(fs.readFileSync(scriptFile, "utf8"));
const logFile = process.env.FAKE_ANTHROPIC_LOG ?? null;
let next = 0;

const log = (o) => logFile && fs.appendFileSync(logFile, `${JSON.stringify({ t: Date.now(), ...o })}\n`);

function sse(res, events) {
  res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache", connection: "keep-alive", "request-id": "req_fake" });
  for (const [event, data] of events) {
    res.write(`event: ${event}\ndata: ${JSON.stringify({ type: event, ...data })}\n\n`);
  }
  res.end();
}

function message(model, blocks, stopReason) {
  return { id: `msg_fake_${Math.random().toString(36).slice(2, 10)}`, type: "message", role: "assistant", model, content: blocks, stop_reason: stopReason, stop_sequence: null, usage: { input_tokens: 10, output_tokens: 5 } };
}

function answer(req, res, body) {
  const model = body.model ?? "claude-sonnet-4-6";
  const main = Array.isArray(body.tools) && body.tools.length > 0;
  const lastUser = [...(body.messages ?? [])].reverse().find((m) => m.role === "user");
  const results = Array.isArray(lastUser?.content) ? lastUser.content.filter((c) => c.type === "tool_result") : [];
  let step = { text: "ok" };
  if (main) {
    step = next < steps.length ? steps[next++] : { text: "done" };
  }
  log({ path: req.url, main, step: main ? next : null, toolResults: results.map((r) => ({ id: r.tool_use_id, isError: r.is_error === true, text: typeof r.content === "string" ? r.content.slice(0, 400) : JSON.stringify(r.content ?? "").slice(0, 400) })) });
  const block = step.tool ? { type: "tool_use", id: `toolu_fake_${next}_${Math.random().toString(36).slice(2, 8)}`, name: step.tool, input: step.input ?? {} } : { type: "text", text: step.text ?? "ok" };
  const stop = step.tool ? "tool_use" : "end_turn";
  if (!body.stream) {
    res.writeHead(200, { "content-type": "application/json", "request-id": "req_fake" });
    res.end(JSON.stringify(message(model, [block], stop)));
    return;
  }
  const start = message(model, [], null);
  const events = [["message_start", { message: start }]];
  if (block.type === "tool_use") {
    events.push(["content_block_start", { index: 0, content_block: { ...block, input: {} } }]);
    events.push(["content_block_delta", { index: 0, delta: { type: "input_json_delta", partial_json: JSON.stringify(block.input) } }]);
  } else {
    events.push(["content_block_start", { index: 0, content_block: { type: "text", text: "" } }]);
    events.push(["content_block_delta", { index: 0, delta: { type: "text_delta", text: block.text } }]);
  }
  events.push(["content_block_stop", { index: 0 }]);
  events.push(["message_delta", { delta: { stop_reason: stop, stop_sequence: null }, usage: { output_tokens: 5 } }]);
  events.push(["message_stop", {}]);
  sse(res, events);
}

const server = http.createServer((req, res) => {
  let raw = "";
  req.on("data", (d) => (raw += d));
  req.on("end", () => {
    let body = {};
    try {
      body = raw ? JSON.parse(raw) : {};
    } catch {
      body = {};
    }
    if (req.method === "POST" && /\/v1\/messages\/count_tokens/.test(req.url ?? "")) {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ input_tokens: 10 }));
      return;
    }
    if (req.method === "POST" && /\/v1\/messages/.test(req.url ?? "")) {
      answer(req, res, body);
      return;
    }
    log({ path: req.url, method: req.method, other: true });
    res.writeHead(404, { "content-type": "application/json" });
    res.end(JSON.stringify({ type: "error", error: { type: "not_found_error", message: "not here" } }));
  });
});
server.listen(0, "127.0.0.1", () => fs.writeFileSync(portFile, String(server.address().port)));
