# Authenticated audit anchor (red-team round 3, N10)

Author: Alfredo Metere <alfredo.metere@enclawed.com>

## The finding

Through firmware record v1, `ANCHOR_SET` took a bare 32-byte head. Any process that could open the Enclaweder's HID node could anchor the head of a log it had fabricated, and the device signed it. Round 3 showed this on the real Enclaweder Pro: a same-uid process replaced the log with a fabricated chain, anchored its head, and `ecwctl audit verify` reported "matched" (N10). A truncation behind a saved anchor copy read as "superseded", which `audit verify` did not fail on (N10b).

## The device protocol

The firmware side is specified in the Enclaweder host protocol ("Monotonic audit anchor", record v2). In short:

- `ANCHOR_OPEN` (0x19): the host sends a fresh X25519 public key and a nonce. The device answers with a session id, its own ephemeral key and nonce, and an Ed25519 signature by its identity key over the whole transcript (`"ECW-ANCHOR-OPN-1" | uid | sid | counter | host_pub | dev_pub | host_nonce | dev_nonce`). Both sides derive the session key with HKDF-SHA3-256. The key never crosses the wire, which matters on Linux, where every process that has the hidraw node open receives every IN report.
- `ANCHOR_SET` (0x17): `head | sid | ctr | mac`, with `mac = HMAC-SHA3-256(K, "ECW-ANCHOR-SET-1" | uid | sid | ctr | head)` and `ctr` strictly increasing within the session. A bare head is refused with `ERR_AUTH`.
- `ANCHOR_CLOSE` (0x1A): MAC-authenticated too, because an unauthenticated close would be a session-kill primitive.
- One session at a time. A second `ANCHOR_OPEN` gets `ERR_BUSY`; it never supersedes the open session. The session ends only on power-on reset, USB re-enumeration (replug or a port reset), the tamper response, or an authenticated close.
- Every open is counted in flash, and the count is the session id. Record v2 (`"ECW-ANCHOR-02" | counter | head | uid | sess | opens`, signed) names the session that set the head (`sess`) and the open count (`opens`).
- `ANCHOR_GET` (0x18) stays unauthenticated and read-only.

Enclawed Code does not implement any of this cryptography itself. The host side is enclawed-oss's `AnchorSession` (in `enclaweder-hid.ts`) and the head-anchor sink in `head-anchor.ts`, which opens a session lazily on its first write, raises `HeadAnchorAlarm` (`ANCHOR_SESSION_BUSY`, `ANCHOR_SESSION_HIJACKED`), and reports `HeadAnchorTampered` with the codes `invalid`, `foreign-session` and `downgrade`.

## How Enclawed Code uses it

**The launcher holds the session.** `startAnchoring` (`src/device.mjs`) runs in the launcher process and builds the framework's sink there, so the session key exists only in the launcher's memory. `kernel.yama.ptrace_scope = 1` keeps a non-descendant process of the same user out of `/proc/<launcher>/mem`. A descendant of claude cannot read it either: the hook and the agent's tools are descendants of claude, and claude is a child of the launcher, not its ancestor (round 3 tested `/proc/<launcher>/mem` from a descendant: `EACCES`).

**The hook asks the launcher.** After it appends a record, the hook sends `{ "op": "anchor" }` on the launcher's control socket (`src/control.mjs`). That socket only serves processes that pass the peer check: a descendant of this session's claude, running this Node binary with Enclawed Code's exact hook command line and none of the code-loading environment variables (`NODE_*`, `LD_PRELOAD`, `LD_AUDIT`, `LD_LIBRARY_PATH`, `DYLD_*`). The launcher then anchors the current tail of the log. It also anchors on its own timer, every 2 s, and once more at the end of the session.

**Alarms stop the session.** A `HeadAnchorAlarm` is not treated as a transient error. If the device answers `BUSY`, something else on the host holds the anchor channel. If the session is dropped and the reopen does not get the next session id, something opened the channel in between. Either way the launcher prints an `ALARM` line, writes a `claude-code.launch.anchor-alarm` record, and stops claude (exit 3).

**Shutdown.** The launcher awaits `closeHeadAnchorSessions()` (an authenticated `ANCHOR_CLOSE`) before it releases the hardware-root session. A launcher that crashes without closing leaves the device's session open, and the next `ANCHOR_OPEN` gets `BUSY` until the Enclaweder is unplugged and plugged back in. The framework also writes a best-effort close when the process exits, but that close cannot be awaited.

**`audit verify` checks the sessions.** `checkDeviceAnchor`:

- fails with `foreign-session` when the device's head was set under a session this log never held (from the framework's sink, using the sessions recorded in the anchor file);
- fails with `downgrade` when the device answers with an older record format than this log was anchored with;
- fails with `foreign-open` when the device's `opens` is ahead of the newest session this log held, meaning something opened the channel since;
- fails when Enclawed Code's anchor history (below) shows a newer anchor than the anchor file, an anchored head that is no longer in the log, or a counter ahead of the device's.

`superseded`, the old v1 outcome ("the device was anchored again since"), now fails too (exit 1).

**Anchor history (N10b).** After every anchor the launcher appends the device-signed record to `audit.jsonl.enclaweder-anchors.jsonl` beside the log, exactly as the device signed it: `head`, `counter`, `uid`, `sig`, plus `version`, `sess` and `opens` for record v2, and `bind` too for record v3 (command set 0.5, a session bound to the launch's device activation). The format, the writer and the check are the kit's (hardware-root `anchor-history.ts`: `appendAnchorHistory`, `readAnchorHistory`, `compareAnchoredLog`): each line verifies on its own under its version's signature domain only, a line missing a field its version signs fails, and every v3 line must name one of the log's own launch activations. A restored older anchor file, or a log truncated below an anchored head, is detected even when the device itself is not consulted. The launch gate's comparison is a fresh `ANCHOR_READ` and `ANCHOR_GET` (no anchor open, no unlock use), so it runs before the launch's activation; a launch it refuses spends nothing on the device.

## Verified

- Unit tests (`test/round3.test.mjs`, N10/N10b) run the framework's real `AnchorSession` against `test/fixtures/anchor-sim.mjs`, a frame-level simulator of the record v2 firmware ported from enclawed-oss. They cover a genuine match, a refused bare `ANCHOR_SET`, `BUSY` for a second open, `foreign-session` for a forged or truncated log re-anchored by another session (with and without the history), a forged history line, and `HIJACKED` raising the alarm.
- `test/redteam/integrity/anchor-forge.mjs` ran against the real Enclaweder Pro after the record v2 reflash. The launcher-anchored log matched. The bare `ANCHOR_SET` got `ERR_AUTH`, and a second open while the launcher's session was held got `BUSY`. A forged chain anchored under the attacker's own session, and a truncation behind a saved anchor copy, both made `audit verify` fail with `foreign-session`. A full `ecwcode -p` session on the device also anchored (counter 21), and `audit verify` reported matched.

## What remains

- **The host can still be the attacker before the launcher opens.** Only one session can be open. A process that opens the channel first, before any Enclawed Code launch, makes every launch raise `ANCHOR_SESSION_BUSY` and stop. That is a denial of service, and it is loud. It is not a silent forgery: the attacker can anchor heads only under its own session id, which `audit verify` reports as `foreign-session` for this log.
- **A logger that shares the device.** A second log anchored on the same device (another state directory, a test sandbox) is, to the first log, a foreign session or a foreign open, and makes the first log's `audit verify` fail. That is intended: it cannot be told apart from an attacker's session. Use `--no-device` and compare the counters out of band when this is expected.
- **Old firmware.** On firmware before record v2 the framework's `ANCHOR_OPEN` fails with `AnchorAuthError` "unsupported" (status 8). Enclawed Code then says once that the attached Enclaweder's firmware does not support (authenticated) audit anchoring, and the log is anchored on the host only; `audit verify` reports the device anchor as `unavailable`, and I7 stays open as documented for a host-only log.
- **Not yet covered by a test:** an interactive launch that ends in an anchor alarm (the alarm handler is covered at the `startAnchoring` level, and the stop path is shared with N9 c).

## Round 4: laundering through the launcher (N14) and the lease (N15)

The authenticated session keeps every other process off the anchor channel, but in N14 the launcher itself anchored whatever head the log file ended with on its next tick, so a same-user process that replaced the log mid-session (and deleted the anchor file and history first) got its fabricated head anchored under the genuine session. The launcher now anchors only heads that extend the chain it followed since the start of the session (`src/anchor-chain.mjs`: prefix hash, per-record hash and link checks, rotation-aware, plus the anchor file and history byte for byte); anything else raises `ANCHOR_TAMPER`, stops claude and anchors nothing. `audit verify` requires the anchor history to end at the device's own signed record (`no-history`, `history-behind`, `history-order`).

Residual: a log replaced while no session runs, together with its whole history, is baselined by the next launch. The device then still holds the genuine log's last head, which is not in the replacement, so the first `verify` before that launch fails; after the next session anchors the replacement, only an archived copy of the old history (or the device counter recorded elsewhere) shows the break.

Firmware 0.2 adds a 120 s session lease, `ANCHOR_KEEPALIVE`, `ERR_BUSY | wait_ms` and an operator-quorum takeover (PROTOCOL.md). The framework's head-anchor sink renews the lease every 30 s and reopens as `sid + 1` after a lapse; Enclawed Code's BUSY alarm prints the time left and points to `ecwctl recover-anchor`, which runs the takeover with operator keys (or prints the replug procedure for firmware 0.1).
