// zcode backend shim for reproof — v4 protocol client, simplified JSONL out.
// stdio contract (v1):
//   env: ZCODE_CLI, ZCODE_WORKSPACE, ZCODE_PROVIDER, ZCODE_MODEL, ZCODE_REASONING (default "default")
//   stdin : one JSON line {"prompt": "..."}        (further lines: {"sendText": "..."} — future)
//   stdout: {"type":"session","sessionId":...}
//           {"type":"turn","kind":"started|completed|failed","turnId":...}
//           {"type":"row","kind":"assistantText|userInput|turnHeader|...","rowId":...,"turnId":...,"state":...,"text":...}
//           {"type":"done","turnHeaders":N}
//           {"type":"error","message":...}
import { spawn } from "node:child_process";
import { existsSync, mkdirSync } from "node:fs";
import readline from "node:readline";

const CLI = process.env.ZCODE_CLI ?? "/work/ZCode/apps/zcode-cli/packages/cli/dist/zcode.cjs";
const WS = process.env.ZCODE_WORKSPACE ?? "/work";
const PROVIDER = process.env.ZCODE_PROVIDER ?? "stub";
const MODEL = process.env.ZCODE_MODEL ?? "glm-test";
const REASONING = process.env.ZCODE_REASONING ?? "enabled";

const emit = o => process.stdout.write(JSON.stringify(o) + "\n");
const err = m => { emit({ type: "error", message: m }); };

// ADR-002 R4: the registry refuses to start without the paired config envs —
// fail fast instead of hanging to the wall-clock timeout (observed in the
// run-integration smoke when REPROOF_AGENT_BACKEND was unset).
if (!process.env.ZCODE_BUILTIN_PROVIDER_CONFIG_FILE ||
    !process.env.ZCODE_PERSONAL_PROVIDER_CONFIG_FILE) {
  err("missing ZCODE_BUILTIN_PROVIDER_CONFIG_FILE / ZCODE_PERSONAL_PROVIDER_CONFIG_FILE pair");
  process.exit(2);
}

// A non-existent cwd makes every Bash tool spawn fail as `spawn /usr/bin/bash
// ENOENT` (Node reports a bad cwd on the command, not the directory). Ensure the
// workspace exists before app-server adopts it as --cwd; fail loud otherwise.
try { if (!existsSync(WS)) mkdirSync(WS, { recursive: true }); }
catch (e) { err("workspace dir unusable: " + WS + " (" + e.message + ")"); process.exit(2); }

const proc = spawn("node", [CLI, "app-server", "--cwd", WS], {
  env: process.env, stdio: ["pipe", "pipe", "pipe"],
});
const PREFS = { nativeSearchEnhancementsEnabled: false, memoryEnabled: false };
let nextId = 1;
let sessionId = null;
let subscriptionDone = false;
const seenRows = new Set();
let turnHeadersDone = 0;
let lastActivity = Date.now();
let doneEmitted = false;
let started = false;
let runningTurns = 0;        // turn-started vs turn-completed/failed balance
let turnsStarted = 0;        // lifetime count (optional budget, ZCODE_MAX_TURNS)
const MAX_TURNS = Number(process.env.ZCODE_MAX_TURNS ?? 0);  // 0 = unlimited

const send = o => proc.stdin.write(JSON.stringify(o) + "\n");

function handleLine(line) {
  let e; try { e = JSON.parse(line); } catch { return; }
  if (e.method === "startup/storageState" || e.method === "v4/telemetry/event"
      || e.method === "process/resourceSample" || e.method === "process/mcpTelemetry") return;
  // Server→client REQUESTS must all be answered or turns hang silently
  // (learned live: interaction/requestPermission re-announces every second;
  // an unanswered one froze the turn after the model response). The shim is
  // a headless host: permissions auto-ALLOW — the gVisor container is the
  // only boundary (ADR-002 R7 decision).
  if (e.id !== undefined && e.method) {
    let result = {};
    if (e.method === "session/requestRuntimePreferences") result = PREFS;
    else if (e.method === "interaction/requestPermission") result = { decision: "allow" };
    send({ id: e.id, result });
    if (e.method === "interaction/requestPermission") {
      // Record WHAT was auto-allowed (blanket allow is the gVisor-boundary R7
      // tradeoff). Transcript is scrubbed downstream (redact.scrub) before fsync.
      emit({ type: "permission", tool: e.params?.toolName, decision: "allow",
             detail: JSON.stringify(e.params ?? {}).slice(0, 800) });
    }
    return;
  }
  if (e.method === "computer-use/operation-event") {
    const k = e.params?.kind;
    if (k === "turn-started" || k === "turn-completed" || k === "turn-failed") {
      emit({ type: "turn", kind: k, turnId: e.params?.turnId }); lastActivity = Date.now();
      if (k === "turn-started") { runningTurns++; turnsStarted++; }
      else runningTurns = Math.max(0, runningTurns - 1);
      if (MAX_TURNS > 0 && turnsStarted > MAX_TURNS && !doneEmitted) {
        doneEmitted = true;
        emit({ type: "done", turnHeaders: turnHeadersDone, reason: "max-turns" });
        proc.kill(); process.exit(0);
      }
    }
    return;
  }
  if (e.method === "v4/conversation/frame") {
    lastActivity = Date.now();
    if (!registryReady && line.includes('"providerId":"' + PROVIDER + '"')) {
      registryReady = true;
      maybeStartReal();
    }
    ingestFrame(e.params?.frame?.payload);
    return;
  }
  if (e.id !== undefined && e.error) {
    err("rpc " + JSON.stringify(e.error).slice(0, 300));
  }
}

function walkRows(node, out) {
  if (Array.isArray(node)) { for (const x of node) walkRows(x, out); return; }
  if (!node || typeof node !== "object") return;
  if (typeof node.rowId === "number" && typeof node.kind === "string") { out.push(node); return; }
  for (const v of Object.values(node)) walkRows(v, out);
}

function ingestFrame(payload) {
  if (!payload) return;
  const rows = [];
  walkRows(payload, rows);
  for (const r of rows) {
    const key = r.rowId + ":" + r.entityId + ":" + (r.state ?? "");
    if (seenRows.has(key)) continue;
    seenRows.add(key);
    if (r.kind === "assistantText" || r.kind === "userInput" || r.kind === "turnHeader"
        || (r.kind ?? "").toLowerCase().includes("tool")) {
      emit({ type: "row", kind: r.kind, rowId: r.rowId, turnId: r.turnId,
             state: r.state ?? null, text: (r.text ?? "").slice(0, 4000) });
      if (r.kind === "turnHeader" && String(r.state).startsWith("completed")) turnHeadersDone++;
    }
  }
}

// Single line-framed reader over app-server stdout. A v4 frame can split across
// pipe chunks, so splitting raw "data" chunks and JSON.parse-ing the halves drops
// frames — including the createSession result (→ no sessionId → turn hangs to the
// watchdog). readline gives proper newline framing; every complete line feeds both
// the frame handler and the commandId→session binder.
const outRl = readline.createInterface({ input: proc.stdout });
outRl.on("line", l => { if (l.trim()) { handleLine(l); bindCommandIds(l); } });
proc.stderr.on("data", d => process.stderr.write("[app-server] " + d.toString()));
proc.on("exit", code => {
  if (!doneEmitted) { emit({ type: "error", message: "app-server exited rc=" + code }); process.exit(code ?? 1); }
});

// Registry-readiness probe: under gVisor the provider registry loads well
// after process start; a createSession issued too early falls back SILENTLY
// to the default (account) provider. Probe with a draft session and wait for
// any frame mentioning our providerId (= the personal overlay loaded), then
// send the real createSession. Learned on the first rust-canary run.
let startedAt = 0;
let registryReady = false;
let pendingPrompt = null;
let probeSent = false;
let realSent = false;

let probeCommandId = null;
function maybeProbe() {
  if (probeSent || !pendingPrompt) return;
  probeSent = true;
  probeCommandId = "shim-probe-" + Date.now();
  send({ id: nextId++, method: "v4/command", params: {
    commandId: probeCommandId, clientId: "reproof-shim", sessionId: null,
    type: "createSession", issuedAt: Date.now(),
    payload: { workspaceId: WS } } });
}
// subscribe to the probe session too — registry state (model.available with
// our providerId) only flows on a conversation subscription.

let realCommandId = null;
let realSubscribed = false;

function maybeStartReal() {
  if (realSent || !registryReady || !pendingPrompt) return;
  realSent = true;
  realCommandId = "shim-" + Date.now();
  const sel = { providerId: PROVIDER, modelId: MODEL, options: { reasoningLevel: REASONING } };
  send({ id: nextId++, method: "v4/command", params: {
    commandId: realCommandId, clientId: "reproof-shim", sessionId: null,
    type: "createSession", issuedAt: Date.now(),
    payload: { workspaceId: WS, config: { modelSelection: sel },
               firstInput: { text: pendingPrompt, modelSelection: sel } } } });
}

const rl = readline.createInterface({ input: process.stdin });
rl.on("line", line => {
  let req; try { req = JSON.parse(line); } catch { err("bad stdin line"); return; }
  if (req.prompt && !started) {
    started = true;
    startedAt = Date.now();
    pendingPrompt = req.prompt;
    setTimeout(maybeProbe, 3000);
  }
});

// result frames: bind to the REAL session (by commandId — the readiness
// probe session must not steal the subscription), then subscribe to it.
// Fed per complete line by the single outRl reader above (hoisted; module-scope
// state below is assigned by the time lines arrive).
function bindCommandIds(l) {
  let e; try { e = JSON.parse(l); } catch { return; }
  if (realCommandId && e.result?.commandId === realCommandId
      && e.result.result?.sessionId && !sessionId) {
    sessionId = e.result.result.sessionId;
    emit({ type: "session", sessionId });
  }
  if (probeCommandId && e.result?.commandId === probeCommandId
      && e.result.result?.sessionId && !subscriptionDone) {
    subscriptionDone = true;
    send({ id: nextId++, method: "v4/conversation/subscribe", params: {
      topic: "conversation/" + e.result.result.sessionId, connectionId: "reproof-shim-probe",
      clientMode: "desktop-continuous" } });
  }
  if (sessionId && !realSubscribed) { realSubscribed = true;
    send({ id: nextId++, method: "v4/conversation/subscribe", params: {
      topic: "conversation/" + sessionId, connectionId: "reproof-shim-real",
      clientMode: "desktop-continuous" } }); }
}

// registry-readiness timeout: no frame mentioning our provider in 90s -> fail loud
setInterval(() => {
  if (doneEmitted || !started || registryReady) return;
  if (Date.now() - startedAt > 90000) {
    err("registry readiness timeout: personal overlay (provider '" + PROVIDER + "') never appeared in frames");
    proc.kill(); process.exit(3);
  }
}, 3000);
// completion watchdog: quiet for 20s after >=1 completed turnHeader AND no turn
// currently running. The wider window + runningTurns guard stop a long silent
// detector/crash-PoC run (no intermediate frames) from being cut off as "done".
setInterval(() => {
  if (doneEmitted || !sessionId) return;
  const quiet = Date.now() - lastActivity > 20000;
  if (quiet && turnHeadersDone > 0 && runningTurns === 0) {
    doneEmitted = true;
    emit({ type: "done", turnHeaders: turnHeadersDone });
    proc.kill(); process.exit(0);
  }
}, 2000);
const HARD_TIMEOUT_MS = Number(process.env.ZCODE_SHIM_TIMEOUT_MS ?? 1800000);
setTimeout(() => { if (!doneEmitted) { err("timeout " + Math.round(HARD_TIMEOUT_MS / 1000) + "s"); proc.kill(); process.exit(1); } }, HARD_TIMEOUT_MS);
