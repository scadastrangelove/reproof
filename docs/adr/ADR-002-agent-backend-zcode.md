# ADR-002 — ZCode CLI as a second agent backend

**Status:** accepted — Phase 0 complete; E2E verified live on a from-source
build (pinned zai-org/ZCode commit `29628c9`, CLI 0.16.9) under Linux/Docker
on the Tamm runner, 2026-10-05: custom api-key provider → app-server v4
`createSession` → `turn-completed` → provider traffic observed with the
configured bearer key; multi-turn `sendText` resume verified.
**Date:** 2026-10-05 (Phase 0 measurements updated same day)

## Context

Phase 6 plans a 3-lens × 2-model campaign and GLM proved itself on the
interactive half (the ZCode variant-scan campaign of 2026-10-05 was executed
end-to-end by a zcode agent on GLM-5.3 — 15 lens subagents, skeptic panel,
PoC harness). zai-org/ZCode is newly open-source, so the agent runtime can be
built from a pinned commit inside the agent image, like every other pipeline
dependency.

Coupling points are the same four as ADR-001 (agent adapter, agent image,
auth, redact/egress). ZCode exposes two drive surfaces:

| Surface | Shape | Verdict |
|---|---|---|
| `-p` one-shot | hidden `--output-format stream-json`, `--resume`, `--cwd`, `--mode`, `--disallowed-tools` | **unsuitable** — no model-selection source (R1) |
| `app-server` | `zcode app-server`: NDJSON ZCode Protocol (v4) over stdio, bidirectional | **the backend** |

## Decision (proposed)

Drive ZCode through the **app-server protocol**, not `-p`. The adapter speaks
NDJSON frames, answers server→client requests, and issues `v4/command`
`createSession` with `firstInput.modelSelection` +
`config.modelSelection`. Custom providers (OpenAI/Anthropic-compatible,
`apiKey` + `baseURL`) are declared in the personal overlay
(`$HOME/.zcode/v2/provider_config.json`) — no OAuth inside the container, any
compatible endpoint reachable (including GLM's).

## Phase 0 measurements (2026-10-05, final)

Probes ran in two waves: discovery against the desktop-bundled CLI (same
0.16.9 build), then verification on a **from-source build** (rsync of the
pinned clone → `pnpm install --filter @zcode/cli...` → `pnpm --filter
@zcode/cli... build` inside `node:24-bookworm` on the Tamm runner;
`dist/zcode.cjs` 31 MB, `version` → 0.16.9). Harness preserved on Tamm:
`~/zcode-src/{run-e2e.sh,drive.mjs,stub-node.mjs,zcode-builtin.json,p0/…}`
and locally at `/tmp/zcode-p0/`.

### R1 — model selection `[live, verified E2E]`

- `-p`: no `--model`; no default-selection source for NEW sessions (legacy
  `model:` default ignored; resume restores the persisted per-session
  selection but the registry must validate it). `-p` is ruled out.
- app-server: `v4/command` `createSession` with `config.modelSelection` +
  `firstInput.modelSelection` → `{"status":"accepted","result":{"type":
  "createSession","sessionId":"sess_…","input":{"delivery":"startNow"}}}`.
  **`options.reasoningLevel` is REQUIRED at execution** — the model factory
  dereferences `target.selection.options!.reasoningLevel!`
  (`provider-registry-model-runtime.ts`); a selection without it fails model
  creation with no useful log line. `defaultModelSelection` in the personal
  overlay file is the persistence analog.

### R2 — stream contract `[live, verified E2E]`

NDJSON `{id, method, params}` / `{id, result|error}` (JSON-RPC-ish codes;
zod errors in `error.data` make the protocol self-describing). Lifecycle
arrives as `computer-use/operation-event` with `kind: turn-started |
turn-completed | turn-failed` (+ `turnId`, `sequenceNumber`); other
notifications: `startup/storageState`, `state.updated` (session patches incl.
`model.available`), `process/mcpTelemetry`, `process/resourceSample`,
`v4/telemetry/event`. Second turn on the same session: `v4/command`
`sendText` → `{"status":"accepted","result":{"type":"inputAccepted",
"delivery":"startNow"}}` → turn events; provider request body grew by exactly
the accumulated turn (46920 → 47009 bytes) — **session continuity and
context carry confirmed**.

**Assistant-content channel (milestone 1, verified live):** the
operation-event stream carries lifecycle only; content requires a
subscription — `v4/conversation/subscribe {topic:
"conversation/<sessionId>", connectionId, clientMode:
"desktop-continuous"}` → ack `{subscriptionId, mode: "snapshot", logEpoch,
snapshotRowCount}` → `v4/conversation/frame` pushes
`{wireVersion, kind: "complete", deliveryKind: "initial" | "online",
logicalFrameId, logicalFrameOrdinal, topic, subscriptionId, frame:
<rows snapshot/delta>}` — snapshot on subscribe, per-turn deltas after;
`base {logEpoch, seq}` enables resync resume. This is the `AgentResult`
feed for the adapter.

### R3 — bidirectionality `[live]`

The server interrogates the client at session start:
`session/requestRuntimePreferences` (answer
`{nativeSearchEnhancementsEnabled: boolean, memoryEnabled: boolean}` — zod
strict; extra keys rejected) and
`interaction/requestOfficialMcpAuthHeaders`. Unanswered requests fail the
command. **The adapter is a responder, not just a reader.**

### R4 — custom providers / auth `[live, verified E2E]`

Personal overlay at `$HOME/.zcode/v2/provider_config.json` (or the paired
envs `ZCODE_BUILTIN_PROVIDER_CONFIG_FILE` +
`ZCODE_PERSONAL_PROVIDER_CONFIG_FILE`, which must be set together — the
registry startup throws otherwise):

```
providerRules: [{providerId, providerName, enabled: true, config: {
  group: "standard-personal",
  access: {type: "api-key", apiKey},
  api: {type: "openai-chat-completions" | "anthropic-messages" |
        "openai-responses", baseUrl},
  personalModelIds: ["<model>"]}}]
manualProviderModelRules: [{providerId, modelId, config: {…STRICT…}}]
defaultModelSelection: {providerId, modelId}
```

**The manual model config is strict and silently fatal**: `optionSpecs.
reasoningLevel {values[], map: <restricted-CEL string>}`,
`optionSpecs.maxOutputTokens.max`, `properties.inputFormat{…}`,
`properties.supportsMidConversationSystem` are required; a file failing this
schema is dropped whole ("recovery") with **no error in any log** and
`providerCount: 0` — the single biggest Phase-0 time sink. Validated recipe
lives in the harness (`p0/home/.zcode/v2/provider_config.json`).

Verified end-to-end: `providerCount: 1`, `model.available` populated, turn
`turn-completed`, and the stub endpoint received `POST /v1/chat/completions`
with `Authorization: Bearer <configured api key>` — main turn (~47 KB body:
system prompt + tools) plus a title-generation sidecar
(`x-zcode-session-type: other`). Egress for the agent image = the custom
provider's host only. The `provider/updateAccountConfig` protocol channel
accepts only `zhipu-account` providers — ignore it; the file overlay is the
auth surface.

### R4b — model-traffic proxying: CONFIRMED WORKING `[re-measured 2026-10-06; supersedes the 2026-10-05 "ignored" claim, which was an instrument artifact]`

Source-traced (contributor analysis, verified against the pinned tree) and
then confirmed live with a FIXED MITM recorder: the model fetch is
`createNetworkProxyFetch` wired into `createAnthropic({fetch})`
(`model-execution.ts:293,440,508`); its resolver honors ONLY
`config.network.httpProxy` / env `ZCODE_HTTP_PROXY` (+ `ZCODE_NO_PROXY`,
`ZCODE_AGENT_CA_CERT` → `network.caCertFile` via `env-config.adapter.ts`) —
classic `HTTP_PROXY`/`HTTPS_PROXY`/`NODE_EXTRA_CA_CERTS` are stripped from
runtime env BY DESIGN (`SANITIZED_RUNTIME_ENV_KEYS`). The CA **replaces**
the trust store — for a TLS-terminating recorder the recorder CA is
mandatory; without it the failure masquerades as "proxy not applied".

Live proof (recorder v2; v1 deadlock made the first measurement a false
negative — a lesson now in LESSONS.md): main-turn request to
`api.z.ai/api/anthropic/v1/messages` with the overlay api-key, recorded and
forwarded, upstream 200.

**Residual:** auxiliary calls (session-title sidecar) route to the CLI's
DEFAULT gateway `zcode.z.ai/api/v1/ultra-zai/anthropic/...` regardless of
the session provider — the egress allowlist must cover BOTH
`api.z.ai:443` (provider) and `zcode.z.ai:443` (sidecars), else the proxy's
403 denial surfaces as `Provider authentication failed` and drowns the real
state. The 2026-10-05 run4 "403" was exactly this (denied sidecar/gateway
traffic), not an auth problem.

### R5 — isolation `[live]`

Session db is hardwired to `os.homedir()/.zcode`; the isolation knob is the
**HOME override** (fresh db + migrations under `HOME=<dir>` verified).
`ZCODE_DATA_BASE_DIR` redirects only part of the tree — do not rely on it.
Container recipe: `HOME=$ZCODE_HOME` + the provider-config env pair above.

### R6 — budget `[gap — accepted deviation]`

No `--max-turns`/`loop_control` analog exists. Fallback: wall-clock timeout
per turn + capped retries + `turn-completed`-watchdog. Deviation from the
kimi contract recorded here; revisit if upstream adds loop control.

### R7 — system prompt + tools `[live, structural; decision 2026-10-05]`

No `--system-prompt`/`--agent-file`. Carrier VERIFIED live: a canary
`AGENTS.md` in the `--cwd` workspace appears verbatim in the provider request
(system context) — the per-stage agent-file mechanism ports directly (write a
generated AGENTS.md into the stage workspace).

**Tool surface decision: NO allowlist — all default tools stay enabled.**
The default surface (20 tools, enumerated from the captured request: Agent,
AskUserQuestion, Bash, Cron{Create,Delete,List,Update}, Edit, EnterPlanMode,
ExitPlanMode, Read, Skill, TaskOutput, TaskStop, TodoRead, TodoWrite,
WebFetch, Write, SendMessage, ReadSessionContext) ships as-is. Rationale: the
gVisor container is the ONLY trust boundary (consistent with R1–R4 scan
findings — the CLI's internal permission gates are untrustworthy, so
duplicating them adds no safety), and unrestricted tools let find/grade
agents self-organize (Todo*, TaskOutput). The kimi contract's
`tools=["Read","Write","Bash"]` / no-tools-for-judge is therefore carried at
the PROMPT level only (judge/report-grader prompts already instruct
no-tool-use; verdicts come from the manifest, not self-verification) — zero
mechanism, and a stage prompt claiming tool restrictions would be a lie, so
zcode stage prompts must not claim them.

### R8 — runtime `[live]`

From-source build on Linux/docker verified end-to-end (root workspace
install; the CLI sub-workspace's own lockfile is stale — install from the
monorepo root). The desktop's bundled `zcode.cjs` (node ≥24) also runs
standalone — useful for laptop probes; the agent image pins the from-source
build.

## Adapter implications

- **Adapter shape — node shim, not a hand-rolled Python protocol client.**
  The v4 client machinery already exists in the pinned sources
  (`packages/client`, `@zcode/shared/zcode-protocol-v4` — the same code the
  desktop uses to drive the CLI). Put a small node shim in the agent image
  that speaks v4 via the official client and exposes a simplified
  request/response JSONL contract on stdio; `reproof/agent_zcode.py` then
  stays as thin as the kimi adapter (spawn shim, read JSONL, normalize into
  `AgentResult`). The Phase-0 `drive.mjs` harness (Tamm `~/zcode-src/`) is
  the working seed for the shim. Python-side responsibilities: config
  seeding (HOME override, builtin+personal env pair, strict model-config
  recipe), responder answers, frame→AgentResult normalization (third
  dialect).
- Agent image: from-source CLI build (same pinned commit), `HOME` redirected,
  egress = provider host. API key lands in the personal overlay file inside
  the ephemeral single-agent container (kimi keeps keys env-only) — accepted
  deviation; `redact.py` scrubs `provider_config.json` paths + keys
  regardless.
- Fixtures: capture the harness runs into
  `tests/fixtures/zcode_appserver_*.jsonl` per the `test_agent_kimi.py`
  pattern.

### R9 — the Bash-tool ENOENT: `workspaceId` must be the workspace PATH `[solved 2026-10-06]`

Symptom: every Bash-tool call failed `spawn /usr/bin/bash ENOENT` in
target-populated containers while raw node spawns of the same binary worked.
Root cause chain (source-differential + live probe): the v4 createSession
contract maps LOCAL workspaces as `workspaceId = workspacePath`
(session-mgmt.ts: "本地工作区 = workspacePath"); the shim sent
`workspaceId: "reproof"` (an opaque id), the session workingDirectory
resolved EMPTY, and Node's `spawn(file, args, {cwd: ""})` reports
`spawn <file> ENOENT` — blaming the command, not the cwd (the snapshot
spawn, which passes no cwd, always worked — the decisive differential).
Node probe matrix confirmed: cwd `""` → ENOENT; `/work`, `/tmp`, undefined
→ OK. Fix: `workspaceId: <workspace path>` in both shim createSession
payloads. After the fix the rust-canary completed the FULL pipeline under
gVisor with real GLM-5.3 (find → grade 3/3 ASAN reproduction PASSED →
report → aggregate confirmed, 20261006T055340Z).

## Open items (adapter milestones)

1. ~~Assistant-text extraction~~ — DONE: `v4/conversation/subscribe` →
   `v4/conversation/frame` (see R2); row-shape dump for the normalizer lands
   with the shim (one harness run prints full frames).
2. ~~Tool allowlist~~ — DROPPED by owner decision (see R7): all default
   tools; gVisor is the only boundary; judge no-tools is prompt-level.
3. Budget watchdog design (R6) and crash/resume semantics across process
   restarts (`inputDiscardedOnRestart` on poisoned pending commands — wipe
   state or confirm-resend).
4. Node shim (`packages/client`-based) + `agent_zcode.py` +
   `REPROOF_AGENT_BACKEND` routing + `redact.py` patterns + agent-image
   build; then `rust-canary` smoke and the phase-6 campaign.
