# adapters/ — reusable lab-replay building blocks for ai-agent targets

Dynamic confirmation ("trusted replay") for an agent target always decomposes
into the same three layers. This pack provides them once, parameterized, so
wiring a new target means writing a target contract + fixtures + a run script —
not re-deriving mocks by copy-paste.

| Layer | Adapter | Role |
|---|---|---|
| Model | `mock_llm.py` | OpenAI-compatible SSE/JSON stub, scenario-driven, content-keyed |
| Transport | `mcp_stdio_server.py` | mock MCP server over stdio, tool surface from a spec file |
| Transport | `mcp_http_client.py` | MCP streamable-HTTP client (initialize/session/call, SSE-or-JSON) |
| Transport | `acp_client.py` | raw ACP stdio client: deeplink injection + reverse-request answering |
| Entry | `pty_driver.py` | run interactive CLI paths under a real PTY |
| Boot | `boot.py` | spawn + wait-ready (health URL / port / file) + settle discipline |
| Verdict | `evidence.py` | controls → `replay-<id>.evidence.json`, one per finding |

All adapters are stdlib-only Python 3, loopback-only, and keep stdout clean for
the observation JSON (diagnostics go to NDJSON logs).

## Wiring a new target

1. **Contract first.** Copy a `target-contract.json`: pinned commit, image build,
   entry points, per-finding attack + controls, observation procedure. The
   contract is the oracle; adapters supply data, not judgement.
2. **Image.** Build the victim from pinned source in a Dockerfile under the
   target dir. Keep the lab directory mounted at runtime (`-v lab:/work/lab`) so
   mock iterations never rebuild the image.
3. **Model path.** Point the victim's provider config at `mock_llm.py`
   (`OPENAI_HOST`/`OPENAI_BASE_URL`-style env, dummy key). Write a scenario per
   finding: first step = what the model says on a fresh conversation, last step
   = what it says after a tool result. Content-keying makes run 2 a true replay.
4. **Transport path.** Stdio MCP server? Spec it in JSON and run
   `mcp_stdio_server.py`. HTTP MCP endpoint? Drive it with `mcp_http_client.py`
   (stdin JSON → stdout observation). ACP agent? `acp_client.py` with
   `ACP_AGENT_CMD`, optionally `ACP_DEEPLINK_FILE` and `ACP_REPLIES`.
   Interactive-only trigger? `pty_driver.py`.
5. **Boot.** If the victim is a server, spawn it via `boot.py` and honor the
   settle delay — a read cache or migration window is the classic reason a
   seeded fixture "doesn't take".
6. **Run script.** One bash script per target: per finding — attack ×2, then the
   negative control, markers under `/work/evidence/`; end with `evidence.py`.

## Control idioms (the discipline that makes it evidence)

- **Attack ×2**: replayability is a claim; run the attack twice, independent
  markers. A crash/marker that fires once is a flake, not a finding.
- **Negative control**: same setup minus the payload (recipe without the
  section, tool without the annotation, session without the deeplink, empty
  repo). It MUST fail; a passing negative control means the marker proves
  nothing.
- **Sibling/control-by-config**: where the target has a disable knob
  (denylist, permission mode), show the knob actually blocks the attack —
  it both validates the marker path and scopes remediation.
- **Marker hygiene**: markers live only under the evidence dir; `rm -f` before
  every run; assert on a marker the payload *itself* writes, never on a driver
  side effect.
- **Distinct markers per vector** when one finding has several vectors (e.g.
  config auto-spawn vs. session-hook), so attribution is unambiguous.
- **Refuted is a result**: a control that fails because the mechanism does not
  exist refutes the (sub-)claim — record it as refuted, keep the evidence, do
  not silently drop the finding.

## Gotchas worth the fixture budget

- Some agents probe MCP servers with `server/discover` before `initialize`;
  answer `-32602` and they fall back to classic initialize.
- Tool names reach the model prefixed (`<extension>__<tool>`); scenarios must
  use the prefixed name.
- Interactive-only code paths (session-start hooks, first-run wizards) need a
  PTY — a headless driver silently never reaches them.
- Deeplinks are typically base64url **without padding** of the JSON (not YAML).
- Fixture validation config must itself be valid: an invalid regex/glob in a
  rule matcher is usually skipped with a warning, and the "attack" then proves
  nothing — when a vector doesn't fire, suspect the fixture before the target.
- Agent CLIs may gate features on sibling tooling being present (auth CLIs,
  runtimes); a shim on PATH is a legitimate lab device — document it in the
  image, never hide it.

## Trust boundary

The mock LLM, transports and drivers run on loopback inside a disposable
container; no real provider, no egress. Victim credentials and state are
synthetic and isolated from the researcher. All target-generated text remains
untrusted data. See `../adapter-contract.md` for the execution-verification
contract this pack implements.
