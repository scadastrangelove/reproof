# The pipeline: deep dive

An autonomous, multi-agent pipeline for finding memory-safety, panic, and
soundness bugs — the `rust` profile (Miri / ASan / panic / hang + cargo-fuzz) is
the worked default; the retained `cpp` profile finds C/C++ memory bugs with ASan.
This document explains what each stage does, how to watch a run, and the relevant
CLI flags.

> ⚠️ **The pipeline spawns autonomous agents and executes target code.** 
> The pipeline runs each agent inside a gVisor container with egress restricted 
> to the model API. Agent-spawning subcommands refuse to start outside it unless 
> explicitly overridden. For more information, see [security.md](security.md)
> and [agent-sandbox.md](agent-sandbox.md).

> This document covers how the reference pipeline works. For the general
> best practices it implements, see the [blog post](https://claude.com/blog/using-llms-to-secure-source-code).

> **SAST-driven find mode.** Alongside the blind / threat-model / CVE-seeded find passes, a fourth,
> deliberately isolated mode runs every static-analysis engine's default rules in a container (six
> baked in, plus CodeQL as an opt-in BYOL 7th), clusters the output into *cells*, and hands them to
> `/triage`. It is documented separately: [`docs/sast-layer.md`](sast-layer.md) (design + the CodeQL
> BYOL contract), [`docker/sast/README.md`](../docker/sast/README.md) (the image + runner), and the
> `/sast-driven` + `/sast-prioritise` skills.

## Install and first run

```bash
# One-time setup
python3 -m venv .venv && .venv/bin/pip install -e .
./scripts/setup_sandbox.sh   # installs gVisor, builds the agent images, and verifies isolation; note: requires Docker
export KIMI_MODEL_NAME=... KIMI_MODEL_API_KEY=... KIMI_MODEL_BASE_URL=...   # see docs/agent-sandbox.md

# Run recon → find(union) → grade → judge → report on the rust demo target
bin/reproof-sandboxed run rust-canary --model <model-id> --parallel --stream --auto-focus --aggregate union
# find→fuzz: turn graded findings into reproducing harnesses, then gate on the scorecard
bin/reproof-sandboxed reattack results/rust-canary/<timestamp>/ --model <model-id> --aggregate union
reproof scorecard   results/rust-canary/<timestamp>/
# Generate a candidate patch for each finding
bin/reproof-sandboxed patch    results/rust-canary/<timestamp>/ --model <model-id>
```

Start with a small wave like this one to get a feel for how the pipeline works
and the token burn before scaling up. Results land in `results/<target>/<timestamp>/`.
With `--stream`, the first report usually appears within minutes under 
`reports/bug_NN/`, so you don't have to wait for the whole batch to finish.

You can drive the pipeline using Kimi Code. The repo's `AGENTS.md` teaches
the agent how to run each phase of the pipeline and what to watch. Launching runs
from a Kimi Code session makes it easy to tail transcripts, ask what's 
happening mid-run, and stop early without losing anything.

## What each stage does

![Overview of the demo pipeline stages.](../static/harness-diagram.png)

**Build.** The target's `Dockerfile` is built into a detector-instrumented image
the first time you run a scan against it (the detector is profile-dependent: ASan
for the cpp base; Miri/sanitizer/panic/hang for rust). The same image is reused
for find, grade, and re-attack, so every agent sees the same code in the same
environment.

**Recon** (optional). An agent reads the source tree and proposes a partition
of the attack surface (*"here are 8 distinct parsers worth attacking
separately"*). This gives parallel runs different starting places so they
don't all converge on the same bug. `--auto-focus` runs this as a part of
the full pipeline. You can skip recon if you've hand-written `focus_areas:`
in the target's `config.yaml`.

**Find.** The core part of the loop. Each run gets one agent in its own 
network-isolated container. The agent reads the source, crafts malformed inputs, 
and runs the detector-instrumented binary until an input crashes 3 out of 3 times
(the detector is profile-dependent: ASan for cpp; Miri/sanitizer/panic/hang for
rust). It outputs
the crashing input file (not a written report). Parallel find agents share a 
`found_bugs.jsonl` log and must justify why their addition is not a duplicate 
of something already listed before adding to it.

**Grade.** A second agent in a fresh container re-runs the PoC and checks that the 
crash is real (i.e., it reproduces under the profile's detector — ASan for cpp,
Miri/sanitizer/panic/hang for rust — it's in project code, and it isn't just memory 
exhaustion). The only thing that crosses from the find container to the grader is 
the PoC bytes, so the grader isn't influenced by the find agent's reasoning. 
Flaky-but-real crashes (races, heap-layout-dependent) can pass this step, though
they will receive a lower score. Each run's verdict is written to `run_NNN/result.json` 
as soon as the grader agent finishes.

**Judge.** When a finding passes the grader, a short no-tools agent compares 
the crash against the bugs already in `reports/manifest.jsonl` and decides 
whether the finding is a new bug (in which case it's accepted), a cleaner example 
of a known bug (in which case it replaces the old version), or a duplicate (in 
which case it's skipped). Judge agents run serially so that two duplicate findings 
arriving around the same time aren't accidentally both classified as new. The
judge stage is only run when the `--stream` modifier is used.

**Report.** For each new bug, a report agent writes a structured exploitability 
analysis using only the PoC and the source. The report includes details on what 
the corrupted memory lets an attacker do, how reachable it is from real input, a 
sketch of the escalation path, and a severity. A separate grader agent then scores
the report, checking that its claims are backed by evidence (e.g., line numbers,
observed re-runs) rather than plausible prose. Reports land in `reports/bug_NN/report.json` 
and include the grader's score so you can tell which reports are most trustworthy.
The `--novelty` modifier (off by default) lets the orchestrator check the upstream
git history so the report can include whether the bug has already been fixed there.

**Dedup.** A separate command that can be run post-hoc to cluster the pipeline
results by detector signature (ASan for cpp; Miri/panic/hang for rust). It's useful for a quick summary of "these N crashes
cluster into M signatures".

**Patch.** A separate command that generates a candidate patch for each unique
bug. For details, see [patching.md](patching.md).

**Predisclose.** A separate command that runs a skeptical-maintainer agent
against each `reports/bug_NN/`'s report + (if one exists) `patch.diff`, before
anything is filed upstream. The agent's only job is to try to reject,
downgrade, or wontfix the finding using the target's own code — see
`reproof/prompts/maintainer_review_prompt.py` for the four axes it attacks
(misunderstanding / inflated severity / weak reachability / broken fix).
Verdict lands in `reports/bug_NN/predisclose.json`. This is the first
structural home for the pre-disclosure checklist that used to live only in
LESSONS.md prose — re-verifying against the target's current default branch,
checking the target's own issue tracker for prior art, and computing a
severity baseline against real-world data are documented disciplines (L15/
L23/L33/L34) that don't have code here yet; they belong in this stage when
they do, not a parallel one.

## Watching a run

Transcripts and results are written to disk the moment they're produced,
so you can watch a run without stopping it:

- Each find and grade agent's transcript lands under `results/<target>/<ts>/run_NNN/`
  as the agent works. Transcripts persist on failed or killed runs.
- `found_bugs.jsonl` lists every crash submitted so far.
- Each run's `result.json` is written as soon as the grader finishes reviewing
  it, so counting `run_*/result.json` files tells you how many runs are finished.
- Filtering a transcript for `"type":"tool_use"` shows each command the agent ran.
  This is the quickest way to see what it's actually doing when you're iterating
  on prompts.
- With `--stream`, the `reports/` directory also fills in during the run. Judge
  and report transcripts are saved there, and `ls reports/bug_*/report.json` shows
  the reports written so far.

## CLI reference

```bash
bin/reproof-sandboxed recon  <target> --model <m>             # propose focus_areas (prints YAML to stdout)
bin/reproof-sandboxed run    <target> --model <m>             # do a single find agent + grade agent run
bin/reproof-sandboxed run    <target> --runs N --parallel     # run N find agents at once (spread by focus area)
bin/reproof-sandboxed run    <target> --stream                # run judge + report on each crash as its grade lands (recommended)
bin/reproof-sandboxed run    <target> --auto-focus            # run recon first and use its partition
bin/reproof-sandboxed run    <target> --find-only             # skip grading (useful for prompt iteration)
bin/reproof-sandboxed run    <target> --accept-dos            # count DoS-class crashes as valid finds
bin/reproof-sandboxed run    <target> --novelty               # reports check upstream git history to determine fix status
bin/reproof-sandboxed run    <target> --max-turns N           # per-agent turn budget
bin/reproof-sandboxed run    <target> --engagement-context F  # file with your org's authorization scope, threaded into every agent prompt
bin/reproof-sandboxed run    <target> --resume <results-dir>  # continue a killed batch, skipping finished runs
bin/reproof-sandboxed report results/<target>/<ts>/           # batch-mode reports, for runs done without --stream
bin/reproof-sandboxed report results/<target>/<ts>/ --fresh   # redo reports, ignoring existing report.json checkpoints
bin/reproof-sandboxed patch  results/<target>/<ts>/           # propose and verify a fix per unique bug
bin/reproof-sandboxed predisclose results/<target>/<ts>/      # skeptical-maintainer gate before filing
bin/reproof-sandboxed dedup  results/<target>/<ts>/           # group crashes by signature
```

> This reference includes the most commonly used flags. For the full set of
> flags, use `--help` on any subcommand.

## Design principles

In short, the essential steps of an effective vulnerability-finding pipeline:

1. Build the target.
2. Spin up N agents to search for vulnerabilities.
3. Grade the findings.

The loop is broken into modular steps, each of which saves its progress durably;
over time it grew more — de-duplication, the find→fuzz bridge, the scorecard,
report writing, and so on. A Docker container image is a great way to store a
reusable build artifact and provides an environment in
which exploits can be attempted safely. Vulnerability-finding agents should
store their results in a standard format which can be verified by graders.
These agents can decide their own exploration path from the beginning, or you
can seed them with "focus areas" via a recon step. Graders should be able to
run over any findings multiple times as they're calibrated with human
feedback.

Aside from modularity, a critical component is an effective grader. The
grader must run as a separate agent with access to a clean sandbox in which
it can run any proofs of concept. It should be framed as an adversary
actively trying to disprove findings, which are guilty until proven innocent.
Proof-of-concept exploits that produce a witness are best, but not always
possible. The grader should also be tailored for the vulnerability types
under inspection: some bugs are proven by PoC, others by logical argument.
Skills or a lightweight routing layer to different verifiers may be good
approaches when multiple classes are in scope.

## Resume-on-error

Hitting a rate limit or other error mid-run does not lose work. Each agent 
is one long-lived `kimi -p` session. A 429 or 5xx is first retried with
backoff inside the Kimi CLI itself. If those retries exhaust, the pipeline
runs its own retry loop with backoff. These retries relaunch the agent with
the Kimi CLI's `--session <session_id>` resume, which restores the full
conversation so the agent can continue from the failed turn (ADR-001 R2 —
note `--agent-file` is first-attempt-only; resumed agents keep their
original system prompt). This repeats up to 20 times
before the run is marked as failed. Even then, you can restart the run 
using `bin/reproof-sandboxed run <target> --resume <results-dir>`.

Carry over similar logic if you build your own pipeline.

## Usage marker

The upstream Anthropic usage marker (`anthropic-cyber-runbook` header +
`cyber-runbook/` User-Agent token) was dropped in this port: on the Kimi
backend, agent API requests carry exactly the env auth
(`KIMI_MODEL_NAME` / `KIMI_MODEL_API_KEY` / `KIMI_MODEL_BASE_URL`) and
nothing else — no injected headers, no telemetry marker. Auth is env-only;
nothing is read from or written to credential files (ADR-001 R1).
