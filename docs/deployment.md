# Deploying on a Linux host

The pipeline's live path needs Linux + Docker (gVisor is Linux-only). This
is the runbook used for the first live deployment (host `Tamm`, Ubuntu
24.04, 12c/62G, Docker 29) — the canary run found 3/3 planted bugs
end-to-end on the Kimi backend.

## Host requirements

- Linux x86_64/aarch64, Docker with `sudo`-less `sudo -n true` for setup
  (gVisor install touches `/etc/docker/daemon.json`)
- Python 3.12+, git, ~10 GB free disk for the canary + rust-canary images
  (all 28 targets need ~40–60 GB — use `SETUP_TARGETS` to build a subset)
- Outbound HTTPS to your model endpoint (default `agent-gw.kimi.com:443`)

## Layout

```bash
# transfer (repo has no public remote yet — git bundle preserves history)
git bundle create /tmp/reproof.bundle --all            # on your workstation
scp /tmp/reproof.bundle user@host:~/
ssh user@host
git clone ~/reproof.bundle ~/reproof && cd ~/reproof
python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'
.venv/bin/python -m pytest tests/ -q                    # expect: 395 passed, 4 skipped

# auth (chmod 600 — the only place the key lives on the host)
cat > ~/.reproof-env <<'EOF'
export KIMI_MODEL_NAME=kimi-for-coding
export KIMI_MODEL_API_KEY=sk-...
export KIMI_MODEL_BASE_URL=https://agent-gw.kimi.com/coding/v1
EOF
chmod 600 ~/.reproof-env

# sandbox: gVisor + egress proxy + images (subset on disk-tight hosts)
source ~/.reproof-env
SETUP_TARGETS="canary rust-canary" ./scripts/setup_sandbox.sh

# first live run (small wave; canary ≈ 6–10 min with 3 parallel agents)
tmux new-session -d -s reproof-run \
  "cd ~/reproof && source ~/.reproof-env && \
   bin/reproof-sandboxed run canary --model kimi-for-coding \
     --runs 3 --parallel --stream --max-turns 100 > ~/reproof-run.log 2>&1"
```

Updating later: `git fetch ~/reproof.bundle main && git reset --hard FETCH_HEAD
&& .venv/bin/pip install -e '.[dev]'`.

## First-run verification checklist

1. `setup_sandbox.sh` ends with `EXIT=0` and four `ok` lines: gVisor active
   (guest kernel ≠ host), kimi CLI runs under gVisor, egress allowlist
   enforced, host fs unreachable.
2. `tail ~/reproof-run.log` — find agents start with focus areas; progress
   lines `[find:N] → Bash: ...` mean the in-container CLI is alive.
3. `cat results/canary/<ts>/found_bugs.jsonl` — ASan excerpts per crash.
4. `cat results/canary/<ts>/reports/manifest.jsonl` — one NEW per distinct
   bug (canary has exactly 3 planted).
5. `results/canary/<ts>/reports/bug_NN/report.json` — `status:
   report_submitted`, `verdict.severity_rating` + `rubric_score` set.
6. Transcripts (`run_*/find_transcript.jsonl`) contain no key material —
   they are scrubbed through `reproof/redact.py`; the API key never lands
   on disk (containers get it via `api_key_env` in a generated config).

## Pitfalls found on the first live deployment

Both are fixed in-tree; noted here for anyone porting the setup elsewhere.

- **Node 20 vs 22 in the agent base image.** Debian's apt `nodejs` is 20.x;
  kimi-code 2.1.x imports `createZstdDecompress` from `node:zlib` (Node
  ≥22.15) and crashes at startup. The base image installs Node 22 via
  NodeSource; `agent_image.BASE_LAYER_REV` busts stale cached bases.
- **`--model` needs a real alias.** `KIMI_MODEL_*` env synthesizes an
  in-memory alias (`__kimi_env_model__`) that `-m/--model` cannot see —
  `kimi -p ... --model kimi-for-coding` fails with "Model not configured
  in config.toml". `run_agent` therefore writes the container's
  `config.toml` per run: `[providers.reproof]` + `[models.<alias>]` with
  `api_key_env = "KIMI_MODEL_API_KEY"` (key stays in env), plus
  `loop_control.max_steps_per_turn` from the run's `--max-turns`.
