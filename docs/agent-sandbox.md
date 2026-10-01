# Agent sandbox

> This document describes the sandboxing implementation details for
> this reference harness. For general sandboxing recommendations and best
> practices, see the [blog post's sandboxing section](https://claude.com/blog/using-llms-to-secure-source-code).

The reference pipeline consists of both deterministic orchestration code and
non-deterministic agents. The orchestration code (the `reproof` process
itself) is trusted and never runs target code or model-chosen commands. As such,
it can run unsandboxed. The agents run as `kimi -p` processes and can execute 
arbitrary commands. For that reason, the agent CLI processes run *inside* a
gVisor container alongside the target binary and source.

## What's isolated

| Surface              | Without sandbox       | With sandbox                                           |
| -------------------- | --------------------- | ------------------------------------------------------ |
| Agent `Read`/`Write` | host filesystem       | container filesystem only                              |
| Agent `Bash`         | host shell            | container shell only (gVisor netstack/kernel)          |
| Network egress       | whatever the host has | the configured allowlist (derived from `KIMI_MODEL_BASE_URL`) |
| Host coupling        | full                  | `docker exec cat` PoC out, `-v found_bugs.jsonl:ro` in |

gVisor provides the isolation between the agent and your machine. The agent's
`Read`, `Write`, and `Bash` tools run inside the container, and that container
runs on gVisor's own kernel rather than your host's. So, if the agent (or the
target code it's running) does something unexpected, any effects stay inside
the container.

The container network setup provides the isolation between the agent and the internet.
Agent containers are attached to a Docker network (`reproof-internal`) that has no
connection to the internet. The egress route is through a small proxy container
on the same network, which only forwards traffic to the model API.

## One-time setup

Run this once per machine. It needs `sudo` (to install a new Docker runtime
and edit `/etc/docker/daemon.json`) and is safe to re-run.

```bash
./scripts/setup_sandbox.sh
```

This script sets up:
- gVisor: Downloads `runsc` (the gVisor runtime) and registers it with
Docker, so containers can run on gVisor's kernel instead of your host's.
- The locked-down network: Creates the `reproof-internal` Docker network,
which has no route to the internet, and starts the allowlist proxy to
support model API traffic.
- Images: Builds each target's Docker image, plus a copy of each with
the Kimi Code CLI installed (for running the agent).
- Checks: Runs the verification commands shown below.

gVisor only runs on Linux. On macOS or Windows, run the pipeline
inside a Linux VM or use `--dangerously-no-sandbox` (see 
[Opting out](#opting-out) for details on what you lose).

The proxy allowlist is derived from `KIMI_MODEL_BASE_URL` by default, so
API traffic to your configured endpoint (managed service, Moonshot
platform, or an OpenAI-compatible gateway) is allowed and everything else
is blocked. To override, set `REPROOF_EGRESS_ALLOW=host-1:443,host-2:443`
(as a comma separated list) before running the script. If you need to
change this allowlist later, re-run the script to create the proxy with
the new value.

### Model endpoint and auth

Auth is env-only (see `reproof/auth.py` and ADR-001). Before running
`setup_sandbox.sh` and any pipeline run, set:

- `KIMI_MODEL_NAME` — the model alias (e.g. `kimi-for-coding`)
- `KIMI_MODEL_API_KEY` — the API key for your endpoint
- `KIMI_MODEL_BASE_URL` — the base URL of an OpenAI-compatible endpoint,
  **without** the `/v1` suffix semantics handled by your deployment;
  `reproof.auth` derives the egress host:port from this URL

These three are the only credentials the agent containers ever see — the
sandbox never mounts credential files, and nothing is read from disk. For
long batch runs, use a key whose TTL outlives the run: the key is visible
to the agent process inside the sandbox.

`REPROOF_EGRESS_ALLOW` accepts wildcard entries (`*.domain.tld:port`) for
explicit overrides only; auto-derived defaults never use wildcards.

The script downloads a pinned `runsc` release. Set `RUNSC_RELEASE=<yyyymmdd>`
to use a different one.

Some Docker setups (rootless Docker, or Docker nested inside another
container) don't let runsc manage cgroups. The script detects this during
verification and re-registers runsc with `--ignore-cgroups`. Isolation is
unaffected — gVisor's kernel, the network allowlist, and filesystem
confinement all still apply; the only loss is that per-container `--memory`
caps aren't enforced.

## Run

```bash
export KIMI_MODEL_NAME=... KIMI_MODEL_API_KEY=... KIMI_MODEL_BASE_URL=...   # see above
bin/reproof-sandboxed run rust-canary --model "$KIMI_MODEL_NAME" --runs 3 --parallel --stream
```

`bin/reproof-sandboxed` is a small wrapper around the normal `reproof`
command. It checks that gVisor is registered and the proxy is running. If 
either is missing, it stops and tells you to run setup, rather than falling
back to run unsandboxed. If both are running correctly, it launches the 
pipeline with the isolation described above.

## Verifying isolation yourself

```bash
# 1. Is gVisor actually in use? Confirm the two lines print different kernel versions
docker run --rm --runtime=runsc reproof-rust-canary-latest-agent:2.1.1 uname -r
uname -r

# 2. Is the host filesystem unreachable? Confirm the cat fails with "No such file or directory"
echo host > /tmp/probe-$$; \
  docker run --rm --runtime=runsc reproof-rust-canary-latest-agent:2.1.1 cat /tmp/probe-$$

# 3. Can the model API be reached? Confirm any HTTP status code is printed
docker run --rm --runtime=runsc --network=reproof-internal -e HTTPS_PROXY=http://<proxy_ip>:3128 \
  reproof-rust-canary-latest-agent:2.1.1 sh -c 'curl -sI https://agent-gw.kimi.com/ -o /dev/null -w "%{http_code}\n"'

# 4. Can another host be reached? Confirm connection is refused
docker run --rm --runtime=runsc --network=reproof-internal -e HTTPS_PROXY=http://<proxy_ip>:3128 \
  reproof-rust-canary-latest-agent:2.1.1 sh -c 'curl -sI https://example.com/ -o /dev/null -w "%{http_code}\n"'
```

## Opting out

`--dangerously-no-sandbox` runs the pipeline without the sandbox. The agents
still run inside Docker containers, but:

- Containers run on your host's kernel, so any unexpected agent actions or
malicious target code have a much shorter path to the host.
- Containers get normal Docker networking with full internet access.
- The agent's credentials are in the same container as the target it's compiling
and crashing.

Use of this flag is not recommended and should be done with caution, for
development, on a throwaway VM.