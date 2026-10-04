#!/usr/bin/env python3
"""Boot discipline for lab victims — spawn, wait-ready, settle.

Real targets have boot quirks that silently invalidate replays if ignored:
migrations on first boot, settings read caches, lazy plugin discovery. This
helper makes the pattern explicit: spawn the process with output captured to a
log, wait for a readiness signal (HTTP health endpoint, TCP port, or marker
file) inside a budget, then optionally settle a fixed extra delay (e.g. to
outlast a known read cache).

CLI:
  boot.py --cmd "node server.mjs" [--env-file env.json] [--cwd DIR]
          --log /work/state/boot.log
          [--health-url http://127.0.0.1:PORT/health | --port PORT | --ready-file PATH]
          [--budget-ms 240000] [--poll-ms 2000] [--settle-ms 0]

Prints ONE JSON line: {"ok": bool, "pid": int, "waited_ms": int, "reason": str}.
Also importable: spawn_logged(), wait_ready(), settle().
"""
import argparse, json, os, shlex, socket, subprocess, sys, time
import urllib.request


def spawn_logged(cmd, env_extra=None, cwd=None, log_path='/work/state/boot.log'):
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    fd = os.open(log_path, os.O_CREAT | os.O_APPEND | os.O_WRONLY)
    env = dict(os.environ)
    if env_extra:
        env.update(env_extra)
    child = subprocess.Popen(shlex.split(cmd), cwd=cwd, env=env,
                             stdin=subprocess.DEVNULL, stdout=fd, stderr=fd,
                             start_new_session=True)
    return child


def _http_ok(url):
    try:
        with urllib.request.urlopen(url, timeout=3) as res:
            return 200 <= res.status < 400
    except Exception:
        return False


def _port_ok(port):
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=1):
            return True
    except OSError:
        return False


def wait_ready(health_url=None, port=None, ready_file=None, budget_ms=240000, poll_ms=2000):
    """Wait for the first configured readiness signal. Returns (ok, waited_ms, reason)."""
    start = time.time()
    deadline = start + budget_ms / 1000
    while time.time() < deadline:
        if health_url and _http_ok(health_url):
            return True, int((time.time() - start) * 1000), 'health-url'
        if port and _port_ok(port):
            return True, int((time.time() - start) * 1000), 'port'
        if ready_file and os.path.exists(ready_file):
            return True, int((time.time() - start) * 1000), 'ready-file'
        time.sleep(poll_ms / 1000)
    return False, int((time.time() - start) * 1000), 'budget-exhausted'


def settle(ms):
    """Outlast known caches/quiet periods AFTER readiness, before attacking."""
    if ms > 0:
        time.sleep(ms / 1000)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--cmd', required=True)
    ap.add_argument('--env-file')
    ap.add_argument('--cwd')
    ap.add_argument('--log', default='/work/state/boot.log')
    ap.add_argument('--health-url')
    ap.add_argument('--port', type=int)
    ap.add_argument('--ready-file')
    ap.add_argument('--budget-ms', type=int, default=240000)
    ap.add_argument('--poll-ms', type=int, default=2000)
    ap.add_argument('--settle-ms', type=int, default=0)
    args = ap.parse_args(argv)

    env_extra = json.load(open(args.env_file)) if args.env_file else None
    child = spawn_logged(args.cmd, env_extra, args.cwd, args.log)
    ok, waited, reason = wait_ready(args.health_url, args.port, args.ready_file,
                                    args.budget_ms, args.poll_ms)
    if ok:
        settle(args.settle_ms)
    print(json.dumps({'ok': ok, 'pid': child.pid, 'waited_ms': waited, 'reason': reason}))
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
