#!/usr/bin/env python3
"""Generic PTY driver — run an interactive agent CLI under a real PTY.

Some agent code paths only fire on the interactive path (e.g. session-start
hooks inside an interactive() routine, before the prompt loop); a headless
driver never reaches them. This adapter allocates its own pty via
pty.openpty() — no `docker -t` needed — starts the agent, waits for a
readiness pattern, optionally sends a clean-exit command, and reaps.

Usage: pty_driver.py <cwd> <logfile>
Env:
  PTY_CMD            (required) command line, e.g. "myagent session"
  PTY_ENV_FILE       JSON file with extra environment for the child
  PTY_READY_PATTERN  substring marking "session is up" (optional)
  PTY_READY_GRACE_S  send the exit string after this many seconds even if the
                     pattern never appeared (default 6)
  PTY_SEND           string written to the pty once ready (default "/exit\\n")
  PTY_CTRL_D_AFTER_S Ctrl-D fallback this many seconds after start (default 12)
  PTY_DEADLINE_S     hard deadline (default 45)

The raw session transcript goes to <logfile> with a trailing "[pty] exit=N".
Markers/assertions belong to the payload the session triggers, not to this
driver — check them in the caller.
"""
import json, os, pty, select, shlex, signal, subprocess, sys, time

cwd = sys.argv[1] if len(sys.argv) > 1 else '/work'
logfile = sys.argv[2] if len(sys.argv) > 2 else '/work/evidence/pty_driver.log'

CMD = os.environ.get('PTY_CMD')
if not CMD:
    sys.exit('PTY_CMD is required (e.g. PTY_CMD="myagent session")')
READY = os.environ.get('PTY_READY_PATTERN', '').encode()
GRACE = float(os.environ.get('PTY_READY_GRACE_S', '6'))
# env-passed strings carry literal "\n" — decode the common escapes
SEND = os.environ.get('PTY_SEND', '/exit\n').replace('\\n', '\n').replace('\\t', '\t').encode()
CTRL_D_AFTER = float(os.environ.get('PTY_CTRL_D_AFTER_S', '12'))
DEADLINE = float(os.environ.get('PTY_DEADLINE_S', '45'))

env = dict(os.environ)
if os.environ.get('PTY_ENV_FILE'):
    env.update(json.load(open(os.environ['PTY_ENV_FILE'])))
env.setdefault('TERM', 'xterm')

master, slave = pty.openpty()
p = subprocess.Popen(
    shlex.split(CMD),
    stdin=slave, stdout=slave, stderr=slave,
    cwd=cwd, env=env, start_new_session=True,
)
os.close(slave)

buf = b""
start = time.time()
deadline = start + DEADLINE
sent_exit = False
while time.time() < deadline:
    try:
        r, _, _ = select.select([master], [], [], 1.0)
    except (OSError, ValueError):
        break
    if master in r:
        try:
            data = os.read(master, 4096)
        except OSError:
            break
        if not data:
            break
        buf += data
    # Once the session is up (or after a short grace), ask it to exit cleanly.
    if not sent_exit and ((READY and READY in buf) or time.time() - start > GRACE):
        try:
            os.write(master, SEND)
        except OSError:
            pass
        sent_exit = True
    elif sent_exit and time.time() - start > CTRL_D_AFTER:
        try:
            os.write(master, b"\x04")  # Ctrl-D fallback
        except OSError:
            pass
    if p.poll() is not None:
        break

try:
    p.terminate()
    p.wait(timeout=5)
except Exception:
    try:
        os.killpg(p.pid, signal.SIGKILL)  # child is a session leader: take the group
    except Exception:
        try:
            p.kill()
        except Exception:
            pass
    try:
        p.wait(timeout=5)
    except Exception:
        pass

with open(logfile, "wb") as f:
    f.write(buf)
    f.write(f"\n[pty] exit={p.returncode}\n".encode())
