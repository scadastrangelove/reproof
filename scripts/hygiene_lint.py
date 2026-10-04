#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fail-closed hygiene linter for the output path (L69/W55).

Blocks committing/packaging artifacts that leak operator identifiers or
credentials. Scrubbing by review is probabilistic; the artifacts that leak are
the generated ones (logs, evidence, run metadata) that nobody re-reads. This
gate is cheap, deterministic, and runs BEFORE the history-rewrite moment.

Rules (per text file, per line):
  - credential-shaped strings (private keys, tokens, api keys, passwords)
  - user@IP identifiers (operator login of an execution host)
  - routable public IPs (loopback/unspecified/RFC1918/doc-ranges are benign)
  - local absolute paths (/Users/<name>, /home/<name> outside the sandbox)

Usage:
    python scripts/hygiene_lint.py [PATH ...]   # default: git ls-files
    python scripts/hygiene_lint.py --staged     # pre-commit mode

Exit 0 = clean, 1 = leaks found (printed as path:line: rule). Allowlist:
.hygiene-allow at the repo root, one Python regex per line (matched per line).
"""
from __future__ import annotations

import ipaddress
import re
import subprocess
import sys
from pathlib import Path

MAX_FILE_BYTES = 2 * 1024 * 1024

_CREDENTIAL = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"
    r"|ghp_[A-Za-z0-9]{30,}"
    r"|github_pat_[A-Za-z0-9_]{30,}"
    r"|AKIA[0-9A-Z]{16}"
    r"|xox[baprs]-[A-Za-z0-9-]{10,}"
    r"|eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}"  # JWT header.payload
    r"|(?:api[_-]?key|secret|token|password|passwd)[\"'\s]*[:=][\"'\s]*[A-Za-z0-9_./+-]{16,}",
    re.IGNORECASE)
_USER_AT_IP = re.compile(r"\b[\w.-]+@(?:\d{1,3}\.){3}\d{1,3}\b")
_ANY_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_LOCAL_PATH = re.compile(r"/Users/[^/\s\"']+|/home/([^/\s\"']+)")

_BENIGN_IPS = {"0.0.0.0", "255.255.255.255"}
_BENIGN_HOME_USERS = {"oai"}  # sandbox convention, not an operator machine


def _benign_ip(raw: str) -> bool:
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError:
        return True  # not an IP (e.g. version string 1.2.3.400) — not our rule
    return (raw in _BENIGN_IPS or ip.is_loopback or ip.is_unspecified
            or ip.is_private or ip.is_link_local or ip.is_multicast
            or ip.is_reserved)


def scan_line(line: str) -> list[str]:
    """Rules that fire on one line. Pure function — unit-testable."""
    hits = []
    if _CREDENTIAL.search(line):
        hits.append("credential-shaped string")
    if _USER_AT_IP.search(line):
        hits.append("user@IP identifier")
    for raw in _ANY_IP.findall(line):
        if not _benign_ip(raw):
            hits.append(f"routable IP {raw}")
            break
    for match in _LOCAL_PATH.finditer(line):
        if match.group(0).startswith("/Users/"):
            hits.append("local absolute path (/Users/...)")
            break
        if match.group(1) and match.group(1) not in _BENIGN_HOME_USERS:
            hits.append(f"local absolute path (/home/{match.group(1)})")
            break
    return hits


def scan_text(text: str, allow: list[re.Pattern] | None = None) -> dict[int, list[str]]:
    """line number (1-based) -> rules; allowlisted lines are skipped."""
    findings = {}
    for lineno, line in enumerate(text.splitlines(), 1):
        if allow and any(a.search(line) for a in allow):
            continue
        hits = scan_line(line)
        if hits:
            findings[lineno] = hits
    return findings


def _load_allow(repo: Path) -> list[re.Pattern]:
    allow_file = repo / ".hygiene-allow"
    if not allow_file.exists():
        return []
    return [re.compile(line) for line in allow_file.read_text().splitlines()
            if line.strip() and not line.startswith("#")]


def _git_files(repo: Path, staged: bool) -> list[Path]:
    argv = (["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"] if staged
            else ["git", "ls-files"])
    out = subprocess.run(argv, cwd=repo, capture_output=True, text=True)
    if out.returncode:
        raise SystemExit(f"hygiene-lint: {' '.join(argv)} failed: {out.stderr.strip()}")
    return [repo / line for line in out.stdout.splitlines() if line.strip()]


def main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    staged = "--staged" in args
    if staged:
        args.remove("--staged")
    repo = Path(__file__).resolve().parents[1]
    paths = [Path(a) for a in args] if args else _git_files(repo, staged)
    allow = _load_allow(repo)
    leaks = 0
    for path in paths:
        if path.name == ".hygiene-allow":
            continue  # the allowlist itself is meta, not content
        try:
            raw = path.read_bytes()
        except OSError:
            continue
        if len(raw) > MAX_FILE_BYTES or b"\x00" in raw:
            continue  # too large or binary — not a text artifact
        findings = scan_text(raw.decode("utf-8", errors="replace"), allow)
        for lineno, rules in findings.items():
            leaks += 1
            print(f"{path}:{lineno}: {', '.join(rules)}")
    if leaks:
        print(f"hygiene-lint: {leaks} leak(s) — commit/package BLOCKED (L69). "
              "Move host config to untracked files; allowlist only via .hygiene-allow.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
