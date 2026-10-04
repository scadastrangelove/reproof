#!/usr/bin/env python3
"""Evidence aggregator — turn pass/fail controls into replay-<id>.evidence.json.

One discipline for every ai-agent target: the run script executes attacks and
controls, records each control as "pass"/"fail", and this aggregator emits one
evidence file per finding. Verdict rule: `dynamically_confirmed` iff EVERY
control is "pass"; otherwise `not_confirmed`. A finding whose sub-claim was
refuted on purpose should model that sub-claim as its own finding/control set —
do not overload the verdict string (a "not_confirmed" that really means
"core confirmed, sub-claim refuted" will be misread by tooling).

CLI:
  evidence.py --spec controls.json --evidence-dir /work/evidence \
              --target <name> --commit <pin> --method "trusted replay ..."

Spec JSON:
  {
    "findings": {
      "<finding-id>": {
        "controls": {"attack_run1_marker": "pass", "negative_control": "fail", ...},
        "logs": ["run1.log", "control1.log"]          # tails captured into evidence
      }
    }
  }

Control values may be literal "pass"/"fail" or "${ENV_VAR}" references resolved
from the environment (so a bash run script can export its results).
"""
import argparse, json, os, re, time


def logtail(path, n=4000):
    try:
        with open(path, 'rb') as f:
            return f.read()[-n:].decode('utf-8', 'replace')
    except FileNotFoundError:
        return ''


def resolve(value):
    if isinstance(value, str):
        m = re.fullmatch(r'\$\{(\w+)\}', value)
        if m:
            return os.environ.get(m.group(1), '')
    return value


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--spec', required=True)
    ap.add_argument('--evidence-dir', default='/work/evidence')
    ap.add_argument('--target', required=True)
    ap.add_argument('--commit', required=True)
    ap.add_argument('--method', default='trusted replay in lab container')
    args = ap.parse_args(argv)

    spec = json.load(open(args.spec))
    rc = 0
    for fid, entry in spec.get('findings', {}).items():
        controls = {k: resolve(v) for k, v in entry.get('controls', {}).items()}
        ok = bool(controls) and all(v == 'pass' for v in controls.values())
        out = {
            'target': args.target,
            'commit': args.commit,
            'date': time.strftime('%Y-%m-%d'),
            'method': args.method,
            'verdict': 'dynamically_confirmed' if ok else 'not_confirmed',
            'controls': controls,
            'log_tails': {p: logtail(os.path.join(args.evidence_dir, p))
                          for p in entry.get('logs', [])},
        }
        path = os.path.join(args.evidence_dir, f'replay-{fid}.evidence.json')
        with open(path, 'w') as f:
            json.dump(out, f, indent=1)
        print(fid, '->', out['verdict'], controls)
        if not ok:
            rc = 1
    return rc


if __name__ == '__main__':
    raise SystemExit(main())
