# SPDX-License-Identifier: Apache-2.0
"""Reproof CLI — bootstrap placeholder.

The real subcommands (run / recon / grade / report / patch / scorecard)
arrive in Phase 2 with the harness port. For now this exists so the
`reproof` entry point resolves.
"""
from __future__ import annotations


def main() -> None:
    print("reproof 0.0.1 — bootstrap. See docs/adr/ADR-001-agent-backend-kimi.md")


if __name__ == "__main__":
    main()
