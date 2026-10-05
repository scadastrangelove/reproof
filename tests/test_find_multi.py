# Copyright 2026 Sergey Gordeychik
# SPDX-License-Identifier: Apache-2.0
"""W64 multi-candidate extraction: one find run may submit several candidates.

`extract_crashes` must collect EVERY complete `<poc_path>` submission across
the run's assistant messages — not just the last one (the pre-W64 ceiling that
capped recall at one candidate per run). docker_ops.read_file is monkeypatched;
no Docker, no network.
"""
from __future__ import annotations

from reproof import find as find_mod
from reproof.agent_kimi import AgentResult


def _msg(text: str) -> dict:
    return {"role": "assistant", "content": text}


def _submission(path: str, crash_type: str = "heap-buffer-overflow",
                dup: str | None = "distinct: new root cause") -> str:
    parts = [
        f"<poc_path>{path}</poc_path>",
        f"<reproduction_command>/work/entry {path}</reproduction_command>",
        f"<crash_type>{crash_type}</crash_type>",
        "<crash_output>SUMMARY: boom</crash_output>",
        "<exit_code>134</exit_code>",
    ]
    if dup is not None:
        parts.append(f"<dup_check>{dup}</dup_check>")
    return "\n".join(parts)


def _patch_reads(monkeypatch, files: dict[str, bytes]) -> None:
    monkeypatch.setattr(find_mod.docker_ops, "read_file",
                        lambda container, path: files.get(path, b""))


def test_multiple_submissions_all_collected(monkeypatch):
    _patch_reads(monkeypatch, {"/tmp/a.bin": b"AAA", "/tmp/b.bin": b"BBB"})
    r = AgentResult(messages=[
        _msg("hunting..."),
        _msg(_submission("/tmp/a.bin", crash_type="heap-buffer-overflow")),
        {"role": "tool", "content": "ok"},
        _msg("kept hunting and found another"),
        _msg(_submission("/tmp/b.bin", crash_type="stack-buffer-overflow")),
    ])
    crashes = find_mod.extract_crashes(r, container="c")
    assert [c.poc_path for c in crashes] == ["/tmp/a.bin", "/tmp/b.bin"]
    assert crashes[0].poc_bytes == b"AAA"
    assert crashes[1].crash_type == "stack-buffer-overflow"
    assert crashes[1].exit_code == 134


def test_resubmission_last_block_wins(monkeypatch):
    _patch_reads(monkeypatch, {"/tmp/a.bin": b"FINAL"})
    r = AgentResult(messages=[
        _msg(_submission("/tmp/a.bin", crash_type="unknown")),
        _msg(_submission("/tmp/a.bin", crash_type="use-after-free")),
    ])
    crashes = find_mod.extract_crashes(r, container="c")
    assert len(crashes) == 1
    assert crashes[0].crash_type == "use-after-free"
    assert crashes[0].poc_bytes == b"FINAL"


def test_incomplete_and_unwritten_submissions_dropped(monkeypatch):
    _patch_reads(monkeypatch, {"/tmp/real.bin": b"x"})
    r = AgentResult(messages=[
        # no reproduction_command → incomplete
        _msg("<poc_path>/tmp/nocmd.bin</poc_path>"),
        # narrated but never written → empty bytes
        _msg(_submission("/tmp/ghost.bin")),
        # prose mention without a closing tag → not a submission
        _msg("the bug is at <poc_path>: /tmp/prose.bin as shown"),
        _msg(_submission("/tmp/real.bin")),
    ])
    crashes = find_mod.extract_crashes(r, container="c")
    assert [c.poc_path for c in crashes] == ["/tmp/real.bin"]


def test_missing_dup_check_survives_extraction(monkeypatch):
    """The dup_check gate lives in the CLI (per-candidate), not in extraction —
    a submission without it must still surface so the run can report which
    candidate was rejected."""
    _patch_reads(monkeypatch, {"/tmp/a.bin": b"x"})
    r = AgentResult(messages=[_msg(_submission("/tmp/a.bin", dup=None))])
    crashes = find_mod.extract_crashes(r, container="c")
    assert len(crashes) == 1
    assert crashes[0].dup_check is None


def test_packed_submissions_in_one_message(monkeypatch):
    """Both kimi models pack several complete submissions into ONE assistant
    message when told to keep hunting (2026-10-05 campaign). Every packed
    block must be extracted, not just the first."""
    _patch_reads(monkeypatch, {"/tmp/a.bin": b"AAA", "/tmp/b.bin": b"BBB", "/tmp/c.bin": b"CCC"})
    packed = "\n\n".join([
        _submission("/tmp/a.bin", crash_type="heap-buffer-overflow"),
        _submission("/tmp/b.bin", crash_type="stack-buffer-overflow"),
        _submission("/tmp/c.bin", crash_type="use-after-free"),
    ])
    r = AgentResult(messages=[_msg(packed)])
    crashes = find_mod.extract_crashes(r, container="c")
    assert [c.poc_path for c in crashes] == ["/tmp/a.bin", "/tmp/b.bin", "/tmp/c.bin"]
    assert crashes[2].crash_type == "use-after-free"
    assert crashes[1].dup_check is not None


def test_no_submissions_returns_empty(monkeypatch):
    _patch_reads(monkeypatch, {})
    r = AgentResult(messages=[_msg("found nothing solid")])
    assert find_mod.extract_crashes(r, container="c") == []
