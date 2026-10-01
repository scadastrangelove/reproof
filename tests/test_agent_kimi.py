# SPDX-License-Identifier: Apache-2.0
"""Adapter contract tests, driven by Phase-0 live captures (ADR-001).

Fixtures are real `kimi -p --output-format stream-json` streams recorded
against CLI 2.1.1. If a future CLI version changes the schema, these tests
fail before the pipeline does.
"""
from __future__ import annotations

import json
from pathlib import Path

from reproof.agent_kimi import (AgentResult, iter_tool_calls,
                                normalize_message_text, parse_xml_tag)

FIXTURES = Path(__file__).parent / "fixtures"


def _load(name: str) -> list[dict]:
    return [json.loads(l) for l in
            (FIXTURES / name).read_text().splitlines() if l.strip()]


def test_tooluse_stream_shape():
    events = _load("kimi_streamjson_tooluse.jsonl")
    assert events[0]["type"] == "system.version"
    assert events[-1]["type"] == "session.resume_hint"
    assert events[-1]["session_id"].startswith("session_")


def test_normalizer_extracts_assistant_text_only():
    events = _load("kimi_streamjson_tooluse.jsonl")
    texts = [t for e in events if (t := normalize_message_text(e))]
    assert texts == ["DONE"]


def test_tool_call_extraction_with_key_arg():
    events = _load("kimi_streamjson_tooluse.jsonl")
    calls = [c for e in events for c in iter_tool_calls(e)]
    assert calls == [("Bash", "echo hello-reproof && echo CONFIRMED > /tmp/reproof_probe.txt")]


def test_parallel_tool_batch():
    events = _load("kimi_streamjson_maxsteps.jsonl")
    calls = [c for e in events for c in iter_tool_calls(e)]
    assert len(calls) == 5 and all(n == "Write" for n, _ in calls)


def test_resume_stream_contains_only_new_events():
    events = _load("kimi_streamjson_resume.jsonl")
    assert [e["role"] for e in events] == ["meta", "assistant", "meta"]
    assert normalize_message_text(events[1]) == "CONFIRMED"


def test_agent_file_disables_tools():
    events = _load("kimi_streamjson_agentfile.jsonl")
    assert not [c for e in events for c in iter_tool_calls(e)]
    assert normalize_message_text(events[1]) == "REPROOF-ORACLE"


def test_find_tagged_message_scans_backwards():
    r = AgentResult(messages=[
        {"role": "assistant", "content": "<poc_path>/tmp/x</poc_path>"},
        {"role": "assistant", "content": "Done!"},
    ])
    assert parse_xml_tag(r.find_tagged_message("poc_path"), "poc_path") == "/tmp/x"


# ── argv / agent-file construction (ADR-001 decisions) ───────────────────────

def test_agent_file_on_first_attempt_only(tmp_path):
    from reproof.agent_kimi import build_argv
    first = build_argv("c", "p", model="m", agent_file="/work/find.md",
                       session_id=None)
    resumed = build_argv("c", "p", model="m", agent_file="/work/find.md",
                         session_id="session_x")
    assert "--agent-file" in first and "--session" not in first
    assert "--session" in resumed and "--agent-file" not in resumed


def test_write_agent_file_tools_semantics(tmp_path):
    from reproof.agent_kimi import write_agent_file
    p = tmp_path / "judge.md"
    write_agent_file(str(p), name="judge", description="d", tools=[],
                     system_prompt="You judge.")
    body = p.read_text()
    assert "tools: []\n" in body and "You judge." in body
    p2 = tmp_path / "find.md"
    write_agent_file(str(p2), name="find", description="d",
                     tools=["Read", "Write", "Bash"], system_prompt="You find.")
    assert "tools: [Read, Write, Bash]" in p2.read_text()
