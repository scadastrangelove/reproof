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


def test_transcript_and_last_assistant_parity():
    from reproof.agent_kimi import AgentResult
    big = "A" * 9000
    r = AgentResult(messages=[
        {"role": "meta", "type": "system.version", "version": "2.1.1"},
        {"role": "assistant", "content": "first"},
        {"role": "tool", "content": big},
        {"role": "assistant", "content": "last <poc_path>/work/poc</poc_path>"},
    ])
    assert r.last_assistant_message() == "last <poc_path>/work/poc</poc_path>"
    assert r.find_tagged_message("poc_path").startswith("last")
    t = r.transcript()
    assert len(t[2]["content"]) == 5000          # tool output clipped
    assert t[1]["content"] == "first"            # assistant text untouched
    # upstream-shaped messages clip too
    r2 = AgentResult(messages=[{
        "type": "user",
        "message": {"content": [{"type": "tool_result", "content": big}]},
    }])
    assert len(r2.transcript()[0]["message"]["content"][0]["content"]) == 5000


def test_kimi_config_toml_alias_and_key_env():
    from reproof.agent_kimi import kimi_config_toml
    t = kimi_config_toml("kimi-for-coding", max_steps=100,
                         base_url="https://gw.example/v1")
    assert 'default_model = "kimi-for-coding"' in t
    assert '[models."kimi-for-coding"]' in t
    assert 'api_key_env = "KIMI_MODEL_API_KEY"' in t
    assert 'base_url = "https://gw.example/v1"' in t
    assert "max_steps_per_turn = 100" in t
    assert "sk-" not in t  # no key material on disk, ever


def test_kimi_config_toml_env_fallback(monkeypatch):
    from reproof.agent_kimi import kimi_config_toml
    monkeypatch.setenv("KIMI_MODEL_BASE_URL", "https://env-gw/v1")
    monkeypatch.setenv("KIMI_MODEL_PROVIDER_TYPE", "openai")
    t = kimi_config_toml("m/x", max_steps=50)
    assert 'base_url = "https://env-gw/v1"' in t and 'type = "openai"' in t
    monkeypatch.delenv("KIMI_MODEL_BASE_URL")
    assert "base_url" not in kimi_config_toml("m", max_steps=50)


def test_discover_session_id_parses_newest(monkeypatch):
    from reproof import agent_kimi
    calls = {}
    def fake_exec_sh(container, command, timeout=None):
        calls["cmd"] = command
        return (0, "/opt/reproof/kimi-home/sessions/wd_work_abc/session_e961dfd1-0515-4942-97a6-16b5cb00e9f9\n", "")
    monkeypatch.setattr("reproof.docker_ops.exec_sh", fake_exec_sh)
    sid = agent_kimi.discover_session_id("c")
    assert sid == "session_e961dfd1-0515-4942-97a6-16b5cb00e9f9"
    assert "sessions/*/session_*" in calls["cmd"]


def test_discover_session_id_empty(monkeypatch):
    from reproof import agent_kimi
    monkeypatch.setattr("reproof.docker_ops.exec_sh",
                        lambda *a, **k: (0, "", ""))
    assert agent_kimi.discover_session_id("c") is None
    monkeypatch.setattr("reproof.docker_ops.exec_sh",
                        lambda *a, **k: (1, "", "no such dir"))
    assert agent_kimi.discover_session_id("c") is None
