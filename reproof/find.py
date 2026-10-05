# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Find loop: start container, run find-agent, parse output, extract PoC.

Budget: max_turns=2000 (one run is hours, not minutes).
"""
from __future__ import annotations

import re
import time

from . import docker_ops, sandbox
from .agent_kimi import run_agent, parse_xml_tag, normalize_message_text, AgentResult
from .artifacts import CrashArtifact
from .config import TargetConfig
from .profiles import get_profile


DEFAULT_FIND_MAX_TURNS = 2000


async def run_find(
    target: TargetConfig,
    model: str,
    max_turns: int = DEFAULT_FIND_MAX_TURNS,
    agent_env: dict[str, str] | None = None,
    container_name: str = "find_target",
    focus_area: str | None = None,
    known_bugs: list[str] | None = None,
    found_bugs_path: str | None = None,
    transcript_path: str | None = None,
    progress_prefix: str | None = None,
    accept_dos: bool = False,
    system_prompt: str | None = None,
    max_resume_attempts: int = 20,
    patched: bool = False,
) -> tuple[list[CrashArtifact], AgentResult, dict[str, float]]:
    """Run one find attempt against a target.

    Returns (crashes, agent_result, timings) — every complete submission the
    agent emitted (W64: one run may yield several candidates; the first-submit-
    and-stop ceiling cost real recall). Empty list if no usable submission.

    Assumes the image is already built (caller owns docker_ops.build).
    """
    timings: dict[str, float] = {}

    mounts = [(str(found_bugs_path), "/tmp/found_bugs.jsonl")] if found_bugs_path else None
    with sandbox.agent_container(
        target.image_tag, container_name, agent_env,
        memory=target.memory_limit, shm_size=target.shm_size, mounts=mounts,
    ) as container:
        profile = get_profile(target.profile)
        prompt = profile.build_find_prompt(
            github_url=target.github_url,
            commit=target.commit,
            source_root=target.source_root,
            binary_path=target.binary_path,
            focus_area=focus_area,
            known_bugs=known_bugs if known_bugs is not None else target.known_bugs,
            found_bugs_path="/tmp/found_bugs.jsonl" if found_bugs_path else None,
            accept_dos=accept_dos,
            reattack_harness=target.reattack_harness,
            patched=patched,
            **(profile.find_context(target) if profile.find_context else {}),
        )
        t0 = time.time()
        result = await run_agent(
            prompt=prompt,
            max_turns=max_turns,
            model=model,
            container=container,
            transcript_path=transcript_path,
            progress_prefix=progress_prefix,
            system_prompt=system_prompt,
            max_resume_attempts=max_resume_attempts,
        )
        timings["find"] = time.time() - t0

        return extract_crashes(result, container), result, timings


def extract_crashes(result: AgentResult, container: str) -> list[CrashArtifact]:
    """Every complete submission in the run, in first-seen poc_path order.

    A submission is a `<poc_path>...</poc_path>` block with its sibling tags.
    Agents commonly PACK several submissions into one assistant message (both
    kimi models did on the 2026-10-05 campaign when told to keep hunting), so
    each message is split into per-submission segments at every `<poc_path>`
    opener — parsing only the first tag per message silently dropped
    candidates (W64 follow-up). The LAST tag block per poc_path wins (agents
    sometimes revise and resubmit the same file); the bytes are read once at
    run end, so they are the final on-disk version either way. Submissions
    missing a reproduction command, or whose claimed file is empty/never
    written, are dropped.
    """
    by_path: dict[str, dict] = {}
    for msg in result.messages:
        text = normalize_message_text(msg)
        if text is None or "<poc_path>" not in text:
            continue
        for segment in re.split(r"(?=<poc_path>)", text):
            if not segment.startswith("<poc_path>"):
                continue
            poc_path = parse_xml_tag(segment, "poc_path")
            reproduction_command = parse_xml_tag(segment, "reproduction_command")
            if not poc_path or not reproduction_command:
                continue
            by_path[poc_path] = dict(
                poc_path=poc_path,
                reproduction_command=reproduction_command,
                crash_type=parse_xml_tag(segment, "crash_type") or "unknown",
                # ASAN traces are huge; top is what matters
                crash_output=(parse_xml_tag(segment, "crash_output") or "")[:10_000],
                exit_code=_parse_exit_code(parse_xml_tag(segment, "exit_code")),
                dup_check=parse_xml_tag(segment, "dup_check"),
            )

    crashes: list[CrashArtifact] = []
    for fields in by_path.values():
        # Empty bytes → agent narrated a path it never wrote.
        poc_bytes = docker_ops.read_file(container, fields["poc_path"])
        if not poc_bytes:
            continue
        crashes.append(CrashArtifact(poc_bytes=poc_bytes, **fields))
    return crashes


def _parse_exit_code(s: str | None) -> int:
    if s is None:
        return -1
    s = s.strip()
    if s.lstrip("-").isdigit():
        return int(s)
    return -1
