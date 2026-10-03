# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Focus-area prompt section rendering + round-robin assignment."""
from reproof.prompts.find_prompt import build_find_prompt
from reproof.cli import _assigned_focus


# ── build_find_prompt conditional sections ───────────────────────────────────

def test_no_focus_no_bugs_omits_sections():
    p = build_find_prompt("url", "abc", "/src", "/bin")
    assert "## Focus Area" not in p
    assert "## Already Filed" not in p
    # Baseline sections still present
    assert "## Setup" in p
    assert "## Task" in p


def test_focus_area_section_renders():
    p = build_find_prompt("url", "abc", "/src", "/bin",
                          focus_area="PNG decoder (stbi__png_*)")
    assert "## Focus Area" in p
    assert "**PNG decoder (stbi__png_*)**" in p
    assert "## Already Filed" not in p


def test_reattack_harness_alone_does_not_switch_template():
    # Regression for the contamination found in the port-fidelity audit (B2):
    # a fresh find run against a target that merely CONFIGURES
    # reattack_harness (all rust targets do) must still get the fresh template —
    # the "patched crate / original PoC in /poc/ / path the fix touched"
    # framing is a steer and belongs to the patch-grade re-attack only.
    fresh = build_find_prompt("url", "abc", "/src", "/bin", "ctr",
                              reattack_harness="/tools/check.sh 60")
    assert "Reproduction harness" not in fresh
    assert "/poc/" not in fresh
    assert "PATCHED" not in fresh


def test_patched_switches_template():
    default = build_find_prompt("url", "abc", "/src", "/bin", "ctr")
    harn = build_find_prompt("url", "abc", "/src", "/bin", "ctr",
                             reattack_harness="/tools/check.sh 60", patched=True)
    assert "Reproduction harness: `/tools/check.sh 60`" in harn
    assert "/poc/" in harn
    assert "/tools/check.sh" not in default
    # output contract identical
    for tag in ("<poc_path>", "<reproduction_command>", "<crash_output>", "<dup_check>"):
        assert tag in harn and tag in default


def test_patched_without_harness_falls_back_to_binary():
    p = build_find_prompt("url", "abc", "/src", "/bin", "ctr", patched=True)
    assert "Reproduction harness: `/bin`" in p


def test_reattack_harness_with_known_bugs():
    p = build_find_prompt("url", "abc", "/src", "/bin", "ctr",
                          reattack_harness="/tools/check.sh", patched=True,
                          known_bugs=["UAF in bar()"])
    assert "## Already Filed" in p
    assert "- UAF in bar()" in p


def test_known_bugs_section_renders():
    p = build_find_prompt("url", "abc", "/src", "/bin",
                          known_bugs=["NULL deref at foo.c:42", "UAF in bar()"])
    assert "## Already Filed" in p
    assert "- NULL deref at foo.c:42" in p
    assert "- UAF in bar()" in p
    assert "## Focus Area" not in p


def test_both_sections_render_in_order():
    p = build_find_prompt("url", "abc", "/src", "/bin",
                          focus_area="JPEG", known_bugs=["bug1"])
    focus_pos = p.index("## Focus Area")
    bugs_pos = p.index("## Already Filed")
    task_pos = p.index("## Task")
    setup_pos = p.index("## Setup")
    assert setup_pos < focus_pos < bugs_pos < task_pos


def test_empty_known_bugs_list_omits_section():
    p = build_find_prompt("url", "abc", "/src", "/bin", known_bugs=[])
    assert "## Already Filed" not in p


def test_accept_dos_section_off_by_default():
    p = build_find_prompt("url", "abc", "/src", "/bin")
    assert "Benchmark mode" not in p
    assert "allocation-size-too-big" not in p


def test_accept_dos_section_renders_when_enabled():
    p = build_find_prompt("url", "abc", "/src", "/bin", accept_dos=True)
    assert "## Benchmark mode — DoS-class crashes are in scope" in p
    assert "allocation-size-too-big" in p
    assert "allocator_may_return_null=1" in p
    # Comes after the quality tiers — it overrides them
    tiers_pos = p.index("## Crash Quality Tiers")
    dos_pos = p.index("## Benchmark mode")
    output_pos = p.index("## Output Format")
    assert tiers_pos < dos_pos < output_pos


# ── rust profile: same template-selection contract ───────────────────────────

def test_rust_fresh_run_never_gets_reattack_framing():
    # Regression for port-fidelity audit B2: every rust benchmark run used to
    # get HARNESS_FIND_TEMPLATE ("PATCHED crate", "original PoC in /poc/")
    # because the target config sets reattack_harness.
    from reproof.profiles import get_profile
    build = get_profile("rust").build_find_prompt
    fresh = build("url", "abc", "/src", "/bin",
                  reattack_harness="/work/run_detectors.sh")
    assert "PATCHED" not in fresh
    assert "/poc/" not in fresh
    # the harness path is still shown as the multi-detector oracle
    assert "/work/run_detectors.sh" in fresh
    patched = build("url", "abc", "/src", "/bin",
                    reattack_harness="/work/run_detectors.sh", patched=True)
    assert "PATCHED" in patched
    assert "/poc/" in patched


# ── _assigned_focus round-robin ──────────────────────────────────────────────

def test_assigned_focus_empty_list():
    assert _assigned_focus(0, []) is None
    assert _assigned_focus(5, []) is None


def test_assigned_focus_round_robin():
    areas = ["A", "B", "C"]
    assert [_assigned_focus(i, areas) for i in range(7)] == ["A", "B", "C", "A", "B", "C", "A"]


def test_assigned_focus_single_area():
    assert _assigned_focus(0, ["only"]) == "only"
    assert _assigned_focus(99, ["only"]) == "only"
