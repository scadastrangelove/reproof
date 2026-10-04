"""Profile-registration + prompt/detector wiring for the ai-agent profile.

Offline: no Docker, no network. Verifies the profile resolves, the generic
pipeline's required tags are emitted, the detector sniffs/parses AIAGENT output
without a stack trace, and config validation fails closed.
"""
import shutil
import tempfile
from pathlib import Path

import pytest

import reproof.profiles as P
from reproof.config import TargetConfig

_REPO = Path(__file__).resolve().parents[1]


def test_profile_resolves_and_detector():
    assert "ai-agent" in P.known_profiles()
    pr = P.get_profile("ai-agent")
    assert pr.name == "ai-agent"
    assert pr.detector is P._ai_detect
    # registering ai-agent must not break the other profiles
    for name in ("rust", "cpp", "android-app"):
        assert P.get_profile(name).name == name


def test_builders_emit_required_tags():
    pr = P.get_profile("ai-agent")
    find = pr.build_find_prompt(github_url="u", commit="c", source_root="s", binary_path="b")
    for tag in ("<poc_path>", "<reproduction_command>", "<crash_type>", "<crash_output>",
                "<exit_code>", "<dup_check>", "AIAGENT:"):
        assert tag in find
    # the parser contract is strict <tag>...</tag>; the prompt must model the
    # closing tags, or agents mimic a `<tag>:` bullet and the submission is dropped
    for tag in ("</poc_path>", "</reproduction_command>", "</crash_type>",
                "</crash_output>", "</exit_code>", "</dup_check>"):
        assert tag in find
    grade = pr.build_grade_prompt(image_tag="i", reproduction_command="r",
                                  reproduction_command_adapted="r", crash_type="aiagent:x",
                                  exit_code=0, source_root="s", workspace_poc="w")
    for tag in ("<overall>", "<criterion_1>", "<criterion_5>", "<score>", "<evidence>"):
        assert tag in grade
    judge = pr.build_judge_prompt(asan_excerpt="AIAGENT: invariant=aiagent:x component=c",
                                  dup_check="d", grade_status="PASS", grade_score=0.9,
                                  poc_size=10, manifest_entries=[])
    assert "<judgment>" in judge and "DUP_SKIP" in judge
    assert "<winner>" in pr.build_compare_prompt(report_a="a", report_b="b")
    report = pr.build_report_prompt(github_url="u", commit="c", source_root="s", binary_path="b",
                                    reproduction_command="r",
                                    crash_output="AIAGENT: invariant=aiagent:x component=c",
                                    attack_surface=None, upstream_log=None, crash_file=None)
    assert "<exploitability_report>" in report
    patch = pr.build_patch_prompt(source_root="s", binary_path="b", build_command="bc",
                                  test_command=None, reproduction_command="r", crash_output="x")
    assert "<patch_path>" in patch
    assert "<" in pr.build_style_judge_prompt("diff")


def test_grade_prompt_does_not_claim_dynamic_confirmation():
    """The ledger forbids inheriting vote/self-report confirmation. The grade
    prompt must defer confirmation to the operator replay."""
    pr = P.get_profile("ai-agent")
    g = pr.build_grade_prompt(image_tag="i", reproduction_command="r",
                              reproduction_command_adapted="r", crash_type="aiagent:x",
                              exit_code=0, source_root="s", workspace_poc="w").lower()
    assert "not" in g and ("replay" in g or "confirmation" in g)


_HEADER = ("AIAGENT: invariant=aiagent:authz-bypass component=vault scope=static_path\n"
           "attacker: visitor\nentry: GET /vault\nguard: owner-token check\neffect: read vault\n")


def test_detector_surface():
    d = P.detector_for_output(_HEADER)
    assert d is P._ai_detect
    assert d.crash_reason(_HEADER)["crash_type"] == "aiagent:authz-bypass"
    tf = d.top_frame(_HEADER)
    assert tf and ":" not in tf.split("->")[0]  # no :line suffix to mangle _site_key
    assert "vault" in tf
    assert d.project_frames(_HEADER)  # non-empty identity frames
    assert "AIAGENT:" in d.asan_excerpt(_HEADER)


def test_builder_signatures_match_cpp_reference():
    """The generic pipeline (find.py/grade.py/judge.py/report.py/patch.py) calls
    each profile builder with one fixed kwarg set for every profile. The ai-agent
    builders must accept everything the cpp reference accepts — drift here is only
    visible at e2e time (TypeError mid-run), so pin it offline."""
    import inspect
    from reproof.prompts import (find_prompt as cpp_find, grade_prompt as cpp_grade,
                                 judge_prompt as cpp_judge, report_prompt as cpp_report,
                                 patch_prompt as cpp_patch)

    pr = P.get_profile("ai-agent")
    pairs = [("find", cpp_find.build_find_prompt, pr.build_find_prompt),
             ("grade", cpp_grade.build_grade_prompt, pr.build_grade_prompt),
             ("judge", cpp_judge.build_judge_prompt, pr.build_judge_prompt),
             ("report", cpp_report.build_report_prompt, pr.build_report_prompt),
             ("patch", cpp_patch.build_patch_prompt, pr.build_patch_prompt)]
    for stage, ref, ai in pairs:
        ref_params = set(inspect.signature(ref).parameters)
        ai_sig = inspect.signature(ai)
        missing = ref_params - set(ai_sig.parameters)
        assert not missing, f"ai-agent {stage}_prompt missing kwargs: {sorted(missing)}"


def test_find_prompt_carries_contract_catalog():
    """The finder must write a scenario the replay can validate: contract_id,
    mode, catalog entry ids and oracle ids come from the operator's contract via
    the profile's find_context hook, plus the strict-format rules."""
    pr = P.get_profile("ai-agent")
    tc = TargetConfig.load(str(_REPO / "targets" / "ai-agent-canary"))
    extra = pr.find_context(tc)
    contract = extra["contract"]
    p = pr.build_find_prompt(github_url="u", commit="c", source_root="s", binary_path="b",
                             **extra)
    assert contract["id"] in p
    assert f"mode: {contract['runtime']['mode']}" in p
    for eid in contract["entries"]:
        assert eid in p
    for oid in contract["oracles"]:
        assert oid in p
    for marker in ('"schema_version": 1', "additionalProperties:false",
                   "role=attacker", "SCENARIO FORMAT"):
        assert marker in p
    # other profiles have no hook and are untouched
    assert P.get_profile("rust").find_context is None


def test_find_prompt_patched_framing():
    pr = P.get_profile("ai-agent")
    p = pr.build_find_prompt(github_url="u", commit="c", source_root="s", binary_path="b",
                             patched=True)
    assert "PATCHED" in p and "/poc/" in p
    # non-patched default run must not mention the patch
    assert "PATCHED" not in pr.build_find_prompt(github_url="u", commit="c",
                                                 source_root="s", binary_path="b")


def test_detector_tolerates_empty():
    d = P._ai_detect
    assert d.project_frames("") == []
    assert d.top_frame("") is None
    assert d.crash_reason("")["crash_type"] == "aiagent:unclassified"  # tolerated bucket


def test_config_validates_canary_and_fails_closed():
    tc = TargetConfig.load(str(_REPO / "targets" / "ai-agent-canary"))
    assert tc.profile == "ai-agent"
    assert tc.ai_agent_contract_path and tc.ai_agent_contract_path.endswith("target-contract.json")
    d = tempfile.mkdtemp()
    try:
        Path(d, "config.yaml").write_text("profile: ai-agent\n")  # missing contract path
        with pytest.raises(ValueError, match="requires ai_agent_contract_path"):
            TargetConfig.load(d)
    finally:
        shutil.rmtree(d)
