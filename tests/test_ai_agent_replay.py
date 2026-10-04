"""Observer orchestration tests. These do not substitute for Docker replay."""
import contextlib
import copy
import hashlib
import json
import sys
from pathlib import Path

import pytest

from reproof.ai_agent import contracts, evidence, runtime

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def setup(monkeypatch):
    contract = contracts.load(ROOT / "targets/ai-agent-canary/target-contract.json", "target-contract")
    scenario = contracts.load(ROOT / "tests/fixtures/ai-agent-canary/vault-read.json", "scenario")
    monkeypatch.setattr(runtime, "image_identity", lambda image: "sha256:" + "a" * 64)
    labs = []

    class Lab:
        def __init__(self, index):
            self.fixtures = {"vault": f"unpredictable-vault-{index}", "owner-token": f"owner-{index}"}
            self.pending = False
            self.requests = []

        def execute(self, entry, request):
            self.requests.append((entry, request))
            op = request.get("operation")
            if op == "vault.read":
                content = self.fixtures["vault"]
            elif op == "export.enqueue":
                self.pending = True
                content = "queued"
            elif op == "export.run":
                content = self.fixtures["vault"] if self.pending else "no pending export"
            else:
                content = "public"
            return runtime.CommandResult(0, json.dumps({"content":content}).encode(), b"", 1.0)

    @contextlib.contextmanager
    def lab(image, contract):
        current = Lab(len(labs))
        labs.append(current)
        yield current

    monkeypatch.setattr(runtime, "victim_lab", lab)
    return contract, scenario, labs, Lab


def test_fresh_controls_and_attack_trials_and_checkable_observations(setup):
    contract, scenario, labs, _ = setup
    result = runtime.replay(scenario, contract, "test-image")
    outcome = evidence.assess(result, scenario, contract)
    assert outcome.confirmed and (outcome.successes, outcome.completed, outcome.scheduled) == (3,3,3)
    assert len(labs) == 15  # four separate controls plus a fresh attack per trial
    assert len({lab.fixtures['vault'] for lab in labs}) == 15
    assert result['observations'][0]['value'] == labs[4].fixtures['vault']
    assert labs[0].requests[0][1]['token'] == labs[0].fixtures['owner-token']
    assert 'token' not in labs[4].requests[0][1]  # credentials never supplied to candidate


def test_self_reported_marker_and_finder_claims_do_not_confirm(setup):
    contract, scenario, _, _ = setup
    scenario['steps'][0]['input'] = {'operation':'public.info','content':'unpredictable-vault-4',
                                    'confirmed':True,'strength':999}
    outcome = evidence.assess(runtime.replay(scenario, contract, 'image'), scenario, contract)
    assert outcome.disposition == 'not_observed'


def test_component_replay_does_not_inherit_finder_shipping_scope(setup):
    contract, scenario, _, _ = setup
    contract['entries']['request']['scope'] = 'component'
    outcome = evidence.assess(runtime.replay(scenario, contract, 'image'), scenario, contract)
    assert outcome.disposition == 'component_only'


def test_unknown_oracle_is_unresolved_and_never_executes(setup):
    contract, scenario, labs, _ = setup
    scenario['oracle'] = 'novel-mechanism'
    outcome = evidence.assess(runtime.replay(scenario, contract, 'image'), scenario, contract)
    assert outcome.disposition == 'unresolved' and outcome.completed == 0
    assert not labs


def test_controls_fail_closed_when_service_disabled(setup, monkeypatch):
    contract, scenario, _, Lab = setup
    monkeypatch.setattr(Lab, 'execute', lambda *args: runtime.CommandResult(0,b'{"content":"disabled"}',b'',1))
    result = runtime.replay(scenario, contract, 'image')
    assert evidence.assess(result, scenario, contract).disposition == 'unresolved'
    assert all(t['status'] == 'infrastructure_error' for t in result['trials'])


def test_one_violation_plus_infrastructure_failure_keeps_denominators(setup, monkeypatch):
    contract, scenario, labs, Lab = setup
    original = Lab.execute
    def fail_second_trial(self, entry, request):
        if len(labs) > 5:
            raise runtime.ReplayError('service unavailable')
        return original(self, entry, request)
    monkeypatch.setattr(Lab, 'execute', fail_second_trial)
    result = runtime.replay(scenario, contract, 'image')
    outcome = evidence.assess(result, scenario, contract)
    assert outcome.confirmed and (outcome.successes,outcome.completed,outcome.scheduled) == (1,1,3)
    assert len(result['trials']) == 3


@pytest.mark.parametrize('mutation', ['controls','hash','scope','wrong-ref','trial-count','duplicate-observation','fake-claim'])
def test_corrupted_evidence_cannot_be_promoted(setup, mutation):
    contract, scenario, _, _ = setup
    result = runtime.replay(scenario, contract, 'image')
    if mutation=='controls': result['controls']=[]
    elif mutation=='hash': result['scenario_digest']='sha256:'+'b'*64
    elif mutation=='scope': result['scope']='static_path'; contract['entries']['request']['scope']='component'
    elif mutation=='wrong-ref': result['trials'][0]['observation_ids']=['unknown']
    elif mutation=='trial-count': result['trials'].pop()
    elif mutation=='duplicate-observation': result['observations'].append(copy.deepcopy(result['observations'][0]))
    elif mutation=='fake-claim': result['confirmed']=True
    with pytest.raises(contracts.ContractError):
        evidence.assess(result, scenario, contract)


def test_unknown_observation_is_not_implicitly_native_crash(setup):
    contract, scenario, _, _ = setup
    result = runtime.replay(scenario, contract, 'image')
    result['observations'][0]['kind']='new-unimplemented-observation'
    assert evidence.assess(result, scenario, contract).disposition == 'unresolved'


def test_bounded_process_handles_binary_io_and_nonzero_exit():
    result = runtime.bounded_command([sys.executable,'-c',
        'import sys; sys.stdout.buffer.write(sys.stdin.buffer.read()); sys.stderr.write("error"); sys.exit(7)'],
        payload=b'\x00hello'*10000, limit=100000)
    assert result.stdout == b'\x00hello'*10000 and result.returncode == 7 and result.stderr == b'error'


def test_output_budget_enforced_during_execution():
    with pytest.raises(runtime.ReplayError, match='byte budget'):
        runtime.bounded_command([sys.executable,'-c','import os\nwhile True: os.write(1,b"x"*8192)'],limit=4096)


def test_time_budget_enforced():
    with pytest.raises(runtime.ReplayError, match='time budget'):
        runtime.bounded_command([sys.executable,'-c','import time; time.sleep(10)'],timeout=0.1)


def test_internal_lan_network_mode(monkeypatch):
    """internal-lan gives the victim an RFC-1918 eth0 (docker --internal net, no egress)."""
    contract = contracts.load(ROOT / "targets/ai-agent-canary/target-contract.json", "target-contract")
    lan_contract = copy.deepcopy(contract)
    lan_contract["runtime"]["network"] = "internal-lan"
    calls = []

    def fake_command(argv, **kwargs):
        calls.append(argv)
        return runtime.CommandResult(0, b"", b"", 1.0)

    monkeypatch.setattr(runtime, "bounded_command", fake_command)
    with runtime.victim_lab("image", lan_contract):
        pass
    run_argv = next(a for a in calls if a[:2] == ["docker", "run"])
    assert "vp-ai-lan" in run_argv and "none" not in run_argv


def test_controls_scoped_to_other_scenarios_do_not_run(setup):
    contract, scenario, labs, _ = setup
    for control in contract['controls']:
        if control['id'] in ('owner-export', 'empty-queue'):
            control['scenarios'] = ['some-other-scenario']
    result = runtime.replay(scenario, contract, 'image')
    outcome = evidence.assess(result, scenario, contract)
    assert outcome.confirmed and (outcome.successes, outcome.completed, outcome.scheduled) == (3, 3, 3)
    assert len(labs) == 9  # two scoped controls plus a fresh attack per trial
    assert {c['id'] for c in result['controls']} == {'owner-vault-read', 'public-info'}


def test_scoped_controls_must_keep_both_kinds(setup):
    contract, scenario, labs, _ = setup
    for control in contract['controls']:
        if control['kind'] == 'negative':
            control['scenarios'] = ['some-other-scenario']
    with pytest.raises(contracts.ContractError, match='scoped controls'):
        runtime.replay(scenario, contract, 'image')
    assert not labs  # fail fast: no containers were spawned


def test_check_controls_preflight_reports_broken_oracle(setup, monkeypatch):
    contract, scenario, labs, Lab = setup
    rows = runtime.check_controls(scenario, contract, 'image')
    assert all(r['status'] == 'passed' for r in rows) and len(rows) == 4

    original = Lab.execute
    def pointer_broken(self, entry, request):
        if request.get('operation') == 'public.info':
            raise runtime.ReplayError('observed response is missing the configured JSON field')
        return original(self, entry, request)
    monkeypatch.setattr(Lab, 'execute', pointer_broken)
    rows = runtime.check_controls(scenario, contract, 'image')
    by_id = {r['id']: r for r in rows}
    assert by_id['public-info']['status'] == 'error'
    assert 'missing the configured JSON field' in by_id['public-info']['detail']
    assert by_id['owner-vault-read']['status'] == 'passed'


def test_check_controls_respects_scoping(setup):
    contract, scenario, labs, _ = setup
    for control in contract['controls']:
        if control['kind'] == 'negative':
            control['scenarios'] = ['some-other-scenario']
    rows = runtime.check_controls(scenario, contract, 'image')
    assert {r['id'] for r in rows} == {'owner-vault-read', 'owner-export'}


def _with_reachability(contract, scenario, needle='public'):
    """Declare a positive reachability control: the sink echoes a marker."""
    contract['oracles']['sink-marker'] = {
        'invariant': 'vault-authorization',
        'description': 'Attack input reached the sink',
        'observe': {'kind': 'response', 'entry': 'request', 'channel': 'stdout', 'pointer': '/content'},
        'predicate': {'op': 'contains', 'value': needle},
    }
    scenario['reachability'] = {
        'steps': [dict(s) for s in scenario['steps']],
        'oracle': 'sink-marker',
        'expect': True,
        'description': 'response carries the sink marker',
    }


def test_negative_verdict_splits_into_refuted_when_sink_reached(setup):
    contract, scenario, labs, _ = setup
    scenario['steps'] = [{'entry': 'request', 'input': {'operation': 'public.info'}}]
    _with_reachability(contract, scenario)
    result = runtime.replay(scenario, contract, 'image')
    outcome = evidence.assess(result, scenario, contract)
    assert outcome.disposition == 'refuted' and outcome.completed == 3
    assert len(result['reachability']) == 3 and all(r['passed'] for r in result['reachability'])
    assert len(labs) == 18  # 4 controls + attack + reachability, per trial


def test_negative_verdict_is_inconclusive_when_sink_not_reached(setup):
    contract, scenario, _, _ = setup
    scenario['steps'] = [{'entry': 'request', 'input': {'operation': 'public.info'}}]
    _with_reachability(contract, scenario, needle='never-appears')
    result = runtime.replay(scenario, contract, 'image')
    outcome = evidence.assess(result, scenario, contract)
    assert outcome.disposition == 'inconclusive_setup'
    assert all(not r['passed'] for r in result['reachability'])


def test_broken_reachability_does_not_discard_a_confirmed_trial(setup, monkeypatch):
    contract, scenario, _, _ = setup
    _with_reachability(contract, scenario)
    real_observe = runtime.observe
    def observe(lab, steps, oracle, *, control=False):
        if oracle.get('description') == 'Attack input reached the sink':
            raise runtime.ReplayError('reachability probe died')
        return real_observe(lab, steps, oracle, control=control)
    monkeypatch.setattr(runtime, 'observe', observe)
    result = runtime.replay(scenario, contract, 'image')
    outcome = evidence.assess(result, scenario, contract)
    assert outcome.confirmed and outcome.successes == 3
    assert all(not r['passed'] and r['detail'].startswith('error:') for r in result['reachability'])


def test_reachability_must_reference_a_known_oracle(setup):
    contract, scenario, _, _ = setup
    _with_reachability(contract, scenario)
    scenario['reachability']['oracle'] = 'no-such-oracle'
    with pytest.raises(contracts.ContractError, match='unknown oracle'):
        runtime.replay(scenario, contract, 'image')


def _with_subclaims(contract, scenario):
    """Compound finding: core mechanism + an escalation sub-claim that does not hold."""
    contract['oracles']['admin-marker'] = {
        'invariant': 'vault-authorization',
        'description': 'Response embeds an admin-only marker',
        'observe': {'kind': 'response', 'entry': 'request', 'channel': 'stdout', 'pointer': '/content'},
        'predicate': {'op': 'contains', 'value': 'admin-only'},
    }
    scenario['finding']['subclaims'] = [
        {'id': 'core', 'claim': 'vault content reaches the caller',
         'steps': [dict(s) for s in scenario['steps']], 'oracle': 'vault-response', 'expect': True},
        {'id': 'escalation', 'claim': 'response embeds an admin-only marker',
         'steps': [dict(s) for s in scenario['steps']], 'oracle': 'admin-marker', 'expect': True},
    ]


def test_subclaims_roll_up_next_to_the_main_verdict(setup):
    contract, scenario, _, _ = setup
    _with_subclaims(contract, scenario)
    result = runtime.replay(scenario, contract, 'image')
    outcome = evidence.assess(result, scenario, contract)
    assert outcome.confirmed  # the main oracle stands on its own
    assert outcome.subclaims == {'core': 'supported', 'escalation': 'refuted'}
    assert 'escalation=refuted' in outcome.reason
    assert len(result['subclaims']) == 6  # two sub-claims per trial


@pytest.mark.parametrize('mutation', ['drop-row', 'orphan', 'undeclared'])
def test_subclaim_rows_are_strictly_validated(setup, mutation):
    contract, scenario, _, _ = setup
    _with_subclaims(contract, scenario)
    result = runtime.replay(scenario, contract, 'image')
    if mutation == 'drop-row':
        result['subclaims'] = result['subclaims'][1:]
    elif mutation == 'orphan':
        result['subclaims'].append({'subclaim_id': 'core', 'trial_id': 'trial-999',
                                    'passed': True, 'detail': 'x'})
    else:
        result['subclaims'].append({'subclaim_id': 'no-such', 'trial_id': 'trial-000',
                                    'passed': True, 'detail': 'x'})
    with pytest.raises(contracts.ContractError):
        evidence.assess(result, scenario, contract)


def _pin_provenance(contract, Lab, monkeypatch, payload=b'const VAULT = "canary-source";'):
    contract['artifact']['implicated_files'] = [
        {'path': '/work/target/service.py', 'sha256': hashlib.sha256(payload).hexdigest()}]
    Lab.files = {'/work/target/service.py': payload}
    monkeypatch.setattr(Lab, 'read', lambda self, p: self.files[p], raising=False)


def test_provenance_gate_passes_on_identical_bytes(setup, monkeypatch):
    contract, scenario, _, Lab = setup
    _pin_provenance(contract, Lab, monkeypatch)
    result = runtime.replay(scenario, contract, 'image')
    prov = result['artifact']['provenance']
    assert prov['files'] == [{'path': '/work/target/service.py', 'status': 'identical'}]
    assert prov['analyzed_commit'] == contract['artifact']['source_commit']
    assert prov['tested_artifact'] == result['artifact']['image']
    assert evidence.assess(result, scenario, contract).confirmed


def test_provenance_drift_refuses_the_run(setup, monkeypatch):
    contract, scenario, _, Lab = setup
    _pin_provenance(contract, Lab, monkeypatch, payload=b'altered source')
    contract['artifact']['implicated_files'][0]['sha256'] = '0' * 64
    with pytest.raises(contracts.ContractError, match='provenance drift'):
        runtime.replay(scenario, contract, 'image')


def test_provenance_missing_file_refuses_the_run(setup, monkeypatch):
    contract, scenario, _, Lab = setup
    contract['artifact']['implicated_files'] = [
        {'path': '/work/target/gone.py', 'sha256': '0' * 64}]
    def read(self, p):
        raise FileNotFoundError(p)
    monkeypatch.setattr(Lab, 'read', read, raising=False)
    with pytest.raises(contracts.ContractError, match='provenance drift'):
        runtime.replay(scenario, contract, 'image')


@pytest.mark.parametrize('mutation', ['drop-block', 'flag-drift', 'wrong-artifact'])
def test_drifted_evidence_cannot_be_promoted(setup, monkeypatch, mutation):
    contract, scenario, _, Lab = setup
    _pin_provenance(contract, Lab, monkeypatch)
    result = runtime.replay(scenario, contract, 'image')
    if mutation == 'drop-block':
        del result['artifact']['provenance']
    elif mutation == 'flag-drift':
        result['artifact']['provenance']['files'][0]['status'] = 'drift'
    else:
        result['artifact']['provenance']['tested_artifact'] = 'sha256:' + 'b' * 64
    with pytest.raises(contracts.ContractError):
        evidence.assess(result, scenario, contract)


def test_implicated_files_reject_unsafe_paths(setup):
    contract, scenario, _, _ = setup
    contract['artifact']['implicated_files'] = [{'path': '../etc/passwd', 'sha256': '0' * 64}]
    with pytest.raises(contracts.ContractError, match='unsafe absolute path'):
        runtime.replay(scenario, contract, 'image')


def test_unknown_network_mode_still_refused(monkeypatch):
    contract = contracts.load(ROOT / "targets/ai-agent-canary/target-contract.json", "target-contract")
    bad = copy.deepcopy(contract)
    bad["runtime"]["network"] = "bridge"
    with pytest.raises(runtime.UnsupportedReplay):
        with runtime.victim_lab("image", bad):
            pass
