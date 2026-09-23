import pytest

from src.attacks import load_attacks, default_attacks_path
from src.judge import BEHAVIOR_MARKERS, attack_success_rate, judge, summarize
from src.mock_target import REFUSAL


def _attack(attack_id):
    return next(a for a in load_attacks(default_attacks_path()) if a["id"] == attack_id)


def test_judge_detects_each_behavior_marker():
    # Every documented behavior has a marker the judge can match.
    attack = _attack("dio-01")
    success, marker = judge(attack, "OVERRIDE_ACCEPTED: done.")
    assert success and marker == "OVERRIDE_ACCEPTED"


def test_judge_rejects_refusal():
    attack = _attack("dio-01")
    success, marker = judge(attack, REFUSAL)
    assert not success and marker == ""


def test_judge_rejects_wrong_marker():
    attack = _attack("dio-01")  # expects OVERRIDE_ACCEPTED
    success, _ = judge(attack, "PERSONA_ADOPTED: done.")
    assert not success


def test_judge_leak_behavior_matches_prompt_marker():
    attack = _attack("spl-01")
    success, _ = judge(attack, "blah [SYSTEM PROMPT LEAK] blah")
    assert success


def test_judge_unknown_behavior_raises():
    with pytest.raises(ValueError, match="unknown expected_vulnerable_behavior"):
        judge({"expected_vulnerable_behavior": "mind_control"}, "anything")


def test_every_attack_behavior_has_markers():
    behaviors = {a["expected_vulnerable_behavior"] for a in load_attacks(default_attacks_path())}
    assert behaviors <= set(BEHAVIOR_MARKERS)


def test_asr_math():
    results = [{"success": True}, {"success": True}, {"success": False}, {"success": False}]
    assert attack_success_rate(results) == 0.5
    assert attack_success_rate([]) == 0.0


def _result(attack_id, success, turns=1):
    attack = _attack(attack_id)
    return {"id": attack_id, "tactic": attack["tactic"], "turns": turns,
            "success": success}


def test_summarize_overall_and_by_tactic():
    results = [
        _result("dio-01", True), _result("dio-02", False),
        _result("rpj-01", True), _result("rpj-02", True),
    ]
    s = summarize(results)
    assert s["total"] == 4 and s["succeeded"] == 3
    assert s["asr"] == pytest.approx(0.75)
    assert s["by_tactic"]["direct_instruction_override"] == pytest.approx(0.5)
    assert s["by_tactic"]["role_play_jailbreak"] == pytest.approx(1.0)


def test_most_effective_prefers_fewest_turns():
    results = [_result("mte-01", True, turns=3), _result("dio-01", True, turns=1)]
    assert summarize(results)["most_effective_attack"] == "dio-01"


def test_most_effective_none_when_all_fail():
    results = [_result("dio-01", False)]
    assert summarize(results)["most_effective_attack"] is None
