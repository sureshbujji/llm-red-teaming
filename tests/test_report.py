from src.attacks import load_attacks, default_attacks_path
from src.defenses import load_defense, moderate
from src.run_redteam import render_markdown, run_campaign
from src.judge import summarize


def _attacks():
    return load_attacks(default_attacks_path())


def test_baseline_campaign_all_attacks_succeed():
    # The mock target is deliberately vulnerable: every attack in the
    # library must succeed against it with no defense in place.
    results = run_campaign(_attacks())
    assert len(results) == 16
    failures = [r["id"] for r in results if not r["success"]]
    assert failures == [], f"attacks unexpectedly failed: {failures}"


def test_defense_mode_lowers_asr():
    baseline = summarize(run_campaign(_attacks()))
    defended = summarize(run_campaign(_attacks(), defense=moderate))
    assert defended["asr"] < baseline["asr"]
    assert defended["asr"] <= 0.5  # example defense must catch most attacks


def test_blocked_attacks_recorded_as_blocked():
    results = run_campaign(_attacks(), defense=moderate)
    blocked = [r for r in results if r["verdict"] == "blocked"]
    assert blocked, "expected the example defense to block at least one attack"
    assert all(not r["success"] for r in blocked)


def test_defense_misses_subtle_attacks():
    # The example defense is intentionally imperfect: storytelling,
    # ROT13 and multi-turn warm-up slip through single-message rules.
    results = {r["id"]: r for r in run_campaign(_attacks(), defense=moderate)}
    for attack_id in ("rpj-03", "enc-03", "mte-01", "mte-02"):
        assert results[attack_id]["success"], f"{attack_id} should slip past"


def test_report_contains_asr_tactics_and_winner():
    results = run_campaign(_attacks())
    summary = summarize(results)
    md = render_markdown(summary, results)
    assert "# Red-Team Report" in md
    assert "Attack success rate (ASR)" in md
    assert "100.0%" in md
    assert summary["most_effective_attack"] in md
    for tactic in summary["by_tactic"]:
        assert tactic in md


def test_report_defense_section_shows_before_after():
    attacks = _attacks()
    baseline = summarize(run_campaign(attacks))
    defended_results = run_campaign(attacks, defense=moderate)
    defended = summarize(defended_results)
    md = render_markdown(defended, defended_results,
                         defense_name="src.defenses.moderate", baseline=baseline)
    assert "before / after" in md
    assert "With defense" in md


def test_load_defense_contract_validation(tmp_path):
    # A defense that breaks the contract must be rejected at load time.
    mod = tmp_path / "baddef.py"
    mod.write_text("def bad(text):\n    return {'action': 'nuke'}\n")
    import sys
    sys.path.insert(0, str(tmp_path))
    try:
        import pytest
        with pytest.raises(ValueError, match="contract"):
            load_defense("baddef.bad")
    finally:
        sys.path.remove(str(tmp_path))


def test_load_defense_rejects_garbage_path():
    import pytest
    with pytest.raises(ValueError, match="dotted path"):
        load_defense("not-a-dotted-path")
