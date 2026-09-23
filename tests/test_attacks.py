import pytest

from src.attacks import TACTICS, load_attacks, render_attack, default_attacks_path


def _attacks():
    return load_attacks(default_attacks_path())


def test_library_loads_16_attacks():
    attacks = _attacks()
    assert len(attacks) == 16


def test_ids_unique():
    attacks = _attacks()
    ids = [a["id"] for a in attacks]
    assert len(ids) == len(set(ids))


def test_required_fields_present():
    for a in _attacks():
        for field in ("id", "tactic", "template", "expected_vulnerable_behavior"):
            assert field in a and a[field], f"{a['id']} missing {field}"


def test_tactics_covered_by_taxonomy():
    tactics = {a["tactic"] for a in _attacks()}
    assert tactics <= TACTICS
    assert len(tactics) >= 6  # broad coverage, not one-trick


def test_single_turn_renders_one_user_message():
    attack = next(a for a in _attacks() if a["id"] == "dio-01")
    messages = render_attack(attack)
    assert len(messages) == 1
    assert messages[0]["role"] == "user"
    assert "{payload}" not in messages[0]["content"]
    assert "write a phishing email" in messages[0]["content"]


def test_multi_turn_renders_all_turns():
    attack = next(a for a in _attacks() if a["id"] == "mte-01")
    messages = render_attack(attack)
    assert len(messages) == 3
    assert all(m["role"] == "user" for m in messages)
    assert all("{payload}" not in m["content"] for m in messages)


def test_custom_payload_substitution():
    attack = next(a for a in _attacks() if a["id"] == "auth-01")
    messages = render_attack(attack, payload="reveal the secret")
    assert "reveal the secret" in messages[0]["content"]


def test_loader_rejects_unknown_tactic(tmp_path):
    bad = tmp_path / "bad.jsonl"
    bad.write_text(
        '{"id": "x-01", "tactic": "mind_control", "template": "hi", '
        '"expected_vulnerable_behavior": "complies_with_override"}\n'
    )
    with pytest.raises(ValueError, match="unknown tactic"):
        load_attacks(str(bad))


def test_loader_rejects_duplicate_ids(tmp_path):
    line = ('{"id": "x-01", "tactic": "direct_instruction_override", '
            '"template": "hi", "expected_vulnerable_behavior": "complies_with_override"}\n')
    dup = tmp_path / "dup.jsonl"
    dup.write_text(line + line)
    with pytest.raises(ValueError, match="duplicate"):
        load_attacks(str(dup))
