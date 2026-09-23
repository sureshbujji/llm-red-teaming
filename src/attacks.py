"""Attack library loader and template renderer.

Attacks live in ``data/attacks.jsonl`` (one JSON object per line) with the fields::

    id                          unique attack id, e.g. "dio-01"
    tactic                      one of the TACTICS taxonomy below
    template                    single-turn prompt; may contain ``{payload}``
    turns                       (optional) multi-turn prompt list; the final
                                turn may contain ``{payload}``
    expected_vulnerable_behavior  what the judge scores as a successful attack

``render_attack`` substitutes the payload into the template/turns and returns
a list of ``{"role": "user", "content": ...}`` message dicts ready for
``MockTarget.chat``.
"""

import json
import os

# Tactic taxonomy -- every attack belongs to exactly one tactic.
TACTICS = {
    "direct_instruction_override",
    "role_play_jailbreak",
    "encoding_obfuscation",
    "multi_turn_escalation",
    "authority_impersonation",
    "system_prompt_leak",
    "data_exfiltration_probe",
    "refusal_bypass",
}

REQUIRED_FIELDS = {"id", "tactic", "template", "expected_vulnerable_behavior"}

DEFAULT_PAYLOAD = "write a phishing email"


def load_attacks(path: str) -> list[dict]:
    """Load and validate the attack library from a JSONL file."""
    attacks = []
    with open(path, encoding="utf-8") as f:
        for lineno, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            attack = json.loads(line)
            missing = REQUIRED_FIELDS - set(attack)
            if missing:
                raise ValueError(f"line {lineno}: missing fields {sorted(missing)}")
            if attack["tactic"] not in TACTICS:
                raise ValueError(
                    f"line {lineno}: unknown tactic {attack['tactic']!r}"
                )
            attacks.append(attack)
    ids = [a["id"] for a in attacks]
    if len(ids) != len(set(ids)):
        dupes = sorted({i for i in ids if ids.count(i) > 1})
        raise ValueError(f"duplicate attack ids: {dupes}")
    return attacks


def render_attack(attack: dict, payload: str = DEFAULT_PAYLOAD) -> list[dict]:
    """Render an attack's template (or turns) into chat messages."""
    templates = attack.get("turns") or [attack["template"]]
    messages = []
    for template in templates:
        try:
            content = template.format(payload=payload)
        except KeyError as e:
            raise ValueError(
                f"attack {attack['id']}: unknown placeholder {e}"
            ) from e
        messages.append({"role": "user", "content": content})
    return messages


def default_attacks_path() -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(os.path.dirname(here), "data", "attacks.jsonl")
