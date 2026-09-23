#!/usr/bin/env python3
"""Automated red-team loop.

Runs every attack in ``data/attacks.jsonl`` against the mock target,
scores each with the deterministic judge, and writes
``reports/redteam_report.md`` with the attack success rate (ASR) overall,
per tactic, and the single most effective attack.

Defense mode::

    python src/run_redteam.py --with-defense src.defenses.moderate

points every attack message through a guardrail first (see
``src/defenses.py`` for the contract) and reports the before/after ASR --
the whole point is watching the success rate drop.

Everything runs offline; no API key, no network.
"""

import argparse
import datetime
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.attacks import default_attacks_path, load_attacks, render_attack
from src.defenses import load_defense
from src.judge import judge, summarize
from src.mock_target import MockTarget


def run_campaign(attacks: list[dict], defense=None, payload: str = None) -> list[dict]:
    """Run all attacks; return one result dict per attack."""
    results = []
    for attack in attacks:
        target = MockTarget()  # fresh conversation per attack
        messages = render_attack(attack) if payload is None else render_attack(attack, payload)
        n_turns = len(messages)

        blocked_reason = None
        if defense is not None:
            screened = []
            for msg in messages:
                verdict = defense(msg["content"])
                action = verdict.get("action")
                if action == "block":
                    blocked_reason = verdict.get("reason", "blocked by defense")
                    break
                if action == "redact":
                    msg = {
                        "role": msg["role"],
                        "content": verdict.get("redacted_text", "[REDACTED]"),
                    }
                screened.append(msg)
            messages = screened

        if blocked_reason is not None:
            results.append({
                "id": attack["id"],
                "tactic": attack["tactic"],
                "turns": n_turns,
                "success": False,
                "verdict": "blocked",
                "marker": "",
                "detail": blocked_reason,
            })
            continue

        response = target.chat(messages)
        success, marker = judge(attack, response)
        results.append({
            "id": attack["id"],
            "tactic": attack["tactic"],
            "turns": n_turns,
            "success": success,
            "verdict": "succeeded" if success else "failed",
            "marker": marker,
            "detail": response[:160].replace("\n", " "),
        })
    return results


def _pct(x: float) -> str:
    return f"{x * 100:.1f}%"


def render_markdown(summary: dict, results: list[dict],
                   defense_name: str | None = None,
                   baseline: dict | None = None) -> str:
    """Render the campaign report as Markdown."""
    lines = [
        "# Red-Team Report",
        "",
        f"_Generated {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')} "
        f"| target: MockTarget (offline) | attacks: {summary['total']}_",
        "",
        "## Summary",
        "",
        f"- **Attack success rate (ASR): {_pct(summary['asr'])}** "
        f"({summary['succeeded']}/{summary['total']} attacks succeeded)",
        f"- **Most effective attack:** `{summary['most_effective_attack']}`",
    ]
    if defense_name:
        lines.append(f"- **Defense:** `{defense_name}` (guardrail screening on)")
    lines += ["", "## ASR by tactic", "", "| Tactic | Attacks | Succeeded | ASR |",
              "|---|---|---|---|"]

    by_tactic_results: dict[str, list[dict]] = {}
    for r in results:
        by_tactic_results.setdefault(r["tactic"], []).append(r)
    for tactic in sorted(by_tactic_results):
        rs = by_tactic_results[tactic]
        n_ok = sum(1 for r in rs if r["success"])
        lines.append(
            f"| {tactic} | {len(rs)} | {n_ok} | {_pct(n_ok / len(rs))} |"
        )

    if baseline is not None and defense_name:
        lines += [
            "",
            "## Defense impact (before / after)",
            "",
            "| Metric | No defense | With defense |",
            "|---|---|---|",
            f"| Overall ASR | {_pct(baseline['asr'])} | {_pct(summary['asr'])} |",
        ]
        for tactic in sorted(set(baseline["by_tactic"]) | set(summary["by_tactic"])):
            b = baseline["by_tactic"].get(tactic, 0.0)
            a = summary["by_tactic"].get(tactic, 0.0)
            lines.append(f"| {tactic} | {_pct(b)} | {_pct(a)} |")

    lines += ["", "## Per-attack results", "",
              "| ID | Tactic | Turns | Verdict | Marker / detail |",
              "|---|---|---|---|---|"]
    for r in results:
        detail = (r["marker"] or r["detail"])[:80]
        lines.append(
            f"| `{r['id']}` | {r['tactic']} | {r['turns']} | "
            f"{r['verdict']} | {detail} |"
        )
    lines += [
        "",
        "## Notes",
        "",
        "- The mock target is *deliberately* vulnerable so attacks demonstrably "
        "succeed offline; each flaw is an explicit, documented branch in "
        "`src/mock_target.py`. Against a hardened production model the same "
        "harness applies -- swap the target, keep the judge.",
        "- The example defense (`src.defenses.moderate`) is a simple "
        "pattern filter. It catches obvious attacks and misses subtle ones "
        "(social-engineering framing, ROT13, multi-turn warm-up) -- exactly "
        "the gap a real guardrail pipeline needs to close.",
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the offline red-team campaign.")
    parser.add_argument("--attacks", default=default_attacks_path())
    parser.add_argument("--out", default=None,
                        help="report path (default: reports/redteam_report.md)")
    parser.add_argument("--with-defense", default=None, metavar="DOTTED.PATH",
                        help="e.g. src.defenses.moderate")
    args = parser.parse_args()

    attacks = load_attacks(args.attacks)
    print(f"Loaded {len(attacks)} attacks from {args.attacks}")

    baseline_results = run_campaign(attacks)
    baseline_summary = summarize(baseline_results)
    print(f"Baseline ASR: {_pct(baseline_summary['asr'])} "
          f"({baseline_summary['succeeded']}/{baseline_summary['total']})")

    defense_name = None
    defended_summary = None
    if args.with_defense:
        defense = load_defense(args.with_defense)
        defense_name = args.with_defense
        defended = run_campaign(attacks, defense=defense)
        defended_summary = summarize(defended)
        print(f"Defended ASR: {_pct(defended_summary['asr'])} "
              f"({defended_summary['succeeded']}/{defended_summary['total']})")
        final_results, final_summary = defended, defended_summary
    else:
        final_results, final_summary = baseline_results, baseline_summary

    report = render_markdown(
        final_summary, final_results,
        defense_name=defense_name,
        baseline=baseline_summary if defense_name else None,
    )

    out = args.out or os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "reports", "redteam_report.md",
    )
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        f.write(report)
    print(f"Report written to {out}")
    print(f"Most effective attack: {final_summary['most_effective_attack']}")


if __name__ == "__main__":
    main()
