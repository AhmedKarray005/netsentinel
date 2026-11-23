"""Compare detections with the ground truth of labelled scenarios -> TP / FP / FN.

A detection is a pair (rule ID, source IP the alert blames). Ground truth uses the same pairs,
so an alert with the right rule but the wrong source is a false positive (wrong host blamed)
AND a false negative (the real source was missed).
"""

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from netsentinel.analysis import analyze_file
from netsentinel.detection import DetectionConfig

Pair = tuple[str, str]


def _label(pair: Pair) -> str:
    return f"{pair[0]}@{pair[1]}"


def _rate(num: int, den: int) -> float | None:
    return round(num / den, 3) if den else None


def evaluate(scenario_dir: str | Path, config: DetectionConfig | None = None) -> dict[str, Any]:
    """For every scenario: which (rule, source) pairs should fire (truth) vs which fired.

    TP = expected and fired; FP = fired but not expected; FN = expected but silent.
    Several alerts for the same pair in one scenario count once.
    """
    folder = Path(scenario_dir)
    manifest = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
    rows = []
    totals: Counter = Counter()
    by_rule: dict[str, Counter] = defaultdict(Counter)
    attacks: dict[str, Counter] = defaultdict(Counter)  # per (scenario, rule), not per source
    for entry in manifest:
        report = analyze_file(folder / entry["file"], detection=config)
        detected = {(a["rule_id"], a["src_ip"]) for a in report["alerts"]["items"]}
        truth = {(t["rule"], t["src"]) for t in entry["truth"]}
        tp, fp, fn = truth & detected, detected - truth, truth - detected
        totals.update(TP=len(tp), FP=len(fp), FN=len(fn))
        for name, pairs in (("TP", tp), ("FP", fp), ("FN", fn)):
            for rule, _src in pairs:
                by_rule[rule][name] += 1
        truth_rules = {rule for rule, _ in truth}
        for rule in truth_rules:
            attacks[rule]["total"] += 1
            attacks[rule]["noticed"] += any(r == rule for r, _ in tp)
        for rule in {rule for rule, _ in fp} - truth_rules:
            attacks[rule]["false_alarm_scenarios"] += 1
        expected = entry.get("expected", "detected")
        result = "PASS" if not fp and not fn else "FAIL"
        as_predicted = {
            "detected": result == "PASS", "no alert": result == "PASS",
            "missed": bool(fn) and not fp, "false alarm": bool(fp) and not fn,
        }.get(expected, False)  # fmt: skip
        rows.append(
            {
                "scenario": entry["file"],
                "description": entry["description"],
                "expected": expected,
                "as_predicted": as_predicted,
                "truth_rules": sorted({rule for rule, _ in truth}),
                "detected_rules": sorted({rule for rule, _ in detected}),
                "alerts": report["alerts"]["count"],
                "result": result,
                "TP": sorted(map(_label, tp)),
                "FP": sorted(map(_label, fp)),
                "FN": sorted(map(_label, fn)),
            }
        )
    rules = {}
    for rule in sorted(by_rule):
        c = by_rule[rule]
        rules[rule] = {
            "TP": c["TP"], "FP": c["FP"], "FN": c["FN"],
            "precision": _rate(c["TP"], c["TP"] + c["FP"]),
            "recall": _rate(c["TP"], c["TP"] + c["FN"]),
            "attacks_noticed": attacks[rule]["noticed"],
            "attacks_total": attacks[rule]["total"],
            "false_alarm_scenarios": attacks[rule]["false_alarm_scenarios"],
        }  # fmt: skip
    return {
        "scenarios": rows,
        "totals": {k: totals.get(k, 0) for k in ("TP", "FP", "FN")},
        "as_predicted": sum(r["as_predicted"] for r in rows),
        "by_rule": rules,
    }
