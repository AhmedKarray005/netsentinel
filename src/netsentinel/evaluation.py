"""Compare detections with the ground truth of labelled scenarios -> TP / FP / FN."""

import json
from collections import Counter
from pathlib import Path
from typing import Any

from netsentinel.analysis import analyze_file
from netsentinel.detection import DetectionConfig


def evaluate(scenario_dir: str | Path, config: DetectionConfig | None = None) -> dict[str, Any]:
    """For every scenario: which rules should fire (truth) vs which fired (detected).

    TP = rule expected and fired; FP = fired but not expected; FN = expected but silent.
    """
    folder = Path(scenario_dir)
    manifest = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
    rows = []
    totals: Counter = Counter()
    for entry in manifest:
        report = analyze_file(folder / entry["file"], detection=config)
        detected = set(report["alerts"]["by_rule"])
        truth = set(entry["truth"])
        tp, fp, fn = truth & detected, detected - truth, truth - detected
        totals.update(TP=len(tp), FP=len(fp), FN=len(fn))
        rows.append(
            {
                "scenario": entry["file"],
                "description": entry["description"],
                "truth": sorted(truth),
                "detected": sorted(detected),
                "alerts": report["alerts"]["count"],
                "result": "PASS" if not fp and not fn else "FAIL",
                "TP": sorted(tp),
                "FP": sorted(fp),
                "FN": sorted(fn),
            }
        )
    return {"scenarios": rows, "totals": dict(totals)}
