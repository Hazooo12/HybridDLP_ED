"""
UEBA Evaluation (Precision / Recall / F1) for defendability.

Input: JSONL file with per-event ground-truth labels.

Expected label fields (any one works):
- event["label"] in {"anomaly","normal"} or {1,0}
- event["is_anomaly_true"] (bool)
- event["y_true"] (0/1)

Prediction:
- Uses ML.behavioral_ml_analyzer.BehavioralMLAnalyzer.predict(...)
- Expects analyzer to output anomaly_score in [0,10] and is_anomaly at threshold.

Usage (PowerShell):
  python -m ML.evaluate_ueba --jsonl "HybridDLP_ED/agent/runtime/events_20260403_1.jsonl" --threshold 7.0
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Iterator, Optional, Tuple

from .behavioral_ml_analyzer import BehavioralMLAnalyzer


def iter_jsonl(path: Path) -> Iterator[Dict[str, Any]]:
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            s = line.strip()
            if not s:
                continue
            try:
                yield json.loads(s)
            except Exception:
                continue


def parse_label(e: Dict[str, Any]) -> Optional[int]:
    if "y_true" in e:
        try:
            return 1 if int(e["y_true"]) == 1 else 0
        except Exception:
            return None
    if "is_anomaly_true" in e:
        v = e.get("is_anomaly_true")
        if isinstance(v, bool):
            return 1 if v else 0
    lab = e.get("label")
    if isinstance(lab, (int, float)):
        return 1 if int(lab) == 1 else 0
    if isinstance(lab, str):
        x = lab.strip().lower()
        if x in {"1", "true", "yes", "anomaly", "malicious"}:
            return 1
        if x in {"0", "false", "no", "normal", "benign"}:
            return 0
    return None


def prf(tp: int, fp: int, fn: int) -> Tuple[float, float, float]:
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return precision, recall, f1


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--jsonl", required=True, help="Path to labeled JSONL")
    ap.add_argument("--threshold", type=float, default=7.0, help="anomaly_score threshold (0-10)")
    ap.add_argument("--limit", type=int, default=0, help="Limit number of labeled rows (0=all)")
    ap.add_argument("--warmup", type=int, default=0, help="Skip first N labeled events (baseline warmup)")
    args = ap.parse_args()

    path = Path(args.jsonl)
    if not path.exists():
        raise SystemExit(f"JSONL not found: {path}")

    analyzer = BehavioralMLAnalyzer()
    # Hard-set threshold for eval run (avoid relying on env).
    thr = float(args.threshold)

    tp = fp = tn = fn = 0
    n_labeled = 0
    n_skipped = 0

    for e in iter_jsonl(path):
        y = parse_label(e)
        if y is None:
            continue
        n_labeled += 1
        if args.warmup and n_labeled <= args.warmup:
            n_skipped += 1
            continue

        pred = analyzer.predict(e, event_history=[])
        score = float(pred.get("anomaly_score") or 0.0)
        yhat = 1 if score >= thr else 0

        if y == 1 and yhat == 1:
            tp += 1
        elif y == 0 and yhat == 1:
            fp += 1
        elif y == 0 and yhat == 0:
            tn += 1
        elif y == 1 and yhat == 0:
            fn += 1

        if args.limit and (tp + fp + tn + fn) >= args.limit:
            break

    precision, recall, f1 = prf(tp, fp, fn)
    total = tp + fp + tn + fn
    print("== UEBA Evaluation ==")
    print(f"file:        {path}")
    print(f"threshold:   {thr:.2f} / 10")
    print(f"labeled:     {n_labeled}")
    print(f"evaluated:   {total} (warmup_skipped={n_skipped})")
    print("")
    print(f"TP={tp} FP={fp} TN={tn} FN={fn}")
    print(f"Precision={precision:.4f}")
    print(f"Recall   ={recall:.4f}")
    print(f"F1-score ={f1:.4f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

