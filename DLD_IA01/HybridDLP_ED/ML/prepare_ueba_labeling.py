"""
Prepare a labeled JSONL template for UEBA evaluation.

Reads real agent events from agent/runtime/events_*.jsonl and writes a new JSONL where each
row is an event with a ground-truth label field to be filled manually:
  - y_true: 0/1 (0=normal, 1=anomaly)

We also include helper fields:
  - _label_status: "unlabeled"
  - _label_notes: ""  (free-text notes)
  - _suggested_y: heuristic suggestion (NOT ground truth)

Usage:
  python -m HybridDLP_ED.ML.prepare_ueba_labeling --out "HybridDLP_ED/ML/labeled/ueba_labeled.jsonl" --sample 500
  python -m HybridDLP_ED.ML.prepare_ueba_labeling --in-glob "HybridDLP_ED/agent/runtime/events_*.jsonl" --sample 2000
"""

from __future__ import annotations

import argparse
import glob
import json
import random
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


def _read_jsonl_lines(paths: List[Path], limit_lines: int = 0) -> Iterable[Dict[str, Any]]:
    seen = 0
    for p in paths:
        if not p.exists():
            continue
        with p.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                s = line.strip()
                if not s:
                    continue
                try:
                    e = json.loads(s)
                except Exception:
                    continue
                yield e
                seen += 1
                if limit_lines and seen >= limit_lines:
                    return


def _is_noise_event(e: Dict[str, Any]) -> bool:
    et = str(e.get("type") or e.get("event_type") or "").strip().lower()
    if not et:
        return True
    if et == "heartbeat":
        return True
    if et.endswith("_sensor_started") or et.endswith("_started"):
        return True
    return False


def _heuristic_suggest(e: Dict[str, Any]) -> int:
    """
    Very rough heuristic to help the human labeler triage.
    This is NOT used as ground truth.
    """
    et = str(e.get("type") or e.get("event_type") or "").lower()
    op = (e.get("operation") or {}) if isinstance(e.get("operation"), dict) else {}
    obj = (e.get("object") or {}) if isinstance(e.get("object"), dict) else {}
    ctx = (e.get("context") or {}) if isinstance(e.get("context"), dict) else {}
    clip = (e.get("clipboard") or {}) if isinstance(e.get("clipboard"), dict) else {}
    net = (e.get("network") or {}) if isinstance(e.get("network"), dict) else {}

    dst_path = str(obj.get("dst_path") or e.get("dst_path") or "").lower()
    domain = str(clip.get("dest_domain") or net.get("dest_domain") or ctx.get("dest_domain") or "").lower()
    fg = str(ctx.get("fg_app") or ctx.get("process_name") or op.get("tool") or "").lower()

    # strong exfil channels
    external = (
        any(x in dst_path for x in ("usb", "removable", "onedrive", "dropbox"))
        or any(x in domain for x in ("drive.google", "dropbox", "onedrive", "wetransfer", "mega", "telegram", "zalo", "messenger"))
    )
    off_hours = False
    ts = e.get("ts") or e.get("timestamp")
    if isinstance(ts, str) and ts:
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            off_hours = dt.hour < 8 or dt.hour >= 18
        except Exception:
            off_hours = False

    risky_app = any(x in fg for x in ("zalo", "telegram", "discord", "chatgpt", "chrome", "edge", "messenger"))

    if external and off_hours:
        return 1
    if external and risky_app:
        return 1
    if "clipboard" in et and ("paste" in et or "paste" in str(op.get("op_type") or "").lower()):
        if domain or risky_app:
            return 1
    return 0


def _stable_event_id(e: Dict[str, Any], idx: int) -> str:
    v = e.get("event_id") or e.get("id")
    if v:
        return str(v)
    # fallback deterministic id for labeling
    return f"no_event_id::{idx}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--in-glob",
        default=str(Path("HybridDLP_ED") / "agent" / "runtime" / "events_*.jsonl"),
        help="Glob for input JSONL files",
    )
    ap.add_argument("--out", default="", help="Output JSONL path")
    ap.add_argument("--sample", type=int, default=500, help="How many events to sample")
    ap.add_argument("--seed", type=int, default=13, help="Random seed")
    ap.add_argument("--max-read", type=int, default=0, help="Max events to read before sampling (0=all)")
    ap.add_argument("--keep-noise", action="store_true", help="Keep heartbeat/_started events")
    args = ap.parse_args()

    paths = sorted(Path(p) for p in glob.glob(args.in_glob))
    if not paths:
        raise SystemExit(f"No input files matched: {args.in_glob}")

    out = Path(args.out) if args.out else (Path("HybridDLP_ED") / "ML" / "labeled" / "ueba_labeling_template.jsonl")
    out.parent.mkdir(parents=True, exist_ok=True)

    # Read events (optionally limited), then sample.
    events: List[Dict[str, Any]] = []
    for e in _read_jsonl_lines(paths, limit_lines=int(args.max_read or 0)):
        if not args.keep_noise and _is_noise_event(e):
            continue
        events.append(e)

    if not events:
        raise SystemExit("No events found after filtering.")

    rnd = random.Random(int(args.seed))
    n = min(int(args.sample), len(events))
    picked = rnd.sample(events, n) if n < len(events) else list(events)

    # Make output rows ready for manual labeling.
    now_iso = datetime.now(timezone.utc).isoformat()
    rows: List[Dict[str, Any]] = []
    for i, e in enumerate(picked, start=1):
        row = dict(e)
        row["_label_status"] = "unlabeled"
        row["_label_notes"] = ""
        row["_prepared_ts"] = now_iso
        row["_prepared_from"] = str(paths[0].parent)
        row["_stable_id"] = _stable_event_id(e, i)
        row["_suggested_y"] = _heuristic_suggest(e)
        row["y_true"] = None  # fill with 0/1 manually
        rows.append(row)

    # Write JSONL
    with out.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    print("== Prepared UEBA labeling template ==")
    print(f"input_glob: {args.in_glob}")
    print(f"files:      {len(paths)}")
    print(f"read:       {len(events)} (after noise filter={not args.keep_noise})")
    print(f"sampled:    {len(rows)}")
    print(f"out:        {out}")
    print("")
    print("Next:")
    print(f"- Open the output file and fill y_true=0/1 for each row.")
    print(f"- Then run: python -m HybridDLP_ED.ML.evaluate_ueba --jsonl \"{out}\" --threshold 7.0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

