"""
Demo generator: Off-hours bulk copy to USB/sensitive destination → ML/deep scan forced.

This script creates dummy files locally (source paths must exist for the worker),
then enqueues "file_copy" events into the persistent SQLite queue consumed by the worker.

Usage (PowerShell):
  python HybridDLP_ED/worker/tools/demo_bulk_exfil.py

Optional env overrides:
  DEMO_USER, DEMO_SRC_DIR, DEMO_DST_ROOT, DEMO_FILE_COUNT, DEMO_FILE_SIZE_MB,
  DEMO_OFF_HOURS_ISO (e.g. 2026-04-08T21:30:00+07:00)
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

# Queue lives in agent/ (L1/L2) but is used by the worker.
from agent.persistent_queue import PersistentEventQueue


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except Exception:
        return int(default)


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except Exception:
        return float(default)


def _now_off_hours_iso() -> str:
    # Default: force an off-hours time for the demo (local timezone if available).
    # If the system can't infer local tz reliably, keep it UTC.
    dt = datetime.now().astimezone()
    forced = dt.replace(hour=21, minute=30, second=0, microsecond=0)
    return forced.isoformat()


def _make_sparse_file(path: Path, size_mb: float) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    size_bytes = int(max(1.0, size_mb) * 1024 * 1024)
    # Create "large" file quickly: seek then write one byte.
    with open(path, "wb") as f:
        f.seek(size_bytes - 1)
        f.write(b"\0")


def main() -> int:
    user = os.getenv("DEMO_USER", "demo.user").strip() or "demo.user"
    src_dir = Path(os.getenv("DEMO_SRC_DIR", r"C:\DemoDLP\source")).resolve()
    dst_root = os.getenv("DEMO_DST_ROOT", r"F:\DLP_DEMO").strip() or r"F:\DLP_DEMO"
    n_files = max(1, _env_int("DEMO_FILE_COUNT", 10))
    size_mb = max(1.0, _env_float("DEMO_FILE_SIZE_MB", 10.0))
    ts_iso = os.getenv("DEMO_OFF_HOURS_ISO", _now_off_hours_iso()).strip()

    # Make files
    print(f"[demo] Creating {n_files} files x {size_mb:.1f}MB under {src_dir}")
    files: list[Path] = []
    for i in range(n_files):
        p = src_dir / f"demo_bulk_{i+1:03d}.bin"
        _make_sparse_file(p, size_mb=size_mb)
        files.append(p)

    # Enqueue events
    q = PersistentEventQueue()
    print(f"[demo] Enqueuing {len(files)} events with ts={ts_iso}")

    for i, fp in enumerate(files, start=1):
        size_bytes = fp.stat().st_size
        event = {
            "event_id": f"demo-bulk-{uuid.uuid4()}",
            "type": "file_copy",
            "source": "demo_script",
            "ts": ts_iso,
            "object": {
                "name": fp.name,
                "path": str(fp),
                "size_bytes": size_bytes,
                "dst_path": str(Path(dst_root) / fp.name),
                "dest_volume_type": "removable",
                "volume_type": "removable",
            },
            # Hints to worker for external transfer detection
            "operation": {
                "op_type": "file_copy",
                "semantic_action": "copy_to_removable",
                "dest_volume_type": "removable",
                "dlp_semantic_hint": "external_transfer",
            },
            "destination": dst_root,
            "metrics": {
                # Trigger existing BehavioralRulesEngine Bulk_File_Copy rule (>=50)
                # so the risk score is clearly elevated for the demo.
                "file_count_10s": 60,
            },
            "context": {
                "user": user,
                "process_name": "explorer.exe",
                "window_title": "Windows Explorer",
                # Optional domain field (kept empty for USB demo)
                "domain": "",
            },
        }
        q.enqueue(event)
        if i % 10 == 0:
            q.flush()
            print(f"[demo] queued {i}/{len(files)}")

    q.flush()
    pending = q.pending_count()
    print(f"[demo] Done. Queue pending≈{pending}. Start worker + dashboard to observe alerts.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

