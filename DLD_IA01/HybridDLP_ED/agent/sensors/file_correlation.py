"""
Short-window correlation of raw filesystem notifications (Layer B).

Pairs cross-volume delete+create with matching size into a single inferred action
so the sensor can emit one higher-level operation instead of two ambiguous raw events.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class RawPendingEvent:
    ts: float
    kind: str
    src_path: str
    dst_path: Optional[str]
    ctx: Dict[str, Any]
    size_hint: Optional[int] = None
    hash_hint: Optional[str] = None
    src_volume_type: Optional[str] = None
    dst_volume_type: Optional[str] = None


@dataclass
class CorrelatedEmit:
    """What the sensor should pass to _build_event (plus correlation metadata)."""

    evt_kind: str
    src_path: str
    dst_path: Optional[str]
    ctx: Dict[str, Any]
    correlation_action: Optional[str] = None
    correlation_detail: Dict[str, Any] = field(default_factory=dict)
    raw_trace: List[str] = field(default_factory=list)
    consume_paths: List[str] = field(default_factory=list)


def _is_fixed(vt: Optional[str]) -> bool:
    return (vt or "") == "Fixed"


def _is_external_vol(vt: Optional[str]) -> bool:
    return vt in {"Removable", "Network"}


def _drive_letter(path: str) -> Optional[str]:
    if not path:
        return None
    p = path.replace("/", "\\")
    if len(p) >= 2 and p[1] == ":":
        return p[:2].upper()
    return None


class FileCorrelationEngine:
    def __init__(self, window_sec: float):
        self.window_sec = max(0.1, float(window_sec))
        self._pending: List[RawPendingEvent] = []

    def clear(self) -> None:
        self._pending.clear()

    @staticmethod
    def _is_candidate(ev: RawPendingEvent) -> bool:
        if ev.kind == "deleted" and _is_fixed(ev.src_volume_type) and ev.size_hint is not None:
            return True
        # Buffer creates with size so we can merge with a prior delete (same vol or USB).
        if ev.kind == "created" and ev.size_hint is not None:
            if _is_fixed(ev.src_volume_type) or _is_external_vol(ev.src_volume_type):
                return True
        return False

    def handle(self, ev: RawPendingEvent, now: float) -> List[CorrelatedEmit]:
        """
        Ingest one raw notification.

        Non-candidates flush aged pending then emit immediately. Buffered deletes/creates
        infer cross-volume or same-volume moves when size and timing match.
        """
        if self._is_candidate(ev):
            self._pending.append(ev)
            out = list(self._pair_cross_volume_moves())
            out.extend(self._pair_same_volume_moves())
            out.extend(self.flush_due(now))
            return out
        out = list(self.flush_due(now))
        out.append(self._singleton(ev))
        return out

    def tick_flush(self, now: float) -> List[CorrelatedEmit]:
        """Call from the watchdog idle loop so buffered candidates eventually emit."""
        return self.flush_due(now)

    def flush_due(self, now: float) -> List[CorrelatedEmit]:
        """Emit singletons that are older than the correlation window."""
        cutoff = now - self.window_sec
        due: List[RawPendingEvent] = []
        remain: List[RawPendingEvent] = []
        for e in self._pending:
            if e.ts <= cutoff:
                due.append(e)
            else:
                remain.append(e)
        self._pending = remain
        out: List[CorrelatedEmit] = []
        for e in due:
            out.append(self._singleton(e))
        return out

    def _singleton(self, e: RawPendingEvent) -> CorrelatedEmit:
        return CorrelatedEmit(
            evt_kind=e.kind,
            src_path=e.src_path,
            dst_path=e.dst_path,
            ctx=e.ctx,
            correlation_action=None,
            correlation_detail={"layer_b": "flush_single"},
            raw_trace=[e.kind],
            consume_paths=[],
        )

    def _pair_cross_volume_moves(self) -> List[CorrelatedEmit]:
        """
        Fixed delete + external create (same size, within window) → inferred move to USB/network.
        """
        emits: List[CorrelatedEmit] = []
        used: set[int] = set()

        for i, a in enumerate(self._pending):
            if i in used or a.kind != "deleted":
                continue
            if not _is_fixed(a.src_volume_type):
                continue
            if a.size_hint is None:
                continue
            da = _drive_letter(a.src_path)
            if not da:
                continue
            best_j: Optional[int] = None
            best_dt: float = 1e9
            for j, b in enumerate(self._pending):
                if j == i or j in used or b.kind != "created":
                    continue
                db = _drive_letter(b.src_path)
                if not db:
                    continue
                # Removable/network, or second fixed drive (USB often misreported as Fixed).
                cross_drive = da != db
                if not (
                    _is_external_vol(b.src_volume_type)
                    or (_is_fixed(b.src_volume_type) and cross_drive)
                ):
                    continue
                if b.size_hint is None or b.size_hint != a.size_hint:
                    continue
                dt = abs(a.ts - b.ts)
                if dt <= self.window_sec and dt < best_dt:
                    best_dt = dt
                    best_j = j

            if best_j is None:
                continue

            b = self._pending[best_j]
            used.add(i)
            used.add(best_j)

            dst = b.src_path
            detail = {
                "layer_b": "cross_volume_move_inferred",
                "inferred": True,
                "prior_src_volume_type": a.src_volume_type,
                "dst_volume_type": b.src_volume_type,
                "size_hint": a.size_hint,
                "delta_t_sec": best_dt,
            }
            emits.append(
                CorrelatedEmit(
                    evt_kind="moved",
                    src_path=a.src_path,
                    dst_path=dst,
                    ctx=b.ctx,
                    correlation_action="move_to_external",
                    correlation_detail=detail,
                    raw_trace=["deleted", "created"],
                    consume_paths=[a.src_path, b.src_path],
                )
            )

        if used:
            self._pending = [e for k, e in enumerate(self._pending) if k not in used]
        return emits

    def _pair_same_volume_moves(self) -> List[CorrelatedEmit]:
        """
        Windows often reports same-volume move as delete + create. Pair Fixed→Fixed,
        same drive letter, different paths, matching size.
        """
        emits: List[CorrelatedEmit] = []
        used: set[int] = set()

        for i, a in enumerate(self._pending):
            if i in used or a.kind != "deleted":
                continue
            if not _is_fixed(a.src_volume_type):
                continue
            if a.size_hint is None:
                continue
            da = _drive_letter(a.src_path)
            if not da:
                continue
            best_j: Optional[int] = None
            best_dt: float = 1e9
            for j, b in enumerate(self._pending):
                if j == i or j in used or b.kind != "created":
                    continue
                if not _is_fixed(b.src_volume_type):
                    continue
                if b.size_hint is None or b.size_hint != a.size_hint:
                    continue
                db = _drive_letter(b.src_path)
                if not db or db != da:
                    continue
                if os.path.normcase(a.src_path) == os.path.normcase(b.src_path):
                    continue
                dt = abs(a.ts - b.ts)
                if dt <= self.window_sec and dt < best_dt:
                    best_dt = dt
                    best_j = j

            if best_j is None:
                continue

            b = self._pending[best_j]
            used.add(i)
            used.add(best_j)
            dst = b.src_path
            detail = {
                "layer_b": "same_volume_move_inferred",
                "inferred": True,
                "volume_type": a.src_volume_type,
                "size_hint": a.size_hint,
                "delta_t_sec": best_dt,
            }
            emits.append(
                CorrelatedEmit(
                    evt_kind="moved",
                    src_path=a.src_path,
                    dst_path=dst,
                    ctx=b.ctx,
                    correlation_action="move_same_volume",
                    correlation_detail=detail,
                    raw_trace=["deleted", "created"],
                    consume_paths=[a.src_path, b.src_path],
                )
            )

        if used:
            self._pending = [e for k, e in enumerate(self._pending) if k not in used]
        return emits
