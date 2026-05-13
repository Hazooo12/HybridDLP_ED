from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional, List

from agent.event_schema import normalize_event


def _iso_utc(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def emit_event(
    *,
    type: str,
    source: str,
    severity: Any = 0,
    ts: Optional[Any] = None,
    timestamp: Optional[str] = None,
    tags: Optional[List[Any]] = None,
    ioc_hits: Optional[List[Any]] = None,

    actor: Optional[Dict[str, Any]] = None,
    object: Optional[Dict[str, Any]] = None,
    context: Optional[Dict[str, Any]] = None,
    operation: Optional[Dict[str, Any]] = None,
    metrics: Optional[Dict[str, Any]] = None,
    flags: Optional[Dict[str, Any]] = None,
    content: Optional[Dict[str, Any]] = None,

    clipboard: Optional[Dict[str, Any]] = None,
    usb: Optional[Dict[str, Any]] = None,
    print: Optional[Dict[str, Any]] = None,
    network: Optional[Dict[str, Any]] = None,
    decision: Optional[Dict[str, Any]] = None,
    debug: Optional[Dict[str, Any]] = None,
    device: Optional[Dict[str, Any]] = None,
    process: Optional[Dict[str, Any]] = None,

    drop_hint: Optional[str] = None,

    # optional extra top-level passthrough for legacy/report fields
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    now = time.time()
    final_ts = ts if ts is not None else now
    final_timestamp = timestamp or (_iso_utc(float(final_ts)) if isinstance(final_ts, (int, float)) else _iso_utc(now))

    raw: Dict[str, Any] = {
        "type": type,
        "source": source,
        "severity": severity,
        "ts": final_ts,
        "timestamp": final_timestamp,

        "tags": tags or [],
        "ioc_hits": ioc_hits or [],

        "actor": actor or {},
        "object": object or {},
        "context": context or {},
        "operation": operation or {},
        "metrics": metrics or {},
        "flags": flags or {},
        "content": content or {},

        "clipboard": clipboard or {},
        "usb": usb or {},
        "print": print or {},
        "network": network or {},
        "decision": decision or {},
        "debug": debug or {},
        "device": device or {},
        "process": process or {},

        "drop_hint": drop_hint,
    }

    if extra and isinstance(extra, dict):
        raw.update(extra)

    # preserve original input before normalization
    raw["raw_original"] = dict(raw)

    return normalize_event(raw)