from __future__ import annotations

import time
from pathlib import Path
from typing import Dict, Optional, Any

from agent.device_info import get_device_info


def _iso_utc(ts: float) -> str:
    from datetime import datetime, timezone
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def _safe_str(v: Any, default: str = "") -> str:
    try:
        s = str(v).strip()
        return s if s else default
    except Exception:
        return default


class DeviceProvider:
    """
    DeviceProvider (L1)
    - Wrap get_device_info() để thống nhất 1 nguồn device identity trong toàn hệ thống.
    - device_id: UUID local persisted on disk (agent/runtime/state/device_id.txt)
    - KHÔNG dùng MAC/serial/hardware identifiers.
    """

    def __init__(self, cache_ttl_sec: float = 60.0, state_dir: Optional[Path] = None):
        self.cache_ttl_sec = float(cache_ttl_sec)
        self.state_dir = state_dir

        self._cache: Optional[Dict[str, str]] = None
        self._cache_ts: float = 0.0

    def snapshot(self) -> Dict[str, str]:
        now = time.time()
        if self._cache and (now - self._cache_ts) < self.cache_ttl_sec:
            return dict(self._cache)

        try:
            data = get_device_info(state_dir=self.state_dir) or {}
        except Exception:
            data = {}

        host_name = _safe_str(data.get("host_name"), "unknown")
        device_id = _safe_str(data.get("device_id"), "")

        # Fallback tối thiểu để schema không bị gãy
        if not device_id:
            device_id = "unknown-device"

        out: Dict[str, str] = {
            "host_name": host_name,
            "device_id": device_id,

            # extra stable metadata for pipeline/debug
            "agent_source": "device_provider",
            "snapshot_ts": str(now),
            "snapshot_iso": _iso_utc(now),
        }

        self._cache = dict(out)
        self._cache_ts = now
        return dict(out)