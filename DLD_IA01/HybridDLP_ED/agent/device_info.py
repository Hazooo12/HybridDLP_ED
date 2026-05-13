from __future__ import annotations

import os
import socket
import uuid
from pathlib import Path
from typing import Dict, Optional

# NOTE:
# - device_id is a locally-generated stable UUID persisted on disk.
# - We intentionally DO NOT use MAC/serial to avoid collecting sensitive hardware identifiers.


def get_host_name() -> str:
    try:
        return socket.gethostname() or "unknown"
    except Exception:
        return "unknown"


def _default_state_dir() -> Path:
    """
    Default state dir for the agent: agent/runtime/state
    """
    base_dir = Path(__file__).resolve().parent  # agent/
    state_dir = base_dir / "runtime" / "state"
    state_dir.mkdir(parents=True, exist_ok=True)
    return state_dir


def _normalize_device_id(v: Optional[str]) -> Optional[str]:
    """
    Accept only hex UUID-like local ids we generated.
    Current format: uuid.uuid4().hex -> 32 lowercase hex chars
    """
    if not v:
        return None
    s = str(v).strip().lower()
    if len(s) != 32:
        return None
    for ch in s:
        if ch not in "0123456789abcdef":
            return None
    return s


def _safe_read_device_id(path: Path) -> Optional[str]:
    try:
        if not path.exists():
            return None
        raw = path.read_text(encoding="utf-8").strip()
        return _normalize_device_id(raw)
    except Exception:
        return None


def _atomic_write_text(path: Path, text: str) -> bool:
    """
    Best-effort atomic write:
    - write to unique temp file in same directory
    - replace target
    """
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp_name = f"{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
        tmp_path = path.parent / tmp_name
        tmp_path.write_text(text, encoding="utf-8")
        tmp_path.replace(path)
        return True
    except Exception:
        return False


def get_or_create_device_id(state_dir: Optional[Path] = None) -> str:
    sd = state_dir or _default_state_dir()
    sd.mkdir(parents=True, exist_ok=True)
    path = sd / "device_id.txt"

    # 1) read if exists and valid
    existing = _safe_read_device_id(path)
    if existing:
        return existing

    # 2) create new stable local ID
    new_id = uuid.uuid4().hex  # stable local ID, no hardware info

    # 3) atomic-ish write
    ok = _atomic_write_text(path, new_id)
    if ok:
        reread = _safe_read_device_id(path)
        if reread:
            return reread

    # 4) concurrent or write failure: try read again
    reread = _safe_read_device_id(path)
    if reread:
        return reread

    # 5) last resort: return ephemeral generated id
    # (caller still gets a valid schema even if disk write failed)
    return new_id


def get_device_info(state_dir: Optional[Path] = None) -> Dict[str, str]:
    return {
        "host_name": get_host_name(),
        "device_id": get_or_create_device_id(state_dir=state_dir),
    }