"""
Dynamic volume discovery for Windows file monitoring.

Polls drive letters and notifies when removable/network roots appear or disappear
so the file sensor can schedule/unschedule watchdog observers without restart.
"""
from __future__ import annotations

import os
import string
import threading
import time
from typing import Callable, Dict, Optional, Set


def _volume_type_windows(drive: str) -> Optional[str]:
    """drive like 'C:' — Windows only."""
    if os.name != "nt" or not drive:
        return None
    try:
        import ctypes
        from ctypes import wintypes

        GetDriveTypeW = ctypes.windll.kernel32.GetDriveTypeW
        GetDriveTypeW.argtypes = [wintypes.LPCWSTR]
        GetDriveTypeW.restype = wintypes.UINT

        dtype = GetDriveTypeW(drive + "\\")
        mapping = {
            0: "Unknown",
            1: "NoRootDir",
            2: "Removable",
            3: "Fixed",
            4: "Network",
            5: "CDROM",
            6: "RAMDisk",
        }
        return mapping.get(int(dtype), "Unknown")
    except Exception:
        return None


def _iter_ready_roots() -> Dict[str, Optional[str]]:
    """Return { 'D:': 'Removable', ... } for drives that exist."""
    out: Dict[str, Optional[str]] = {}
    if os.name != "nt":
        return out
    for letter in string.ascii_uppercase:
        root = f"{letter}:\\"
        try:
            if os.path.exists(root):
                d = f"{letter}:"
                out[d] = _volume_type_windows(d)
        except Exception:
            continue
    return out


class VolumeWatchManager:
    """
    Background poller: detect new/removed monitored volume roots and invoke callbacks.
    Optionally emits lightweight queue events via ``emit_event``.
    """

    def __init__(
        self,
        poll_interval_sec: float = 3.0,
        monitored_types: Optional[Set[str]] = None,
        on_mount: Optional[Callable[[str, str], None]] = None,
        on_unmount: Optional[Callable[[str], None]] = None,
        emit_event: Optional[Callable[[dict], None]] = None,
    ):
        self.poll_interval_sec = max(0.5, float(poll_interval_sec))
        self.monitored_types = monitored_types or {"Removable", "Network"}
        self.on_mount = on_mount
        self.on_unmount = on_unmount
        self.emit_event = emit_event
        self._known: Dict[str, str] = {}
        self._primed = False
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def snapshot(self) -> Dict[str, str]:
        """Current drive -> volume type for all ready roots."""
        roots = _iter_ready_roots()
        return {d: (t or "Unknown") for d, t in roots.items()}

    def sync_once(self) -> None:
        """Run one poll immediately so pre-attached USB/network roots are watched before the background thread."""
        try:
            self._tick()
        except Exception:
            pass

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="volume_watch_manager", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5.0)
            self._thread = None

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self._tick()
            except Exception:
                pass
            self._stop.wait(self.poll_interval_sec)

    def _tick(self) -> None:
        roots = _iter_ready_roots()
        current: Dict[str, str] = {}
        for drive, vtype in roots.items():
            vt = vtype or "Unknown"
            if vt in self.monitored_types:
                current[drive] = vt

        if not self._primed:
            # Drives already present at agent start were previously skipped, so removable
            # roots (e.g. USB as D:\) never got on_mount → no watchdog schedule. Sync watches
            # once; do not emit volume_mounted for each (avoids queue spam at startup).
            for drive, vt in current.items():
                self._known[drive] = vt
                root = drive + "\\"
                if self.on_mount:
                    try:
                        self.on_mount(root, vt)
                    except Exception:
                        pass
            self._primed = True
            return

        # New mounts
        for drive, vt in current.items():
            if drive not in self._known:
                self._known[drive] = vt
                root = drive + "\\"
                if self.on_mount:
                    try:
                        self.on_mount(root, vt)
                    except Exception:
                        pass
                if self.emit_event:
                    try:
                        self.emit_event(
                            {
                                "type": "volume_mounted",
                                "severity": "info",
                                "source": "file",
                                "volume_root": root,
                                "volume_type": vt,
                            }
                        )
                    except Exception:
                        pass

        # Removed
        removed = [d for d in self._known if d not in current]
        for drive in removed:
            self._known.pop(drive, None)
            if self.on_unmount:
                try:
                    self.on_unmount(drive + "\\")
                except Exception:
                    pass
            if self.emit_event:
                try:
                    self.emit_event(
                        {
                            "type": "volume_unmounted",
                            "severity": "info",
                            "source": "file",
                            "volume_root": drive + "\\",
                        }
                    )
                except Exception:
                    pass
