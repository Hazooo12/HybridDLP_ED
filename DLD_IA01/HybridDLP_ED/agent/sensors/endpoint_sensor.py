from __future__ import annotations

import hashlib
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    import psutil  # type: ignore
except Exception:
    psutil = None


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def _read_head(path: str, max_bytes: int = 8192) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read(max_bytes)
    except Exception:
        return b""


def _read_text(path: str, max_chars: int = 400) -> Optional[str]:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read(max_chars)
    except Exception:
        return None


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = float(len(data))
    import math
    e = 0.0
    for c in freq:
        if c:
            p = c / n
            e -= p * math.log2(p)
    return float(e)


def _signature(head: bytes, ext: str) -> Optional[str]:
    if not head:
        return None
    if head.startswith(b"%PDF-"):
        return "pdf"
    if head.startswith(b"\x89PNG\r\n\x1A\n"):
        return "png"
    if head.startswith(b"\xFF\xD8\xFF"):
        return "jpg"
    if head.startswith(b"PK\x03\x04"):
        if ext == ".docx":
            return "docx"
        if ext == ".xlsx":
            return "xlsx"
        return "zip"
    return "bin"


class EndpointSensor:
    """
    Endpoint file-access sensor (Phase 1):
      - Emits file_open / file_read / file_close
      - Keeps real path and file metadata/content in object block
      - OS backend hints are exposed in debug.evidence.backend_stack
    """

    def __init__(
        self,
        queue_manager,
        watch_paths: Optional[List[str]] = None,
        watch_processes: Optional[Set[str]] = None,
        poll_interval_sec: float = 0.8,
        read_refresh_sec: float = 3.0,
        max_files_per_process_per_scan: int = 8,
    ):
        self.qm = queue_manager
        self.poll_interval_sec = float(poll_interval_sec)
        self.read_refresh_sec = float(read_refresh_sec)
        self.watch_paths = [str(Path(p).resolve()) for p in (watch_paths or []) if p]
        self.watch_processes = {str(x).lower() for x in (watch_processes or set()) if x}
        self.max_files_per_process_per_scan = max(1, int(max_files_per_process_per_scan))
        self._active: Dict[Tuple[int, str], float] = {}
        self._last_read_emit: Dict[Tuple[int, str], float] = {}
        self._include_system_paths = os.getenv("ENDPOINT_INCLUDE_SYSTEM_PATHS", "0").strip().lower() in {"1", "true", "yes", "on"}
        self._noisy_processes: Set[str] = {
            "svchost.exe",
            "backgroundtaskhost.exe",
            "wmiprvse.exe",
            "officeclicktorun.exe",
            "sqlwriter.exe",
            "rstmwservice.exe",
            "wavesaudioservice.exe",
            "wavessyssvc64.exe",
            "wavessvc64.exe",
            "ovpnhelper_service.exe",
        }
        self._noise_path_tokens = (
            "\\windows\\",
            "\\program files\\",
            "\\program files (x86)\\",
            "\\programdata\\",
            "\\appdata\\",
            "\\$recycle.bin\\",
            "\\system volume information\\",
            "\\appdata\\local\\programs\\",
            "\\appdata\\local\\packages\\",
            "\\appdata\\local\\temp\\",
            "\\appdata\\local\\google\\chrome\\user data\\",
            "\\appdata\\local\\microsoft\\edge\\user data\\",
            "\\appdata\\local\\coccoc\\browser\\user data\\",
            "\\appdata\\locallow\\",
            "\\appdata\\locallow\\intel\\shadercache\\",
            "\\appdata\\roaming\\zalodata\\",
            "\\appdata\\roaming\\openvpn connect\\",
            "\\cache\\",
            "\\code cache\\",
            "\\dawncache\\",
            "\\local storage\\leveldb\\",
            "\\session storage\\",
            "\\webstorage\\",
            "\\gpucache\\",
            "\\indexeddb\\",
            "\\service worker\\",
            "\\logs\\",
            "\\programdata\\a00a6de3-ad8e-4f51-8148-1c16dada4e47\\delloptimizer\\gains\\",
        )
        self._noise_extensions = {
            ".mui",
            ".nlp",
            ".dll",
            ".pak",
            ".asar",
            ".tmp",
            ".log",
            ".wal",
            ".shm",
            ".map",
            ".dat",
            ".db",
            ".db-wal",
            ".db-shm",
            ".db-journal",
            ".sqlite-wal",
            ".sqlite-shm",
            ".vscdb",
            ".vscdb-wal",
            ".vscdb-shm",
            ".vscdb-journal",
            ".ldb",
            ".pma",
            ".vsidx",
            ".idx",
            ".pdb",
            ".bin",
        }
        self._noise_basenames = {
            "dips",
            "history",
            "history-journal",
            "cookies",
            "cookies-journal",
            "web data",
            "web data-journal",
            "network persistent state",
            "preferences",
            "secure preferences",
        }

    def _emit(self, evt: Dict[str, Any]) -> None:
        try:
            self.qm.enqueue_event(evt)
        except Exception:
            pass

    def _backend_stack(self) -> List[str]:
        if os.name == "nt":
            return ["minifilter", "etw", "sysmon", "api_hook", "userspace_psutil_fallback"]
        if os.name == "posix" and Path("/System/Library").exists():
            return ["EndpointSecurity", "userspace_psutil_fallback"]
        return ["fanotify", "auditd", "eBPF", "userspace_psutil_fallback"]

    def _is_watched_path(self, path: str) -> bool:
        if not self.watch_paths:
            return True
        rp = str(Path(path).resolve())
        return any(rp.startswith(root) for root in self.watch_paths)

    def _should_ignore(self, path: str, process_name: str) -> bool:
        lp = (path or "").lower()
        pn = (process_name or "").lower()

        if not self._include_system_paths:
            if any(tok in lp for tok in self._noise_path_tokens):
                return True
            try:
                if Path(lp).suffix.lower() in self._noise_extensions:
                    return True
                if Path(lp).name.lower() in self._noise_basenames:
                    return True
            except Exception:
                pass
            if pn in self._noisy_processes:
                return True
        return False

    def _collect(self) -> List[Dict[str, Any]]:
        if psutil is None:
            return []
        out: List[Dict[str, Any]] = []
        per_process_count: Dict[str, int] = {}
        for p in psutil.process_iter(attrs=["pid", "name", "username", "exe", "cmdline"]):
            try:
                info = p.info or {}
                pname = str(info.get("name") or "").lower()
                if self.watch_processes and pname not in self.watch_processes:
                    continue
                for f in p.open_files() or []:
                    if per_process_count.get(pname, 0) >= self.max_files_per_process_per_scan:
                        break
                    fp = getattr(f, "path", None)
                    if not fp or not self._is_watched_path(fp):
                        continue
                    if self._should_ignore(str(fp), pname):
                        continue
                    per_process_count[pname] = per_process_count.get(pname, 0) + 1
                    out.append(
                        {
                            "pid": int(info.get("pid") or 0),
                            "process": info.get("name"),
                            "user": info.get("username"),
                            "exe": info.get("exe"),
                            "cmdline": " ".join(info.get("cmdline") or [])[:1000] if isinstance(info.get("cmdline"), list) else None,
                            "path": str(fp),
                        }
                    )
            except Exception:
                continue
        return out

    def _file_object(self, path: str) -> Dict[str, Any]:
        p = Path(path)
        ext = p.suffix.lower()
        try:
            st = p.stat()
            exists = True
            size = int(st.st_size)
            mtime = _iso(float(st.st_mtime))
        except Exception:
            exists = False
            size = None
            mtime = None

        head = _read_head(path, 8192) if exists else b""
        sample = _read_text(path, 400) if exists else None
        return {
            "path": path,
            "dst_path": None,
            "name": p.name,
            "ext": ext or None,
            "size": size,
            "mtime": mtime,
            "exists": exists,
            "signature": _signature(head, ext),
            "hash_sha256": hashlib.sha256(head).hexdigest() if head else None,
            "entropy": _entropy(head) if head else None,
            "content_preview": sample,
            "content_preview_len": len(sample) if isinstance(sample, str) else None,
            "metadata": {
                "backend_collector": "psutil.open_files",
                "backend_stack": self._backend_stack(),
            },
        }

    def _event(self, etype: str, ts: float, rec: Dict[str, Any], obj: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "type": etype,
            "source": "endpoint",
            "severity": "warn" if etype in {"file_read", "file_copy", "file_move"} else "info",
            "ts": _iso(ts),
            "actor": {
                "user": rec.get("user"),
                "pid": rec.get("pid"),
                "process": rec.get("process"),
                "cmdline": rec.get("cmdline"),
                "exe": rec.get("exe"),
            },
            "operation": {
                "op_type": etype,
                "tool": rec.get("process"),
            },
            "object": obj,
            "metrics": {"entropy": obj.get("entropy"), "file_count": None, "row_count": None},
            "flags": {"password_protected": None},
            "content": {"sample": obj.get("content_preview"), "sample_len": obj.get("content_preview_len")},
            "debug": {"evidence": {"backend_stack": self._backend_stack(), "collector": "userspace_psutil"}},
        }

    def run_loop(self, stop_event, ctx_provider=None) -> None:
        if psutil is None:
            self._emit(
                {
                    "type": "endpoint_sensor_error",
                    "source": "endpoint",
                    "severity": "warn",
                    "ts": _iso(time.time()),
                    "message": "psutil not available; install psutil to enable EndpointSensor",
                    "debug": {"evidence": {"psutil_missing": True}},
                }
            )
            while not stop_event.is_set():
                time.sleep(1.0)
            return

        while not stop_event.is_set():
            now = time.time()
            keys_now: Set[Tuple[int, str]] = set()
            rows = self._collect()

            for rec in rows:
                pid = int(rec.get("pid") or 0)
                path = str(rec.get("path") or "")
                if pid <= 0 or not path:
                    continue
                key = (pid, path)
                keys_now.add(key)
                obj = self._file_object(path)
                if key not in self._active:
                    self._emit(self._event("file_open", now, rec, obj))
                    self._emit(self._event("file_read", now, rec, obj))
                    self._active[key] = now
                    self._last_read_emit[key] = now
                else:
                    last = float(self._last_read_emit.get(key, 0.0))
                    if now - last >= self.read_refresh_sec:
                        self._emit(self._event("file_read", now, rec, obj))
                        self._last_read_emit[key] = now
                    self._active[key] = now

            stale = [k for k in self._active.keys() if k not in keys_now]
            for key in stale:
                pid, path = key
                rec = {"pid": pid, "path": path, "user": None, "process": None, "cmdline": None, "exe": None}
                self._emit(self._event("file_close", now, rec, self._file_object(path)))
                self._active.pop(key, None)
                self._last_read_emit.pop(key, None)

            time.sleep(self.poll_interval_sec)
