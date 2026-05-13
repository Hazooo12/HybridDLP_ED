from __future__ import annotations

if True:

    import os
    import time
    import hashlib
    from dataclasses import dataclass
    from pathlib import Path
    from typing import Any, Dict, List, Optional, Set, Tuple
    from collections import deque

    # Optional (better rename/move support)
    try:
        from watchdog.observers import Observer  # type: ignore
        from watchdog.events import FileSystemEventHandler  # type: ignore
        _HAS_WATCHDOG = True
    except Exception:
        Observer = None
        FileSystemEventHandler = object
        _HAS_WATCHDOG = False

    try:
        from .volume_watch_manager import VolumeWatchManager
        from .file_correlation import FileCorrelationEngine, RawPendingEvent
    except ImportError:
        VolumeWatchManager = None  # type: ignore[misc, assignment]
        FileCorrelationEngine = None  # type: ignore[misc, assignment]
        RawPendingEvent = None  # type: ignore[misc, assignment]


    # -----------------------------
    # Lightweight helpers (Windows-first)
    # -----------------------------
    _CLOUD_HINTS = [
        "onedrive",
        "dropbox",
        "google drive",
        "gdrive",
        "syncthing",
        "megasync",
        "box",
        "iclouddrive",
        "icloud drive",
    ]

    _ARCHIVE_EXTS = {".zip", ".7z", ".rar", ".tar", ".gz", ".bz2", ".xz"}
    _TABULAR_EXTS = {".csv", ".tsv", ".xlsx", ".xls"}
    _TEXTISH_EXTS = {".txt", ".csv", ".tsv", ".json", ".log", ".env", ".ini", ".cfg", ".yaml", ".yml", ".xml"}


    def _now() -> float:
        return time.time()


    def _iso_utc(ts: float) -> str:
        from datetime import datetime, timezone
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


    def _norm_path(p: str) -> str:
        try:
            p2 = os.path.expandvars(os.path.expanduser(p))
            return str(Path(p2).resolve())
        except Exception:
            return p


    def _default_screenshot_watch_paths() -> List[str]:
        paths: List[str] = []
        up = os.path.expandvars(os.path.expanduser(r"%USERPROFILE%"))
        if up:
            paths.append(os.path.join(up, "Pictures", "Screenshots"))
            paths.append(os.path.join(up, "Pictures"))
            paths.append(os.path.join(up, "Desktop"))
        return paths


    def _get_ext(p: str) -> str:
        try:
            ext = Path(p).suffix.lower()
            return ext if ext else ""
        except Exception:
            return ""


    def _get_name(p: str) -> Optional[str]:
        try:
            return Path(p).name
        except Exception:
            return None


    def _maybe_drive_letter(p: str) -> Optional[str]:
        try:
            if len(p) >= 2 and p[1] == ":":
                return p[:2].upper()
        except Exception:
            pass
        return None


    def _is_cloud_path(p: str) -> bool:
        s = (p or "").lower()
        return any(h in s for h in _CLOUD_HINTS)


    def _entropy_bytes(b: bytes) -> float:
        if not b:
            return 0.0
        freq = [0] * 256
        for x in b:
            freq[x] += 1
        n = len(b)
        import math
        ent = 0.0
        for c in freq:
            if c:
                p = c / n
                ent -= p * math.log2(p)
        return float(ent)


    def _read_head(path: str, max_bytes: int = 8192) -> bytes:
        try:
            with open(path, "rb") as f:
                return f.read(max_bytes)
        except Exception:
            return b""


    def _read_text_sample(path: str, max_chars: int = 400) -> Tuple[Optional[str], Optional[int]]:
        try:
            ext = _get_ext(path)
            if ext not in _TEXTISH_EXTS:
                return None, None
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                txt = f.read(min(4096, max_chars * 4))
            txt = txt[:max_chars]
            return txt, len(txt)
        except Exception:
            return None, None


    def _file_sha256_ex(path: str, max_bytes: Optional[int] = None) -> Tuple[Optional[str], Optional[int]]:
        """Return (hex_digest, bytes_read). bytes_read is None on total failure."""
        bytes_read = 0
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                if max_bytes is None:
                    while True:
                        chunk = f.read(1024 * 1024)
                        if not chunk:
                            break
                        h.update(chunk)
                        bytes_read += len(chunk)
                else:
                    remaining = int(max_bytes)
                    while remaining > 0:
                        chunk = f.read(min(1024 * 1024, remaining))
                        if not chunk:
                            break
                        h.update(chunk)
                        n = len(chunk)
                        bytes_read += n
                        remaining -= n
            return h.hexdigest(), int(bytes_read)
        except Exception:
            return None, None


    @dataclass
    class _HashResult:
        """Single hash computation outcome for DLP semantics (partial vs full, provenance)."""

        value: Optional[str]
        kind: str  # partial | full | none | unknown
        source: str  # fresh_read | path_cache | fallback_previous_meta | fresh_read_failed
        bytes_read: Optional[int]

        def to_dict(self) -> Dict[str, Any]:
            return {
                "value": self.value,
                "kind": self.kind,
                "source": self.source,
                "bytes_read": self.bytes_read,
            }

        @staticmethod
        def from_dict(d: Dict[str, Any], source_override: Optional[str] = None) -> "_HashResult":
            return _HashResult(
                d.get("value"),
                str(d.get("kind") or "none"),
                str(source_override or d.get("source") or "unknown"),
                d.get("bytes_read"),
            )


    def _fingerprint_cache_key(
        size: Optional[int],
        digest: str,
        signature: Optional[str],
    ) -> str:
        sz = int(size) if size is not None else -1
        sig = (signature or "").strip().lower()
        return f"{sz}|{digest}|{sig}"


    def _object_id(path: str, size: Optional[int], mtime: Optional[float]) -> str:
        base = f"{path}|{size if size is not None else 'na'}|{mtime if mtime is not None else 'na'}"
        return hashlib.sha256(base.encode("utf-8", errors="ignore")).hexdigest()[:24]


    def _stable_object_id(
        file_hash: Optional[str],
        path: str,
        size: Optional[int],
        mtime: Optional[float],
    ) -> str:
        if file_hash:
            return hashlib.sha256(f"h|{file_hash}".encode("utf-8", errors="ignore")).hexdigest()[:24]
        fp = f"{size if size is not None else 'na'}|{mtime if mtime is not None else 'na'}"
        return hashlib.sha256(f"fp|{fp}|{path.lower()}".encode("utf-8", errors="ignore")).hexdigest()[:24]


    def _object_identity_strength(hash_kind: str, has_hash: bool) -> str:
        if has_hash and hash_kind == "full":
            return "strong_content"
        if has_hash:
            return "probabilistic_content"
        return "path_fingerprint"


    def _signature_from_magic(head: bytes, ext: str = "") -> Optional[str]:
        if not head:
            return None

        if head.startswith(b"\x37\x7A\xBC\xAF\x27\x1C"):
            return "7z"

        if head.startswith(b"Rar!\x1A\x07\x00") or head.startswith(b"Rar!\x1A\x07\x01\x00"):
            return "rar"

        if head.startswith(b"%PDF-"):
            return "pdf"

        if head.startswith(b"\x89PNG\r\n\x1A\n"):
            return "png"

        if head.startswith(b"\xFF\xD8\xFF"):
            return "jpg"

        if head.startswith(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"):
            if ext == ".doc":
                return "doc"
            if ext == ".xls":
                return "xls"
            if ext == ".ppt":
                return "ppt"
            return "ole"

        if head.startswith(b"RIFF") and head[8:12] == b"AVI ":
            return "avi"

        if head.startswith(b"RIFF") and head[8:12] == b"WAVE":
            return "wav"

        if head.startswith(b"fLaC"):
            return "flac"

        if head.startswith(b"ID3"):
            return "mp3"

        if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06") or head.startswith(b"PK\x07\x08"):
            if ext == ".docx":
                return "docx"
            if ext == ".xlsx":
                return "xlsx"
            if ext == ".pptx":
                return "pptx"
            return "zip"

        return "bin"


    def _zip_password_protected(path: str) -> Optional[bool]:
        try:
            import zipfile
            with zipfile.ZipFile(path, "r") as zf:
                for zi in zf.infolist():
                    if zi.flag_bits & 0x1:
                        return True
            return False
        except Exception:
            return None


    def _volume_type_windows(drive: Optional[str]) -> Optional[str]:
        if not drive:
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


    def _parse_demo_usb_drive_letters() -> Set[str]:
        """Letters (e.g. D) from FILE_SENSOR_DEMO_USB_DRIVES; default env value is ``D``."""
        raw = os.getenv("FILE_SENSOR_DEMO_USB_DRIVES", "D").strip()
        if raw.lower() in {"", "none", "off", "-"}:
            return set()
        out: Set[str] = set()
        for part in raw.replace(",", ";").split(";"):
            p = part.strip().upper()
            if len(p) == 1 and p.isalpha():
                out.add(p)
            elif len(p) >= 2 and p[1] == ":":
                out.add(p[0])
        return out


    def _is_same_parent(a: str, b: str) -> bool:
        try:
            return Path(a).parent == Path(b).parent
        except Exception:
            return False


    def _infer_op_type(evt_kind: str, src_path: str, dst_path: Optional[str], effective_volume_type: Optional[str]) -> str:
        """
        Canonical-ish operation type for rules.
        """
        if evt_kind == "deleted":
            return "file_delete"

        if evt_kind == "modified":
            return "file_modify"

        if evt_kind == "moved":
            if dst_path and _is_same_parent(src_path, dst_path) and _get_name(src_path) != _get_name(dst_path):
                return "file_rename"
            return "file_move"

        if evt_kind == "created":
            # Creation on cloud/removable/network often semantically behaves like copy
            if effective_volume_type in {"Removable", "Network"}:
                return "file_copy_external"
            if dst_path and _is_cloud_path(dst_path):
                return "file_copy_external"
            if _is_cloud_path(src_path):
                return "file_copy_external"
            return "file_create"

        return "file_event"


    def _infer_op_type_v2(
        evt_kind: str,
        src_path: str,
        dst_path: Optional[str],
        src_volume_type: Optional[str],
        dest_volume_type: Optional[str],
        correlation_action: Optional[str] = None,
        external_create_semantic: Optional[str] = None,
    ) -> str:
        if correlation_action == "move_to_external":
            return "file_move_external"
        if correlation_action == "move_same_volume":
            return "file_move"
        if correlation_action == "copy_to_external":
            return "file_copy_external"

        if evt_kind == "deleted":
            return "file_delete"
        if evt_kind == "modified":
            return "file_modify"

        if evt_kind == "moved":
            if dst_path and _is_same_parent(src_path, dst_path) and _get_name(src_path) != _get_name(dst_path):
                return "file_rename"
            sd = _maybe_drive_letter(src_path)
            dd = _maybe_drive_letter(dst_path) if dst_path else None
            if sd and dd and sd != dd:
                if dest_volume_type in {"Removable", "Network"} or _is_cloud_path(dst_path or ""):
                    return "file_move_external"
            return "file_move"

        if evt_kind == "created":
            if external_create_semantic == "move_to_removable":
                return "file_move_external"
            if external_create_semantic == "copy_to_removable":
                return "file_copy_external"
            vt = dest_volume_type or src_volume_type
            if vt in {"Removable", "Network"}:
                return "file_copy_external"
            if _is_cloud_path(src_path) or (dst_path and _is_cloud_path(dst_path)):
                return "file_copy_external"
            return "file_create"

        return _infer_op_type(evt_kind, src_path, dst_path, dest_volume_type or src_volume_type)


    def _infer_report_event_type(evt_kind: str, src_path: str, dst_path: Optional[str]) -> str:
        if evt_kind == "created":
            return "Create"
        if evt_kind == "modified":
            return "Modify"
        if evt_kind == "deleted":
            return "Delete"
        if evt_kind == "moved":
            try:
                if dst_path:
                    sp = Path(src_path)
                    dp = Path(dst_path)
                    if sp.parent == dp.parent and sp.name != dp.name:
                        return "Rename"
            except Exception:
                pass
            return "Move"
        return "Modify"


    def _infer_operation_type(
        evt_kind: str,
        src_path: str,
        dst_path: Optional[str],
        overwrite: bool = False,
        effective_volume_type: Optional[str] = None,
        correlation_action: Optional[str] = None,
        external_create_semantic: Optional[str] = None,
    ) -> str:
        if correlation_action == "move_to_external":
            return "MoveExternal"
        if correlation_action == "move_same_volume":
            return "Move"
        if correlation_action == "copy_to_external":
            return "CopyExternal"

        if evt_kind == "moved":
            try:
                if dst_path and Path(src_path).parent == Path(dst_path).parent and Path(src_path).name != Path(dst_path).name:
                    return "Rename"
            except Exception:
                pass
            return "Move"

        if evt_kind == "created":
            if external_create_semantic == "move_to_removable":
                return "MoveExternal"
            if external_create_semantic == "copy_to_removable":
                return "CopyExternal"
            if external_create_semantic == "unknown_external_create":
                return "CopyExternal"
            if effective_volume_type in {"Removable", "Network"} or _is_cloud_path(dst_path or src_path):
                return "Copy"
            return "Create"

        if overwrite:
            return "Overwrite"
        if evt_kind == "deleted":
            return "Delete"
        return "Modify"


    def _looks_like_leaked_browser_domain(value: str) -> bool:
        """Foreground URL/domain hints that should not drive file/USB conclusions."""
        s = (value or "").strip().lower()
        if not s:
            return False
        if "drive.google.com" in s or s.endswith(".google.com") or "docs.google.com" in s:
            return True
        if "sharepoint.com" in s or "onedrive" in s:
            return True
        if "dropbox.com" in s:
            return True
        if "box.com" in s:
            return True
        return False


    def _classify_sensitivity(ext: str, signature: Optional[str], path: str) -> str:
        p = (path or "").lower()
        is_doc = (ext in {".doc", ".docx", ".pdf"}) or (signature in {"pdf", "doc", "docx"})
        is_tab = ext in {".csv", ".tsv", ".xlsx", ".xls"}
        is_office_zip = ext in {".docx", ".xlsx", ".pptx"} or (signature in {"docx", "xlsx", "pptx"})

        if ("finance" in p or "hr" in p or "customer" in p or "payroll" in p or "salary" in p or "employee" in p) and (is_tab or is_doc or is_office_zip):
            return "Highly Sensitive"
        if is_tab or is_doc or is_office_zip:
            return "Sensitive"
        return "Normal"


    def _should_enrich(path: str, dst_path: Optional[str], ext: str, dest_volume_type: Optional[str], op_type: str) -> Dict[str, bool]:
        risk_dst = bool((dst_path and _is_cloud_path(dst_path)) or _is_cloud_path(path))
        risk_volume = bool(dest_volume_type is not None and dest_volume_type != "Fixed")
        rename_like = bool(op_type in {"file_move", "file_rename", "file_move_external"} and dst_path and (_get_ext(path) != _get_ext(dst_path)))
        archive_like = (ext in _ARCHIVE_EXTS) or bool(dst_path and _get_ext(dst_path) in _ARCHIVE_EXTS)
        tabular_like = ext in _TABULAR_EXTS
        textish_like = ext in _TEXTISH_EXTS

        return {
            "need_signature": bool(risk_dst or risk_volume or rename_like or archive_like or tabular_like),
            "need_hash": bool(risk_dst or risk_volume or rename_like or op_type in {"file_copy", "file_copy_external", "file_move", "file_move_external", "file_rename"}),
            "need_entropy": bool(archive_like or rename_like),
            "need_zip_pw": bool((ext == ".zip") or (dst_path and _get_ext(dst_path) == ".zip")),
            "need_sample": bool(tabular_like or textish_like),
        }


    def _cloud_provider_from_path(p: Optional[str]) -> Optional[str]:
        s = (p or "").lower()
        if "onedrive" in s:
            return "OneDrive"
        if "dropbox" in s:
            return "Dropbox"
        if "google drive" in s or "gdrive" in s:
            return "Google Drive"
        if "box" in s:
            return "Box"
        if "iclouddrive" in s or "icloud drive" in s:
            return "iCloud Drive"
        if "megasync" in s or "\\mega" in s:
            return "MEGA"
        if "syncthing" in s:
            return "Syncthing"
        return None


    @dataclass
    class _StatLite:
        size: int
        mtime: float
        exists: bool


    class FileSystemSensor:
        """
        FILE SYSTEM SENSOR (L1 - metadata only)

        Emits canonical fields:
        - actor.*
        - object.*
        - operation.*
        - metrics.*
        - flags.*
        - content.*

        Keeps legacy flat/report fields for backward compatibility.
        """

        def __init__(
            self,
            queue_manager,
            watch_paths: Optional[List[str]] = None,
            poll_interval_sec: float = 0.5,
            max_head_bytes: int = 8192,
            hash_max_bytes: Optional[int] = 2 * 1024 * 1024,
            sample_max_chars: int = 400,
            agg_window_sec: float = 180.0,
            auto_watch_screenshots: bool = True,
            include_exts: Optional[List[str]] = None,
            exclude_dirs: Optional[List[str]] = None,
        ):
            self.qm = queue_manager
            self.poll_interval_sec = float(poll_interval_sec)
            self.max_head_bytes = int(max_head_bytes)
            self.hash_max_bytes = hash_max_bytes
            self.sample_max_chars = int(sample_max_chars)
            # Keep sensor lightweight by default, but require hash field for user file ops when possible.
            self.require_sha256_for_user_ops = os.getenv("FILE_SENSOR_REQUIRE_SHA256", "1").strip().lower() in {"1", "true", "yes", "on"}
            self.hash_full_for_user_ops = os.getenv("FILE_SENSOR_HASH_FULL_FOR_USER_OPS", "0").strip().lower() in {"1", "true", "yes", "on"}
            self.full_hash_on_external = os.getenv("FILE_SENSOR_FULL_HASH_ON_EXTERNAL", "0").strip().lower() in {
                "1",
                "true",
                "yes",
                "on",
            }
            # path|size|mtime → last _HashResult dict (L1 path-state cache)
            self._hash_cache: Dict[str, Dict[str, Any]] = {}
            # size|digest|signature → same dict (hint for L2 correlation; optional reuse guarded by env)
            self._content_fp_cache: Dict[str, Dict[str, Any]] = {}

            self.agg_window_sec = float(agg_window_sec)
            self.bulk_count_window_sec = float(os.getenv("FILE_SENSOR_BULK_WINDOW_SEC", "10.0"))
            self._recent_events: deque[Tuple[float, str]] = deque(maxlen=10000)
            self._recent_events_short: deque[Tuple[float, str]] = deque(maxlen=10000)
            self._recent_sensitive_artifacts: deque[Tuple[float, str, str]] = deque(maxlen=5000)
            self._recent_files_by_pid: Dict[int, deque[Dict[str, Any]]] = {}
            self._recent_sensitive_by_pid: Dict[int, deque[Dict[str, Any]]] = {}

            self.include_exts = [e.lower() for e in (include_exts or [])] or None
            self.exclude_dirs = [s.lower() for s in (exclude_dirs or [])] or []

            self.watch_paths: List[str] = []
            for p in (watch_paths or []):
                self.add_watch_path(p)

            if auto_watch_screenshots and not self.watch_paths:
                for p in _default_screenshot_watch_paths():
                    self.add_watch_path(p)

            # Demo: treat chosen letters as Removable (USB) and watch their roots (default D: on Windows).
            self._demo_usb_enabled = os.name == "nt" and os.getenv("FILE_SENSOR_DEMO_USB", "1").strip().lower() in {
                "1",
                "true",
                "yes",
                "on",
            }
            self._demo_usb_letters: Set[str] = set()
            if self._demo_usb_enabled:
                self._demo_usb_letters = _parse_demo_usb_drive_letters()
                if not self._demo_usb_letters:
                    self._demo_usb_letters = {"D"}
                for letter in sorted(self._demo_usb_letters):
                    root = f"{letter}:\\"
                    try:
                        if os.path.exists(root):
                            self.add_watch_path(root)
                    except Exception:
                        pass

            self._snap: Dict[str, _StatLite] = {}
            self._last_meta: Dict[str, Dict[str, Any]] = {}

            self._observer = None
            self._watch_handler_ref: Any = None
            self._observed_watch_by_path: Dict[str, Any] = {}
            self._volume_manager: Any = None

            # Default > 0 merges same-volume delete+create and C:→USB pairs without extra env.
            # Set FILE_SENSOR_CORRELATION_WINDOW_SEC=0 to disable (legacy two-event behavior).
            cw = float(os.getenv("FILE_SENSOR_CORRELATION_WINDOW_SEC", "0.75"))
            self._correlation_engine = (
                FileCorrelationEngine(cw) if (cw > 0 and FileCorrelationEngine is not None) else None
            )

            self._fixed_candidate_ttl_sec = float(os.getenv("FILE_SENSOR_FIXED_CANDIDATE_TTL_SEC", "120"))
            self._usb_semantic_window_sec = float(os.getenv("FILE_SENSOR_USB_SEMANTIC_WINDOW_SEC", "30"))
            self._fixed_content_candidates: deque = deque(maxlen=800)
            self._fixed_deleted_recent: deque = deque(maxlen=400)

            if os.name == "nt" and VolumeWatchManager is not None and os.getenv(
                "FILE_SENSOR_VOLUME_WATCH", "1"
            ).strip().lower() in {"1", "true", "yes", "on"}:
                self._volume_manager = VolumeWatchManager(
                    poll_interval_sec=float(os.getenv("FILE_SENSOR_VOLUME_POLL_SEC", "3")),
                    on_mount=self._volume_mount_callback,
                    on_unmount=self._volume_unmount_callback,
                    emit_event=self._emit,
                )

            # Soft-ignore: still emit with flags.soft_noise_path (comma/semicolon path substring list, lowered)
            _soft_raw = os.getenv("FILE_SENSOR_SOFT_NOISE_TOKENS", "")
            self._soft_noise_path_tokens = tuple(
                x.strip().lower().replace("/", "\\")
                for x in _soft_raw.replace(",", ";").split(";")
                if x.strip()
            )

            # Noise suppression (ported concept from Sensor/sensor_system/sensors/file_sensor.py)
            # Goal: reduce duplicates / false positives from temp caches and fast re-writes.
            self._suppress_modified_until: Dict[str, float] = {}
            self._modified_suppress_window_seconds = 2.0
            # Dedup/rate-limit knobs (env-configurable to tune without code change).
            self._event_dedup_window_seconds = float(os.getenv("FILE_SENSOR_DEDUP_WINDOW_SEC", "2.0"))
            self._proc_rate_window_seconds = float(os.getenv("FILE_SENSOR_PROCESS_WINDOW_SEC", "5.0"))
            self._max_events_per_process_window = int(os.getenv("FILE_SENSOR_MAX_EVENTS_PER_PROCESS_WINDOW", "40"))
            self._recent_event_keys: Dict[str, float] = {}
            self._recent_event_times_by_pid: Dict[str, deque[float]] = {}
            # Chuỗi so sánh với path đã .lower() — luôn viết thường (Note: trước đây HybridDLP_ED hoa → không khớp).
            _default_noise = (
                "\\windows\\",
                "\\program files\\",
                "\\program files (x86)\\",
                "\\programdata\\",
                "\\appdata\\",
                "\\system32\\",
                "\\$recycle.bin\\",
                "\\system volume information\\",
                "\\cache\\",
                "\\dawncache\\",
                "\\local storage\\leveldb\\",
                "\\session storage\\",
                "\\webstorage\\",
                "\\antigravity\\",
                "\\code cache\\",
                "\\gpucache\\",
                "\\python\\python312\\",
                "\\python\\python311\\",
                "\\python\\python310\\",
                "\\hybriddlp_ed\\",
                "\\dld_ia01\\",
                "\\programs\\cursor\\",
                "\\.cursor\\",
                "\\.vscode\\",
                "\\.idea\\",
                "\\roaming\\github desktop\\",
                "\\zalo\\local storage\\",
                "\\network\\",
                "\\logs\\",
                "\\indexeddb\\",
                "\\service worker\\",
                "\\localstate\\tabstate\\",
                "\\microsoft visual studio\\",
                "\\.git\\",
                "\\__pycache__\\",
                "\\node_modules\\",
                "\\.pytest_cache\\",
                "\\.venv\\",
                "\\venv\\",
                "\\site-packages\\",
                "\\.mypy_cache\\",
                "\\.ruff_cache\\",
                "\\dist\\",
                "\\build\\",
                "\\.egg-info\\",
            )
            extra = os.getenv("FILE_SENSOR_EXTRA_NOISE_TOKENS", "").strip()
            _extra_toks = tuple(
                x.strip().lower()
                for x in extra.split(";")
                if x.strip()
            )
            self._noise_path_tokens = tuple(
                t.lower().replace("/", "\\") for t in (_default_noise + _extra_toks)
            )
            self._noise_extensions = {
                ".tmp",
                ".temp",
                ".log",
                ".log1",
                ".log2",
                ".mui",
                ".nlp",
                ".dll",
                ".db",
                ".jsonl",
                ".ldb",
                ".sqlite",
                ".journal",
                ".wal",
                ".idx",
                ".pack",
                ".pkl",
                ".bin",
                ".exe",
                ".pyc",
                ".pyo",
                ".pyd",
                ".so",
                ".cache",
                ".lock",
                ".bak",
                ".swp",
                ".swo",
                ".db-wal",
                ".db-journal",
                ".db-shm",
            }
            # .json trong noise gây bỏ sót file cấu hình nhạy cảm — chỉ lọc .json dưới thư mục cache/editor
            self._noise_json_path_markers = (
                "\\cache\\",
                "leveldb",
                "code cache",
                "vscode",
                "cursor",
                "appdata",
                "node_modules",
                ".git",
            )

        def add_watch_path(self, path: str) -> None:
            p = _norm_path(path)
            try:
                if p and os.path.isdir(p):
                    if p not in self.watch_paths:
                        self.watch_paths.append(p)
                    self._schedule_observer_path(p)
            except Exception:
                pass

        def _volume_mount_callback(self, root: str, vt: str) -> None:
            self.add_watch_path(root)

        def _volume_unmount_callback(self, root: str) -> None:
            self._unschedule_observer_path(_norm_path(root))

        def _schedule_observer_path(self, path: str) -> None:
            if not path or not os.path.isdir(path):
                return
            if path in self._observed_watch_by_path:
                return
            obs = self._observer
            h = self._watch_handler_ref
            if not obs or not h:
                return
            try:
                w = obs.schedule(h, path, recursive=True)
                self._observed_watch_by_path[path] = w
            except Exception:
                pass

        def _unschedule_observer_path(self, path: str) -> None:
            p = _norm_path(path)
            to_drop = [
                k
                for k in list(self._observed_watch_by_path.keys())
                if _norm_path(k).lower() == p.lower()
            ]
            obs = self._observer
            for k in to_drop:
                w = self._observed_watch_by_path.pop(k, None)
                if obs and w is not None:
                    try:
                        obs.unschedule(w)
                    except Exception:
                        try:
                            obs.remove_watch(w)  # type: ignore[attr-defined]
                        except Exception:
                            pass
            self.watch_paths[:] = [
                w for w in self.watch_paths if _norm_path(w).lower() != p.lower()
            ]

        def _ignore_level(self, path: str) -> str:
            lp = (path or "").lower().replace("/", "\\")
            if self.exclude_dirs and any((x or "").lower() in lp for x in self.exclude_dirs):
                return "hard"
            if any(tok in lp for tok in self._noise_path_tokens):
                return "hard"
            try:
                suf = Path(lp).suffix
                if suf in self._noise_extensions:
                    return "hard"
                if suf == ".json" and any(m in lp for m in self._noise_json_path_markers):
                    return "hard"
            except Exception:
                pass
            if self.include_exts is not None:
                if _get_ext(path) not in self.include_exts:
                    return "hard"
            if self._soft_noise_path_tokens and any(tok in lp for tok in self._soft_noise_path_tokens):
                return "soft"
            return "ok"

        def _should_ignore(self, path: str) -> bool:
            return self._ignore_level(path) == "hard"

        def _volume_type_effective(self, drive: Optional[str]) -> Optional[str]:
            """Windows GetDriveType, unless drive letter is in demo USB list → Removable."""
            if drive and len(drive) >= 2 and drive[1] == ":":
                letter = drive[0].upper()
                if letter in self._demo_usb_letters:
                    return "Removable"
            return _volume_type_windows(drive)

        def _prune_fixed_buffers(self, now: float) -> None:
            ttl = max(1.0, self._fixed_candidate_ttl_sec)
            while self._fixed_content_candidates and (now - self._fixed_content_candidates[0]["ts"]) > ttl:
                self._fixed_content_candidates.popleft()
            while self._fixed_deleted_recent and (now - self._fixed_deleted_recent[0]["ts"]) > ttl:
                self._fixed_deleted_recent.popleft()

        def _remember_fixed_delete(
            self,
            ts: float,
            path: str,
            size: Optional[int],
            file_hash: Optional[str],
        ) -> None:
            if not file_hash or size is None:
                return
            self._prune_fixed_buffers(ts)
            self._fixed_deleted_recent.append(
                {"ts": ts, "path": path, "size": int(size), "hash": file_hash}
            )

        def _remember_fixed_file_observation(
            self,
            ts: float,
            path: str,
            size: int,
            file_hash: str,
            pid: Any,
            process: Any,
        ) -> None:
            d = _maybe_drive_letter(path)
            if self._volume_type_effective(d) != "Fixed":
                return
            self._prune_fixed_buffers(ts)
            self._fixed_content_candidates.append(
                {
                    "ts": ts,
                    "path": path,
                    "size": int(size),
                    "hash": file_hash,
                    "pid": pid,
                    "process": process,
                }
            )

        def _infer_external_create_semantic(
            self,
            dest_path: str,
            dest_size: int,
            dest_hash: str,
            ts: float,
            ctx: Dict[str, Any],
        ) -> Tuple[str, Optional[str], Dict[str, Any]]:
            """
            Infer copy vs move onto Removable/Network when only a destination create is flushed.
            Uses recent Fixed deletes (hash+size) and Fixed file observations (hash+size + path exists).

            Rule flow (L1, evidence-based; D = external dest, C = fixed internal path):
            - Create on D + hash matches a recent delete on C (same hash+size, within window)
              -> move_strong (source disappeared: delete event).
            - Create on D + hash matches a recent observation on C + reconcile shows path gone
              -> move_likely.
            - Create on D + hash matches observation on C + path still exists
              -> copy_not_move.
            - Create on D but no correlation to recent fixed-disk hash+size state
              -> copy_or_move_candidate (ambiguous; not enough to prove move from C).
            """
            detail: Dict[str, Any] = {}
            win = max(0.5, self._usb_semantic_window_sec)
            self._prune_fixed_buffers(ts)

            for rec in reversed(self._fixed_deleted_recent):
                if ts - rec["ts"] > win:
                    continue
                if rec.get("hash") == dest_hash and rec.get("size") == dest_size:
                    detail["match"] = "fixed_delete_hash_size"
                    detail["matched_ts_delta_sec"] = round(ts - rec["ts"], 4)
                    detail["copy_move_verdict"] = "move_strong"
                    detail["copy_move_evidence"] = "source_delete_hash_size_in_window"
                    detail["inferred_source_path"] = rec.get("path")
                    return "move_to_removable", rec.get("path"), detail

            best: Optional[Dict[str, Any]] = None
            for rec in reversed(self._fixed_content_candidates):
                if ts - rec["ts"] > win:
                    continue
                if rec.get("hash") != dest_hash or rec.get("size") != dest_size:
                    continue
                if best is None or rec["ts"] > best["ts"]:
                    best = rec

            if best is None:
                detail["match"] = "none"
                detail["copy_move_verdict"] = "copy_or_move_candidate"
                detail["copy_move_evidence"] = "no_fixed_disk_hash_size_correlation"
                return "unknown_external_create", None, detail

            src_path = str(best["path"])
            detail["match"] = "fixed_candidate_hash_size"
            detail["matched_ts_delta_sec"] = round(ts - best["ts"], 4)
            detail["inferred_source_path"] = src_path
            try:
                still = bool(os.path.exists(src_path))
            except Exception:
                still = True
            detail["source_still_exists"] = still
            if still:
                detail["copy_move_verdict"] = "copy_not_move"
                detail["copy_move_evidence"] = "reconcile_source_path_still_exists"
                return "copy_to_removable", src_path, detail
            detail["copy_move_verdict"] = "move_likely"
            detail["copy_move_evidence"] = "reconcile_source_path_missing"
            return "move_to_removable", src_path, detail

        def _sanitize_ctx_for_file_external(
            self,
            ctx: Dict[str, Any],
            dest_volume_type: Optional[str],
            evt_kind: str,
        ) -> Dict[str, Any]:
            if evt_kind not in {"created", "modified", "moved"}:
                return ctx
            if dest_volume_type not in {"Removable", "Network"}:
                return ctx
            out = dict(ctx)
            suppressed = False
            for k in ("fg_domain", "dest_domain", "domain", "resolved_domain", "fg_url_hint"):
                v = out.get(k)
                if v and _looks_like_leaked_browser_domain(str(v)):
                    out[k] = None
                    suppressed = True
            if suppressed:
                out["file_context_domain_suppressed"] = True
            return out

        def _ingest_fs_event(
            self,
            evt_kind: str,
            src_path: str,
            dst_path: Optional[str],
            ctx: Dict[str, Any],
        ) -> None:
            p = _norm_path(src_path)
            dp = _norm_path(dst_path) if dst_path else None
            target = dp or p
            lev = self._ignore_level(target)
            if lev == "hard":
                return
            soft = lev == "soft"

            if self._should_drop_burst_event(evt_kind, p, dp, ctx):
                return

            src_drive = _maybe_drive_letter(p)
            dst_drive = _maybe_drive_letter(dp) if dp else None
            src_vol = self._volume_type_effective(src_drive)
            dst_vol = self._volume_type_effective(dst_drive) if dp else None

            if evt_kind == "deleted" and src_vol == "Fixed":
                meta = self._last_meta.get(p) or {}
                self._remember_fixed_delete(_now(), p, meta.get("size"), meta.get("hash"))

            size_hint: Optional[int] = None
            if evt_kind == "deleted":
                meta = self._last_meta.get(p)
                if meta:
                    size_hint = meta.get("size")
            else:
                st = self._stat_best_effort(dp or p)
                if st.get("size") is not None:
                    size_hint = int(st["size"])

            if not self._correlation_engine or RawPendingEvent is None:
                try:
                    self._emit(
                        self._build_event(
                            evt_kind, src_path, dst_path, ctx, soft_noise=soft, skip_dedup=True
                        )
                    )
                except RuntimeError:
                    pass
                return

            raw = RawPendingEvent(
                ts=_now(),
                kind=evt_kind,
                src_path=p,
                dst_path=dp,
                ctx=ctx,
                size_hint=size_hint,
                hash_hint=(self._last_meta.get(p) or {}).get("hash") if evt_kind == "deleted" else None,
                src_volume_type=src_vol,
                dst_volume_type=dst_vol,
            )
            for plan in self._correlation_engine.handle(raw, _now()):
                try:
                    self._emit(
                        self._build_event(
                            plan.evt_kind,
                            plan.src_path,
                            plan.dst_path,
                            plan.ctx,
                            correlation_action=plan.correlation_action,
                            correlation_detail=plan.correlation_detail,
                            soft_noise=soft,
                            skip_dedup=True,
                        )
                    )
                except RuntimeError:
                    pass

        def _hash_cache_key(self, path: str, size: Optional[int], mtime: Optional[float]) -> Optional[str]:
            if not path:
                return None
            if size is None or mtime is None:
                return None
            return f"{path.lower()}|{int(size)}|{float(mtime)}"

        def _resolve_file_hash(
            self,
            path: str,
            size: Optional[int],
            mtime: Optional[float],
            want_full: bool,
            signature: Optional[str],
        ) -> "_HashResult":
            """
            Tier 1: path|size|mtime cache. Then disk read; tier 2 registers size|digest|signature for L2 correlation.
            """
            key = self._hash_cache_key(path, size=size, mtime=mtime)
            if key:
                cached = self._hash_cache.get(key)
                if cached:
                    return _HashResult.from_dict(cached, source_override="path_cache")
            max_bytes = None if want_full else self.hash_max_bytes
            digest, bread = _file_sha256_ex(path, max_bytes=max_bytes)
            if digest is None:
                return _HashResult(None, "none", "fresh_read_failed", bread)
            kind: str = "full" if want_full or max_bytes is None else "partial"
            res = _HashResult(digest, kind, "fresh_read", bread)
            if key:
                self._hash_cache[key] = res.to_dict()
            fpk = _fingerprint_cache_key(size, digest, signature)
            if fpk:
                self._content_fp_cache[fpk] = res.to_dict()
            return res

        def _mark_suppress_modified(self, path: Optional[str]) -> None:
            if not path:
                return
            self._suppress_modified_until[str(path)] = time.monotonic() + self._modified_suppress_window_seconds

        def _should_suppress_modified(self, path: Optional[str]) -> bool:
            if not path:
                return False
            now = time.monotonic()
            exp = self._suppress_modified_until.get(str(path))
            if exp is None:
                return False
            if now <= exp:
                return True
            # expired
            self._suppress_modified_until.pop(str(path), None)
            return False

        def _emit(self, evt: Dict[str, Any]) -> None:
            try:
                self.qm.enqueue_event(evt)
            except Exception:
                pass

        def _event_dedup_key(
            self,
            evt_kind: str,
            src_path: str,
            dst_path: Optional[str],
            pid: Optional[Any],
            proc_name: Optional[str],
        ) -> str:
            src = (src_path or "").lower()
            dst = (dst_path or "").lower()
            pid_s = str(pid) if pid is not None else "na"
            proc_s = (proc_name or "").lower()
            return f"{evt_kind}|{src}|{dst}|{pid_s}|{proc_s}"

        def _cleanup_recent_event_keys(self, now_mono: float) -> None:
            cutoff = now_mono - self._event_dedup_window_seconds
            stale = [k for k, ts in self._recent_event_keys.items() if ts < cutoff]
            for k in stale:
                self._recent_event_keys.pop(k, None)

        def _should_drop_burst_event(
            self,
            evt_kind: str,
            src_path: str,
            dst_path: Optional[str],
            ctx: Dict[str, Any],
        ) -> bool:
            now_mono = time.monotonic()
            self._cleanup_recent_event_keys(now_mono)

            pid = ctx.get("fg_pid")
            proc_name = ctx.get("fg_app") or ctx.get("fg_process")
            key = self._event_dedup_key(evt_kind, src_path, dst_path, pid, proc_name)
            last = self._recent_event_keys.get(key)
            if last is not None and (now_mono - last) < self._event_dedup_window_seconds:
                return True
            self._recent_event_keys[key] = now_mono

            pid_key = str(pid) if pid is not None else "na"
            dq = self._recent_event_times_by_pid.setdefault(pid_key, deque())
            cutoff = now_mono - self._proc_rate_window_seconds
            while dq and dq[0] < cutoff:
                dq.popleft()
            if len(dq) >= self._max_events_per_process_window:
                return True
            dq.append(now_mono)
            return False

        def _ctx_snapshot(self, ctx_provider: Optional[Any]) -> Dict[str, Any]:
            if not ctx_provider:
                return {}
            try:
                return (ctx_provider.snapshot() or {}) if hasattr(ctx_provider, "snapshot") else {}
            except Exception:
                return {}

        def _stat_best_effort(self, p: str) -> Dict[str, Any]:
            try:
                st = os.stat(p)
                return {"size": int(st.st_size), "mtime": float(st.st_mtime), "exists": True}
            except Exception:
                return {"size": None, "mtime": None, "exists": False}

        def _agg_count(self, now: float, bucket: str) -> int:
            self._recent_events.append((now, bucket))
            cutoff = now - self.agg_window_sec
            while self._recent_events and self._recent_events[0][0] < cutoff:
                self._recent_events.popleft()
            return sum(1 for _, b in self._recent_events if b == bucket)

        def _agg_count_short(self, now: float, bucket: str) -> int:
            self._recent_events_short.append((now, bucket))
            cutoff = now - self.bulk_count_window_sec
            while self._recent_events_short and self._recent_events_short[0][0] < cutoff:
                self._recent_events_short.popleft()
            return sum(1 for _, b in self._recent_events_short if b == bucket)

        def _remember_sensitive_artifact(self, ts: float, path: str, sensitivity: str) -> None:
            if sensitivity not in {"Sensitive", "Highly Sensitive"}:
                return
            self._recent_sensitive_artifacts.append((ts, path, sensitivity))
            cutoff = ts - self.agg_window_sec
            while self._recent_sensitive_artifacts and self._recent_sensitive_artifacts[0][0] < cutoff:
                self._recent_sensitive_artifacts.popleft()

        def _recent_staging_count(self, ts: float) -> int:
            cutoff = ts - self.agg_window_sec
            while self._recent_sensitive_artifacts and self._recent_sensitive_artifacts[0][0] < cutoff:
                self._recent_sensitive_artifacts.popleft()
            return len(self._recent_sensitive_artifacts)

        def _remember_file_by_pid(
            self,
            ts: float,
            pid: Optional[int],
            process: Optional[str],
            path: str,
            size: Optional[int],
            file_hash: Optional[str],
            sensitivity: Optional[str],
        ) -> None:
            if pid is None:
                return
            try:
                pid_i = int(pid)
            except Exception:
                return
            rec = {
                "ts": ts,
                "pid": pid_i,
                "process": process,
                "path": path,
                "size": size,
                "hash": file_hash,
                "sensitivity": sensitivity,
            }
            q = self._recent_files_by_pid.setdefault(pid_i, deque(maxlen=256))
            q.append(rec)
            cutoff = ts - self.agg_window_sec
            while q and float(q[0].get("ts", 0.0)) < cutoff:
                q.popleft()

            if sensitivity in {"Sensitive", "Highly Sensitive"}:
                sq = self._recent_sensitive_by_pid.setdefault(pid_i, deque(maxlen=256))
                sq.append(rec)
                while sq and float(sq[0].get("ts", 0.0)) < cutoff:
                    sq.popleft()

        def _recent_pid_summary(self, ts: float, pid: Optional[int]) -> Dict[str, Any]:
            if pid is None:
                return {"pid_file_count": 0, "pid_sensitive_count": 0, "pid_recent_paths": []}
            try:
                pid_i = int(pid)
            except Exception:
                return {"pid_file_count": 0, "pid_sensitive_count": 0, "pid_recent_paths": []}
            cutoff = ts - self.agg_window_sec
            q = self._recent_files_by_pid.get(pid_i, deque())
            sq = self._recent_sensitive_by_pid.get(pid_i, deque())
            pid_paths: List[str] = []
            for x in list(q)[-5:]:
                if float(x.get("ts", 0.0)) >= cutoff and x.get("path"):
                    pid_paths.append(str(x.get("path")))
            pid_sensitive_count = sum(1 for x in list(sq) if float(x.get("ts", 0.0)) >= cutoff)
            pid_file_count = sum(1 for x in list(q) if float(x.get("ts", 0.0)) >= cutoff)
            return {
                "pid_file_count": pid_file_count,
                "pid_sensitive_count": pid_sensitive_count,
                "pid_recent_paths": pid_paths,
            }

        def _build_actor(self, ctx: Dict[str, Any]) -> Dict[str, Any]:
            return {
                "user": ctx.get("user"),
                "pid": ctx.get("fg_pid"),
                "process": (ctx.get("fg_process") or ctx.get("fg_app")),
                "cmdline": ctx.get("fg_cmdline"),
                "exe_path": ctx.get("fg_exe_path"),
            }

        def _build_object(
            self,
            src_path: str,
            dst_path: Optional[str],
            size: Optional[int],
            mtime: Optional[float],
            src_drive: Optional[str],
            src_volume_type: Optional[str],
            dest_drive: Optional[str],
            dest_volume_type: Optional[str],
            old_ext: Optional[str],
            new_ext: Optional[str],
            signature: Optional[str],
            sensitivity: str,
            file_name: Optional[str],
            file_ext: str,
            file_hash: Optional[str],
            object_id: str,
            cloud_provider: Optional[str],
        ) -> Dict[str, Any]:
            return {
                "id": object_id,
                "path": src_path,
                "dst_path": dst_path,
                "name": file_name,
                "ext": file_ext,
                "size": size,
                "mtime": _iso_utc(mtime) if isinstance(mtime, (int, float)) else None,
                "hash_sha256": file_hash,
                "signature": signature,
                "drive": dest_drive or src_drive,
                "volume_type": dest_volume_type or src_volume_type,
                "src_drive": src_drive,
                "src_volume_type": src_volume_type,
                "dest_drive": dest_drive,
                "dest_volume_type": dest_volume_type,
                "old_ext": old_ext,
                "new_ext": new_ext,
                "sensitivity": sensitivity,
                "cloud_provider": cloud_provider,
                "metadata": {},
                "content_preview": None,
                "content_preview_len": None,
            }

        def _build_event(
            self,
            evt_kind: str,
            src_path: str,
            dst_path: Optional[str],
            ctx: Dict[str, Any],
            *,
            correlation_action: Optional[str] = None,
            correlation_detail: Optional[Dict[str, Any]] = None,
            soft_noise: bool = False,
            skip_dedup: bool = False,
        ) -> Dict[str, Any]:
            ts = _now()
            p = _norm_path(src_path)
            dp = _norm_path(dst_path) if dst_path else None

            lev = self._ignore_level(dp or p)
            if lev == "hard":
                raise RuntimeError("ignored")
            soft_noise = bool(soft_noise or lev == "soft")

            if (not skip_dedup) and self._should_drop_burst_event(evt_kind, p, dp, ctx):
                raise RuntimeError("ignored")

            target_for_content = dp or p

            src_drive = _maybe_drive_letter(p)
            src_volume_type = self._volume_type_effective(src_drive)

            dest_drive = _maybe_drive_letter(dp) if dp else _maybe_drive_letter(target_for_content)
            dest_volume_type = self._volume_type_effective(dest_drive) if dest_drive else None

            effective_drive = dest_drive or src_drive
            effective_volume_type = dest_volume_type or src_volume_type

            prelim_op_type = _infer_op_type_v2(
                evt_kind,
                p,
                dp,
                src_volume_type,
                dest_volume_type,
                correlation_action,
                None,
            )
            report_event_type = _infer_report_event_type(evt_kind, p, dp)
            event_type = "file_renamed" if report_event_type == "Rename" else f"file_{evt_kind}"

            old_ext = None
            new_ext = None
            src_ext = _get_ext(p)
            target_ext = _get_ext(target_for_content)

            if prelim_op_type in {"file_move", "file_rename", "file_move_external"} and dp:
                old_ext = _get_ext(p)
                new_ext = _get_ext(dp)

            enrich_flags = _should_enrich(p, dp, target_ext, effective_volume_type, prelim_op_type)

            if evt_kind == "deleted":
                size = None
                mtime = None
                exists = False
            else:
                stx = self._stat_best_effort(target_for_content)
                size = stx["size"]
                mtime = stx["mtime"]
                exists = bool(stx["exists"])

            signature = None
            entropy = None
            pw_protected = None
            sample = None
            sample_len = None

            before = self._last_meta.get(p) or self._last_meta.get(target_for_content) or {}
            before_size = before.get("size")
            before_hash = before.get("hash")
            before_ext = before.get("ext")

            head = b""
            if exists and enrich_flags["need_signature"]:
                head = _read_head(target_for_content, max_bytes=self.max_head_bytes)
                signature = _signature_from_magic(head, ext=target_ext)

            if head and enrich_flags["need_entropy"]:
                try:
                    entropy = _entropy_bytes(head)
                except Exception:
                    entropy = None

            if exists and enrich_flags["need_zip_pw"]:
                pw_protected = _zip_password_protected(target_for_content)

            force_hash = bool(
                self.require_sha256_for_user_ops
                and prelim_op_type
                in {
                    "file_copy",
                    "file_copy_external",
                    "file_move",
                    "file_move_external",
                    "file_rename",
                    "file_create",
                    "file_modify",
                }
            )
            external_like = bool(
                effective_volume_type in {"Removable", "Network"}
                or prelim_op_type in {"file_copy_external", "file_move_external"}
                or (dp and _is_cloud_path(dp))
                or _is_cloud_path(target_for_content)
            )
            want_full = bool(
                exists
                and (
                    (force_hash and self.hash_full_for_user_ops)
                    or (self.full_hash_on_external and external_like)
                )
            )

            hash_res = _HashResult(None, "none", "none", None)
            hash_sha256_partial: Optional[str] = None
            hash_sha256_full: Optional[str] = None

            if exists and (enrich_flags["need_hash"] or force_hash):
                hash_res = self._resolve_file_hash(
                    target_for_content,
                    size=size,
                    mtime=mtime,
                    want_full=want_full,
                    signature=signature,
                )

            if (not hash_res.value) and prelim_op_type in {"file_move", "file_rename", "file_move_external"} and before_hash:
                fb_kind = str(before.get("hash_kind") or "unknown")
                if fb_kind not in {"partial", "full"}:
                    fb_kind = "unknown"
                hash_res = _HashResult(
                    before_hash,
                    fb_kind,
                    "fallback_previous_meta",
                    before.get("hash_bytes_read"),
                )

            hash_sha256 = hash_res.value
            if hash_res.kind == "full":
                hash_sha256_full = hash_res.value
            elif hash_res.kind == "partial":
                hash_sha256_partial = hash_res.value
            elif hash_res.kind == "unknown" and hash_res.value:
                hash_sha256_partial = hash_res.value

            content_fingerprint_key = (
                _fingerprint_cache_key(size, hash_res.value, signature) if hash_res.value else None
            )

            external_create_semantic: Optional[str] = None
            external_semantic_detail: Dict[str, Any] = {}
            inferred_source_path: Optional[str] = None
            copy_move_verdict: Optional[str] = None
            copy_move_evidence: Optional[str] = None
            if (
                evt_kind == "created"
                and not dp
                and correlation_action is None
                and dest_volume_type in {"Removable", "Network"}
                and hash_res.value
                and size is not None
                and exists
            ):
                external_create_semantic, inferred_source_path, external_semantic_detail = (
                    self._infer_external_create_semantic(
                        dest_path=target_for_content,
                        dest_size=int(size),
                        dest_hash=hash_res.value,
                        ts=ts,
                        ctx=ctx,
                    )
                )
                copy_move_verdict = external_semantic_detail.get("copy_move_verdict")
                copy_move_evidence = external_semantic_detail.get("copy_move_evidence")
                if inferred_source_path is None and external_semantic_detail.get("inferred_source_path"):
                    inferred_source_path = external_semantic_detail.get("inferred_source_path")

            op_type = _infer_op_type_v2(
                evt_kind,
                p,
                dp,
                src_volume_type,
                dest_volume_type,
                correlation_action,
                external_create_semantic,
            )
            report_op_type = _infer_operation_type(
                evt_kind,
                p,
                dp,
                overwrite=(evt_kind == "modified"),
                effective_volume_type=effective_volume_type,
                correlation_action=correlation_action,
                external_create_semantic=external_create_semantic,
            )

            if evt_kind == "moved" and dp:
                obj_src_drive, obj_src_volume_type = src_drive, src_volume_type
                obj_dest_drive, obj_dest_volume_type = dest_drive, dest_volume_type
            elif evt_kind == "created" and not dp:
                obj_src_drive, obj_src_volume_type = None, None
                obj_dest_drive, obj_dest_volume_type = dest_drive, dest_volume_type
            elif evt_kind == "deleted":
                obj_src_drive, obj_src_volume_type = src_drive, src_volume_type
                obj_dest_drive, obj_dest_volume_type = None, None
            else:
                obj_src_drive, obj_src_volume_type = None, None
                obj_dest_drive, obj_dest_volume_type = dest_drive, dest_volume_type

            object_identity_strength = _object_identity_strength(hash_res.kind, bool(hash_res.value))
            identity_tier = "hash" if hash_res.value else "path_fingerprint"

            if exists and enrich_flags["need_sample"]:
                # Prefer text sample for textish files
                sample, sample_len = _read_text_sample(target_for_content, max_chars=self.sample_max_chars)

            if evt_kind != "deleted":
                self._last_meta[target_for_content] = {
                    "size": size,
                    "hash": hash_res.value,
                    "hash_kind": hash_res.kind,
                    "hash_source": hash_res.source,
                    "hash_bytes_read": hash_res.bytes_read,
                    "ext": target_ext,
                    "last_seen_ts": ts,
                }
                if evt_kind == "moved" and dp:
                    self._last_meta.pop(p, None)

            bucket = effective_drive or "NA"
            file_count_window = self._agg_count(ts, bucket)
            file_count_10s = self._agg_count_short(ts, bucket)

            sensitivity = _classify_sensitivity(target_ext, signature, target_for_content)
            self._remember_sensitive_artifact(ts, target_for_content, sensitivity)

            proc_name = ctx.get("fg_app") or ctx.get("fg_process")
            proc_id = ctx.get("fg_pid")
            cmdline = ctx.get("fg_cmdline")
            cloud_provider = _cloud_provider_from_path(dp or p)
            object_id = _stable_object_id(hash_sha256, target_for_content, size=size, mtime=mtime)

            if evt_kind != "deleted" and hash_res.value and size is not None and exists:
                cand_path = p
                if self._volume_type_effective(_maybe_drive_letter(cand_path)) == "Fixed":
                    self._remember_fixed_file_observation(
                        ts, cand_path, int(size), hash_res.value, proc_id, proc_name
                    )

            ctx_out = self._sanitize_ctx_for_file_external(ctx, dest_volume_type, evt_kind)

            file_name = _get_name(target_for_content)
            object_block = self._build_object(
                src_path=p,
                dst_path=dp,
                size=size,
                mtime=mtime,
                src_drive=obj_src_drive,
                src_volume_type=obj_src_volume_type,
                dest_drive=obj_dest_drive,
                dest_volume_type=obj_dest_volume_type,
                old_ext=(before_ext if report_event_type == "Rename" else old_ext),
                new_ext=(target_ext if report_event_type == "Rename" else new_ext),
                signature=signature,
                sensitivity=sensitivity,
                file_name=file_name,
                file_ext=target_ext,
                file_hash=hash_sha256,
                object_id=object_id,
                cloud_provider=cloud_provider,
            )
            object_block["hash_sha256_partial"] = hash_sha256_partial
            object_block["hash_sha256_full"] = hash_sha256_full
            object_block["metadata"] = {
                "mtime": _iso_utc(mtime) if isinstance(mtime, (int, float)) else None,
                "original_size": before_size,
                "hash_before": before_hash,
                "hash_after": hash_sha256,
                "hash_kind": hash_res.kind,
                "hash_source": hash_res.source,
                "hash_bytes_read": hash_res.bytes_read,
                "content_fingerprint_key": content_fingerprint_key,
                "object_identity_strength": object_identity_strength,
                "event_type": report_event_type,
                "operation_type": report_op_type,
                "identity_tier": identity_tier,
            }
            object_block["content_preview"] = sample
            object_block["content_preview_len"] = sample_len

            dest_like_external = bool(effective_volume_type in {"Removable", "Network"} or cloud_provider)
            if op_type == "file_copy_external":
                report_op_type = "CopyExternal"
            if op_type == "file_move_external":
                report_op_type = "MoveExternal"
            dlp_semantic_hint = "local"
            if op_type in {"file_copy_external", "file_move_external"}:
                dlp_semantic_hint = "external_transfer"
            elif cloud_provider:
                dlp_semantic_hint = "cloud_sync_path"
            rename_ext_changed = bool((before_ext or old_ext) and (target_ext or new_ext) and (before_ext or old_ext) != (target_ext or new_ext))
            recent_staging = self._recent_staging_count(ts)
            self._remember_file_by_pid(
                ts=ts,
                pid=proc_id,
                process=proc_name,
                path=(dp or p),
                size=size,
                file_hash=hash_sha256,
                sensitivity=sensitivity,
            )
            pid_summary = self._recent_pid_summary(ts, proc_id)

            evt: Dict[str, Any] = {
                "type": event_type,
                "severity": "info",
                "source": "file",
                "ts": ts,
                "timestamp": _iso_utc(ts),
                "context": ctx_out,

                # canonical
                "actor": self._build_actor(ctx_out),
                "object": object_block,

                # legacy flat fields
                "path": p,
                "dst_path": dp,
                "ext": src_ext,
                "size": size,
                "mtime": mtime,
                "exists": exists,
                "drive": effective_drive,
                "volume_type": effective_volume_type,
                "old_ext": old_ext,
                "new_ext": new_ext,
                "signature": signature,
                "hash_sha256": hash_sha256,

                "operation": {
                    "op_type": op_type,
                    "tool": proc_name,
                    "raw_fs_kind": evt_kind,
                    "correlation_action": correlation_action,
                    "correlation": correlation_detail or {},
                    "src_volume_type": obj_src_volume_type,
                    "dest_volume_type": dest_volume_type,
                    "semantic_action": external_create_semantic,
                    "inferred_source_path": inferred_source_path,
                    "copy_move_verdict": copy_move_verdict,
                    "copy_move_evidence": copy_move_evidence,
                    "dlp_semantic_hint": dlp_semantic_hint,
                    "hash_kind": hash_res.kind,
                    "hash_source": hash_res.source,
                },
                "metrics": {
                    "entropy": entropy,
                    "row_count": None,
                    "file_count": file_count_window,
                    "file_count_10s": file_count_10s,
                },
                "flags": {
                    "password_protected": pw_protected,
                    "soft_noise_path": soft_noise,
                },
                "content": {
                    "sample": sample,
                    "sample_len": sample_len,
                },

                # report fields
                "Event_Type": report_event_type,
                "Operation_Type": report_op_type,
                "Timestamp": _iso_utc(ts),

                "File_Name": file_name,
                "File_Extension": target_ext,
                "File_Size": size,
                "File_Path": target_for_content,
                "File_Hash": hash_sha256,
                "File_Hash_Partial": hash_sha256_partial,
                "File_Hash_Full": hash_sha256_full,
                "Hash_Kind": hash_res.kind,
                "Hash_Source": hash_res.source,
                "Hash_Bytes_Read": hash_res.bytes_read,
                "Content_Fingerprint_Key": content_fingerprint_key,
                "Object_Identity_Strength": object_identity_strength,
                "File_Signature": signature,
                "File_Sensitivity": sensitivity,

                "Source_Path": p,
                "Dest_Path": dp,
                "Dest_Volume_Type": dest_volume_type,
                "Dest_Drive": dest_drive,
                "Source_Volume_Type": obj_src_volume_type,
                "Source_Drive": obj_src_drive,
                "Cloud_Provider": cloud_provider,

                "Process_Name": proc_name,
                "Process_ID": proc_id,
                "Command_Line": cmdline,

                "File_Count": file_count_window,
                "File_Count_10s": file_count_10s,
                "Entropy_Value": entropy,
                "Password_Flag": pw_protected,
                "Original_File_Size": before_size,
                "New_File_Size": size,
                "File_Hash_Before": before_hash,
                "File_Hash_After": hash_sha256,
                "Object_ID": object_id,
                "Old_Extension": before_ext if report_event_type == "Rename" else old_ext,
                "New_Extension": target_ext if report_event_type == "Rename" else new_ext,

                "debug": {
                    "layers": {
                        "raw_fs": evt_kind,
                        "correlation": correlation_detail or {},
                        "dlp_semantic_hint": dlp_semantic_hint,
                    },
                    "evidence": {
                        "dest_like_external": dest_like_external,
                        "rename_ext_changed": rename_ext_changed,
                        "cloud_provider": cloud_provider,
                        "recent_staging": recent_staging,
                        "sample_available": bool(sample),
                        "signature_available": bool(signature),
                        "hash_available": bool(hash_sha256),
                        "hash_kind": hash_res.kind,
                        "hash_source": hash_res.source,
                        "hash_bytes_read": hash_res.bytes_read,
                        "identity_tier": identity_tier,
                        "object_identity_strength": object_identity_strength,
                        "content_fingerprint_key": content_fingerprint_key,
                        "pid_recent_file_count": pid_summary.get("pid_file_count"),
                        "pid_recent_sensitive_count": pid_summary.get("pid_sensitive_count"),
                        "pid_recent_paths": pid_summary.get("pid_recent_paths"),
                        "external_create_semantic": external_create_semantic,
                        "external_semantic_detail": external_semantic_detail,
                        "inferred_source_path": inferred_source_path,
                    },
                },
            }

            # mild severity tuning
            if sensitivity == "Highly Sensitive":
                evt["severity"] = "high"
            elif sensitivity == "Sensitive" or dest_like_external or pw_protected:
                evt["severity"] = "warn"
            else:
                evt["severity"] = "info"

            return evt

        # -----------------------------
        # Watchdog mode
        # -----------------------------
        def _run_watchdog(self, stop_event, ctx_provider: Optional[Any] = None) -> None:
            class _Handler(FileSystemEventHandler):
                def __init__(self, outer: "FileSystemSensor"):
                    self.outer = outer

                def on_created(self, event):
                    if getattr(event, "is_directory", False):
                        return
                    ctx = self.outer._ctx_snapshot(ctx_provider)
                    try:
                        self.outer._mark_suppress_modified(getattr(event, "src_path", None))
                    except Exception:
                        pass
                    self.outer._ingest_fs_event("created", event.src_path, None, ctx)

                def on_modified(self, event):
                    if getattr(event, "is_directory", False):
                        return
                    if self.outer._should_suppress_modified(getattr(event, "src_path", None)):
                        return
                    ctx = self.outer._ctx_snapshot(ctx_provider)
                    self.outer._ingest_fs_event("modified", event.src_path, None, ctx)

                def on_deleted(self, event):
                    if getattr(event, "is_directory", False):
                        return
                    ctx = self.outer._ctx_snapshot(ctx_provider)
                    self.outer._ingest_fs_event("deleted", event.src_path, None, ctx)

                def on_moved(self, event):
                    if getattr(event, "is_directory", False):
                        return
                    ctx = self.outer._ctx_snapshot(ctx_provider)
                    try:
                        self.outer._mark_suppress_modified(getattr(event, "dest_path", None))
                    except Exception:
                        pass
                    self.outer._ingest_fs_event(
                        "moved", event.src_path, getattr(event, "dest_path", None), ctx
                    )

            vol_mgr = self._volume_manager
            try:
                handler = _Handler(self)
                observer = Observer()
                self._observer = observer
                self._watch_handler_ref = handler
                self._observed_watch_by_path.clear()

                if vol_mgr:
                    try:
                        vol_mgr.sync_once()
                    except Exception:
                        pass

                for p in list(self.watch_paths):
                    self._schedule_observer_path(p)

                observer.start()
                if vol_mgr:
                    vol_mgr.start()

                while not stop_event.is_set():
                    time.sleep(0.25)
                    if self._correlation_engine:
                        for plan in self._correlation_engine.tick_flush(_now()):
                            try:
                                self._emit(
                                    self._build_event(
                                        plan.evt_kind,
                                        plan.src_path,
                                        plan.dst_path,
                                        plan.ctx,
                                        correlation_action=plan.correlation_action,
                                        correlation_detail=plan.correlation_detail,
                                        skip_dedup=True,
                                    )
                                )
                            except RuntimeError:
                                pass

                try:
                    observer.stop()
                    observer.join(timeout=2.0)
                except Exception:
                    pass
            except Exception:
                self._run_polling(stop_event, ctx_provider)
            finally:
                if vol_mgr:
                    try:
                        vol_mgr.stop()
                    except Exception:
                        pass
                self._observer = None
                self._watch_handler_ref = None
                self._observed_watch_by_path.clear()

        # -----------------------------
        # Polling fallback
        # -----------------------------
        def _scan(self) -> Dict[str, _StatLite]:
            snap: Dict[str, _StatLite] = {}
            for root in self.watch_paths:
                try:
                    for dirpath, _, filenames in os.walk(root):
                        for fn in filenames:
                            fp = os.path.join(dirpath, fn)
                            fp_norm = _norm_path(fp)
                            if self._ignore_level(fp_norm) == "hard":
                                continue
                            try:
                                st = os.stat(fp_norm)
                                snap[fp_norm] = _StatLite(size=int(st.st_size), mtime=float(st.st_mtime), exists=True)
                            except Exception:
                                continue
                except Exception:
                    continue
            return snap

        def _run_polling(self, stop_event, ctx_provider: Optional[Any] = None) -> None:
            vol_mgr = self._volume_manager
            if vol_mgr:
                try:
                    vol_mgr.sync_once()
                    vol_mgr.start()
                except Exception:
                    pass
            self._snap = self._scan()

            while not stop_event.is_set():
                time.sleep(self.poll_interval_sec)

                if self._correlation_engine:
                    for plan in self._correlation_engine.tick_flush(_now()):
                        try:
                            self._emit(
                                self._build_event(
                                    plan.evt_kind,
                                    plan.src_path,
                                    plan.dst_path,
                                    plan.ctx,
                                    correlation_action=plan.correlation_action,
                                    correlation_detail=plan.correlation_detail,
                                    skip_dedup=True,
                                )
                            )
                        except RuntimeError:
                            pass

                cur = self._scan()
                prev = self._snap
                self._snap = cur

                prev_keys = set(prev.keys())
                cur_keys = set(cur.keys())

                created = cur_keys - prev_keys
                deleted = prev_keys - cur_keys
                common = cur_keys & prev_keys

                ctx = self._ctx_snapshot(ctx_provider)

                for p in created:
                    self._ingest_fs_event("created", p, None, ctx)

                for p in deleted:
                    self._ingest_fs_event("deleted", p, None, ctx)

                for p in common:
                    if (cur[p].mtime != prev[p].mtime) or (cur[p].size != prev[p].size):
                        self._ingest_fs_event("modified", p, None, ctx)
            if vol_mgr:
                try:
                    vol_mgr.stop()
                except Exception:
                    pass

        def run_loop(self, stop_event, ctx_provider: Optional[Any] = None) -> None:
            if not self.watch_paths:
                while not stop_event.is_set():
                    time.sleep(1.0)
                return

            if _HAS_WATCHDOG:
                self._run_watchdog(stop_event, ctx_provider)
            else:
                self._run_polling(stop_event, ctx_provider)