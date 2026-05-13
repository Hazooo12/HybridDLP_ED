from __future__ import annotations

import json
import os
import socket
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

try:
    # Optional import: chỉ để fallback context snapshot nếu có ContextProvider.
    from agent.sensors.context import ContextProvider  # type: ignore
except Exception:
    ContextProvider = None  # type: ignore

# Extension nhớm như ảnh — resolve vào Pictures\Screenshots
_IMAGE_EXTENSIONS: frozenset = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".bmp",
    ".tiff", ".tif", ".webp", ".heic", ".heif",
})


def _browser_upload_search_dirs(home: Path, ext: str) -> List[Path]:
    env_dirs = os.getenv("BROWSER_UPLOAD_SEARCH_PATHS", "").strip()
    dirs: List[Path] = []
    if env_dirs:
        for raw in env_dirs.split(";"):
            raw = raw.strip()
            if raw:
                dirs.append(Path(os.path.expandvars(os.path.expanduser(raw))))

    dirs.append(home / "Downloads" / "TestDemo")
    if ext in _IMAGE_EXTENSIONS:
        dirs.extend([home / "Pictures" / "Screenshots", home / "Downloads", home / "Pictures"])
    else:
        dirs.extend([home / "Downloads", home / "Documents", home / "Desktop"])

    seen: Set[str] = set()
    unique: List[Path] = []
    for d in dirs:
        key = str(d).lower()
        if key not in seen:
            seen.add(key)
            unique.append(d)
    return unique


class BrowserUploadSensor:
    """
    L1 sensor: Browser upload via local TCP server.

    Port/Host compatible with Sensor/sensor_system/sensors/browser_upload_sensor.py:
      - host: 127.0.0.1
      - port: 47266
      - newline-delimited JSON messages from native host / browser extension

    Output events:
      - type: "browser_upload"
      - operation.op_type: "upload" (so upload rules can match)
      - network.dest_domain/dest_url/method/content_type + bytes_sent_total
      - object.path/local_path (if message provides it) to enable correlator fallback
    """

    def __init__(
        self,
        queue_manager,
        host: str = "127.0.0.1",
        port: int = 47266,
        poll_timeout_sec: float = 0.5,
        max_message_bytes: int = 1024 * 1024,
    ):
        self.qm = queue_manager
        self.host = host
        self.port = int(port)
        self.poll_timeout_sec = float(poll_timeout_sec)
        self.max_message_bytes = int(max_message_bytes)

        self.known_browsers: Set[str] = {
            "chrome",
            "firefox",
            "edge",
            "brave",
            "opera",
            "safari",
            "chromium",
            "msedge",
            "vivaldi",
        }
        self.trigger_types: Set[str] = {"file_input", "drag_drop", "xhr", "fetch", "form_submit", "blocked_upload"}

        self._server_sock: Optional[socket.socket] = None

    def _emit(self, evt: Dict[str, Any]) -> None:
        try:
            self.qm.enqueue_event(evt)
        except Exception:
            pass

    def _browser_to_exe(self, browser: str) -> str:
        b = (browser or "").lower().strip()
        if b in {"msedge", "edge"}:
            return "msedge.exe"
        if b in {"chrome", "chromium"}:
            return "chrome.exe"
        if b in {"firefox"}:
            return "firefox.exe"
        if b in {"brave"}:
            return "brave.exe"
        if b in {"opera"}:
            return "opera.exe"
        if b in {"vivaldi"}:
            return "vivaldi.exe"
        return f"{b or 'browser'}.exe"

    @staticmethod
    def _extract_domain(url: str) -> Optional[str]:
        if not url:
            return None
        try:
            no_scheme = url.split("//", 1)[-1]
            domain = no_scheme.split("/")[0].split("?")[0].split(":")[0].lower()
            return domain if domain else None
        except Exception:
            return None

    @staticmethod
    def _safe_float(v: Any) -> Optional[float]:
        try:
            if v is None:
                return None
            return float(v)
        except Exception:
            return None

    @staticmethod
    def _is_truthy_env(name: str, default: str = "1") -> bool:
        return str(os.getenv(name, default)).strip().lower() not in {"0", "false", "no", "off"}

    @staticmethod
    def _resolve_local_path(filename: str) -> Optional[str]:
        """
        Resolve full path từ filename khi extension không gửi local_path.

        Quy tắc:
          - Ảnh (.png, .jpg, …) → Pictures\\Screenshots
          - Các loại khác       → Downloads

        Chỉ trả về path nếu file thực sự tồn tại; nếu không trả về None.
        """
        if not filename:
            return None
        try:
            stem = Path(filename).name  # giữ nguyên tên (kể cả sub-path)
            ext = Path(filename).suffix.lower()
            home = Path.home()

            # Smart resolve: prioritize the demo focus folder, then common user folders.
            candidates = [folder / stem for folder in _browser_upload_search_dirs(home, ext)]

            for candidate in candidates:
                if candidate.exists():
                    return str(candidate)

            # Fallback to the strict requested rule if file is not found
            if ext in _IMAGE_EXTENSIONS:
                return str(home / "Pictures" / "Screenshots" / stem)
            return str(home / "Downloads" / stem)
        except Exception:
            return None

    @staticmethod
    def _extract_file_items(msg: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Normalize multi-file payloads from browser/native-host variants.

        Some builds send {"files": [{"filename": ..., "size": ...}]}, while older
        builds only send filename/local_path at the top level. This keeps both forms
        compatible and lets the sensor emit one upload event per actual file.
        """
        raw_files: Any = None
        for key in ("files", "file_list", "uploaded_files", "items"):
            value = msg.get(key)
            if isinstance(value, list) and value:
                raw_files = value
                break

        items: List[Dict[str, Any]] = []
        if isinstance(raw_files, list):
            for raw in raw_files:
                if isinstance(raw, dict):
                    filename = raw.get("filename") or raw.get("name") or raw.get("fileName")
                    local_path = raw.get("local_path") or raw.get("path") or raw.get("full_path")
                    item = {
                        "filename": str(filename or Path(str(local_path)).name if local_path else filename or ""),
                        "local_path": str(local_path) if local_path else None,
                        "size": raw.get("size") or raw.get("file_size") or raw.get("bytes"),
                    }
                else:
                    raw_text = str(raw or "")
                    path = Path(raw_text)
                    item = {
                        "filename": path.name if path.name else raw_text,
                        "local_path": raw_text if path.suffix or "\\" in raw_text or "/" in raw_text else None,
                        "size": None,
                    }
                if item.get("filename") or item.get("local_path"):
                    items.append(item)

        for key in ("filenames", "paths"):
            value = msg.get(key)
            if not isinstance(value, list):
                continue
            for raw in value:
                raw_text = str(raw or "")
                if not raw_text:
                    continue
                path = Path(raw_text)
                items.append(
                    {
                        "filename": path.name if path.name else raw_text,
                        "local_path": raw_text if key == "paths" or "\\" in raw_text or "/" in raw_text else None,
                        "size": None,
                    }
                )

        seen: Set[str] = set()
        unique: List[Dict[str, Any]] = []
        for item in items:
            key = str(item.get("local_path") or item.get("filename") or "").lower()
            if key and key not in seen:
                seen.add(key)
                unique.append(item)
        return unique

    def _with_file_item(self, msg: Dict[str, Any], item: Dict[str, Any]) -> Dict[str, Any]:
        file_msg = dict(msg)
        filename = item.get("filename")
        local_path = item.get("local_path")
        size = item.get("size")
        if filename:
            file_msg["filename"] = filename
        if local_path:
            file_msg["local_path"] = local_path
            file_msg["path"] = local_path
        if size is not None:
            file_msg["size"] = size
        return file_msg

    def _infer_same_dir_companion_uploads(
        self,
        msg: Dict[str, Any],
        primary_evt: Dict[str, Any],
        ctx_snapshot: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        if not self._is_truthy_env("BROWSER_UPLOAD_INFER_SAME_DIR_FILES", "1"):
            return []

        trigger = str(primary_evt.get("browser_upload", {}).get("trigger") or "").lower()
        if trigger not in {"drag_drop", "file_input"}:
            return []

        primary_path_text = primary_evt.get("object", {}).get("path")
        if not primary_path_text:
            return []

        try:
            primary_path = Path(str(primary_path_text))
            if not primary_path.exists() or not primary_path.parent.exists():
                return []
            primary_size = primary_path.stat().st_size
        except Exception:
            return []

        reported_size = self._safe_float(msg.get("size"))
        if reported_size is not None and reported_size <= primary_size + 1024:
            return []

        focus_dir = Path.home() / "Downloads" / "TestDemo"
        if primary_path.parent.resolve() != focus_dir.resolve():
            return []

        max_extra = int(os.getenv("BROWSER_UPLOAD_INFER_SAME_DIR_MAX", "1") or "1")
        suffixes = {".docx", ".doc", ".pdf", ".xlsx", ".xls", ".csv", ".txt", ".zip"}

        try:
            candidates = [
                p
                for p in primary_path.parent.iterdir()
                if p.is_file() and p.resolve() != primary_path.resolve() and p.suffix.lower() in suffixes
            ]
        except Exception:
            return []

        if not candidates:
            return []

        primary_mtime = primary_path.stat().st_mtime
        close_candidates = []
        for path in candidates:
            try:
                if abs(path.stat().st_mtime - primary_mtime) <= 300:
                    close_candidates.append(path)
            except Exception:
                continue
        if close_candidates:
            candidates = close_candidates

        candidates.sort(key=lambda p: (abs(p.stat().st_mtime - primary_mtime), p.name.lower()))

        events: List[Dict[str, Any]] = []
        for path in candidates[:max_extra]:
            try:
                size = path.stat().st_size
            except Exception:
                size = None
            inferred_msg = self._with_file_item(
                msg,
                {"filename": path.name, "local_path": str(path), "size": size},
            )
            evt = self._build_event(inferred_msg, ctx_snapshot)
            if not evt:
                continue
            evt.setdefault("tags", []).append("inferred_companion_upload")
            evt.setdefault("browser_upload", {})["inferred_companion_upload"] = True
            evt["browser_upload"]["primary_upload_file"] = str(primary_path)
            events.append(evt)

        return events

    def _build_events(self, msg: Dict[str, Any], ctx_snapshot: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not isinstance(msg, dict) or msg.get("type") == "ping":
            return []

        file_items = self._extract_file_items(msg)
        events: List[Dict[str, Any]] = []

        if file_items:
            for item in file_items:
                evt = self._build_event(self._with_file_item(msg, item), ctx_snapshot)
                if evt:
                    events.append(evt)
        else:
            evt = self._build_event(msg, ctx_snapshot)
            if evt:
                events.append(evt)

        if len(events) == 1 and not file_items:
            events.extend(self._infer_same_dir_companion_uploads(msg, events[0], ctx_snapshot))

        return events

    def _build_event(self, msg: Dict[str, Any], ctx_snapshot: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not isinstance(msg, dict):
            return None
        if msg.get("type") == "ping":
            return None

        browser = str(msg.get("browser") or "unknown_browser").lower()
        tab_url = str(msg.get("tab_url") or "") or None
        destination = str(msg.get("destination") or "") or None
        if not destination and tab_url:
            destination = self._extract_domain(tab_url)

        filename = str(msg.get("filename") or "")
        size_bytes = self._safe_float(msg.get("size"))
        trigger = str(msg.get("trigger") or "unknown").lower()
        if trigger not in self.trigger_types:
            trigger = "unknown"

        confidence_score = self._safe_float(msg.get("confidence_score"))
        confidence_score = float(confidence_score) if confidence_score is not None else 0.80
        confidence_score = max(0.0, min(1.0, confidence_score))
        severity = "high" if confidence_score >= 0.85 else "medium"

        tags: List[str] = ["browser_upload", f"trigger_{trigger}"]
        if browser in self.known_browsers:
            tags.append(f"browser_{browser}")

        # If extension provides local_path, set it to object.path so correlator/rules can use it.
        local_path = msg.get("local_path") or msg.get("path") or None
        local_path = str(local_path) if local_path else None

        # Nếu không có local_path nhưng có filename, thử resolve từ các folder mặc định.
        if not local_path and filename:
            local_path = self._resolve_local_path(filename)

        ext = None
        if local_path:
            try:
                ext = Path(local_path).suffix.lower() or None
            except Exception:
                ext = None

        # Lightweight sensitivity heuristic by extension, so upload rules can fire without file_sensor evidence.
        sensitive_exts = {".xlsx", ".xls", ".csv", ".docx", ".doc", ".pdf", ".sql", ".zip", ".7z", ".env"}
        sensitivity = "Sensitive" if (ext in sensitive_exts) else "Normal"

        browser_exe = self._browser_to_exe(browser)

        method = "POST" if trigger in {"xhr", "fetch", "form_submit"} else None
        content_type = "multipart/form-data" if filename else None

        evt: Dict[str, Any] = {
            "type": "browser_upload",
            "source": "browser_upload_sensor",
            "severity": severity,
            "ts": time.time(),
            "context": ctx_snapshot,
            "actor": {
                "user": ctx_snapshot.get("user"),
                "pid": ctx_snapshot.get("fg_pid"),
                "process": browser_exe,
                "cmdline": ctx_snapshot.get("fg_cmdline"),
                "exe": ctx_snapshot.get("fg_exe_path"),
            },
            "process": {"pid": ctx_snapshot.get("fg_pid"), "name": browser_exe, "exe": ctx_snapshot.get("fg_exe_path"), "cmdline": ctx_snapshot.get("fg_cmdline")},
            "operation": {"op_type": "upload", "tool": browser_exe},
            "object": {
                "path": local_path,
                "dst_path": None,
                "name": filename or (Path(local_path).name if local_path else None),
                "ext": ext,
                "size": int(size_bytes) if size_bytes is not None else None,
                "mtime": None,
                "exists": None,
                "signature": None,
                "hash_sha256": None,
                "sensitivity": sensitivity,
            },
            "network": {
                "dest_domain": destination,
                "dest_ip": None,
                "dest_url": tab_url,
                "method": method,
                "content_type": content_type,
                "bytes_sent_total": int(size_bytes) if size_bytes is not None else None,
                "bytes_out_total": int(size_bytes) if size_bytes is not None else None,
                "bytes_in_total": 0,
                "external_dst": True,
            },
            "browser_upload": {
                "filename": filename or None,
                "size": int(size_bytes) if size_bytes is not None else None,
                "tab_url": tab_url[:1024] if tab_url else None,
                "destination": destination,
                "trigger": trigger,
                "browser": browser,
                "confidence_score": round(confidence_score, 3),
                "local_path": local_path,
            },
            "metrics": {"file_count": None, "entropy": None},
            "flags": {"password_protected": None},
            "ioc_hits": [],
            "tags": tags,
        }
        return evt

    def run_loop(self, stop_event, ctx_provider: Optional[Any] = None) -> None:
        # Build a snapshot once per loop iteration.
        def snapshot_ctx() -> Dict[str, Any]:
            if ctx_provider is None:
                return {}
            try:
                if hasattr(ctx_provider, "snapshot"):
                    return ctx_provider.snapshot() or {}
            except Exception:
                pass
            return {}

        host = self.host
        port = self.port

        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind((host, port))
        self._server_sock.listen(1)
        self._server_sock.settimeout(self.poll_timeout_sec)

        # started event (optional but useful in JSONL)
        self._emit(
            {
                "type": "browser_upload_sensor_started",
                "source": "l1",
                "severity": "info",
                "ts": time.time(),
                "context": snapshot_ctx(),
            }
        )

        buffer_per_conn: bytes = b""

        while not stop_event.is_set():
            try:
                conn, _addr = self._server_sock.accept()
            except socket.timeout:
                continue
            except Exception:
                break

            with conn:
                conn.settimeout(self.poll_timeout_sec)
                buffer_per_conn = b""
                while not stop_event.is_set():
                    try:
                        chunk = conn.recv(4096)
                    except socket.timeout:
                        continue
                    except Exception:
                        break

                    if not chunk:
                        break

                    buffer_per_conn += chunk
                    if len(buffer_per_conn) > self.max_message_bytes:
                        buffer_per_conn = b""
                        continue

                    while b"\n" in buffer_per_conn:
                        line, buffer_per_conn = buffer_per_conn.split(b"\n", 1)
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            msg = json.loads(line.decode("utf-8", errors="replace"))
                        except Exception:
                            continue

                        ctx_snapshot = snapshot_ctx()
                        for evt in self._build_events(msg, ctx_snapshot):
                            self._emit(evt)

        try:
            if self._server_sock:
                self._server_sock.close()
        except Exception:
            pass

