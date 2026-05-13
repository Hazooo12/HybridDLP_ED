"""
JSONL Queue Consumer — đọc events_*.jsonl kiểu append-only (byte offset, giống tail -f).

Không rewrite file nguồn (tránh cạnh tranh với agent đang append và I/O khổng lồ).
Trạng thái offset lưu trong worker_jsonl_offsets.json (phục hồi sau restart).
"""
from __future__ import annotations

import glob
import json
import os
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from loguru import logger

import sys

sys.path.insert(0, str(Path(__file__).parent.parent))
from config import WorkerConfig


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return float(default)


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return int(default)


def _env_bool(name: str, default: bool) -> bool:
    v = os.getenv(name, "").strip().lower()
    if not v:
        return default
    return v in {"1", "true", "yes", "on"}


class JSONLQueueConsumer:
    """Consumer JSONL: chỉ đọc phần mới từ offset đã commit, không đụng file agent."""

    def __init__(self, lookback_hours: int = 1):
        self.panic_mode = False
        self.queue_size = 0
        self.runtime_dir = WorkerConfig.RUNTIME_DIR
        self.pid = os.getpid()
        self.lookback_hours = _env_int("WORKER_JSONL_LOOKBACK_HOURS", lookback_hours)

        self.output_dir = WorkerConfig.LOGS_DIR / "processed_events"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._offset_state_path = Path(
            os.getenv("WORKER_JSONL_OFFSET_STATE", str(self.output_dir / "worker_jsonl_offsets.json"))
        )
        self._offset_state_path.parent.mkdir(parents=True, exist_ok=True)

        self._mirror_output = _env_bool("WORKER_JSONL_MIRROR_OUTPUT", True)
        self._start_at_eof = _env_bool("WORKER_JSONL_START_AT_EOF", False)
        # File lớn chưa có offset trong state: bắt đầu từ EOF (tránh đọc lại cả file cũ một lần).
        self._tail_only_mb = max(0, _env_int("WORKER_JSONL_TAIL_ONLY_MB", 0))
        self._bytes_per_event_est = max(80, _env_int("WORKER_JSONL_BYTES_PER_EVENT_EST", 320))

        self._filelist_ttl = max(0.2, _env_float("WORKER_JSONL_FILELIST_CACHE_SEC", 2.0))
        self._filelist_cache: Optional[List[Path]] = None
        self._filelist_cache_ts = 0.0

        self._queue_size_cache_ts = 0.0
        self._queue_size_ttl = max(0.15, _env_float("WORKER_JSONL_QUEUE_STATS_SEC", 0.45))

        self._offsets: Dict[str, int] = {}
        self._offsets_lock = threading.Lock()
        self._persist_every = max(1, _env_int("WORKER_JSONL_SAVE_OFFSET_EVERY", 5))
        self._persist_min_interval = max(0.05, _env_float("WORKER_JSONL_SAVE_OFFSET_MIN_SEC", 0.8))
        self._events_since_persist = 0
        self._last_persist_ts = 0.0

        self._panic_on = int(getattr(WorkerConfig, "PANIC_MODE_THRESHOLD", 1000))
        self._panic_off = int(getattr(WorkerConfig, "PANIC_MODE_DISABLE_THRESHOLD", 500))
        self._last_panic_state_write = 0.0
        self._last_panic_mode_written: Optional[bool] = None

        self._load_offset_state()
        self._loaded_offset_keys = set(self._offsets.keys())

        logger.info(
            f"[PID={self.pid}] JSONLQueueConsumer: runtime={self.runtime_dir}, "
            f"lookback_h={self.lookback_hours}, mirror={self._mirror_output}, "
            f"start_at_eof={self._start_at_eof}, tail_only_mb={self._tail_only_mb}, "
            f"state={self._offset_state_path}"
        )

    def _load_offset_state(self) -> None:
        if not self._offset_state_path.exists():
            return
        try:
            raw = self._offset_state_path.read_text(encoding="utf-8")
            data = json.loads(raw)
            offs = data.get("offsets") if isinstance(data, dict) else None
            if isinstance(offs, dict):
                self._offsets = {str(k): int(v) for k, v in offs.items() if int(v) >= 0}
                self._last_persist_ts = time.time()
        except Exception as e:
            logger.warning(f"[PID={self.pid}] Could not load JSONL offset state: {e}")

    def _persist_offsets(self, force: bool = False) -> None:
        now = time.time()
        with self._offsets_lock:
            payload = {"version": 1, "offsets": dict(self._offsets)}
        tmp = self._offset_state_path.with_suffix(".tmp")
        try:
            tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=0), encoding="utf-8")
            tmp.replace(self._offset_state_path)
            self._last_persist_ts = now
            self._events_since_persist = 0
        except Exception as e:
            logger.debug(f"[PID={self.pid}] persist JSONL offsets failed: {e}")

    def _maybe_persist_offsets(self, force: bool = False) -> None:
        now = time.time()
        self._events_since_persist += 1
        if force:
            self._persist_offsets(force=True)
            return
        if self._events_since_persist >= self._persist_every:
            self._persist_offsets()
            return
        if now - self._last_persist_ts >= self._persist_min_interval:
            self._persist_offsets()

    def _file_key(self, file_path: Path) -> str:
        return str(file_path.resolve())

    def _ensure_initial_offset(self, file_path: Path, file_size: int) -> int:
        key = self._file_key(file_path)
        with self._offsets_lock:
            if key in self._offsets:
                off = self._offsets[key]
                if file_size < off:
                    self._offsets[key] = 0
                    return 0
                return off
            # Lần đầu thấy file này (hoặc state cũ không có key)
            if self._start_at_eof:
                self._offsets[key] = file_size
                return file_size
            lim = self._tail_only_mb * 1024 * 1024
            if (
                lim > 0
                and file_size > lim
                and key not in self._loaded_offset_keys
            ):
                logger.warning(
                    f"[PID={self.pid}] JSONL {file_path.name}: file≈{file_size // (1024 * 1024)}MB, "
                    f"start at EOF (WORKER_JSONL_TAIL_ONLY_MB={self._tail_only_mb})"
                )
                self._offsets[key] = file_size
                return file_size
            self._offsets[key] = 0
            return 0

    def _set_offset(self, file_path: Path, new_offset: int) -> None:
        key = self._file_key(file_path)
        with self._offsets_lock:
            self._offsets[key] = new_offset

    def _find_jsonl_files(self) -> List[Path]:
        now = time.time()
        if (
            self._filelist_cache is not None
            and now - self._filelist_cache_ts < self._filelist_ttl
        ):
            return self._filelist_cache
        pattern = str(self.runtime_dir / "events_*.jsonl")
        files = sorted(Path(p) for p in glob.glob(pattern))
        self._filelist_cache = files
        self._filelist_cache_ts = now
        return files

    def _get_output_file_path(self) -> Path:
        today = datetime.now(timezone.utc).strftime("%Y%m%d")
        return self.output_dir / f"output_event-{today}.jsonl"

    def _is_event_recent(self, event: Dict[str, Any], lookback_time: datetime) -> bool:
        try:
            ts_str = event.get("ts") or event.get("timestamp", "")
            if not ts_str or not isinstance(ts_str, str):
                return False
            event_time = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            return event_time >= lookback_time
        except Exception:
            return False

    def _skip_heartbeat(self, event: Dict[str, Any]) -> bool:
        return (event.get("type") or "").lower() == "heartbeat"

    def _write_to_output(self, event: Dict[str, Any]) -> None:
        if not self._mirror_output:
            return
        try:
            output_file = self._get_output_file_path()
            with open(output_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(event, ensure_ascii=False) + "\n")
        except Exception as e:
            logger.error(f"Error writing to output file: {e}")

    def _refresh_panic(self, pending_est: int, now: float) -> None:
        changed = False
        if (not self.panic_mode) and pending_est >= self._panic_on:
            self.panic_mode = True
            changed = True
            logger.warning(f"[PID={self.pid}] JSONL panic ON (est. backlog≈{pending_est})")
        elif self.panic_mode and pending_est <= self._panic_off:
            self.panic_mode = False
            changed = True
            logger.info(f"[PID={self.pid}] JSONL panic OFF (est. backlog≈{pending_est})")
        if not changed and self._last_panic_mode_written == self.panic_mode:
            if now - self._last_panic_state_write < 5.0:
                return
        self._last_panic_mode_written = self.panic_mode
        self._last_panic_state_write = now

    def _estimate_pending_events(self) -> int:
        total_bytes = 0
        for fp in self._find_jsonl_files():
            if not fp.exists():
                continue
            try:
                st = fp.stat()
            except OSError:
                continue
            key = self._file_key(fp)
            with self._offsets_lock:
                off = self._offsets.get(key)
            if off is None:
                off = 0
            if st.st_size < off:
                off = 0
            total_bytes += max(0, st.st_size - off)
        return max(0, total_bytes // self._bytes_per_event_est)

    def _update_queue_size(self) -> None:
        now = time.time()
        if now - self._queue_size_cache_ts < self._queue_size_ttl and self.queue_size >= 0:
            return
        self.queue_size = self._estimate_pending_events()
        self._queue_size_cache_ts = now
        self._refresh_panic(self.queue_size, now)

    def _read_next_event_from_file(
        self, file_path: Path, lookback_time: datetime
    ) -> Optional[Dict[str, Any]]:
        if not file_path.exists():
            return None
        try:
            st = file_path.stat()
        except OSError:
            return None
        start = self._ensure_initial_offset(file_path, st.st_size)
        if start > st.st_size:
            start = 0
            self._set_offset(file_path, 0)

        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(start)
                while True:
                    pos = f.tell()
                    line = f.readline()
                    if not line:
                        return None
                    if not line.endswith("\n"):
                        # Agent đang ghi dở dòng — chờ lần sau, không tăng offset
                        return None

                    new_offset = f.tell()
                    line = line.strip()
                    if not line:
                        self._set_offset(file_path, new_offset)
                        continue

                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError as e:
                        logger.warning(f"Invalid JSON at offset ~{pos} in {file_path.name}: {e}")
                        self._set_offset(file_path, new_offset)
                        continue

                    if self._skip_heartbeat(event):
                        self._set_offset(file_path, new_offset)
                        continue

                    if not self._is_event_recent(event, lookback_time):
                        self._set_offset(file_path, new_offset)
                        continue

                    self._set_offset(file_path, new_offset)
                    self._write_to_output(event)
                    self._maybe_persist_offsets()
                    return event
        except (OSError, IOError) as e:
            logger.debug(f"Read error {file_path}: {e}")
            return None

    def get_event(self, timeout: int = 1) -> Optional[Dict[str, Any]]:
        deadline = time.time() + max(0.1, float(timeout))
        lookback_time = datetime.now(timezone.utc) - timedelta(hours=self.lookback_hours)

        while time.time() < deadline:
            jsonl_files = self._find_jsonl_files()
            if not jsonl_files:
                time.sleep(0.05)
                continue

            for file_path in jsonl_files:
                event = self._read_next_event_from_file(file_path, lookback_time)
                if event:
                    eid = event.get("event_id", "unknown")
                    et = event.get("type", "unknown")
                    src = event.get("source", "unknown")
                    logger.info(
                        f"[PID={self.pid}] JSONL event: id={eid} type={et} "
                        f"source={src} file={file_path.name}"
                    )
                    self._update_queue_size()
                    return event

            time.sleep(0.02)

        return None

    def get_queue_size(self) -> int:
        self._update_queue_size()
        return self.queue_size

    def is_panic_mode(self) -> bool:
        return self.panic_mode

    def check_panic_mode(self) -> bool:
        self._update_queue_size()
        return self.panic_mode

    def get_stats(self) -> Dict[str, Any]:
        self._update_queue_size()
        return {
            "queue_size": self.queue_size,
            "panic_mode": self.panic_mode,
            "queue_type": "jsonl",
            "jsonl_files": len(self._find_jsonl_files()),
            "tracked_files": len(self._offsets),
        }

    def flush_state(self) -> None:
        """Ghi ngay offset (vd. trước khi tắt worker)."""
        self._persist_offsets(force=True)
