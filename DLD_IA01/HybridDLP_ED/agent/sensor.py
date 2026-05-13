from __future__ import annotations

import os
import sys
import time
import json
import signal
import threading
import sqlite3
import glob
import traceback
from queue import Queue, Full, Empty
from pathlib import Path

# HybridDLP_ED root — để `import agent.*` khi chạy trực tiếp `python agent/sensor.py`
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
from typing import Any, Dict, List, Optional, Callable
from datetime import datetime, timezone

from agent.sensors.file_sensor import FileSystemSensor
from agent.sensors.usb_sensor import USBSensor
from agent.sensors.process_sensor import ProcessSensor
from agent.sensors.network_sensor import NetworkSensor
from agent.sensors.clipboard_sensor import ClipboardSensor
from agent.sensors.context_correlator import ContextCorrelator
from agent.sensors.endpoint_sensor import EndpointSensor
from agent.sensors.browser_upload_sensor import BrowserUploadSensor
from agent.queue_monitor import QueueMonitor
from agent.event_filter import get_event_filter
from agent.sensors.context import ContextProvider

try:
    from agent.sensors.print_sensor import PrintSensor  # type: ignore
    _HAS_PRINT = True
except Exception:
    PrintSensor = None  # type: ignore
    _HAS_PRINT = False

from agent.event_pipeline import canonicalize_event

try:
    from agent.persistent_queue import PersistentEventQueue
    _HAS_PERSISTENT_QUEUE = True
except Exception:
    PersistentEventQueue = None  # type: ignore
    _HAS_PERSISTENT_QUEUE = False


BASE_DIR = Path(__file__).resolve().parent
RUNTIME_DIR = BASE_DIR / "runtime"
STATE_DIR = RUNTIME_DIR / "state"
STATE_DIR.mkdir(parents=True, exist_ok=True)

HB_FILE = STATE_DIR / "sensor_heartbeat.json"
PID_FILE = STATE_DIR / "sensor.pid"
STOP_FLAG = STATE_DIR / "stop.flag"

EVENTS_JSONL = RUNTIME_DIR / "events.jsonl"
EVENTS_DB = RUNTIME_DIR / "events.db"


def atomic_write_json(path: Path, data: dict) -> None:
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)


def _to_unix(ts: Any) -> float:
    if ts is None:
        return time.time()
    if isinstance(ts, (int, float)):
        return float(ts)
    try:
        s = str(ts).strip()
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except Exception:
        return time.time()


def adapt_for_queue(evt: Dict[str, Any]) -> Dict[str, Any]:
    e = dict(evt) if isinstance(evt, dict) else {"type": "unknown", "source": "unknown"}
    e.setdefault("ts", time.time())
    e["ts"] = _to_unix(e.get("ts"))
    return e


class JsonlFileSink:
    def __init__(
        self,
        path: Path,
        rotate_max_bytes: int = 50 * 1024 * 1024,
        retention_days: int = 7,
        cleanup_interval_sec: float = 300.0,
    ):
        self.base_path = path
        self.base_dir = path.parent
        self.base_dir.mkdir(parents=True, exist_ok=True)

        self.rotate_max_bytes = int(rotate_max_bytes)
        self.retention_days = int(retention_days)
        self.cleanup_interval_sec = float(cleanup_interval_sec)

        self._lock = threading.Lock()
        self._current_path = self._compute_current_path()
        self._last_cleanup_ts = 0.0

    def _today_str(self) -> str:
        return datetime.now(timezone.utc).strftime("%Y%m%d")

    def _compute_current_path(self) -> Path:
        stem = self.base_path.stem
        today = self._today_str()
        pattern = str(self.base_dir / f"{stem}_{today}_*.jsonl")
        existing = sorted(glob.glob(pattern))

        if not existing:
            return self.base_dir / f"{stem}_{today}_1.jsonl"

        last = Path(existing[-1])
        try:
            if last.exists() and last.stat().st_size < self.rotate_max_bytes:
                return last
        except Exception:
            return last

        try:
            n = int(last.stem.split("_")[-1]) + 1
        except Exception:
            n = len(existing) + 1
        return self.base_dir / f"{stem}_{today}_{n}.jsonl"

    def _needs_rollover(self) -> bool:
        try:
            today = self._today_str()
            if today not in self._current_path.name:
                return True
            if self._current_path.exists() and self._current_path.stat().st_size >= self.rotate_max_bytes:
                return True
        except Exception:
            return False
        return False

    def _cleanup_old(self) -> None:
        if self.retention_days <= 0:
            return
        cutoff_ts = time.time() - (self.retention_days * 86400)

        stem = self.base_path.stem
        pattern = str(self.base_dir / f"{stem}_????????_*.jsonl")
        for fp in glob.glob(pattern):
            try:
                p = Path(fp)
                if p.stat().st_mtime < cutoff_ts:
                    p.unlink(missing_ok=True)
            except Exception:
                pass

    def write(self, event: Dict[str, Any]) -> None:
        line = json.dumps(event, ensure_ascii=False)
        with self._lock:
            if self._needs_rollover():
                self._current_path = self._compute_current_path()

            with self._current_path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")

            now = time.time()
            if now - self._last_cleanup_ts >= self.cleanup_interval_sec:
                self._cleanup_old()
                self._last_cleanup_ts = now

    def close(self) -> None:
        return


class SQLiteEventStore:
    def __init__(self, db_path: Path, commit_every: int = 50, commit_interval_sec: float = 2.0):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self._lock = threading.Lock()

        self.commit_every = int(max(1, commit_every))
        self.commit_interval_sec = float(max(0.2, commit_interval_sec))
        self._pending = 0
        self._last_commit = time.time()

        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock:
            self.conn.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL,
                    type TEXT NOT NULL,
                    severity INTEGER,
                    source TEXT,
                    payload_json TEXT
                );
                """
            )
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);")
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_events_type ON events(type);")
            self.conn.commit()

    def write(self, event: Dict[str, Any]) -> None:
        payload = dict(event)
        ts = str(payload.pop("ts", ""))
        etype = str(payload.pop("type", "unknown"))
        severity = payload.pop("severity", None)
        source = payload.pop("source", None)
        payload_json = json.dumps(payload, ensure_ascii=False)

        with self._lock:
            self.conn.execute(
                "INSERT INTO events(ts, type, severity, source, payload_json) VALUES (?, ?, ?, ?, ?)",
                (ts, etype, severity, source, payload_json),
            )
            self._pending += 1
            now = time.time()
            if self._pending >= self.commit_every or (now - self._last_commit) >= self.commit_interval_sec:
                self.conn.commit()
                self._pending = 0
                self._last_commit = now

    def close(self) -> None:
        with self._lock:
            try:
                if self._pending > 0:
                    self.conn.commit()
            except Exception:
                pass
            try:
                self.conn.close()
            except Exception:
                pass


class QueueManager:
    def __init__(self, maxsize: int):
        self.event_queue: Queue = Queue(maxsize=maxsize)
        self.enqueued = 0
        self.dropped = 0
        self.panic_mode = False
        self._lock = threading.Lock()

    def enqueue_event(self, event: Dict[str, Any]) -> bool:
        event = adapt_for_queue(event)

        if self.panic_mode:
            allow_types = {
                "heartbeat",
                "shutdown",
                "overload_drop_summary",
                "proc_sensor_error",
                "print_sensor_error",
                "clipboard_sensor_error",
                "net_sensor_error",
                "network_sensor_error",
                "usb_sensor_error",
                "file_sensor_error",
                "network_sensor_started",
            }
            if event.get("type") not in allow_types:
                with self._lock:
                    self.dropped += 1
                return False

        try:
            self.event_queue.put_nowait(event)
            with self._lock:
                self.enqueued += 1
            return True
        except Full:
            with self._lock:
                self.dropped += 1
            return False

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "qsize": self.event_queue.qsize(),
                "maxsize": self.event_queue.maxsize,
                "enqueued": self.enqueued,
                "dropped": self.dropped,
                "panic_mode": self.panic_mode,
            }


def consumer_loop(
    stop_event: threading.Event,
    qm: QueueManager,
    sinks: List[Any],
    correlator: Optional[ContextCorrelator] = None,
    persistent_queue: Optional[Any] = None,
) -> None:
    def _drop_noisy_jsonl_event(e: Dict[str, Any]) -> bool:
        etype = str(e.get("type") or "").lower()
        source = str(e.get("source") or "").lower()

        # Always drop heartbeat from JSONL.
        if etype == "heartbeat":
            return True

        # Reduce boot-time noise.
        if etype.endswith("_sensor_started"):
            return True

        # Central noise guard for file/endpoint events.
        if etype in {"file_open", "file_read", "file_close", "file_modified"} and source in {"endpoint", "file"}:
            actor = e.get("actor") if isinstance(e.get("actor"), dict) else {}
            obj = e.get("object") if isinstance(e.get("object"), dict) else {}
            pname = str(actor.get("process") or "").lower()
            path = str(obj.get("path") or "").lower()
            ext = str(obj.get("ext") or "").lower()
            name = str(obj.get("name") or "").lower()

            noisy_processes = {
                "svchost.exe",
                "wmiprvse.exe",
                "backgroundtaskhost.exe",
                "searchhost.exe",
                "startmenuexperiencehost.exe",
                "msedgewebview2.exe",
            }
            if pname in noisy_processes:
                return True

            noisy_path_tokens = (
                "\\appdata\\local\\programs\\",
                "\\appdata\\local\\packages\\",
                "\\appdata\\local\\temp\\",
                "\\appdata\\local\\microsoft\\edge\\user data\\",
                "\\appdata\\local\\google\\chrome\\user data\\",
                "\\appdata\\roaming\\cursor\\",
                "\\windows\\",
                "\\program files\\",
                "\\program files (x86)\\",
                "\\cache\\",
                "\\code cache\\",
                "\\gpucache\\",
                "\\indexeddb\\",
                "\\service worker\\",
                "\\logs\\",
            )
            if any(tok in path for tok in noisy_path_tokens):
                return True

            noisy_exts = {
                ".tmp", ".temp", ".log", ".log2", ".mui", ".nlp", ".dll", ".pak", ".asar",
                ".wal", ".shm", ".map", ".dat", ".db", ".db-wal", ".db-shm", ".db-journal",
                ".sqlite", ".sqlite-wal", ".sqlite-shm",
                ".ldb", ".idx", ".pma", ".vsidx", ".vscdb", ".vscdb-wal", ".vscdb-shm", ".vscdb-journal",
                ".bin", ".lock", ".journal",
            }
            if ext in noisy_exts:
                return True

            noisy_names = {
                "dips", "history", "history-journal", "cookies", "cookies-journal",
                "web data", "web data-journal", "network persistent state",
                "preferences", "secure preferences",
            }
            if name in noisy_names:
                return True

        return False

    while (not stop_event.is_set()) or (not qm.event_queue.empty()):
        try:
            event = qm.event_queue.get(timeout=0.5)
        except Empty:
            if persistent_queue is not None:
                try:
                    persistent_queue.maybe_flush()
                except Exception:
                    pass
            continue
        except Exception:
            continue

        try:
            # Correlation nặng (upload_suspected, corr_*) — mặc định tắt ở Sensor;
            # chạy ở Worker (WORKER_ENABLE_CORRELATOR=1).
            if correlator is not None:
                try:
                    corr_events = correlator.on_event(event) or []
                    for ce in corr_events:
                        qm.enqueue_event(ce)
                except Exception:
                    pass

            event_canon = canonicalize_event(event)

            # Fila SQLite bền vững cho Worker (không enqueue heartbeat để giảm tải DB).
            # Apply event filter trước khi enqueue
            if persistent_queue is not None:
                try:
                    et = str(event_canon.get("type") or "").lower()
                    if et != "heartbeat":
                        # Apply event filter (L1 sensor filter)
                        event_filter = get_event_filter()
                        if not event_filter.should_drop(event_canon):
                            persistent_queue.enqueue(event_canon)
                except Exception:
                    pass

            for s in sinks:
                try:
                    # Noise control on JSONL sink only.
                    if isinstance(s, JsonlFileSink) and _drop_noisy_jsonl_event(event_canon):
                        continue
                    s.write(event_canon)
                except Exception:
                    pass
        finally:
            try:
                qm.event_queue.task_done()
            except Exception:
                pass


def heartbeat_loop(
    stop_event: threading.Event,
    qm: QueueManager,
    hb_interval_sec: float,
    hb_file_interval_sec: float,
    start_ts: float,
    ctx: Optional[ContextProvider],
) -> None:
    pid = os.getpid()
    try:
        PID_FILE.write_text(str(pid), encoding="utf-8")
    except Exception:
        pass

    seq = 0
    last_hb_file = 0.0

    while not stop_event.is_set():
        now = time.time()

        if STOP_FLAG.exists():
            stop_event.set()
            break

        seq += 1

        context: Dict[str, Any] = {}
        if ctx is not None:
            try:
                context = ctx.snapshot() or {}
            except Exception:
                context = {}

        qm.enqueue_event(
            {
                "type": "heartbeat",
                "severity": "info",
                "source": "l1",
                "pid": pid,
                "seq": seq,
                "start_ts": start_ts,
                "context": context,
                "ts": now,
            }
        )

        if now - last_hb_file >= hb_file_interval_sec:
            try:
                atomic_write_json(
                    HB_FILE,
                    {
                        "ts": int(now),
                        "start_ts": int(start_ts),
                        "role": "sensor",
                        "pid": pid,
                        "seq": seq,
                        "queue": qm.stats(),
                    },
                )
            except Exception:
                pass
            last_hb_file = now

        time.sleep(hb_interval_sec)


def _safe_call(fn: Callable[..., Any], *args, **kwargs) -> None:
    try:
        fn(*args, **kwargs)
    except Exception:
        pass


def sensor_thread_runner(
    sensor_name: str,
    target: Callable[..., Any],
    qm: QueueManager,
    stop_event: threading.Event,
    *args,
) -> None:
    """
    Chạy sensor trong thread. Nếu một sensor lỗi (vd. network_sensor không có quyền WinDivert),
    chỉ ghi *_error và thử lại sau backoff — KHÔNG dừng toàn bộ agent để các sensor khác
    vẫn lắng nghe sự kiện.
    """
    qm.enqueue_event(
        {
            "type": f"{sensor_name}_started",
            "severity": "info",
            "source": "l1",
            "sensor": sensor_name,
            "ts": time.time(),
        }
    )
    initial = float(os.getenv("SENSOR_RETRY_INITIAL_SEC", "2.0"))
    max_backoff = float(os.getenv("SENSOR_RETRY_MAX_SEC", "60.0"))
    backoff = max(0.5, initial)
    fatal_on_error = os.getenv("SENSOR_FATAL_ON_ERROR", "0").strip().lower() in {"1", "true", "yes", "on"}

    while not stop_event.is_set():
        try:
            target(*args)
            return
        except Exception as e:
            qm.enqueue_event(
                {
                    "type": f"{sensor_name}_error",
                    "severity": "high",
                    "source": "l1",
                    "sensor": sensor_name,
                    "error": repr(e),
                    "traceback": traceback.format_exc(),
                    "recoverable": not fatal_on_error,
                    "ts": time.time(),
                }
            )
            if fatal_on_error:
                stop_event.set()
                return
            if stop_event.is_set():
                return
            # Chờ (có thể bị ngắt bởi stop_event) rồi thử lại run_loop
            waited = 0.0
            while waited < backoff and not stop_event.is_set():
                step = min(0.5, backoff - waited)
                if stop_event.wait(step):
                    return
                waited += step
            backoff = min(max_backoff, backoff * 1.5)


def main() -> None:
    queue_maxsize = 8000

    hb_interval_sec = 2.0
    hb_file_interval_sec = 1.0

    jsonl_rotate_max_bytes = 50 * 1024 * 1024
    jsonl_retention_days = 7

    sqlite_commit_every = 80
    sqlite_commit_interval_sec = 2.0

    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)

    if STOP_FLAG.exists():
        _safe_call(STOP_FLAG.unlink)

    watch_test_dir = RUNTIME_DIR / "watch_test"
    watch_test_dir.mkdir(parents=True, exist_ok=True)

    # Watch paths:
    # - default: demo focus folder in Downloads\TestDemo
    # - optional env SENSOR_WATCH_PATHS (semicolon-separated) to override
    demo_focus_path = os.getenv(
        "SENSOR_DEMO_FOCUS_PATH",
        str(Path.home() / "Downloads" / "TestDemo"),
    ).strip()
    if demo_focus_path:
        try:
            Path(demo_focus_path).mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
    watch_paths: List[str] = [demo_focus_path] if demo_focus_path else [r"C:\\"]

    env_watch_paths = os.getenv("SENSOR_WATCH_PATHS", "").strip()
    if env_watch_paths:
        watch_paths = []
        for p in env_watch_paths.split(";"):
            p = p.strip()
            if p:
                watch_paths.append(p)

    # de-duplicate while preserving order
    _seen_paths = set()
    _dedup_watch_paths: List[str] = []
    for p in watch_paths:
        if p not in _seen_paths:
            _seen_paths.add(p)
            _dedup_watch_paths.append(p)
    watch_paths = _dedup_watch_paths

    # Sensor selection:
    # - default: all sensors enabled (subject to each sensor's own env flag)
    # - SENSOR_ONLY=file_sensor (or comma-separated list) to run only specific sensors
    # - SENSOR_ENABLE_<NAME>=0/1 to explicitly disable/enable each sensor
    known_sensors = {
        "file_sensor",
        "usb_sensor",
        "clipboard_sensor",
        "process_sensor",
        "endpoint_sensor",
        "network_sensor",
        "browser_upload_sensor",
        "print_sensor",
    }
    sensor_only_raw = os.getenv("SENSOR_ONLY", "").strip().lower()
    selected_sensors: Optional[set[str]] = None
    if sensor_only_raw:
        parsed = {
            x.strip().lower()
            for x in sensor_only_raw.split(",")
            if x.strip()
        }
        if parsed:
            selected_sensors = {x for x in parsed if x in known_sensors}
            unknown = sorted(parsed - known_sensors)
            if unknown:
                print(f"[main] warning: unknown sensors in SENSOR_ONLY ignored: {unknown}", flush=True)
            if not selected_sensors:
                print("[main] warning: SENSOR_ONLY had no valid sensor names; fallback to default all sensors", flush=True)
                selected_sensors = None

    def _is_enabled(sensor_name: str, default: bool = True) -> bool:
        env_key = f"SENSOR_ENABLE_{sensor_name.upper()}"
        env_val = os.getenv(env_key, "").strip().lower()
        if env_val:
            return env_val in {"1", "true", "yes", "on"}
        if selected_sensors is not None:
            return sensor_name in selected_sensors
        return default

    start_ts = time.time()
    stop_event = threading.Event()
    qm = QueueManager(maxsize=queue_maxsize)

    sinks: List[Any] = [
        JsonlFileSink(EVENTS_JSONL, rotate_max_bytes=jsonl_rotate_max_bytes, retention_days=jsonl_retention_days),
        SQLiteEventStore(EVENTS_DB, commit_every=sqlite_commit_every, commit_interval_sec=sqlite_commit_interval_sec),
    ]

    qm_monitor = QueueMonitor(queue_manager=qm, state_dir=STATE_DIR, check_interval_sec=1.0)

    # Kiến trúc 2 tầng: Sensor chỉ enqueue nhẹ; correlator mặc định OFF (Worker xử lý).
    # Chuỗi clipboard → USB (agent.sensors.clipboard_usb_matcher) chạy trong ContextCorrelator: bật SENSOR_ENABLE_CORRELATOR=1.
    correlator: Optional[ContextCorrelator] = None
    if os.getenv("SENSOR_ENABLE_CORRELATOR", "0").strip().lower() in {"1", "true", "yes", "on"}:
        correlator = ContextCorrelator(debug=True)

    persistent_queue = None
    if _HAS_PERSISTENT_QUEUE and os.getenv("SENSOR_SQLITE_QUEUE", "1").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }:
        try:
            persistent_queue = PersistentEventQueue()
        except Exception:
            persistent_queue = None

    try:
        ctx: Optional[ContextProvider] = ContextProvider(
            cache_ttl_sec=0.5,
            include_session=True,
            include_exe_path=True,
            include_cmdline=True,
            include_net_snapshot=False,
        )
    except Exception:
        ctx = None

    file_sensor_enabled = _is_enabled("file_sensor", True)
    usb_sensor_enabled = _is_enabled("usb_sensor", True)
    clipboard_sensor_enabled = _is_enabled("clipboard_sensor", True)
    process_sensor_enabled = _is_enabled("process_sensor", True)
    endpoint_sensor_enabled = _is_enabled("endpoint_sensor", True)
    print_sensor_enabled = _is_enabled("print_sensor", True)
    browser_upload_enabled = _is_enabled("browser_upload_sensor", True) and (
        os.getenv("BROWSER_UPLOAD_SENSOR", "0").strip().lower() in {"1", "true", "yes", "on"}
    )

    fs_sensor = (
        FileSystemSensor(queue_manager=qm, watch_paths=watch_paths, poll_interval_sec=0.5)
        if file_sensor_enabled
        else None
    )
    usb_sensor = USBSensor(queue_manager=qm, poll_interval_sec=1.0) if usb_sensor_enabled else None

    def on_usb_connected(drive: str) -> None:
        if fs_sensor is not None:
            _safe_call(fs_sensor.add_watch_path, drive)

    clip_sensor = (
        ClipboardSensor(
            queue_manager=qm,
            poll_interval_sec=0.15,
            min_len=6,
            preview_len=120,
            cooldown_sec=0.6,
        )
        if clipboard_sensor_enabled
        else None
    )

    proc_watch = {
        # Script engines / shells
        "powershell", "pwsh", "cmd", "wscript", "cscript", "python", "pythonw",
        # File transfer / upload tools  → native_download_tool, bitsadmin_download
        "curl", "wget", "rclone", "winscp", "filezilla", "pscp", "scp", "sftp",
        "bitsadmin", "certutil",
        # Archiver tools → archive_staging
        "7z", "7za", "winrar", "rar", "makecab",
        # Bulk copy / exfil
        "robocopy", "xcopy",
        # LOLBins / living-off-the-land binaries
        "mshta", "regsvr32", "rundll32", "msiexec", "cmstp", "installutil",
        # Screen capture
        "snippingtool", "screenclippinghost", "obs64", "obs32", "camtasia", "greenshot", "lightshot",
        # Clipboard helpers
        "autohotkey", "macrorecorder", "copyq", "ditto",
        # Cloud CLI tools → cloud_exfiltration_tool
        "aws", "gsutil", "az", "azcopy",
    }

    proc_sensor = (
        ProcessSensor(
            queue_manager=qm,
            poll_interval_sec=0.5,
            watch_names=proc_watch,
            emit_end=True,
            include_cmdline=True,
            include_parent=True,
            include_username=True,
        )
        if process_sensor_enabled
        else None
    )

    endpoint_sensor = (
        EndpointSensor(
            queue_manager=qm,
            watch_paths=watch_paths,
            # Capture open/read across all processes in watched paths
            # (filtering by process name misses Explorer/Office/editor workflows).
            watch_processes=None,
            poll_interval_sec=0.8,
            read_refresh_sec=8.0,
        )
        if endpoint_sensor_enabled
        else None
    )

    enforce_upload_gate = os.getenv("NET_ENFORCE_UPLOAD_GATE", "0").strip().lower() in {"1", "true", "yes", "on"}
    prefer_sniff = os.getenv("NET_PREFER_SNIFF", "1").strip().lower() in {"1", "true", "yes", "on"}
    gate_hold_sec = float(os.getenv("NET_GATE_HOLD_SEC", "1.2"))

    network_sensor_enabled = _is_enabled("network_sensor", True) and (
        os.getenv("NETWORK_SENSOR_ENABLED", "1").strip().lower() in {"1", "true", "yes", "on"}
    )
    net_sensor = None
    if network_sensor_enabled:
        net_sensor = NetworkSensor(
            queue_manager=qm,
            only_upload_processes=False,
            prefer_sniff=prefer_sniff,
            debug=True,
            min_upload_bytes_browser=64 * 1024,
            min_upload_bytes_tool=64 * 1024,
            min_upload_bytes_default=128 * 1024,
            min_upload_bytes_quic=64 * 1024,
            enforce_upload_gate=enforce_upload_gate,
            gate_hold_sec=gate_hold_sec,
        )

    print_sensor = None
    if _HAS_PRINT and print_sensor_enabled:
        try:
            print_sensor = PrintSensor(queue_manager=qm, poll_interval_sec=1.0)  # type: ignore
        except Exception:
            print_sensor = None

    print("[main] started pid=", os.getpid(), flush=True)
    print("[main] watch_paths:", watch_paths, flush=True)
    print("[main] print_sensor:", bool(print_sensor), flush=True)
    print(f"[main] network_sensor: {'enabled' if network_sensor_enabled else 'disabled'} (prefer_sniff={prefer_sniff}, enforce_upload_gate={enforce_upload_gate}, gate_hold_sec={gate_hold_sec})", flush=True)
    print(f"[main] endpoint_sensor: {'enabled' if endpoint_sensor is not None else 'disabled'} (open/read/close + metadata/content in object)", flush=True)
    # Browser upload sensor (optional): TCP server that receives newline-delimited JSON
    # from browser native messaging host.
    browser_upload_host = os.getenv("BROWSER_UPLOAD_HOST", "127.0.0.1").strip() or "127.0.0.1"
    browser_upload_port = int(os.getenv("BROWSER_UPLOAD_PORT", "47266"))
    browser_upload_sensor = None
    if browser_upload_enabled:
        browser_upload_sensor = BrowserUploadSensor(queue_manager=qm, host=browser_upload_host, port=browser_upload_port)
        print(f"[main] browser_upload_sensor: enabled on {browser_upload_host}:{browser_upload_port}", flush=True)
    else:
        print("[main] browser_upload_sensor: disabled (set BROWSER_UPLOAD_SENSOR=1 to enable)", flush=True)
    print("[main] entering run loop", flush=True)

    threads: List[threading.Thread] = [
        threading.Thread(
            name="consumer",
            target=consumer_loop,
            args=(stop_event, qm, sinks, correlator, persistent_queue),
            daemon=True,
        ),
        threading.Thread(name="heartbeat", target=heartbeat_loop, args=(stop_event, qm, hb_interval_sec, hb_file_interval_sec, start_ts, ctx), daemon=True),
        threading.Thread(name="queue_monitor", target=qm_monitor.loop, args=(stop_event,), daemon=True),
    ]

    if fs_sensor is not None:
        threads.append(
            threading.Thread(
                name="file_sensor",
                target=sensor_thread_runner,
                args=("file_sensor", fs_sensor.run_loop, qm, stop_event, stop_event, ctx),
                daemon=True,
            )
        )
    if usb_sensor is not None:
        threads.append(
            threading.Thread(
                name="usb_sensor",
                target=sensor_thread_runner,
                args=("usb_sensor", usb_sensor.run_loop, qm, stop_event, stop_event, on_usb_connected, None, ctx),
                daemon=True,
            )
        )
    if clip_sensor is not None:
        threads.append(
            threading.Thread(
                name="clipboard_sensor",
                target=sensor_thread_runner,
                args=("clipboard_sensor", clip_sensor.run_loop, qm, stop_event, stop_event, ctx),
                daemon=True,
            )
        )
    if proc_sensor is not None:
        threads.append(
            threading.Thread(
                name="process_sensor",
                target=sensor_thread_runner,
                args=("process_sensor", proc_sensor.run_loop, qm, stop_event, stop_event, ctx),
                daemon=True,
            )
        )
    if endpoint_sensor is not None:
        threads.append(
            threading.Thread(
                name="endpoint_sensor",
                target=sensor_thread_runner,
                args=("endpoint_sensor", endpoint_sensor.run_loop, qm, stop_event, stop_event, ctx),
                daemon=True,
            )
        )
    if net_sensor is not None:
        threads.append(
            threading.Thread(
                name="network_sensor",
                target=sensor_thread_runner,
                args=("network_sensor", net_sensor.run_loop, qm, stop_event, stop_event, ctx),
                daemon=True,
            )
        )

    if browser_upload_sensor is not None:
        threads.append(
            threading.Thread(
                name="browser_upload_sensor",
                target=sensor_thread_runner,
                args=("browser_upload_sensor", browser_upload_sensor.run_loop, qm, stop_event, stop_event, ctx),
                daemon=True,
            )
        )

    if print_sensor is not None:
        threads.append(
            threading.Thread(
                name="print_sensor",
                target=sensor_thread_runner,
                args=("print_sensor", print_sensor.run_loop, qm, stop_event, stop_event, ctx),
                daemon=True,
            )
        )

    for t in threads:
        t.start()

    def _handle_sig(sig, *_):
        reason = "SIGINT" if sig == signal.SIGINT else "SIGTERM"
        print("[main] got", reason, flush=True)

        current_ctx: Dict[str, Any] = {}
        if ctx:
            try:
                current_ctx = ctx.snapshot() or {}
            except Exception:
                current_ctx = {}

        _safe_call(
            qm.enqueue_event,
            {
                "type": "shutdown",
                "severity": "info",
                "source": "l1",
                "reason": reason,
                "pid": os.getpid(),
                "start_ts": start_ts,
                "context": current_ctx,
                "ts": time.time(),
            },
        )
        stop_event.set()

    try:
        signal.signal(signal.SIGINT, _handle_sig)
        signal.signal(signal.SIGTERM, _handle_sig)
    except Exception:
        pass

    try:
        while not stop_event.is_set():
            if STOP_FLAG.exists():
                print("[main] stop.flag detected", flush=True)
                _handle_sig(signal.SIGTERM)
                break
            time.sleep(0.5)
    except KeyboardInterrupt:
        _handle_sig(signal.SIGINT)

    print("[main] stop_event set -> draining queue", flush=True)

    drain_deadline = time.time() + 3.0
    while time.time() < drain_deadline:
        if qm.event_queue.empty():
            break
        time.sleep(0.1)

    for t in threads:
        try:
            t.join(timeout=2.0)
        except Exception:
            pass

    for s in sinks:
        try:
            if hasattr(s, "close"):
                s.close()
        except Exception:
            pass

    if persistent_queue is not None:
        try:
            persistent_queue.flush()
        except Exception:
            pass
        try:
            persistent_queue.close()
        except Exception:
            pass

    print("[main] exit", flush=True)


if __name__ == "__main__":
    main()
