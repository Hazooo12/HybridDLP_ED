import os
import sys
import json
import time
import logging
import subprocess
import threading
from pathlib import Path
from typing import Optional, Tuple, Dict

# ===== Paths =====
SERVICE_DIR = Path(__file__).resolve().parent            # ...\service
PROJECT_ROOT = SERVICE_DIR.parent                        # ...\HybridDLP_ED
AGENT_DIR = PROJECT_ROOT / "agent"
RUNTIME_DIR = AGENT_DIR / "runtime"
LOG_DIR = RUNTIME_DIR / "logs"
STATE_DIR = RUNTIME_DIR / "state"

STOP_FILE = STATE_DIR / "stop.watchdog.flag"
WD_HEARTBEAT_FILE = STATE_DIR / "watchdog_heartbeat.json"
SENSOR_HEARTBEAT_FILE = STATE_DIR / "sensor_heartbeat.json"

LOG_DIR.mkdir(parents=True, exist_ok=True)
STATE_DIR.mkdir(parents=True, exist_ok=True)

# Sensor không update heartbeat quá timeout -> coi như treo
HB_TIMEOUT = 10
STALE_STRIKES_TO_RESTART = 2

# Backoff khi chết liên tục
BACKOFF_SECONDS = [0, 2, 5, 10, 20, 30]


def setup_logger() -> logging.Logger:
    logger = logging.getLogger("HybridDLPWatchdog")
    logger.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")

    # File log cố định
    fh = logging.FileHandler(LOG_DIR / "watchdog.log", encoding="utf-8")
    fh.setFormatter(fmt)

    # Console log (khi chạy foreground)
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)

    if not logger.handlers:
        logger.addHandler(fh)
        logger.addHandler(sh)
    return logger


logger = setup_logger()


def atomic_write_json(path: Path, data: dict) -> None:
    tmp = path.with_suffix(f".{os.getpid()}.tmp")  # unique tmp
    payload = json.dumps(data, ensure_ascii=False)

    for i in range(5):
        try:
            tmp.write_text(payload, encoding="utf-8")
            os.replace(str(tmp), str(path))  # atomic replace
            return
        except PermissionError:
            time.sleep(0.05 * (i + 1))
        except Exception:
            return


def read_json(path: Path) -> Optional[dict]:
    try:
        if not path.exists():
            return None
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def is_heartbeat_stale_by_ts(path: Path, timeout_s: int) -> bool:
    """Stale dựa trên field ts trong JSON (ổn định hơn mtime)."""
    data = read_json(path)
    if not data:
        return True
    try:
        ts = int(data.get("ts", 0))
        return (time.time() - ts) > timeout_s
    except Exception:
        return True


def kill_process_tree_windows(pid: int) -> None:
    """Không dùng psutil: kill tree bằng taskkill."""
    try:
        subprocess.run(
            ["taskkill", "/PID", str(pid), "/T", "/F"],
            capture_output=True,
            text=True,
            check=False,
        )
    except Exception as e:
        logger.warning(f"taskkill failed: {e}")


def get_python_exe() -> str:
    """
    Chọn đúng python.exe để spawn sensor.
    - Ưu tiên env HYBRIDDLP_PYTHON (service cũng đọc được nếu set /M)
    - Nếu sys.executable là pythonservice.exe -> đổi sang python.exe cùng thư mục
    - Fallback: sys.executable
    """
    p = os.environ.get("HYBRIDDLP_PYTHON")
    if p:
        try:
            pp = Path(p)
            if pp.exists() and pp.is_file():
                return str(pp)
        except Exception:
            pass

    exe = Path(sys.executable)

    # Case chạy dưới Windows Service wrapper: sys.executable có thể là pythonservice.exe
    if exe.name.lower() == "pythonservice.exe":
        cand = exe.with_name("python.exe")
        if cand.exists():
            return str(cand)

        # Nếu python.exe không cùng folder, thử common locations (best-effort)
        for guess in [r"C:\Python310\python.exe", r"C:\Python311\python.exe", r"C:\Python312\python.exe"]:
            if Path(guess).exists():
                return guess

    return str(exe)


class Supervisor:
    """
    Day 3 - SV1:
    - Spawn sensor.py
    - Monitor: process exit + heartbeat stale (ts)
    - Restart: kill tree + backoff
    - Emit watchdog heartbeat
    """

    def __init__(self):
        self._stop_evt = threading.Event()
        self.processes: Dict[str, Optional[subprocess.Popen]] = {
            "sensor": None,
            "worker": None,
            "dashboard": None,
        }
        self._backoff_i: Dict[str, int] = {k: 0 for k in self.processes}
        self._stale_strikes = 0
        self._logs: Dict[str, Tuple[Optional[object], Optional[object]]] = {
            k: (None, None) for k in self.processes
        }
        self.enable_sensor = os.getenv("HYBRIDDLP_ENABLE_SENSOR", "1").strip().lower() in {"1", "true", "yes", "on"}
        self.enable_worker = os.getenv("HYBRIDDLP_ENABLE_WORKER", "1").strip().lower() in {"1", "true", "yes", "on"}
        self.enable_dashboard = os.getenv("HYBRIDDLP_ENABLE_DASHBOARD", "1").strip().lower() in {"1", "true", "yes", "on"}

    def request_stop(self):
        self._stop_evt.set()
        try:
            STOP_FILE.write_text("1", encoding="utf-8")
        except Exception:
            pass

    def stopped(self) -> bool:
        return self._stop_evt.is_set() or STOP_FILE.exists()

    def write_watchdog_heartbeat(self, status: str):
        payload = {
            "ts": int(time.time()),
            "role": "watchdog",
            "status": status,
            "pids": {
                name: (proc.pid if proc else None)
                for name, proc in self.processes.items()
            },
        }
        atomic_write_json(WD_HEARTBEAT_FILE, payload)

    def _open_logs(self, name: str) -> Tuple[object, object]:
        out_f = open(LOG_DIR / f"{name}.stdout.log", "ab", buffering=0)
        err_f = open(LOG_DIR / f"{name}.stderr.log", "ab", buffering=0)
        return out_f, err_f

    def _close_logs(self, name: str):
        out_f, err_f = self._logs.get(name, (None, None))
        for f in (out_f, err_f):
            try:
                if f:
                    f.close()
            except Exception:
                pass
        self._logs[name] = (None, None)

    def spawn_process(self, name: str) -> subprocess.Popen:
        python_exe = get_python_exe()
        if name == "sensor":
            cmd = [python_exe, "-m", "agent.sensor"]
            cwd = str(PROJECT_ROOT)
        elif name == "worker":
            cmd = [python_exe, "worker.py"]
            cwd = str(PROJECT_ROOT / "worker")
        elif name == "dashboard":
            cmd = [python_exe, "-m", "streamlit", "run", "dashB.py"]
            cwd = str(PROJECT_ROOT / "dashboard")
        else:
            raise ValueError(f"Unknown process: {name}")
        logger.info(f"Spawning {name}: {cmd}")

        creationflags = 0
        if os.name == "nt":
            creationflags = subprocess.CREATE_NEW_PROCESS_GROUP

        self._close_logs(name)
        out_f, err_f = self._open_logs(name)
        self._logs[name] = (out_f, err_f)

        p = subprocess.Popen(
            cmd,
            cwd=cwd,
            stdout=out_f,
            stderr=err_f,
            creationflags=creationflags,
        )
        return p

    def stop_process(self, name: str):
        proc = self.processes.get(name)
        if proc and proc.poll() is None:
            pid = proc.pid
            logger.info(f"Stopping {name} pid={pid}")
            kill_process_tree_windows(pid)
        self.processes[name] = None
        self._backoff_i[name] = 0
        self._close_logs(name)

    def _sleep_interruptible(self, seconds: int):
        for _ in range(seconds):
            if self.stopped():
                break
            time.sleep(1)

    def monitor_loop(self):
        # ép cwd
        os.chdir(str(PROJECT_ROOT))

        logger.info("Supervisor started.")
        logger.info(f"SERVICE_DIR={SERVICE_DIR}")
        logger.info(f"PROJECT_ROOT={PROJECT_ROOT}")
        logger.info(f"AGENT_DIR={AGENT_DIR}")
        logger.info(f"LOG_DIR={LOG_DIR}")
        logger.info(f"STATE_DIR={STATE_DIR}")
        logger.info(f"Chosen python_exe={get_python_exe()}")
        logger.info(f"sys.executable={sys.executable}")
        logger.info(f"HYBRIDDLP_PYTHON={os.environ.get('HYBRIDDLP_PYTHON')}")
        logger.info(
            f"Enabled stack: sensor={self.enable_sensor}, "
            f"worker={self.enable_worker}, dashboard={self.enable_dashboard}"
        )

        # dọn stop.flag cũ
        if STOP_FILE.exists():
            try:
                STOP_FILE.unlink()
            except Exception:
                pass

        self.write_watchdog_heartbeat("starting")

        while not self.stopped():
            try:
                desired = {
                    "sensor": self.enable_sensor,
                    "worker": self.enable_worker,
                    "dashboard": self.enable_dashboard,
                }
                for name, enabled in desired.items():
                    if not enabled:
                        continue
                    proc = self.processes.get(name)
                    if proc is None or proc.poll() is not None:
                        if proc is not None:
                            logger.warning(f"{name} exited. returncode={proc.returncode}")
                        wait_s = BACKOFF_SECONDS[min(self._backoff_i[name], len(BACKOFF_SECONDS) - 1)]
                        if wait_s > 0:
                            logger.info(f"Backoff {wait_s}s before restarting {name}...")
                            self._sleep_interruptible(wait_s)
                        if self.stopped():
                            break
                        self.processes[name] = self.spawn_process(name)
                        logger.info(f"{name} started pid={self.processes[name].pid}")
                        self._backoff_i[name] = min(self._backoff_i[name] + 1, len(BACKOFF_SECONDS) - 1)

                # Sensor heartbeat health check
                sensor_proc = self.processes.get("sensor")
                if self.enable_sensor and sensor_proc and sensor_proc.poll() is None:
                    if is_heartbeat_stale_by_ts(SENSOR_HEARTBEAT_FILE, HB_TIMEOUT):
                        self._stale_strikes += 1
                        logger.warning(f"Sensor heartbeat stale strike={self._stale_strikes}")
                        if self._stale_strikes >= STALE_STRIKES_TO_RESTART:
                            logger.warning("Sensor stale threshold reached -> restarting sensor")
                            self.stop_process("sensor")
                            continue
                    else:
                        self._stale_strikes = 0
                        self._backoff_i["sensor"] = 0

                self.write_watchdog_heartbeat("running")
                time.sleep(2)

            except Exception as e:
                logger.exception(f"Supervisor loop error: {e}")
                time.sleep(2)

        logger.info("Supervisor stopping...")
        self.write_watchdog_heartbeat("stopping")
        self.stop_process("dashboard")
        self.stop_process("worker")
        self.stop_process("sensor")
        self.write_watchdog_heartbeat("stopped")
        logger.info("Supervisor stopped cleanly.")


def run_foreground():
    Supervisor().monitor_loop()


if __name__ == "__main__":
    run_foreground()
