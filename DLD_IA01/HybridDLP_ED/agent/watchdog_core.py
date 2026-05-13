import os
import sys
import json
import time
import logging
import subprocess
import threading
from pathlib import Path
from typing import Optional, Tuple

# ===== Paths =====
BASE_DIR = Path(__file__).resolve().parent               # ...\agent
PROJECT_ROOT = BASE_DIR.parent                          # ...\HybridDLP_ED
RUNTIME_DIR = PROJECT_ROOT / "runtime"
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
        self.worker: Optional[subprocess.Popen] = None

        self._backoff_i = 0
        self._stale_strikes = 0

        self._sensor_out = None
        self._sensor_err = None

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
            "worker_pid": self.worker.pid if self.worker else None,
        }
        atomic_write_json(WD_HEARTBEAT_FILE, payload)

    def _open_sensor_logs(self) -> Tuple[object, object]:
        # append binary để giữ history + tránh vấn đề encoding
        out_f = open(LOG_DIR / "sensor.stdout.log", "ab", buffering=0)
        err_f = open(LOG_DIR / "sensor.stderr.log", "ab", buffering=0)
        return out_f, err_f

    def _close_sensor_logs(self):
        for f in (self._sensor_out, self._sensor_err):
            try:
                if f:
                    f.close()
            except Exception:
                pass
        self._sensor_out = None
        self._sensor_err = None

    def spawn_worker(self) -> subprocess.Popen:
        python_exe = get_python_exe()
        sensor_path = str(BASE_DIR / "sensor.py")

        cmd = [python_exe, sensor_path]
        logger.info(f"Spawning sensor: {cmd}")

        creationflags = 0
        if os.name == "nt":
            creationflags = subprocess.CREATE_NEW_PROCESS_GROUP

        self._close_sensor_logs()
        self._sensor_out, self._sensor_err = self._open_sensor_logs()

        p = subprocess.Popen(
            cmd,
            cwd=str(BASE_DIR),  # service thường chạy từ System32 -> ép cwd
            stdout=self._sensor_out,
            stderr=self._sensor_err,
            creationflags=creationflags,
        )
        return p

    def stop_worker(self):
        if self.worker and self.worker.poll() is None:
            pid = self.worker.pid
            logger.info(f"Stopping sensor pid={pid}")
            kill_process_tree_windows(pid)

        self.worker = None
        self._stale_strikes = 0
        self._close_sensor_logs()

    def _sleep_interruptible(self, seconds: int):
        for _ in range(seconds):
            if self.stopped():
                break
            time.sleep(1)

    def monitor_loop(self):
        # ép cwd
        os.chdir(str(BASE_DIR))

        logger.info("Supervisor started.")
        logger.info(f"BASE_DIR={BASE_DIR}")
        logger.info(f"PROJECT_ROOT={PROJECT_ROOT}")
        logger.info(f"LOG_DIR={LOG_DIR}")
        logger.info(f"STATE_DIR={STATE_DIR}")
        logger.info(f"Chosen python_exe={get_python_exe()}")
        logger.info(f"sys.executable={sys.executable}")
        logger.info(f"HYBRIDDLP_PYTHON={os.environ.get('HYBRIDDLP_PYTHON')}")

        # dọn stop.flag cũ
        if STOP_FILE.exists():
            try:
                STOP_FILE.unlink()
            except Exception:
                pass

        self.write_watchdog_heartbeat("starting")

        while not self.stopped():
            try:
                # (1) worker chưa có hoặc đã chết
                if self.worker is None or self.worker.poll() is not None:
                    if self.worker is not None:
                        rc = self.worker.returncode
                        logger.warning(f"Sensor exited. returncode={rc}")

                    wait_s = BACKOFF_SECONDS[min(self._backoff_i, len(BACKOFF_SECONDS) - 1)]
                    if wait_s > 0:
                        logger.info(f"Backoff {wait_s}s before restart...")
                        self._sleep_interruptible(wait_s)

                    if self.stopped():
                        break

                    self.worker = self.spawn_worker()
                    logger.info(f"Sensor started pid={self.worker.pid}")

                    # tăng backoff vì vừa phải restart (crash loop)
                    self._backoff_i = min(self._backoff_i + 1, len(BACKOFF_SECONDS) - 1)
                    self._stale_strikes = 0

                # (2) worker đang sống nhưng heartbeat stale
                if self.worker and self.worker.poll() is None:
                    if is_heartbeat_stale_by_ts(SENSOR_HEARTBEAT_FILE, HB_TIMEOUT):
                        self._stale_strikes += 1
                        logger.warning(f"Sensor heartbeat stale strike={self._stale_strikes}")

                        if self._stale_strikes >= STALE_STRIKES_TO_RESTART:
                            logger.warning("Sensor stale threshold reached -> restarting sensor")
                            self.stop_worker()
                            continue
                    else:
                        # heartbeat OK -> reset strikes + reset backoff
                        self._stale_strikes = 0
                        self._backoff_i = 0

                self.write_watchdog_heartbeat("running")
                time.sleep(2)

            except Exception as e:
                logger.exception(f"Supervisor loop error: {e}")
                time.sleep(2)

        logger.info("Supervisor stopping...")
        self.write_watchdog_heartbeat("stopping")
        self.stop_worker()
        self.write_watchdog_heartbeat("stopped")
        logger.info("Supervisor stopped cleanly.")


def run_foreground():
    Supervisor().monitor_loop()


if __name__ == "__main__":
    run_foreground()
