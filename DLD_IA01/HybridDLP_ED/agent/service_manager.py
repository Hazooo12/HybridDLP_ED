"""
service_manager.py — Quản lý Sensor và Worker

Start/Stop sensor và worker processes
"""

import subprocess
import os
import sys
import time
from pathlib import Path
from typing import Optional, Tuple


PROJECT_ROOT = Path(__file__).resolve().parent.parent


class ServiceManager:
    """Quản lý Sensor và Worker."""
    
    def __init__(self):
        self.sensor_process: Optional[subprocess.Popen] = None
        self.worker_process: Optional[subprocess.Popen] = None
    
    def _get_python_executable(self) -> str:
        """Lấy đường dẫn Python executable."""
        return sys.executable
    
    def start_sensor(self) -> Tuple[bool, str]:
        """Khởi động Sensor."""
        try:
            if self.sensor_process and self.sensor_process.poll() is None:
                return False, "Sensor đang chạy"
            
            # Chạy: python -m agent.sensor
            self.sensor_process = subprocess.Popen(
                [self._get_python_executable(), "-m", "agent.sensor"],
                cwd=str(PROJECT_ROOT),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0,
            )
            
            # Chờ xem có crash không
            time.sleep(2)
            if self.sensor_process.poll() is not None:
                return False, "Sensor khởi động thất bại"
            
            return True, "Sensor đã khởi động"
        except Exception as e:
            return False, f"Lỗi khởi động Sensor: {e}"
    
    def stop_sensor(self) -> Tuple[bool, str]:
        """Tắt Sensor."""
        try:
            if not self.sensor_process or self.sensor_process.poll() is not None:
                return False, "Sensor không chạy"
            
            try:
                self.sensor_process.terminate()
                self.sensor_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.sensor_process.kill()
            
            return True, "Sensor đã tắt"
        except Exception as e:
            return False, f"Lỗi tắt Sensor: {e}"
    
    def is_sensor_running(self) -> bool:
        """Kiểm tra Sensor có chạy không."""
        return self.sensor_process is not None and self.sensor_process.poll() is None
    
    def start_worker(self) -> Tuple[bool, str]:
        """Khởi động Worker."""
        try:
            if self.worker_process and self.worker_process.poll() is None:
                return False, "Worker đang chạy"
            
            # Chạy: python worker/worker.py
            log_path = PROJECT_ROOT / "worker_process.log"
            log_path.parent.mkdir(parents=True, exist_ok=True)

            self.worker_process = subprocess.Popen(
                [self._get_python_executable(), "worker/worker.py"],
                cwd=str(PROJECT_ROOT),
                stdout=open(log_path, "a", encoding="utf-8"),
                stderr=subprocess.STDOUT,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0,
            )
            
            # Chờ xem có crash không (tăng timeout để worker khởi động)
            time.sleep(3)
            if self.worker_process.poll() is not None:
                try:
                    text = log_path.read_text(encoding="utf-8", errors="ignore")[-2000:]
                    return False, f"Worker khởi động thất bại. Xem {log_path}.\n{text}"
                except Exception:
                    return False, "Worker khởi động thất bại (xem worker_process.log)."
            
            return True, "Worker đã khởi động"
        except Exception as e:
            return False, f"Lỗi khởi động Worker: {e}"
    
    def stop_worker(self) -> Tuple[bool, str]:
        """Tắt Worker."""
        try:
            if not self.worker_process or self.worker_process.poll() is not None:
                return False, "Worker không chạy"
            
            try:
                self.worker_process.terminate()
                self.worker_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.worker_process.kill()
            
            return True, "Worker đã tắt"
        except Exception as e:
            return False, f"Lỗi tắt Worker: {e}"
    
    def is_worker_running(self) -> bool:
        """Kiểm tra Worker có chạy không."""
        return self.worker_process is not None and self.worker_process.poll() is None


_service_manager = ServiceManager()

def get_service_manager() -> ServiceManager:
    return _service_manager
