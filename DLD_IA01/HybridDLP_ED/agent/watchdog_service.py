import os
import time
import threading

import win32event
import win32service
import win32serviceutil
import servicemanager

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class HybridDLPWatchdogService(win32serviceutil.ServiceFramework):
    """
    Day 3 - SV1:
    Windows Service wrapper cho watchdog_core.
    - Start: chạy watchdog_core.run_foreground() trong thread daemon
    - Stop: tạo stop flag để watchdog dừng sạch
    """
    _svc_name_ = "HybridDLPWatchdog"
    _svc_display_name_ = "HybridDLP Watchdog Service"
    _svc_description_ = "Supervisor service that monitors and restarts the HybridDLP sensor process."

    def __init__(self, args):
        super().__init__(args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self._thread = None

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)

        # tạo stop.flag để watchdog_core dừng sạch
        try:
            state_dir = os.path.join(os.path.dirname(BASE_DIR), "runtime", "state")
            os.makedirs(state_dir, exist_ok=True)
            with open(os.path.join(state_dir, "stop.watchdog.flag"), "w", encoding="utf-8") as f:
                f.write("1")
        except Exception:
            pass

        win32event.SetEvent(self.hWaitStop)

    def SvcDoRun(self):
        os.chdir(BASE_DIR)  # service thường chạy từ System32 -> ép cwd về project

        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, "")
        )

        self._thread = threading.Thread(target=self._run_watchdog, daemon=True)
        self._thread.start()

        # chờ stop
        win32event.WaitForSingleObject(self.hWaitStop, win32event.INFINITE)

        # cho watchdog thời gian dừng
        for _ in range(15):
            if not self._thread.is_alive():
                break
            time.sleep(1)

        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STOPPED,
            (self._svc_name_, "")
        )

    def _run_watchdog(self):
        try:
            import watchdog_core
            watchdog_core.run_foreground()
        except Exception as e:
            servicemanager.LogErrorMsg(f"Watchdog crashed: {e}")


if __name__ == "__main__":
    win32serviceutil.HandleCommandLine(HybridDLPWatchdogService)
