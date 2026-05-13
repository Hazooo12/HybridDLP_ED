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
    Windows Service wrapper cho watchdog.
    - Start: chạy watchdog.run_foreground() trong thread riêng
    - Stop: tạo stop.flag để watchdog dừng sạch + signal stop event
    """
    _svc_name_ = "HybridDLPWatchdog"
    _svc_display_name_ = "HybridDLP Watchdog Service"
    _svc_description_ = "Supervisor service that monitors and restarts the HybridDLP sensor process."

    def __init__(self, args):
        super().__init__(args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self._thread = None
        self._stop_requested = threading.Event()

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self._stop_requested.set()

        # Tạo stop.flag để watchdog dừng sạch
        try:
            runtime_state = os.path.join(BASE_DIR, "runtime", "state")
            os.makedirs(runtime_state, exist_ok=True)
            with open(os.path.join(runtime_state, "stop.flag"), "w", encoding="utf-8") as f:
                f.write("1")
        except Exception:
            pass

        win32event.SetEvent(self.hWaitStop)

    def SvcDoRun(self):
        # IMPORTANT: khi chạy service, cwd thường là System32 -> ép về folder project
        os.chdir(BASE_DIR)

        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, "")
        )

        self._thread = threading.Thread(target=self._run_watchdog, daemon=True)
        self._thread.start()

        # chờ signal stop
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
            import HybridDLP_ED.agent.watchdog_service as watchdog_service  # watchdog.py cùng folder
            watchdog_service.run_foreground()
        except Exception as e:
            servicemanager.LogErrorMsg(f"Watchdog crashed: {e}")


if __name__ == "__main__":
    win32serviceutil.HandleCommandLine(HybridDLPWatchdogService)
