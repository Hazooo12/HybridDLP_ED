from watchdog_service import HybridDLPWatchdogService

class ServiceRunner:
    def __init__(self):
        self.watchdog_service = HybridDLPWatchdogService

    def start_all(self):
        """Khởi động tất cả các module trong service."""
        # Dùng Windows service để start watchdog
        self.watchdog_service.SvcDoRun()

    def stop_all(self):
        """Dừng tất cả các module trong service."""
        self.watchdog_service.SvcStop()