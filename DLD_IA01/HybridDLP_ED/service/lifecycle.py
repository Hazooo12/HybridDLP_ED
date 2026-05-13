import time

class LifecycleManager:
    def __init__(self, service_runner):
        self.service_runner = service_runner

    def monitor_service(self):
        """Theo dõi service để đảm bảo nó hoạt động ổn định."""
        while True:
            if not self.service_runner.watchdog_service.is_healthy():
                self.service_runner.stop_all()  # Dừng các module nếu không ổn định
                time.sleep(2)
                self.service_runner.start_all()  # Khởi động lại các module
            time.sleep(10)