import time

class RecoveryPolicy:
    def __init__(self, service_runner):
        self.service_runner = service_runner

    def apply_policy(self):
        """Áp dụng chính sách phục hồi khi có sự cố."""
        while True:
            if self.service_runner.watchdog_service.is_healthy():
                # Nếu mọi thứ ổn định, không làm gì
                time.sleep(10)
            else:
                # Nếu có lỗi, dừng lại và khởi động lại các module
                self.service_runner.stop_all()
                time.sleep(2)
                self.service_runner.start_all()