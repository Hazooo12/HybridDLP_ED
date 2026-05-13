from watchdog_core import WatchdogCore
from recovery_policy import RecoveryPolicy

class WatchdogService:
    def __init__(self):
        self.watchdog_core = WatchdogCore()
        self.recovery_policy = RecoveryPolicy(self)

    def start(self):
        """Bắt đầu giám sát toàn bộ service."""
        self.watchdog_core.start()
        self.recovery_policy.apply_policy()

    def stop(self):
        """Dừng giám sát toàn bộ service."""
        self.watchdog_core.stop()