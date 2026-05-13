import logging
import os

def setup_logging():
    log_dir = 'logs'
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    logging.basicConfig(
        filename=os.path.join(log_dir, 'watchdog.log'),
        level=logging.DEBUG,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

def load_config():
    # Đọc cấu hình từ file hoặc môi trường
    config = {
        "sensor_type": "usb",
        "max_event_queue_size": 1000
    }
    return config