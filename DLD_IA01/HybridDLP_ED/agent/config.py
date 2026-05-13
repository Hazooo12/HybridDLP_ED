"""
config.py — Quản lý cấu hình HybridDLP (Server URL, API Key)
"""

import os
import json
from pathlib import Path


CONFIG_DIR = Path(__file__).resolve().parent / "runtime" / "config"
CONFIG_FILE = CONFIG_DIR / "config.json"

DEFAULT_SERVER_URL = "http://100.91.22.25:8000"
DEFAULT_API_KEY = "dlp-key-may-ketoan-01"


class Config:
    """Quản lý cấu hình DLP."""
    
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._init_config()
        return cls._instance
    
    def _init_config(self):
        """Khởi tạo config từ file hoặc env vars."""
        self._config = {}
        self._load_from_file()
        # Ghi đè bằng env vars nếu tồn tại
        if os.getenv("DLP_SERVER_URL"):
            self._config["server_url"] = os.getenv("DLP_SERVER_URL")
        if os.getenv("DLP_API_KEY"):
            self._config["api_key"] = os.getenv("DLP_API_KEY")
    
    def _load_from_file(self) -> None:
        """Đọc config từ file JSON."""
        if CONFIG_FILE.exists():
            try:
                with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                    self._config = json.load(f)
            except Exception as e:
                print(f"[WARN]  Lỗi đọc config: {e}, sử dụng mặc định")
                self._config = self._get_defaults()
        else:
            self._config = self._get_defaults()
            self._save_to_file()
    
    def _get_defaults(self) -> dict:
        """Giá trị mặc định."""
        return {
            "server_url": DEFAULT_SERVER_URL,
            "api_key": DEFAULT_API_KEY,
        }
    
    def _save_to_file(self) -> None:
        """Ghi config vào file JSON."""
        try:
            CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(self._config, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"[FAIL] Lỗi ghi config: {e}")
    
    def get(self, key: str, default=None):
        """Lấy giá trị từ config."""
        return self._config.get(key, default)
    
    def set(self, key: str, value) -> None:
        """Cập nhật giá trị và lưu vào file."""
        self._config[key] = value
        self._save_to_file()
    
    def get_server_url(self) -> str:
        """Lấy Server URL."""
        return self.get("server_url", DEFAULT_SERVER_URL)
    
    def get_api_key(self) -> str:
        """Lấy API Key."""
        return self.get("api_key", DEFAULT_API_KEY)
    
    def update(self, server_url: str, api_key: str) -> None:
        """Cập nhật Server URL và API Key."""
        self.set("server_url", server_url)
        self.set("api_key", api_key)
    
    def __repr__(self) -> str:
        return f"Config(server_url={self.get_server_url()!r}, api_key=***)"


_config = Config()

def get_config() -> Config:
    return _config

def get_server_url() -> str:
    return _config.get_server_url()

def get_api_key() -> str:
    return _config.get_api_key()

def update_config(server_url: str, api_key: str) -> None:
    _config.update(server_url, api_key)
