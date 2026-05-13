"""
password_manager.py — Quản lý mật khẩu hệ thống

Lưu mật khẩu hash (tidak lưu plain text)
"""

import hashlib
import os
import json
from pathlib import Path


CONFIG_DIR = Path(__file__).resolve().parent / "runtime" / "config"
PASSWORD_FILE = CONFIG_DIR / "password.json"


class PasswordManager:
    """Quản lý mật khẩu hệ thống."""
    
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._init()
        return cls._instance
    
    def _init(self):
        """Khởi tạo."""
        self._password_hash = None
        self._load()
    
    def _load(self):
        """Tải password hash từ file."""
        if PASSWORD_FILE.exists():
            try:
                with open(PASSWORD_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self._password_hash = data.get("password_hash")
            except Exception as e:
                print(f"[FAIL] Lỗi tải password: {e}")
    
    def _save(self):
        """Lưu password hash vào file."""
        try:
            CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            with open(PASSWORD_FILE, "w", encoding="utf-8") as f:
                json.dump({"password_hash": self._password_hash}, f)
        except Exception as e:
            print(f"[FAIL] Lỗi lưu password: {e}")
    
    def set_password(self, password: str) -> None:
        """Set password mới (salt + hash)."""
        if not password:
            raise ValueError("Password không được rỗng")
        
        # Salt + Hash
        salt = os.urandom(32).hex()  # 32 bytes = 64 hex chars
        pwd_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            bytes.fromhex(salt),
            100000  # iterations
        ).hex()
        
        self._password_hash = f"{salt}${pwd_hash}"
        self._save()
    
    def verify_password(self, password: str) -> bool:
        """Kiểm tra password có khớp không."""
        if not self._password_hash:
            return False
        
        try:
            salt, pwd_hash = self._password_hash.split("$", 1)
            computed_hash = hashlib.pbkdf2_hmac(
                'sha256',
                password.encode('utf-8'),
                bytes.fromhex(salt),
                100000
            ).hex()
            return computed_hash == pwd_hash
        except Exception:
            return False
    
    def is_initialized(self) -> bool:
        """Kiểm tra đã set password chưa."""
        return self._password_hash is not None


_password_manager = PasswordManager()

def get_password_manager() -> PasswordManager:
    return _password_manager

def set_password(password: str) -> None:
    _password_manager.set_password(password)

def verify_password(password: str) -> bool:
    return _password_manager.verify_password(password)

def is_password_set() -> bool:
    return _password_manager.is_initialized()
