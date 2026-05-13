"""
config_sync.py — Đồng bộ Rules Config từ Central Admin Server

Chức năng:
1. Periodically pull config từ admin server (qua Tailscale)
2. Lưu config locally
3. Notify khi config thay đổi để reload behavioral rules

Cách sử dụng:
    from config_sync import ConfigSync
    
    sync = ConfigSync(
        server_ip="100.x.x.x",  # Tailscale IP của admin
        api_key="dlp-key-...",
        local_config_path="rules_config.json"
    )
    
    sync.start()  # Chạy background sync
    sync.stop()
"""

import httpx
import threading
import time
import json
from pathlib import Path
from typing import Dict, Any, Optional, Callable
from datetime import datetime
from loguru import logger
import hashlib


class ConfigSync:
    """Đồng bộ config từ admin server"""
    
    def __init__(
        self,
        server_ip: str,
        api_key: str,
        local_config_path: str = "rules_config.json",
        sync_interval: int = 30,  # Giây
        timeout: int = 10  # HTTP timeout
    ):
        """
        Khởi tạo ConfigSync
        
        Args:
            server_ip: IP (Tailscale) của admin server
            api_key: API key của máy này
            local_config_path: Đường dẫn file config local
            sync_interval: Khoảng thời gian giữa mỗi lần sync (giây)
            timeout: HTTP request timeout (giây)
        """
        self.server_url = f"http://{server_ip}:8000"
        self.api_key = api_key
        self.local_config_path = Path(local_config_path)
        self.sync_interval = sync_interval
        self.timeout = timeout
        
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._local_config: Optional[Dict[str, Any]] = None
        self._config_hash = None  # Hash của config để detect changes
        self._on_config_updated: Optional[Callable] = None
        
        # Tạo thư mục nếu chưa có
        self.local_config_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Load config từ file local nếu có
        self._load_local_config()
        
        logger.info(
            f"ConfigSync initialized: server={self.server_url}, "
            f"api_key={self.api_key[:20]}..., "
            f"local_path={self.local_config_path}, "
            f"sync_interval={sync_interval}s"
        )
    
    def _load_local_config(self):
        """Load config từ file local"""
        try:
            if self.local_config_path.exists():
                with open(self.local_config_path, 'r', encoding='utf-8') as f:
                    self._local_config = json.load(f)
                logger.info(f"Loaded local config from {self.local_config_path}")
            else:
                logger.warning(f"Local config file not found: {self.local_config_path}")
                self._local_config = {}
        except Exception as e:
            logger.error(f"Error loading local config: {e}")
            self._local_config = {}
    
    def _save_local_config(self, config: Dict[str, Any]):
        """Lưu config vào file local"""
        try:
            with open(self.local_config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
            logger.info(f"Config saved to {self.local_config_path}")
            self._local_config = config
            return True
        except Exception as e:
            logger.error(f"Error saving local config: {e}")
            return False
    
    def _compute_config_hash(self, config: Dict[str, Any]) -> str:
        """Tính hash của config để detect changes"""
        try:
            config_str = json.dumps(config, sort_keys=True, ensure_ascii=False)
            return hashlib.sha256(config_str.encode()).hexdigest()
        except Exception as e:
            logger.error(f"Error computing config hash: {e}")
            return ""
    
    def _fetch_config_from_server(self) -> Optional[Dict[str, Any]]:
        """Fetch config từ admin server"""
        try:
            headers = {"X-API-Key": self.api_key}
            
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.get(
                    f"{self.server_url}/api/rules/config",
                    headers=headers
                )
            
            if resp.status_code == 200:
                data = resp.json()
                if data.get('status') == 'ok':
                    config = data.get('config', {})
                    logger.debug(f"Fetched config from server: {len(json.dumps(config))} bytes")
                    return config
                else:
                    logger.warning(f"Server returned error: {data.get('message')}")
            else:
                logger.warning(f"HTTP {resp.status_code}: {resp.text[:100]}")
        except httpx.TimeoutException:
            logger.warning(f"Timeout connecting to {self.server_url}")
        except Exception as e:
            logger.error(f"Error fetching config from server: {e}")
        
        return None
    
    def _on_config_changed(self, old_config: Dict[str, Any], new_config: Dict[str, Any]):
        """Gọi callback khi config thay đổi"""
        try:
            if self._on_config_updated:
                logger.info("Calling config update callback...")
                self._on_config_updated(new_config)
        except Exception as e:
            logger.error(f"Error in config update callback: {e}")
    
    def _sync_worker(self):
        """Background thread: periodically sync config"""
        logger.info("Config sync worker started")
        
        while self._running:
            try:
                # Fetch config từ server
                server_config = self._fetch_config_from_server()
                
                if server_config:
                    # Compute hash để detect changes
                    new_hash = self._compute_config_hash(server_config)
                    
                    # Nếu config thay đổi hoặc lần đầu tiên
                    if new_hash != self._config_hash:
                        logger.info(f"Config changed (hash: {self._config_hash} -> {new_hash})")
                        
                        old_config = self._local_config.copy() if self._local_config else {}
                        
                        # Lưu config local
                        if self._save_local_config(server_config):
                            self._config_hash = new_hash
                            
                            # Gọi callback nếu có
                            self._on_config_changed(old_config, server_config)
                        else:
                            logger.error("Failed to save config locally")
                    else:
                        logger.debug(f"Config unchanged (hash: {self._config_hash})")
                
            except Exception as e:
                logger.error(f"Sync worker error: {e}")
            
            # Chờ đến lần sync tiếp theo
            time.sleep(self.sync_interval)
        
        logger.info("Config sync worker stopped")
    
    def start(self):
        """Bắt đầu background sync"""
        if self._running:
            logger.warning("ConfigSync already running")
            return
        
        self._running = True
        self._thread = threading.Thread(target=self._sync_worker, daemon=True)
        self._thread.start()
        logger.info("ConfigSync started")
    
    def stop(self):
        """Dừng background sync"""
        if not self._running:
            logger.warning("ConfigSync not running")
            return
        
        self._running = False
        if self._thread:
            self._thread.join(timeout=10)
        logger.info("ConfigSync stopped")
    
    def set_on_config_updated(self, callback: Callable[[Dict[str, Any]], None]):
        """
        Set callback để gọi khi config thay đổi
        
        Args:
            callback: function(new_config: Dict[str, Any]) -> None
        """
        self._on_config_updated = callback
        logger.info(f"Config update callback set: {callback.__name__}")
    
    def get_local_config(self) -> Dict[str, Any]:
        """Lấy config hiện tại (local cache)"""
        return self._local_config.copy() if self._local_config else {}
    
    def get_browser_apps(self) -> set:
        """Lấy danh sách browser apps"""
        if not self._local_config:
            return set()
        return set(self._local_config.get('clipboard_paste_rule', {}).get('browser_apps', []))
    
    def get_messaging_apps(self) -> set:
        """Lấy danh sách messaging apps"""
        if not self._local_config:
            return set()
        return set(self._local_config.get('clipboard_paste_rule', {}).get('messaging_apps', []))
    
    def get_sensitive_domains(self) -> set:
        """Lấy danh sách sensitive domains"""
        if not self._local_config:
            return set()
        return set(self._local_config.get('clipboard_paste_rule', {}).get('sensitive_domains', []))
    
    def get_sensitive_title_keywords(self) -> list:
        """Lấy danh sách sensitive title keywords"""
        if not self._local_config:
            return []
        return self._local_config.get('clipboard_paste_rule', {}).get('sensitive_title_keywords', [])
    
    def get_removable_drives(self) -> list:
        """Lấy danh sách removable drives"""
        if not self._local_config:
            return []
        return self._local_config.get('usb_rule', {}).get('removable_drives', [])
    
    def get_upload_types(self) -> set:
        """Lấy danh sách upload types"""
        if not self._local_config:
            return set()
        return set(self._local_config.get('network_rule', {}).get('upload_types', []))
    
    def get_network_browser_apps(self) -> set:
        """Lấy danh sách browser apps cho network rule"""
        if not self._local_config:
            return set()
        return set(self._local_config.get('network_rule', {}).get('browser_apps', []))
    
    def get_desktop_upload_apps(self) -> set:
        """Lấy danh sách desktop upload apps"""
        if not self._local_config:
            return set()
        return set(self._local_config.get('network_rule', {}).get('desktop_upload_apps', []))
    
    def get_cli_tools(self) -> set:
        """Lấy danh sách CLI tools"""
        if not self._local_config:
            return set()
        return set(self._local_config.get('network_rule', {}).get('cli_tools', []))
    
    def get_network_sensitive_domains(self) -> set:
        """Lấy danh sách sensitive domains cho network rule"""
        if not self._local_config:
            return set()
        return set(self._local_config.get('network_rule', {}).get('sensitive_domains', []))


# Global instance
_config_sync: Optional[ConfigSync] = None


def init_config_sync(
    server_ip: str,
    api_key: str,
    local_config_path: str = "rules_config.json",
    sync_interval: int = 30,
    on_config_updated: Optional[Callable] = None
) -> ConfigSync:
    """
    Khởi tạo global ConfigSync instance
    
    Args:
        server_ip: IP (Tailscale) của admin server
        api_key: API key của máy này
        local_config_path: Đường dẫn file config local
        sync_interval: Khoảng thời gian sync (giây)
        on_config_updated: Callback khi config thay đổi
    
    Returns:
        ConfigSync instance
    """
    global _config_sync
    
    if _config_sync is not None:
        logger.warning("ConfigSync already initialized")
        return _config_sync
    
    _config_sync = ConfigSync(
        server_ip=server_ip,
        api_key=api_key,
        local_config_path=local_config_path,
        sync_interval=sync_interval
    )
    
    if on_config_updated:
        _config_sync.set_on_config_updated(on_config_updated)
    
    _config_sync.start()
    
    return _config_sync


def get_config_sync() -> Optional[ConfigSync]:
    """Lấy global ConfigSync instance"""
    return _config_sync
