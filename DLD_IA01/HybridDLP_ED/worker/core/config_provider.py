"""
config_provider.py — Cung cấp unified interface để lấy rules config

Ưu tiên:
1. Nếu config_sync (agent) khả dụng → dùng config realtime từ server
2. Nếu không → fallback to rules_config_manager (local file, deprecated)

Cách dùng:
    from .config_provider import get_config_provider
    
    provider = get_config_provider()
    browser_apps = provider.get_browser_apps()
"""

from typing import Optional, Set, List, Dict, Any
from loguru import logger


class ConfigProvider:
    """Unified interface để lấy config từ nhiều source"""
    
    def __init__(self):
        self._config_sync = None
        self._config_manager = None
        
        # Thử load config_sync từ agent
        try:
            from pathlib import Path
            import sys
            
            # Đường dẫn agent folder
            agent_path = Path(__file__).parent.parent.parent / "agent"
            if agent_path.exists() and str(agent_path) not in sys.path:
                sys.path.insert(0, str(agent_path))
            
            from config_sync import get_config_sync
            
            sync = get_config_sync()
            if sync:
                self._config_sync = sync
                logger.info("ConfigProvider using config_sync from agent")
        except Exception as e:
            logger.debug(f"Config sync not available: {e}")
        
        # Fallback to local rules_config_manager
        if not self._config_sync:
            try:
                from .rules_config_manager import get_config_manager
                
                self._config_manager = get_config_manager()
                logger.info("ConfigProvider using rules_config_manager (local)")
            except Exception as e:
                logger.warning(f"Rules config manager not available: {e}")
    
    def _get_from_sync(self, method_name: str, *args, **kwargs):
        """Gọi method từ config_sync nếu có"""
        try:
            if self._config_sync and hasattr(self._config_sync, method_name):
                method = getattr(self._config_sync, method_name)
                return method(*args, **kwargs)
        except Exception as e:
            logger.error(f"ConfigSync call failed ({method_name}): {e}")
        return None
    
    def _get_from_manager(self, method_name: str, *args, **kwargs):
        """Gọi method từ config_manager nếu có"""
        try:
            if self._config_manager and hasattr(self._config_manager, method_name):
                method = getattr(self._config_manager, method_name)
                return method(*args, **kwargs)
        except Exception as e:
            logger.error(f"ConfigManager call failed ({method_name}): {e}")
        return None
    
    def get_config(self) -> Dict[str, Any]:
        """Lấy toàn bộ config"""
        result = self._get_from_sync('get_local_config')
        if result:
            return result
        
        result = self._get_from_manager('get_config')
        return result or {}
    
    # ===== Clipboard Rule =====
    def get_browser_apps(self) -> Set[str]:
        result = self._get_from_sync('get_browser_apps')
        if result is not None:
            return result
        
        result = self._get_from_manager('get_browser_apps')
        return result or set()
    
    def get_messaging_apps(self) -> Set[str]:
        result = self._get_from_sync('get_messaging_apps')
        if result is not None:
            return result
        
        result = self._get_from_manager('get_messaging_apps')
        return result or set()
    
    def get_sensitive_domains(self) -> Set[str]:
        result = self._get_from_sync('get_sensitive_domains')
        if result is not None:
            return result
        
        result = self._get_from_manager('get_sensitive_domains')
        return result or set()
    
    def get_sensitive_title_keywords(self) -> List[str]:
        result = self._get_from_sync('get_sensitive_title_keywords')
        if result is not None:
            return result
        
        result = self._get_from_manager('get_sensitive_title_keywords')
        return result or []
    
    # ===== USB Rule =====
    def get_removable_drives(self) -> List[str]:
        result = self._get_from_sync('get_removable_drives')
        if result is not None:
            return result
        
        result = self._get_from_manager('get_removable_drives')
        return result or []
    
    # ===== Network Rule =====
    def get_upload_types(self) -> Set[str]:
        result = self._get_from_sync('get_upload_types')
        if result is not None:
            return result
        
        result = self._get_from_manager('get_upload_types')
        return result or set()
    
    def get_network_browser_apps(self) -> Set[str]:
        result = self._get_from_sync('get_network_browser_apps')
        if result is not None:
            return result
        
        result = self._get_from_manager('get_network_browser_apps')
        return result or set()
    
    def get_desktop_upload_apps(self) -> Set[str]:
        result = self._get_from_sync('get_desktop_upload_apps')
        if result is not None:
            return result
        
        result = self._get_from_manager('get_desktop_upload_apps')
        return result or set()
    
    def get_cli_tools(self) -> Set[str]:
        result = self._get_from_sync('get_cli_tools')
        if result is not None:
            return result
        
        result = self._get_from_manager('get_cli_tools')
        return result or set()
    
    def get_network_sensitive_domains(self) -> Set[str]:
        result = self._get_from_sync('get_network_sensitive_domains')
        if result is not None:
            return result
        
        result = self._get_from_manager('get_network_sensitive_domains')
        return result or set()


# Global instance
_provider: Optional[ConfigProvider] = None


def get_config_provider() -> ConfigProvider:
    """Lấy global ConfigProvider instance"""
    global _provider
    if _provider is None:
        _provider = ConfigProvider()
    return _provider
