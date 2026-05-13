"""
Rules Config Manager - Quản lý cấu hình các quy tắc từ file JSON
Cho phép admin cập nhật config mà không cần sửa code
"""
import json
from pathlib import Path
from typing import Dict, Any, List, Set, Optional
from loguru import logger


class RulesConfigManager:
    """
    Quản lý cấu hình các behavioral rules
    
    Load config từ JSON file
    Cung cấp interface để truy cập config
    Hỗ trợ reload config từ server
    """
    
    def __init__(self, config_file: Optional[str] = None):
        """
        Khởi tạo config manager
        
        Args:
            config_file: đường dẫn đến file config JSON
                       Nếu None, tìm file tại worker/core/rules_config.json
        """
        self.config_file = config_file
        self.config: Dict[str, Any] = {}
        self._load_config()
    
    def _get_default_config_path(self) -> Path:
        """Tìm file config mặc định"""
        # Thử các đường dẫn có thể
        possible_paths = [
            Path(__file__).parent / "rules_config.json",  # Cùng thư mục
            Path(__file__).parent.parent / "config" / "rules_config.json",  # ../config/
            Path.home() / ".hybridlp" / "rules_config.json",  # Home directory
        ]
        
        for path in possible_paths:
            if path.exists():
                logger.info(f"Found config file: {path}")
                return path
        
        # Nếu không tìm thấy, trả về đường dẫn mặc định
        return Path(__file__).parent / "rules_config.json"
    
    def _load_config(self):
        """Load config từ file JSON"""
        try:
            if self.config_file:
                config_path = Path(self.config_file)
            else:
                config_path = self._get_default_config_path()
            
            if not config_path.exists():
                logger.warning(f"Config file not found: {config_path}, using empty config")
                self.config = {}
                return
            
            with open(config_path, 'r', encoding='utf-8') as f:
                self.config = json.load(f)
            
            logger.info(f"Successfully loaded config from {config_path}")
        except Exception as e:
            logger.error(f"Error loading config: {e}")
            self.config = {}
    
    def reload_config(self):
        """Reload config từ file (dùng khi admin cập nhật)"""
        logger.info("Reloading config from file...")
        self._load_config()
    
    def get_clipboard_rule_config(self) -> Dict[str, Any]:
        """Lấy config cho Clipboard Paste Rule"""
        return self.config.get('clipboard_paste_rule', {})
    
    def get_usb_rule_config(self) -> Dict[str, Any]:
        """Lấy config cho USB Rule"""
        return self.config.get('usb_rule', {})
    
    def get_network_rule_config(self) -> Dict[str, Any]:
        """Lấy config cho Network Upload Rule"""
        return self.config.get('network_rule', {})
    
    # ========== Clipboard Rule Helpers ==========
    def get_browser_apps(self) -> Set[str]:
        """Lấy danh sách browser apps từ config"""
        config = self.get_clipboard_rule_config()
        return set(config.get('browser_apps', []))
    
    def get_messaging_apps(self) -> Set[str]:
        """Lấy danh sách messaging apps từ config"""
        config = self.get_clipboard_rule_config()
        return set(config.get('messaging_apps', []))
    
    def get_sensitive_domains(self) -> Set[str]:
        """Lấy danh sách sensitive domains từ config"""
        config = self.get_clipboard_rule_config()
        return set(config.get('sensitive_domains', []))
    
    def get_sensitive_title_keywords(self) -> List[str]:
        """Lấy danh sách sensitive title keywords từ config"""
        config = self.get_clipboard_rule_config()
        return config.get('sensitive_title_keywords', [])
    
    # ========== USB Rule Helpers ==========
    def get_removable_drives(self) -> List[str]:
        """Lấy danh sách removable drives từ config"""
        config = self.get_usb_rule_config()
        return config.get('removable_drives', [])
    
    # ========== Network Rule Helpers ==========
    def get_upload_types(self) -> Set[str]:
        """Lấy danh sách upload types từ config"""
        config = self.get_network_rule_config()
        return set(config.get('upload_types', []))
    
    def get_network_browser_apps(self) -> Set[str]:
        """Lấy danh sách browser apps cho network rule"""
        config = self.get_network_rule_config()
        return set(config.get('browser_apps', []))
    
    def get_desktop_upload_apps(self) -> Set[str]:
        """Lấy danh sách desktop upload apps từ config"""
        config = self.get_network_rule_config()
        return set(config.get('desktop_upload_apps', []))
    
    def get_cli_tools(self) -> Set[str]:
        """Lấy danh sách CLI tools từ config"""
        config = self.get_network_rule_config()
        return set(config.get('cli_tools', []))
    
    def get_network_sensitive_domains(self) -> Set[str]:
        """Lấy danh sách sensitive domains cho network rule"""
        config = self.get_network_rule_config()
        return set(config.get('sensitive_domains', []))
    
    # ========== Config Update ==========
    def update_config(self, config_data: Dict[str, Any]):
        """
        Cập nhật config (từ server/API)
        
        Args:
            config_data: dictionary chứa config mới
        """
        try:
            self.config.update(config_data)
            logger.info("Config updated successfully")
        except Exception as e:
            logger.error(f"Error updating config: {e}")
    
    def add_browser_app(self, app_name: str):
        """Thêm browser app vào config"""
        if 'clipboard_paste_rule' not in self.config:
            self.config['clipboard_paste_rule'] = {}
        
        if 'browser_apps' not in self.config['clipboard_paste_rule']:
            self.config['clipboard_paste_rule']['browser_apps'] = []
        
        if app_name not in self.config['clipboard_paste_rule']['browser_apps']:
            self.config['clipboard_paste_rule']['browser_apps'].append(app_name)
            logger.info(f"Added browser app: {app_name}")
    
    def add_sensitive_domain(self, domain: str):
        """Thêm sensitive domain vào config"""
        if 'clipboard_paste_rule' not in self.config:
            self.config['clipboard_paste_rule'] = {}
        
        if 'sensitive_domains' not in self.config['clipboard_paste_rule']:
            self.config['clipboard_paste_rule']['sensitive_domains'] = []
        
        if domain not in self.config['clipboard_paste_rule']['sensitive_domains']:
            self.config['clipboard_paste_rule']['sensitive_domains'].append(domain)
            logger.info(f"Added sensitive domain: {domain}")
    
    def remove_domain(self, domain: str):
        """Xóa sensitive domain khỏi config"""
        try:
            config = self.get_clipboard_rule_config()
            domains = config.get('sensitive_domains', [])
            if domain in domains:
                domains.remove(domain)
                logger.info(f"Removed domain: {domain}")
        except Exception as e:
            logger.error(f"Error removing domain: {e}")
    
    def add_keyword(self, keyword: str):
        """Thêm sensitive keyword vào config"""
        if 'clipboard_paste_rule' not in self.config:
            self.config['clipboard_paste_rule'] = {}
        
        if 'sensitive_title_keywords' not in self.config['clipboard_paste_rule']:
            self.config['clipboard_paste_rule']['sensitive_title_keywords'] = []
        
        if keyword not in self.config['clipboard_paste_rule']['sensitive_title_keywords']:
            self.config['clipboard_paste_rule']['sensitive_title_keywords'].append(keyword)
            logger.info(f"Added sensitive keyword: {keyword}")
    
    def remove_keyword(self, keyword: str):
        """Xóa sensitive keyword khỏi config"""
        try:
            config = self.get_clipboard_rule_config()
            keywords = config.get('sensitive_title_keywords', [])
            if keyword in keywords:
                keywords.remove(keyword)
                logger.info(f"Removed keyword: {keyword}")
        except Exception as e:
            logger.error(f"Error removing keyword: {e}")
    
    def remove_app(self, app_name: str, app_type: str = 'browser_apps'):
        """Xóa app khỏi config"""
        try:
            config = self.get_clipboard_rule_config()
            apps = config.get(app_type, [])
            if app_name in apps:
                apps.remove(app_name)
                logger.info(f"Removed {app_name} from {app_type}")
        except Exception as e:
            logger.error(f"Error removing app: {e}")
    
    def save_config(self, output_path: Optional[str] = None):
        """
        Lưu config vào file JSON
        
        Args:
            output_path: đường dẫn để lưu. Nếu None, lưu vào file gốc
        """
        try:
            if output_path is None:
                if self.config_file:
                    output_path = self.config_file
                else:
                    output_path = self._get_default_config_path()
            
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=2, ensure_ascii=False)
            
            logger.info(f"Config saved to {output_path}")
        except Exception as e:
            logger.error(f"Error saving config: {e}")


# Global instance
_config_manager: Optional[RulesConfigManager] = None


def get_config_manager(config_file: Optional[str] = None) -> RulesConfigManager:
    """
    Lấy global config manager instance
    
    Args:
        config_file: đường dẫn file config (chỉ dùng lần đầu)
    
    Returns:
        RulesConfigManager instance
    """
    global _config_manager
    
    if _config_manager is None:
        _config_manager = RulesConfigManager(config_file)
    
    return _config_manager
