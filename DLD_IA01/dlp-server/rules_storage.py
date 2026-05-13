"""
rules_storage.py — Quản lý lưu trữ Rules Config trên Server
Để dlp-server (admin) quản lý config rules độc lập, không phụ thuộc HybridDLP_ED

Lưu trữ config vào:
1. Database SQLite (events.db)
2. Hoặc file JSON (rules_config.json) làm backup

Admin thay đổi config ở Dashboard → API update → Endpoints pull config
"""

import json
import sqlite3
from pathlib import Path
from typing import Dict, Any, List, Set, Optional
from datetime import datetime
from loguru import logger

# Đường dẫn file config backup
CONFIG_FILE = Path(__file__).parent / "rules_config.json"

# Default config (khi chưa có)
DEFAULT_CONFIG = {
    "clipboard_paste_rule": {
        "browser_apps": [
            "chrome.exe", "msedge.exe", "firefox.exe", 
            "brave.exe", "opera.exe", "vivaldi.exe", "test.exe"
        ],
        "messaging_apps": [
            "teams.exe", "slack.exe", "discord.exe", "telegram.exe",
            "whatsapp.exe", "line.exe", "signal.exe", "skype.exe", "zalo.exe"
        ],
        "sensitive_domains": [
            "chat.openai.com", "chatgpt.com", "claude.ai", "gemini.google.com",
            "bard.google.com", "perplexity.ai", "poe.com", "copilot.microsoft.com",
            "phind.com", "you.com", "mail.google.com", "gmail.com",
            "outlook.office.com", "outlook.live.com", "mail.yahoo.com",
            "mail.proton.me", "protonmail.com", "zoho.com", "yandex.com",
            "drive.google.com", "docs.google.com", "dropbox.com", "onedrive.live.com",
            "mega.nz", "box.com", "icloud.com", "pcloud.com", "sync.com",
            "wetransfer.com", "transfer.sh", "file.io", "sendgb.com",
            "wormhole.app", "sendspace.com", "mediafire.com", "zippyshare.com",
            "web.whatsapp.com", "discord.com", "teams.microsoft.com", "slack.com",
            "messenger.com", "facebook.com/messages", "telegram.org", "web.telegram.org",
            "line.me", "signal.org", "zalo.me", "chat.zalo.me", "facebook.com",
            "instagram.com", "twitter.com", "x.com", "tiktok.com", "linkedin.com",
            "reddit.com", "threads.net", "gist.github.com", "pastebin.com",
            "hastebin.com", "gitlab.com", "bitbucket.org", "replit.com",
            "test.example.com"
        ],
        "sensitive_title_keywords": [
            "chatgpt", "claude", "gemini", "bard", "perplexity", "poe ai", "copilot",
            "gmail", "google mail", "outlook", "outlook mail", "yahoo mail", "proton mail",
            "google drive", "dropbox", "onedrive", "mega", "box", "icloud", "slack",
            "teams", "discord", "telegram", "whatsapp", "messenger", "line", "signal",
            "zalo", "facebook", "instagram", "twitter", "linkedin", "tiktok", "reddit",
            "threads", "pastebin", "github gist", "gitlab", "bitbucket", "replit",
            "wetransfer", "sendspace", "mediafire", "test-keyword-api"
        ]
    },
    "usb_rule": {
        "removable_drives": ["e:", "f:", "g:", "h:", "i:", "j:", "k:", "l:"]
    },
    "network_rule": {
        "upload_types": [
            "network_flow", "network_flow_summary", "http_request", "http_upload",
            "file_upload", "browser_upload", "network_upload", "cloud_exfiltration",
            "data_exfiltration", "corr_suspected_upload"
        ],
        "browser_apps": ["chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe"],
        "desktop_upload_apps": ["slack.exe", "teams.exe", "discord.exe", "onedrive.exe", "dropbox.exe", "outlook.exe"],
        "cli_tools": ["curl", "powershell", "certutil", "scp", "winscp", "filezilla"],
        "sensitive_domains": [
            "chat.openai.com", "chatgpt.com", "gmail.com", "mail.google.com",
            "outlook.office.com", "drive.google.com", "dropbox.com", "onedrive.live.com",
            "slack.com", "discord.com", "pastebin.com"
        ]
    }
}


class RulesStorage:
    """Quản lý lưu trữ rules config trên server"""

    def __init__(self, db_path: str = "dlp_events.db"):
        self.db_path = db_path
        self._init_db()
        self._load_or_init_config()

    def _init_db(self):
        """Tạo table rules_config nếu chưa tồn tại"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS rules_config (
                id INTEGER PRIMARY KEY,
                key TEXT UNIQUE NOT NULL,
                config_json TEXT NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        conn.commit()
        conn.close()

    def _load_or_init_config(self):
        """Load config từ DB, nếu chưa có thì init default"""
        try:
            config = self.get_config()
            if not config:
                logger.info("Config not found in DB, initializing with defaults")
                self.update_config(DEFAULT_CONFIG)
        except Exception as e:
            logger.error(f"Error loading config: {e}")

    def get_config(self) -> Dict[str, Any]:
        """Lấy config từ database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("SELECT config_json FROM rules_config WHERE key = 'main'")
            row = cursor.fetchone()
            conn.close()
            
            if row:
                return json.loads(row[0])
            return None
        except Exception as e:
            logger.error(f"Error getting config: {e}")
            return None

    def update_config(self, config: Dict[str, Any]) -> bool:
        """Update config trong database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            config_json = json.dumps(config, indent=2)
            cursor.execute("""
                INSERT OR REPLACE INTO rules_config (key, config_json, updated_at)
                VALUES (?, ?, CURRENT_TIMESTAMP)
            """, ('main', config_json))
            
            conn.commit()
            conn.close()
            
            logger.info("Config updated in database")
            self._save_backup()  # Backup vào file JSON
            return True
        except Exception as e:
            logger.error(f"Error updating config: {e}")
            return False

    def _save_backup(self):
        """Lưu backup config vào file JSON"""
        try:
            config = self.get_config()
            if config:
                with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                    json.dump(config, f, indent=2, ensure_ascii=False)
                logger.debug(f"Config backed up to {CONFIG_FILE}")
        except Exception as e:
            logger.error(f"Error saving backup: {e}")

    # ========== Clipboard Rule ==========
    def get_browser_apps(self) -> Set[str]:
        config = self.get_config()
        if config:
            return set(config.get('clipboard_paste_rule', {}).get('browser_apps', []))
        return set()

    def get_messaging_apps(self) -> Set[str]:
        config = self.get_config()
        if config:
            return set(config.get('clipboard_paste_rule', {}).get('messaging_apps', []))
        return set()

    def get_sensitive_domains(self) -> Set[str]:
        config = self.get_config()
        if config:
            return set(config.get('clipboard_paste_rule', {}).get('sensitive_domains', []))
        return set()

    def get_sensitive_title_keywords(self) -> List[str]:
        config = self.get_config()
        if config:
            return config.get('clipboard_paste_rule', {}).get('sensitive_title_keywords', [])
        return []

    # ========== USB Rule ==========
    def get_removable_drives(self) -> List[str]:
        config = self.get_config()
        if config:
            return config.get('usb_rule', {}).get('removable_drives', [])
        return []

    # ========== Network Rule ==========
    def get_upload_types(self) -> Set[str]:
        config = self.get_config()
        if config:
            return set(config.get('network_rule', {}).get('upload_types', []))
        return set()

    def get_network_browser_apps(self) -> Set[str]:
        config = self.get_config()
        if config:
            return set(config.get('network_rule', {}).get('browser_apps', []))
        return set()

    def get_desktop_upload_apps(self) -> Set[str]:
        config = self.get_config()
        if config:
            return set(config.get('network_rule', {}).get('desktop_upload_apps', []))
        return set()

    def get_cli_tools(self) -> Set[str]:
        config = self.get_config()
        if config:
            return set(config.get('network_rule', {}).get('cli_tools', []))
        return set()

    def get_network_sensitive_domains(self) -> Set[str]:
        config = self.get_config()
        if config:
            return set(config.get('network_rule', {}).get('sensitive_domains', []))
        return set()

    # ========== Modify Config ==========
    def add_browser_app(self, app_name: str) -> bool:
        config = self.get_config()
        if not config:
            return False
        
        apps = config.get('clipboard_paste_rule', {}).get('browser_apps', [])
        if app_name not in apps:
            apps.append(app_name)
            config['clipboard_paste_rule']['browser_apps'] = apps
            return self.update_config(config)
        return False

    def add_messaging_app(self, app_name: str) -> bool:
        config = self.get_config()
        if not config:
            return False
        
        apps = config.get('clipboard_paste_rule', {}).get('messaging_apps', [])
        if app_name not in apps:
            apps.append(app_name)
            config['clipboard_paste_rule']['messaging_apps'] = apps
            return self.update_config(config)
        return False

    def add_sensitive_domain(self, domain: str) -> bool:
        config = self.get_config()
        if not config:
            return False
        
        domains = config.get('clipboard_paste_rule', {}).get('sensitive_domains', [])
        if domain not in domains:
            domains.append(domain)
            config['clipboard_paste_rule']['sensitive_domains'] = domains
            return self.update_config(config)
        return False

    def add_sensitive_keyword(self, keyword: str) -> bool:
        config = self.get_config()
        if not config:
            return False
        
        keywords = config.get('clipboard_paste_rule', {}).get('sensitive_title_keywords', [])
        if keyword not in keywords:
            keywords.append(keyword)
            config['clipboard_paste_rule']['sensitive_title_keywords'] = keywords
            return self.update_config(config)
        return False

    def add_removable_drive(self, drive: str) -> bool:
        config = self.get_config()
        if not config:
            return False
        
        drives = config.get('usb_rule', {}).get('removable_drives', [])
        if drive not in drives:
            drives.append(drive)
            config['usb_rule']['removable_drives'] = drives
            return self.update_config(config)
        return False

    def remove_browser_app(self, app_name: str) -> bool:
        config = self.get_config()
        if not config:
            return False
        
        apps = config.get('clipboard_paste_rule', {}).get('browser_apps', [])
        if app_name in apps:
            apps.remove(app_name)
            config['clipboard_paste_rule']['browser_apps'] = apps
            return self.update_config(config)
        return False

    def remove_messaging_app(self, app_name: str) -> bool:
        config = self.get_config()
        if not config:
            return False
        
        apps = config.get('clipboard_paste_rule', {}).get('messaging_apps', [])
        if app_name in apps:
            apps.remove(app_name)
            config['clipboard_paste_rule']['messaging_apps'] = apps
            return self.update_config(config)
        return False

    def remove_sensitive_domain(self, domain: str) -> bool:
        config = self.get_config()
        if not config:
            return False
        
        domains = config.get('clipboard_paste_rule', {}).get('sensitive_domains', [])
        if domain in domains:
            domains.remove(domain)
            config['clipboard_paste_rule']['sensitive_domains'] = domains
            return self.update_config(config)
        return False

    def remove_sensitive_keyword(self, keyword: str) -> bool:
        config = self.get_config()
        if not config:
            return False
        
        keywords = config.get('clipboard_paste_rule', {}).get('sensitive_title_keywords', [])
        if keyword in keywords:
            keywords.remove(keyword)
            config['clipboard_paste_rule']['sensitive_title_keywords'] = keywords
            return self.update_config(config)
        return False

    def remove_removable_drive(self, drive: str) -> bool:
        config = self.get_config()
        if not config:
            return False
        
        drives = config.get('usb_rule', {}).get('removable_drives', [])
        if drive in drives:
            drives.remove(drive)
            config['usb_rule']['removable_drives'] = drives
            return self.update_config(config)
        return False

    def get_config_stats(self) -> Dict[str, int]:
        """Lấy thống kê config"""
        config = self.get_config()
        if not config:
            return {}
        
        return {
            'browser_apps': len(self.get_browser_apps()),
            'messaging_apps': len(self.get_messaging_apps()),
            'sensitive_domains': len(self.get_sensitive_domains()),
            'sensitive_title_keywords': len(self.get_sensitive_title_keywords()),
            'removable_drives': len(self.get_removable_drives()),
            'upload_types': len(self.get_upload_types()),
        }


# Global instance
_storage: Optional[RulesStorage] = None


def get_rules_storage(db_path: str = "dlp_events.db") -> RulesStorage:
    """Lấy global RulesStorage instance"""
    global _storage
    if _storage is None:
        _storage = RulesStorage(db_path)
    return _storage
