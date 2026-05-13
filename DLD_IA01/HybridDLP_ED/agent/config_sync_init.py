"""
config_sync_init.py — Khởi tạo Config Sync service cho agent

Chức năng:
1. Load server config từ config.py
2. Khởi tạo config_sync để periodically pull config từ admin server
3. Setup callback để reload behavioral rules khi config thay đổi

Cách sử dụng:
    from config_sync_init import initialize_config_sync
    
    initialize_config_sync()
"""

from loguru import logger
from typing import Dict, Any
from pathlib import Path
import sys

# Add agent path
_AGENT_PATH = Path(__file__).resolve().parent
if str(_AGENT_PATH) not in sys.path:
    sys.path.insert(0, str(_AGENT_PATH))

# Add worker path
_WORKER_PATH = _AGENT_PATH.parent / "worker"
if str(_WORKER_PATH) not in sys.path:
    sys.path.insert(0, str(_WORKER_PATH))


def on_config_updated(new_config: Dict[str, Any]):
    """
    Callback khi config từ server được cập nhật
    
    Công việc:
    1. Reloading behavioral rules
    2. Thông báo các components liên quan
    """
    try:
        logger.info("=" * 60)
        logger.info(" Rules Configuration Updated from Server!")
        logger.info("=" * 60)
        
        # Log info về config mới
        clipboard_rule = new_config.get('clipboard_paste_rule', {})
        usb_rule = new_config.get('usb_rule', {})
        network_rule = new_config.get('network_rule', {})
        
        logger.info(f"  Browser Apps: {len(clipboard_rule.get('browser_apps', []))} items")
        logger.info(f"  Messaging Apps: {len(clipboard_rule.get('messaging_apps', []))} items")
        logger.info(f"  Sensitive Domains: {len(clipboard_rule.get('sensitive_domains', []))} items")
        logger.info(f"  Sensitive Keywords: {len(clipboard_rule.get('sensitive_title_keywords', []))} items")
        logger.info(f"  Removable Drives: {len(usb_rule.get('removable_drives', []))} items")
        logger.info(f"  Upload Types: {len(network_rule.get('upload_types', []))} items")
        
        # Nếu có behavioral engine, reload rules
        try:
            # Behavioral rules sẽ automatically pick up new config từ config_provider
            logger.info("[v] Behavioral rules will use new config from next check")
        except Exception as e:
            logger.error(f"Error reloading behavioral rules: {e}")
        
        logger.info("=" * 60)
        
    except Exception as e:
        logger.error(f"Error in config update callback: {e}")
        import traceback
        traceback.print_exc()


def initialize_config_sync():
    """
    Khởi tạo config_sync service
    
    Returns:
        ConfigSync instance nếu thành công, None nếu lỗi
    """
    try:
        from agent.config import Config
        from agent.config_sync import init_config_sync, get_config_sync
        import httpx
        
        # Lấy server config
        logger.info("Step 1: Loading config...")
        cfg = Config()
        server_url = cfg.get_server_url()
        api_key = cfg.get_api_key()
        
        if not server_url or not api_key:
            logger.error("[FAIL] Server URL or API Key not configured!")
            return None
        
        logger.info(f"[v] Config loaded: {server_url}")
        
        # Extract IP từ server_url (remove protocol)
        server_ip = server_url.replace('http://', '').replace('https://', '').split(':')[0]
        
        logger.info(f"\nStep 2: Testing server connectivity...")
        logger.info(f"  Server IP: {server_ip}")
        logger.info(f"  API Key: {api_key[:20]}...")
        
        # Test connection
        try:
            with httpx.Client(timeout=5) as client:
                headers = {"X-API-Key": api_key}
                resp = client.get(
                    f"{server_url}/api/rules/config",
                    headers=headers
                )
            
            if resp.status_code == 200:
                logger.info(f"[v] Server is reachable (HTTP {resp.status_code})")
                data = resp.json()
                if data.get('status') == 'ok':
                    config = data.get('config', {})
                    logger.info(f"[v] Server config valid")
            else:
                logger.warning(f"⚠ Server returned HTTP {resp.status_code}")
        except httpx.TimeoutException:
            logger.warning(f"⚠ Server connection timeout - will retry on sync")
        except Exception as e:
            logger.warning(f"⚠ Server connection test failed: {e}")
        
        logger.info(f"\nStep 3: Initializing Config Sync...")
        
        # Khởi tạo config_sync
        config_sync = init_config_sync(
            server_ip=server_ip,
            api_key=api_key,
            local_config_path=str(Path(__file__).parent / "runtime" / "rules_config.json"),
            sync_interval=30,  # Sync mỗi 30 giây
            on_config_updated=on_config_updated
        )
        
        # ⭐ Start background sync
        config_sync.start()
        
        logger.info("[v] Config Sync initialized successfully")
        logger.info(f"  Sync interval: 30 seconds")
        logger.info(f"  Local cache: {Path(__file__).parent / 'runtime' / 'rules_config.json'}")
        logger.info(f"\n Config Sync is ready!")
        
        return config_sync
        
    except Exception as e:
        logger.error(f"[FAIL] Failed to initialize config sync: {e}")
        import traceback
        traceback.print_exc()
        return None


def get_or_init_config_sync():
    """Lấy hoặc khởi tạo config_sync"""
    try:
        from config_sync import get_config_sync
        
        existing = get_config_sync()
        if existing:
            return existing
        
        return initialize_config_sync()
    except Exception as e:
        logger.error(f"Error getting config sync: {e}")
        return None
