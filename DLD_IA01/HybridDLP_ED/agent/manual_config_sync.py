"""
manual_config_sync.py - Manually trigger config sync for testing

Chạy: python manual_config_sync.py

Dùng để:
1. Kiểm tra config từ server ngay lập tức (không phải chờ 30 giây)
2. Test kết nối tới server
3. Update local config file 
"""

import sys
from pathlib import Path
import json

_AGENT_PATH = Path(__file__).resolve().parent
if str(_AGENT_PATH) not in sys.path:
    sys.path.insert(0, str(_AGENT_PATH))


def manual_sync():
    """Manually fetch and sync config từ server"""
    
    print("\n" + "=" * 70)
    print(" MANUAL CONFIG SYNC")
    print("=" * 70)
    
    try:
        from config_sync import get_config_sync
        from config import Config
        import httpx
        
        # Get config
        print("\n1️⃣  Loading configuration...")
        cfg = Config()
        server_url = cfg.get_server_url()
        api_key = cfg.get_api_key()
        
        print(f"   Server: {server_url}")
        print(f"   API Key: {api_key[:20]}...")
        
        # Test connection
        print("\n2️⃣  Testing server connection...")
        headers = {"X-API-Key": api_key}
        
        try:
            with httpx.Client(timeout=10) as client:
                print(f"   Connecting to: {server_url}/api/rules/config")
                resp = client.get(
                    f"{server_url}/api/rules/config",
                    headers=headers
                )
            
            if resp.status_code == 200:
                print(f"   [v] Server responded: HTTP 200")
                
                data = resp.json()
                if data.get('status') == 'ok':
                    config = data.get('config', {})
                    
                    print(f"\n3️⃣  Fetched config from server:")
                    
                    clipboard_rule = config.get('clipboard_paste_rule', {})
                    print(f"   Browser Apps: {len(clipboard_rule.get('browser_apps', []))}")
                    print(f"   Messaging Apps: {len(clipboard_rule.get('messaging_apps', []))}")
                    print(f"   Sensitive Domains: {len(clipboard_rule.get('sensitive_domains', []))}")
                    print(f"   Keywords: {len(clipboard_rule.get('sensitive_title_keywords', []))}")
                    
                    # Save locally
                    print(f"\n4️⃣  Saving config locally...")
                    local_path = _AGENT_PATH / "runtime" / "rules_config.json"
                    local_path.parent.mkdir(parents=True, exist_ok=True)
                    
                    with open(local_path, 'w', encoding='utf-8') as f:
                        json.dump(config, f, indent=2, ensure_ascii=False)
                    
                    print(f"   [v] Saved: {local_path}")
                    print(f"   Size: {local_path.stat().st_size} bytes")
                    
                    # Trigger callback if config_sync is running
                    print(f"\n5️⃣  Checking for ConfigSync instance...")
                    sync = get_config_sync()
                    if sync and sync._running:
                        print(f"   [v] ConfigSync is running")
                        print(f"   Triggering on_config_updated callback...")
                        if sync._on_config_updated:
                            sync._on_config_updated(config)
                            print(f"   [v] Callback executed")
                    else:
                        print(f"   ⚠ ConfigSync not running (will run on next boot)")
                    
                    print(f"\n[OK] SYNC SUCCESSFUL!")
                    print(f"\nℹ️  Local cache updated. Next time /endpoint starts,")
                    print(f"    behavioral rules will use this config.")
                    
                    return True
                else:
                    print(f"[FAIL] Server error: {data.get('message')}")
                    return False
            else:
                print(f"[FAIL] HTTP Error: {resp.status_code}")
                print(f"   {resp.text[:200]}")
                return False
                
        except httpx.TimeoutException:
            print(f"[FAIL] Connection timeout - server may be unreachable")
            print(f"   Check if server is running at: {server_url}")
            return False
        except Exception as e:
            print(f"[FAIL] Connection error: {e}")
            return False
            
    except Exception as e:
        print(f"[FAIL] ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = manual_sync()
    print("\n" + "=" * 70 + "\n")
    sys.exit(0 if success else 1)
