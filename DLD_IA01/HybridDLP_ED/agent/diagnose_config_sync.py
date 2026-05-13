"""
diagnose_config_sync.py - Chẩn đoán vấn đề Config Sync

Chạy: python diagnose_config_sync.py
"""

import sys
from pathlib import Path
import json

# Add paths
_AGENT_PATH = Path(__file__).resolve().parent
if str(_AGENT_PATH) not in sys.path:
    sys.path.insert(0, str(_AGENT_PATH))

def check_config():
    """Kiểm tra config cơ bản"""
    print("\n" + "=" * 70)
    print(" STEP 1: Check Config File")
    print("=" * 70)
    
    try:
        from config import Config
        cfg = Config()
        
        server_url = cfg.get_server_url()
        api_key = cfg.get_api_key()
        
        print(f"[v] Config loaded from: {_AGENT_PATH / 'runtime' / 'config' / 'config.json'}")
        print(f"  Server URL: {server_url}")
        print(f"  API Key: {api_key[:20]}...")
        
        if not server_url or not api_key:
            print("[FAIL] ERROR: Server URL or API Key is empty!")
            return False
        
        return True
    except Exception as e:
        print(f"[FAIL] ERROR loading config: {e}")
        import traceback
        traceback.print_exc()
        return False


def check_server_connectivity():
    """Kiểm tra kết nối tới server"""
    print("\n" + "=" * 70)
    print(" STEP 2: Check Server Connectivity")
    print("=" * 70)
    
    try:
        from config import Config
        import httpx
        
        cfg = Config()
        server_url = cfg.get_server_url()
        api_key = cfg.get_api_key()
        
        print(f"Connecting to: {server_url}/api/rules/config")
        print(f"Using API Key: {api_key[:20]}...")
        
        headers = {"X-Admin-Key": api_key}
        
        try:
            with httpx.Client(timeout=5) as client:
                resp = client.get(
                    f"{server_url}/api/rules/config",
                    headers=headers
                )
            
            if resp.status_code == 200:
                print(f"[v] Server is reachable (HTTP {resp.status_code})")
                
                data = resp.json()
                if data.get('status') == 'ok':
                    config = data.get('config', {})
                    print(f"[v] Config retrieved successfully")
                    print(f"  Config size: {len(json.dumps(config))} bytes")
                    
                    # Show config stats
                    clipboard_rule = config.get('clipboard_paste_rule', {})
                    print(f"  - Browser Apps: {len(clipboard_rule.get('browser_apps', []))}")
                    print(f"  - Messaging Apps: {len(clipboard_rule.get('messaging_apps', []))}")
                    print(f"  - Sensitive Domains: {len(clipboard_rule.get('sensitive_domains', []))}")
                    print(f"  - Keywords: {len(clipboard_rule.get('sensitive_title_keywords', []))}")
                    
                    return True
                else:
                    print(f"[FAIL] Server error: {data.get('message')}")
                    return False
            else:
                print(f"[FAIL] Server returned HTTP {resp.status_code}")
                print(f"Response: {resp.text[:200]}")
                return False
                
        except httpx.TimeoutException:
            print(f"[FAIL] Connection timeout - server may be down or IP unreachable")
            return False
        except Exception as e:
            print(f"[FAIL] Connection error: {e}")
            return False
            
    except Exception as e:
        print(f"[FAIL] ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False


def check_local_config_path():
    """Kiểm tra đường dẫn local config"""
    print("\n" + "=" * 70)
    print(" STEP 3: Check Local Config Path")
    print("=" * 70)
    
    try:
        local_path = _AGENT_PATH / "runtime" / "rules_config.json"
        
        print(f"Local config path: {local_path}")
        
        if local_path.exists():
            size = local_path.stat().st_size
            print(f"[v] File exists (Size: {size} bytes)")
            
            # Try to parse it
            with open(local_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
            
            print(f"[v] File is valid JSON")
            
            # Show content
            clipboard_rule = config.get('clipboard_paste_rule', {})
            print(f"  - Browser Apps: {len(clipboard_rule.get('browser_apps', []))}")
            print(f"  - Messaging Apps: {len(clipboard_rule.get('messaging_apps', []))}")
            print(f"  - Sensitive Domains: {len(clipboard_rule.get('sensitive_domains', []))}")
            
            return True
        else:
            print(f"⚠ File does not exist (will be created on first sync)")
            
            # Check if directory exists
            local_path.parent.mkdir(parents=True, exist_ok=True)
            print(f"[v] Directory created: {local_path.parent}")
            return True
            
    except json.JSONDecodeError as e:
        print(f"[FAIL] JSON Parse Error: {e}")
        return False
    except Exception as e:
        print(f"[FAIL] ERROR: {e}")
        return False


def check_config_sync_status():
    """Kiểm tra config_sync có đang chạy không"""
    print("\n" + "=" * 70)
    print(" STEP 4: Check Config Sync Status")
    print("=" * 70)
    
    try:
        from config_sync import get_config_sync
        
        sync = get_config_sync()
        
        if sync:
            print(f"[v] Config Sync instance exists")
            print(f"  Running: {sync._running}")
            print(f"  Sync Interval: {sync.sync_interval} seconds")
            print(f"  Server URL: {sync.server_url}")
            print(f"  API Key: {sync.api_key[:20]}...")
            
            if sync._running:
                print(f"[v] Config Sync is RUNNING")
                return True
            else:
                print(f"⚠ Config Sync is NOT running")
                return False
        else:
            print(f"⚠ Config Sync not initialized")
            return False
            
    except Exception as e:
        print(f"⚠ Cannot check config sync: {e}")
        return False


def check_behavioral_rules():
    """Kiểm tra behavioral rules có load config không"""
    print("\n" + "=" * 70)
    print(" STEP 5: Check Behavioral Rules Config")
    print("=" * 70)
    
    try:
        sys.path.insert(0, str(_AGENT_PATH.parent / "worker"))
        from core.config_provider import get_config_provider
        
        provider = get_config_provider()
        
        print(f"[v] Config Provider initialized")
        
        browser_apps = provider.get_browser_apps()
        print(f"[v] Can access browser_apps: {len(browser_apps)} items")
        
        domains = provider.get_sensitive_domains()
        print(f"[v] Can access sensitive_domains: {len(domains)} items")
        
        keywords = provider.get_sensitive_title_keywords()
        print(f"[v] Can access keywords: {len(keywords)} items")
        
        if browser_apps and domains and keywords:
            print(f"\n[OK] All config sources available!")
            return True
        else:
            print(f"\n⚠ Some config sources empty")
            return False
            
    except Exception as e:
        print(f"[FAIL] ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False


def run_all_diagnostics():
    """Chạy tất cả diagnostics"""
    print("\n" + "⚡" * 35)
    print("   CONFIG SYNC DIAGNOSTIC TOOL")
    print("⚡" * 35)
    
    results = []
    
    # Step 1
    results.append(("Config File", check_config()))
    
    # Step 2
    results.append(("Server Connectivity", check_server_connectivity()))
    
    # Step 3
    results.append(("Local Config Path", check_local_config_path()))
    
    # Step 4
    results.append(("Config Sync Status", check_config_sync_status()))
    
    # Step 5
    results.append(("Behavioral Rules Config", check_behavioral_rules()))
    
    # Summary
    print("\n" + "=" * 70)
    print("[DATA] DIAGNOSTIC SUMMARY")
    print("=" * 70)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for name, result in results:
        status = "[OK] PASS" if result else "[FAIL] FAIL"
        print(f"{status:8} - {name}")
    
    print(f"\nResult: {passed}/{total} checks passed")
    
    if passed == total:
        print("\n Everything looks good!")
    else:
        print("\n[WARN]  Some issues detected. Check the output above.")
    
    print("=" * 70 + "\n")
    
    return passed == total


if __name__ == "__main__":
    success = run_all_diagnostics()
    sys.exit(0 if success else 1)
