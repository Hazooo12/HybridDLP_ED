"""
boot.py — Entry point chính cho HybridDLP

Flow:
1. Nếu lần đầu -> run setup wizard (password + config + services)
2. Nếu đã setup -> hiển thị system tray icon
   - Click icon -> yêu cầu password -> control center
"""

import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from agent.password_manager import is_password_set
from agent.setup_wizard import run_setup_wizard
from agent.system_tray_app import show_system_tray
from agent.service_manager import get_service_manager
from agent.config_sync_init import initialize_config_sync


def main():
    """Main entry point."""
    print("\n" + "=" * 60)
    print("  [START] HybridDLP - Startup")
    print("=" * 60 + "\n")
    
    # Check lần đầu setup
    if not is_password_set():
        print("[Boot] First-time setup detected...")
        print("[Boot] Running Setup Wizard...\n")
        
        try:
            if not run_setup_wizard():
                print("\n[FAIL] Setup was canceled")
                sys.exit(1)
            
            print("\n[OK] Setup completed successfully!")
        except Exception as e:
            print(f"\n[FAIL] Setup error: {e}")
            import traceback
            traceback.print_exc()
            sys.exit(1)
    else:
        print("[Boot] Configuration already set")
    
    # Khởi tạo config sync (pull config từ admin server periodically)
    print("\n[Boot] Initializing Config Sync...")
    try:
        from agent.config import Config
        cfg = Config()
        server_url = cfg.get_server_url()
        api_key = cfg.get_api_key()
        
        print(f"  Server URL: {server_url}")
        print(f"  API Key: {api_key[:20]}...")
        
        config_sync = initialize_config_sync()
        if config_sync:
            print("[OK] Config Sync initialized and running")
            print("   ℹ️  First sync will happen in 30 seconds")
            print("   ℹ️  Check agent/runtime/rules_config.json for config cache")
        else:
            print("[WARN]  Config Sync not available (will use local config)")
            print("   ℹ️  Local config: agent/worker/core/rules_config.json")
    except Exception as e:
        print(f"[WARN]  Config Sync initialization failed: {e}")
        import traceback
        traceback.print_exc()
        print("   ℹ️  Continuing with local config...")
    
    print("\n[Boot] [TIP] To test config sync, run: python diagnose_config_sync.py")
    
    # Run system tray
    print("\n[Boot] Starting System Tray Application...")
    
    try:
        tray_app = show_system_tray()
        
        if tray_app:
            print("[OK] System Tray running")
            print("\nℹ️  Click the DLP icon in system tray to:")
            print("   - Access Control Center (yêu cầu password)")
            print("   - Start/Stop Sensor")
            print("   - Start/Stop Worker")
            print("   - Edit Server Settings\n")
            
            # Keep running
            try:
                tray_app.wait()
            except KeyboardInterrupt:
                print("\n\nShutting down...")
                tray_app.stop()
                sys.exit(0)
        else:
            print("[FAIL] Failed to start System Tray")
            sys.exit(1)
    except Exception as e:
        print(f"[FAIL] Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
