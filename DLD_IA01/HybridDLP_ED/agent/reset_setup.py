"""
reset_setup.py — Reset HybridDLP Setup

Dùng để reset password + config khi quên hoặc muốn setup lại

Cách dùng:
  python agent/reset_setup.py
"""

import sys
import argparse
import shutil
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


def reset_password():
    """Reset password file."""
    from agent.password_manager import PASSWORD_FILE
    
    try:
        if PASSWORD_FILE.exists():
            PASSWORD_FILE.unlink()
            print(f"[OK] Password reset: {PASSWORD_FILE} deleted")
            return True
        else:
            print(f"ℹ️  Password file not found: {PASSWORD_FILE}")
            return True
    except Exception as e:
        print(f"[FAIL] Error resetting password: {e}")
        return False


def reset_config():
    """Reset config file."""
    from agent.config import CONFIG_FILE
    
    try:
        if CONFIG_FILE.exists():
            CONFIG_FILE.unlink()
            print(f"[OK] Config reset: {CONFIG_FILE} deleted")
            return True
        else:
            print(f"ℹ️  Config file not found: {CONFIG_FILE}")
            return True
    except Exception as e:
        print(f"[FAIL] Error resetting config: {e}")
        return False


def reset_all():
    """Reset everything."""
    from agent.password_manager import CONFIG_DIR
    
    try:
        if CONFIG_DIR.exists():
            shutil.rmtree(CONFIG_DIR)
            print(f"[OK] Full reset: Deleted {CONFIG_DIR}")
            return True
        else:
            print(f"ℹ️  Config folder not found: {CONFIG_DIR}")
            return True
    except Exception as e:
        print(f"[FAIL] Error resetting: {e}")
        return False


def show_password_file():
    """Show password file location and content."""
    from agent.password_manager import PASSWORD_FILE
    
    print(f"\n Password File Location:")
    print(f"   {PASSWORD_FILE}")
    
    if PASSWORD_FILE.exists():
        print(f"\n   Status: [OK] EXISTS (password is set)")
        print(f"   Size: {PASSWORD_FILE.stat().st_size} bytes")
        try:
            with open(PASSWORD_FILE, 'r') as f:
                content = f.read()
            print(f"\n   Content: {content[:80]}...")
        except:
            print(f"   Content: [unreadable]")
    else:
        print(f"\n   Status: [FAIL] NOT FOUND (password not set)")


def show_config_file():
    """Show config file location and content."""
    from agent.config import CONFIG_FILE
    
    print(f"\n Config File Location:")
    print(f"   {CONFIG_FILE}")
    
    if CONFIG_FILE.exists():
        print(f"\n   Status: [OK] EXISTS (config is set)")
        try:
            import json
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
            print(f"   Server URL: {config.get('server_url', 'N/A')}")
            print(f"   API Key: {config.get('api_key', 'N/A')[:10]}...")
        except Exception as e:
            print(f"   Error reading config: {e}")
    else:
        print(f"\n   Status: [FAIL] NOT FOUND (config not set)")


def main():
    """Main."""
    parser = argparse.ArgumentParser(
        description="HybridDLP Setup Reset Utility",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python agent/reset_setup.py --status          # Show current files
  python agent/reset_setup.py --reset-password  # Reset password only
  python agent/reset_setup.py --reset-config    # Reset config only
  python agent/reset_setup.py --reset-all       # Reset everything
  python agent/reset_setup.py --password        # Show password file
  python agent/reset_setup.py --config          # Show config file
        """
    )
    
    parser.add_argument(
        '--status',
        action='store_true',
        help='Show current files status'
    )
    parser.add_argument(
        '--password',
        action='store_true',
        help='Show password file info'
    )
    parser.add_argument(
        '--config',
        action='store_true',
        help='Show config file info'
    )
    parser.add_argument(
        '--reset-password',
        action='store_true',
        help='Reset password file'
    )
    parser.add_argument(
        '--reset-config',
        action='store_true',
        help='Reset config file'
    )
    parser.add_argument(
        '--reset-all',
        action='store_true',
        help='Reset everything (password + config)'
    )
    
    args = parser.parse_args()
    
    print("\n" + "=" * 60)
    print("  HybridDLP - Setup Reset Utility")
    print("=" * 60)
    
    if not any([
        args.status, args.password, args.config,
        args.reset_password, args.reset_config, args.reset_all
    ]):
        # Default: show status
        args.status = True
    
    if args.status:
        print("\n Current Setup Status:")
        show_password_file()
        show_config_file()
    
    if args.password:
        show_password_file()
    
    if args.config:
        show_config_file()
    
    if args.reset_password:
        print("\n[WARN]  Resetting password...")
        if reset_password():
            print("\n[TIP] Next run: Setup wizard will ask for new password")
        sys.exit(0 if reset_password() else 1)
    
    if args.reset_config:
        print("\n[WARN]  Resetting config...")
        if reset_config():
            print("\n[TIP] Next run: Setup wizard will ask for server details")
        sys.exit(0 if reset_config() else 1)
    
    if args.reset_all:
        print("\n[WARN]  FULL RESET - This will delete all configuration!")
        response = input("   Type 'YES' to confirm: ").strip()
        
        if response == "YES":
            print("\n️  Deleting all configuration files...")
            if reset_all():
                print("\n[OK] Full reset successful!")
                print("\n[TIP] Next run: Setup wizard will start from scratch")
                sys.exit(0)
            else:
                print("\n[FAIL] Reset failed")
                sys.exit(1)
        else:
            print("\n[FAIL] Reset cancelled")
            sys.exit(1)
    
    print()


if __name__ == "__main__":
    main()
