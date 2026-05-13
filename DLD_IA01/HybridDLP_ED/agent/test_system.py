"""
test_system.py — Test HybridDLP System

Test:
1. Password manager
2. Config manager  
3. Service manager
4. Setup wizard
5. Main window
"""

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


def test_password_manager():
    """Test password manager."""
    print("=" * 60)
    print("TEST 1: Password Manager")
    print("=" * 60)
    
    from agent.password_manager import (
        set_password, verify_password, is_password_set
    )
    
    print("[v] Imports successful")
    
    # Check first time
    print(f"[v] is_password_set: {is_password_set()}")
    
    # Set password
    print("Setting password: 'test1234'...")
    set_password("test1234")
    print(f"[v] is_password_set: {is_password_set()}")
    
    # Verify correct
    assert verify_password("test1234"), "Password verification failed"
    print("[v] Correct password verified")
    
    # Verify incorrect
    assert not verify_password("wrongpassword"), "Wrong password should fail"
    print("[v] Wrong password rejected")
    
    print("[v] Password Manager test PASSED\n")


def test_config():
    """Test config manager."""
    print("=" * 60)
    print("TEST 2: Config Manager")
    print("=" * 60)
    
    from agent.config import (
        get_config, get_server_url, get_api_key, update_config
    )
    
    print("[v] Imports successful")
    
    # Get defaults
    server_url = get_server_url()
    api_key = get_api_key()
    print(f"[v] Server URL: {server_url}")
    print(f"[v] API Key: {api_key[:10]}...")
    
    # Update
    print("Updating config...")
    update_config("http://test-server:9000", "test-api-key-123")
    
    config = get_config()
    assert config.get_server_url() == "http://test-server:9000"
    assert config.get_api_key() == "test-api-key-123"
    print("[v] Config updated successfully")
    
    # Reset
    update_config("http://100.91.22.25:8000", "dlp-key-may-ketoan-01")
    print("[v] Config reset to defaults")
    
    print("[v] Config Manager test PASSED\n")


def test_service_manager():
    """Test service manager."""
    print("=" * 60)
    print("TEST 3: Service Manager")
    print("=" * 60)
    
    from agent.service_manager import get_service_manager
    
    manager = get_service_manager()
    print("[v] Service manager initialized")
    
    # Check status
    print(f"[v] Sensor running: {manager.is_sensor_running()}")
    print(f"[v] Worker running: {manager.is_worker_running()}")
    
    print("[v] Service Manager test PASSED\n")


def test_server_tester():
    """Test server tester module."""
    print("=" * 60)
    print("TEST 4: Server Tester")
    print("=" * 60)
    
    from agent.server_tester import test_server_connection
    
    # Test with invalid server
    success, msg = test_server_connection("http://invalid-server:9999", "invalid-key")
    print(f"[v] Invalid server test: {msg[:50]}...")
    assert not success, "Invalid server should fail"
    
    # Test with valid-looking server (may not actually respond)
    success, msg = test_server_connection("http://localhost:8000", "test-key")
    print(f"[v] Localhost test result: {msg[:50]}...")
    
    print("[v] Server Tester test PASSED\n")


def test_agent_sender():
    """Test agent sender integrations."""
    print("=" * 60)
    print("TEST 5: Agent Sender")
    print("=" * 60)
    
    from agent.agent_sender import SERVER_URL, API_KEY
    
    print(f"[v] SERVER_URL: {SERVER_URL}")
    print(f"[v] API_KEY: {API_KEY[:10]}...")
    
    print("[v] Agent Sender test PASSED\n")


def main():
    """Run all tests."""
    print("\n")
    print("╔" + "=" * 58 + "╗")
    print("║" + " " * 18 + "HybridDLP System Test Suite - Extended" + " " * 1 + "║")
    print("╚" + "=" * 58 + "╝")
    print()
    
    try:
        test_password_manager()
        test_config()
        test_service_manager()
        test_server_tester()
        test_agent_sender()
        
        print("=" * 60)
        print("[OK] ALL TESTS PASSED!")
        print("=" * 60)
        print()
        print("Ready to start HybridDLP:")
        print("1. Run: start_hybridlp.bat")
        print("2. Or: python agent/boot.py")
        print()
        
    except AssertionError as e:
        print(f"\n[FAIL] TEST FAILED: {e}\n")
        return 1
    except Exception as e:
        print(f"\n[FAIL] ERROR: {e}\n")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
