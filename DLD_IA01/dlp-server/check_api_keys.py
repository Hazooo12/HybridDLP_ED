"""
check_api_keys.py - Kiểm tra status của API keys trên server

Chạy: python check_api_keys.py
"""

import httpx
import sys
import json

# Config
SERVER_URL = "http://100.91.22.25:8000"
ADMIN_KEY = "admin123"

def check_api_keys():
    """Kiểm tra API keys hiện tại"""
    
    print("\n" + "=" * 70)
    print("🔍 API KEYS DIAGNOSTIC")
    print("=" * 70)
    
    try:
        headers = {"X-Admin-Key": ADMIN_KEY}
        
        # 1. Get debug info
        print("\n1️⃣  Fetching server API keys...")
        with httpx.Client(timeout=5) as client:
            resp = client.get(f"{SERVER_URL}/api/debug/agent-keys", headers=headers)
        
        if resp.status_code == 200:
            data = resp.json()
            print(f"✓ Server is reachable")
            
            agent_keys = data.get('agent_keys', {})
            total = data.get('total', 0)
            
            print(f"  Total API keys: {total}")
            
            if agent_keys:
                print(f"\n  Registered API Keys:")
                for api_key, machine_name in agent_keys.items():
                    print(f"    - {api_key[:20]}... → {machine_name}")
            else:
                print(f"  ⚠ No API keys found!")
        else:
            print(f"❌ HTTP {resp.status_code}: {resp.text[:100]}")
            return False
        
        # 2. Get all agents from database
        print(f"\n2️⃣  Fetching agents from database...")
        with httpx.Client(timeout=5) as client:
            resp = client.get(f"{SERVER_URL}/api/agents", headers=headers)
        
        if resp.status_code == 200:
            agents_data = resp.json()
            agents = agents_data.get('data', [])
            
            print(f"✓ Found {len(agents)} agents in database")
            
            if agents:
                print(f"\n  Database Agents:")
                for agent in agents:
                    api_key = agent.get('api_key', 'N/A')
                    machine_name = agent.get('machine_name', 'N/A')
                    last_connection = agent.get('last_connection', 'Never')
                    print(f"    - {api_key[:20]}... → {machine_name} (Last: {last_connection})")
        else:
            print(f"❌ HTTP {resp.status_code}")
            return False
        
        # 3. Comparison
        print(f"\n3️⃣  Comparison:")
        db_keys = {agent.get('api_key'): agent.get('machine_name') for agent in agents}
        runtime_keys = agent_keys
        
        missing_from_runtime = set(db_keys.keys()) - set(runtime_keys.keys())
        missing_from_db = set(runtime_keys.keys()) - set(db_keys.keys())
        
        if missing_from_runtime:
            print(f"⚠  Keys in DB but NOT in runtime:")
            for key in missing_from_runtime:
                print(f"   - {key[:20]}... (Machine: {db_keys[key]})")
        
        if missing_from_db:
            print(f"⚠  Keys in runtime but NOT in DB:")
            for key in missing_from_db:
                print(f"   - {key[:20]}... (Machine: {runtime_keys[key]})")
        
        if not missing_from_runtime and not missing_from_db:
            print(f"✓ All keys are in sync!")
        
        # 4. Suggest reload if needed
        if missing_from_runtime:
            print(f"\n4️⃣  Recommendation:")
            print(f"   Run: curl -X POST {SERVER_URL}/api/debug/reload-agents \\")
            print(f"        -H 'X-Admin-Key: admin123'")
            print(f"   This will reload AGENT_KEYS from database (no restart needed)")
        
        print("\n" + "=" * 70 + "\n")
        return True
        
    except Exception as e:
        print(f"❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_api_key(api_key: str):
    """Test xem API key có hoạt động không"""
    
    print(f"\n🧪 Testing API Key: {api_key[:20]}...")
    
    try:
        headers = {"X-API-Key": api_key}
        
        with httpx.Client(timeout=5) as client:
            # Try to call an endpoint that requires agent auth
            resp = client.post(
                f"{SERVER_URL}/api/events",
                headers=headers,
                json={"test": "event"}
            )
        
        if resp.status_code == 200:
            print(f"  ✓ API Key is VALID")
            return True
        elif resp.status_code == 401:
            print(f"  ❌ API Key is INVALID (401 Unauthorized)")
            return False
        else:
            print(f"  ⚠ Unexpected HTTP {resp.status_code}")
            return False
            
    except Exception as e:
        print(f"  ❌ Connection error: {e}")
        return False


if __name__ == "__main__":
    check_api_keys()
    
    # Test a specific key if provided
    if len(sys.argv) > 1:
        api_key = sys.argv[1]
        test_api_key(api_key)
