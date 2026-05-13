"""
server_tester.py — Test kết nối tới server

Gửi test event để kiểm tra kết nối
"""

import httpx
import time
from datetime import datetime
from typing import Tuple


def test_server_connection(server_url: str, api_key: str, timeout: int = 5) -> Tuple[bool, str]:
    """
    Test kết nối tới server.
    
    Args:
        server_url: Server URL (e.g., http://100.91.22.25:8000)
        api_key: API Key
        timeout: Timeout in seconds
    
    Returns:
        (success: bool, message: str)
    """
    if not server_url or not api_key:
        return False, "Server URL hoặc API Key trống"
    
    try:
        # Tạo test event
        test_event = {
            "type": "system_test",
            "source": "setup_wizard",
            "timestamp": datetime.now().isoformat(),
            "message": "Test connection from setup wizard",
            "test_time": time.time(),
        }
        
        # Gửi test event
        client = httpx.Client(
            base_url=server_url,
            headers={"X-API-Key": api_key},
            timeout=timeout,
        )
        
        resp = client.post(
            "/api/events",
            json=test_event,
        )
        client.close()
        
        if resp.status_code == 200 or resp.status_code == 201:
            return True, f"[OK] Kết nối thành công! (Status: {resp.status_code})"
        else:
            return False, f"[FAIL] Server phản hồi lỗi (Status: {resp.status_code})"
    
    except httpx.ConnectError:
        return False, "[FAIL] Không thể kết nối tới server (Connection refused)"
    except httpx.TimeoutException:
        return False, f"[FAIL] Kết nối timeout (>{timeout}s)"
    except Exception as e:
        error_msg = str(e)[:100]
        return False, f"[FAIL] Lỗi: {error_msg}"


def test_server_connection_with_retry(
    server_url: str,
    api_key: str,
    retries: int = 3,
    timeout: int = 5,
) -> Tuple[bool, str]:
    """
    Test kết nối với retry.
    
    Args:
        server_url: Server URL
        api_key: API Key
        retries: Số lần thử lại
        timeout: Timeout per attempt
    
    Returns:
        (success: bool, message: str)
    """
    for attempt in range(retries):
        success, msg = test_server_connection(server_url, api_key, timeout)
        if success:
            return True, msg
        
        if attempt < retries - 1:
            time.sleep(1)  # Wait before retry
    
    return False, msg
