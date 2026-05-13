"""
Generate Synthetic DLP Events for UEBA Training
Theo mô tả trong ML_DEVELOPMENT_PLAN.md: 10,000 normal + 50 anomalous events
"""
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional
import argparse


def generate_normal_event(base_time: datetime, user: str = "user001") -> Dict[str, Any]:
    """Generate a normal event (business hours, common apps)"""
    hour = random.randint(8, 17)
    minute = random.randint(0, 59)
    event_time = base_time.replace(hour=hour, minute=minute)
    
    apps = ["notepad.exe", "winword.exe", "excel.exe", "chrome.exe"]
    app = random.choice(apps)
    
    event_types = ["file_copy", "clipboard_copy", "clipboard_paste"]
    event_type = random.choice(event_types)
    
    event = {
        "ts": event_time.isoformat(),
        "timestamp": event_time.isoformat(),
        "type": event_type,
        "event_type": event_type,
        "user": user,
        "source": "agent",
        "context": {"user": user, "process_name": app, "window_title": f"{app} - Document"},
        "object": {"path": f"C:\\Users\\{user}\\Documents\\file_{random.randint(1, 100)}.txt", "size_bytes": random.randint(1000, 50000)},
        "operation": {"op_type": "copy" if event_type == "file_copy" else "paste"},
        "metrics": {"entropy": random.uniform(3.0, 4.5)}
    }
    
    if "clipboard" in event_type:
        event["clipboard"] = {"content_type": "Text", "content": f"Normal document content {random.randint(1, 1000)}", "content_len": random.randint(50, 500), "dest_app": app}
    
    return event


def generate_anomalous_event(base_time: datetime, user: str = "user001") -> Dict[str, Any]:
    """Generate an anomalous event (off-hours, bulk operations, external apps)"""
    is_weekend = random.random() < 0.3
    if is_weekend:
        day_offset = random.choice([5, 6])
        event_time = base_time + timedelta(days=day_offset - base_time.weekday())
        hour = random.randint(0, 23)
    else:
        hour = random.choice(list(range(0, 8)) + list(range(18, 24)))
    
    minute = random.randint(0, 59)
    event_time = base_time.replace(hour=hour, minute=minute)
    
    anomaly_type = random.choice(["bulk_copy_usb", "paste_chatgpt", "off_hours_bulk", "encrypted_zip_copy", "fragmented_exfil"])
    
    event = {
        "ts": event_time.isoformat(), "timestamp": event_time.isoformat(),
        "type": "file_copy", "event_type": "file_copy", "user": user, "source": "agent",
        "context": {"user": user, "process_name": "explorer.exe", "window_title": "File Explorer"},
        "object": {"path": f"C:\\Users\\{user}\\Documents\\sensitive_file_{random.randint(1, 10)}.txt", "dst_path": "", "size_bytes": random.randint(10000, 1000000)},
        "operation": {"op_type": "copy"},
        "metrics": {"entropy": random.uniform(4.5, 7.5)}
    }
    
    if anomaly_type == "bulk_copy_usb":
        event["object"]["dst_path"] = f"F:\\stolen_data_{random.randint(1, 50)}.txt"
        event["object"]["size_bytes"] = random.randint(500000, 5000000)
        event["usb"] = {"to_removable": True}
    
    elif anomaly_type == "paste_chatgpt":
        event["type"] = "clipboard_paste"
        event["event_type"] = "clipboard_paste"
        event["clipboard"] = {"content_type": "Text", "content": f"API_KEY=sk-{random.randint(100000, 999999)}", "content_len": random.randint(100, 1000), "dest_app": "chrome.exe", "dest_domain": "chat.openai.com", "dest_window_title": "ChatGPT", "snapshot_linked": True}
        event["metrics"]["entropy"] = random.uniform(5.0, 7.0)
    
    elif anomaly_type == "off_hours_bulk":
        event["object"]["dst_path"] = f"D:\\backup\\file_{random.randint(1, 100)}.txt"
        event["object"]["size_bytes"] = random.randint(100000, 2000000)
    
    elif anomaly_type == "encrypted_zip_copy":
        event["object"]["path"] = f"C:\\Users\\{user}\\Documents\\secret_{random.randint(1, 5)}.zip"
        event["object"]["dst_path"] = f"F:\\encrypted_{random.randint(1, 10)}.zip"
        event["metrics"]["entropy"] = 7.8
        event["usb"] = {"to_removable": True}
    
    elif anomaly_type == "fragmented_exfil":
        fragment_type = random.choice(["contract_header", "party_info", "address", "id_number", "financial"])
        
        if fragment_type == "contract_header":
            event["type"] = "clipboard_paste"
            event["clipboard"] = {"content_type": "Text", "content": f"CỘNG HÒA XÃ HỘI\nHỢP ĐỒNG\nSố {random.randint(1, 99)}/HĐTT/2026", "content_len": random.randint(100, 500), "dest_app": "zalo.exe", "dest_window_title": "Zalo"}
        
        elif fragment_type == "party_info":
            event["type"] = "clipboard_paste"
            event["clipboard"] = {"content_type": "Text", "content": f"BÊN A: Nguyễn Văn A\nĐại diện: Nguyễn Văn A\nChức vụ: Trưởng phòng", "content_len": random.randint(50, 300), "dest_app": "zalo.exe", "dest_window_title": "Zalo"}
        
        elif fragment_type == "address":
            event["type"] = "file_event"
            event["object"] = {"path": f"C:\\Users\\{user}\\Documents\\info.txt", "dst_path": f"F:\\backup\\info.txt", "size_bytes": random.randint(100, 2000)}
            event["usb"] = {"to_removable": True}
        
        elif fragment_type == "id_number":
            event["type"] = "file_event"
            event["object"] = {"path": f"C:\\Users\\{user}\\Documents\\cccd.txt", "dst_path": f"F:\\backup\\cccd.txt", "size_bytes": random.randint(50, 500)}
            event["usb"] = {"to_removable": True}
        
        elif fragment_type == "financial":
            event["type"] = "browser_upload"
            event["object"] = {"path": f"C:\\Users\\{user}\\Documents\\bank.txt", "size_bytes": random.randint(100, 800)}
            event["upload"] = {"url": "https://drive.google.com/upload", "content": f"Tài khoản: {random.randint(1000, 9999)} {random.randint(1000, 9999)} {random.randint(1000, 9999)} {random.randint(1000, 9999)}\nNgân hàng: Techcombank"}
    
    return event


def generate_synthetic_dataset(output_path: Path, num_normal: int = 10000, num_anomalous: int = 50, start_date: Optional[datetime] = None) -> None:
    """Generate synthetic dataset and save to JSONL"""
    if start_date is None:
        start_date = datetime.now(timezone.utc) - timedelta(days=30)
    
    users = [f"user{i:03d}" for i in range(1, 21)]
    events = []
    
    print(f"Generating {num_normal} normal events...")
    for i in range(num_normal):
        user = random.choice(users)
        days_ago = random.randint(0, 30)
        event_time = start_date + timedelta(days=days_ago)
        events.append(generate_normal_event(event_time, user))
    
    print(f"Generating {num_anomalous} anomalous events...")
    for i in range(num_anomalous):
        user = random.choice(users)
        days_ago = random.randint(0, 30)
        event_time = start_date + timedelta(days=days_ago)
        events.append(generate_anomalous_event(event_time, user))
    
    random.shuffle(events)
    events.sort(key=lambda e: e.get('ts', ''))
    
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        for event in events:
            f.write(json.dumps(event, ensure_ascii=False) + '\n')
    
    print(f"Generated {len(events)} events ({num_normal} normal, {num_anomalous} anomalous)")
    print(f"Saved to: {output_path}")


# ============================================================================
# FRAGMENTED EXFILTRATION SCENARIO GENERATOR
# ============================================================================

def generate_fragmented_exfil_scenario(user: str = "demo_user") -> List[Dict[str, Any]]:
    """
    Generate a complete fragmented exfiltration scenario for testing.
    This simulates the demo case where a user leaks a contract piece by piece.
    Returns list of 5 events that together form a complete sensitive document.
    """
    from datetime import timedelta
    
    base_time = datetime.now(timezone.utc)
    
    events = []
    
    # Event 1: Contract header - paste to messaging app
    event1 = {
        "ts": (base_time + timedelta(minutes=0)).isoformat(),
        "type": "clipboard_paste",
        "event_type": "clipboard_paste",
        "user": user,
        "source": "agent",
        "context": {"user": user, "process_name": "chrome.exe"},
        "clipboard": {
            "content_type": "Text",
            "content": "CỘNG HÒA XÃ HỘI CHỦ NGHĨA VIỆT NAM\nĐộc lập – Tự do – Hạnh phúc\n\nHỢP ĐỒNG TÀI TRỢ - HỖ TRỢ\nSố 03 /HĐTT/2026\n\nCăn cứ Bộ luật Dân sự số 33/2005 QH11.",
            "dest_app": "chrome.exe",
            "dest_domain": "chat.openai.com",
        },
        "metrics": {"entropy": 4.8}
    }
    events.append(event1)
    
    # Event 2: Party info - paste to Zalo
    event2 = {
        "ts": (base_time + timedelta(minutes=5)).isoformat(),
        "type": "clipboard_paste",
        "event_type": "clipboard_paste",
        "user": user,
        "source": "agent",
        "context": {"user": user, "process_name": "zalo.exe"},
        "clipboard": {
            "content_type": "Text",
            "content": "BÊN A: Ban tổ chức Sự kiện Chăm Hội\nĐại diện: Anh Đào Nam Trung\nChức vụ: Trưởng ban Đối Ngoại",
            "dest_app": "zalo.exe",
        },
        "metrics": {"entropy": 4.2}
    }
    events.append(event2)
    
    # Event 3: Address - move file to USB
    event3 = {
        "ts": (base_time + timedelta(minutes=10)).isoformat(),
        "type": "file_move",
        "event_type": "file_event",
        "user": user,
        "source": "agent",
        "context": {"user": user, "process_name": "explorer.exe"},
        "object": {"path": f"C:\\Users\\{user}\\Documents\\contract_part3.txt", "dst_path": f"F:\\backup\\contract_part3.txt", "size_bytes": 250},
        "operation": {"op_type": "move"},
        "usb": {"to_removable": True},
        "metrics": {"entropy": 4.5}
    }
    events.append(event3)
    
    # Event 4: ID number - move file to USB
    event4 = {
        "ts": (base_time + timedelta(minutes=15)).isoformat(),
        "type": "file_move",
        "event_type": "file_event",
        "user": user,
        "source": "agent",
        "context": {"user": user, "process_name": "explorer.exe"},
        "object": {"path": f"C:\\Users\\{user}\\Documents\\contract_part4.txt", "dst_path": f"F:\\backup\\contract_part4.txt", "size_bytes": 150},
        "operation": {"op_type": "move"},
        "usb": {"to_removable": True},
        "metrics": {"entropy": 4.0}
    }
    events.append(event4)
    
    # Event 5: Financial info - upload to cloud
    event5 = {
        "ts": (base_time + timedelta(minutes=20)).isoformat(),
        "type": "browser_upload",
        "event_type": "browser_upload",
        "user": user,
        "source": "agent",
        "context": {"user": user, "process_name": "chrome.exe"},
        "object": {"path": f"C:\\Users\\{user}\\Documents\\contract_part5.txt", "size_bytes": 200},
        "operation": {"op_type": "upload"},
        "upload": {"url": "https://drive.google.com/upload", "content": "Nơi cấp: Cục Cảnh sát\nTài khoản: 1903 8057 4310 14 - Techcombank"},
        "metrics": {"entropy": 5.2}
    }
    events.append(event5)
    
    return events


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate synthetic DLP events for UEBA training")
    parser.add_argument("--output", type=str, default="synthetic_events.jsonl", help="Output JSONL file path")
    parser.add_argument("--normal", type=int, default=10000, help="Number of normal events")
    parser.add_argument("--anomalous", type=int, default=50, help="Number of anomalous events")
    parser.add_argument("--fragmented-scenario", action="store_true", help="Generate fragmented exfiltration scenario for demo")
    parser.add_argument("--fragmented-output", type=str, default="fragmented_exfil_scenario.jsonl", help="Output file for fragmented scenario")
    
    args = parser.parse_args()
    
    if args.fragmented_scenario:
        events = generate_fragmented_exfil_scenario()
        path = Path(args.fragmented_output)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            for event in events:
                f.write(json.dumps(event, ensure_ascii=False) + '\n')
        print(f"Generated {len(events)} events to {path}")
    else:
        generate_synthetic_dataset(Path(args.output), num_normal=args.normal, num_anomalous=args.anomalous)
