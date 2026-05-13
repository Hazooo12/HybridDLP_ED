"""
Generate Synthetic DLP Events for UEBA Training
Creates normal and anomalous events matching agent event format
"""
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional
import argparse


def generate_normal_event(base_time: datetime, user: str = "user001") -> Dict[str, Any]:
    """Generate a normal event (business hours, common apps)"""
    # Random time within business hours (8:00 - 18:00)
    hour = random.randint(8, 17)
    minute = random.randint(0, 59)
    event_time = base_time.replace(hour=hour, minute=minute)
    
    # Common apps
    apps = ["notepad.exe", "winword.exe", "excel.exe", "chrome.exe"]
    app = random.choice(apps)
    
    # Event types
    event_types = ["file_copy", "clipboard_copy", "clipboard_paste"]
    event_type = random.choice(event_types)
    
    event = {
        "ts": event_time.isoformat(),
        "timestamp": event_time.isoformat(),
        "type": event_type,
        "event_type": event_type,
        "user": user,
        "source": "agent",
        "context": {
            "user": user,
            "process_name": app,
            "active_window": f"{app} - Document",
            "window_title": f"{app} - Document"
        },
        "object": {
            "path": f"C:\\Users\\{user}\\Documents\\file_{random.randint(1, 100)}.txt",
            "size_bytes": random.randint(1000, 50000)
        },
        "operation": {
            "op_type": "copy" if event_type == "file_copy" else "paste"
        },
        "metrics": {
            "entropy": random.uniform(3.0, 4.5)  # Normal entropy
        }
    }
    
    if "clipboard" in event_type:
        event["clipboard"] = {
            "content_type": "Text",
            "content": f"Normal document content {random.randint(1, 1000)}",
            "content_len": random.randint(50, 500),
            "dest_app": app,
            "dest_window_title": f"{app} - Document",
            "snapshot_linked": True
        }
    
    return event


def generate_anomalous_event(base_time: datetime, user: str = "user001") -> Dict[str, Any]:
    """Generate an anomalous event (off-hours, bulk operations, external apps)"""
    # Random time outside business hours (18:00 - 08:00) or weekend
    is_weekend = random.random() < 0.3
    if is_weekend:
        day_offset = random.choice([5, 6])  # Saturday or Sunday
        event_time = base_time + timedelta(days=day_offset - base_time.weekday())
        hour = random.randint(0, 23)
    else:
        hour = random.choice(list(range(0, 8)) + list(range(18, 24)))
    
    minute = random.randint(0, 59)
    event_time = base_time.replace(hour=hour, minute=minute)
    
    # Anomalous patterns
    anomaly_type = random.choice([
        "bulk_copy_usb",
        "paste_chatgpt",
        "off_hours_bulk",
        "encrypted_zip_copy"
    ])
    
    event = {
        "ts": event_time.isoformat(),
        "timestamp": event_time.isoformat(),
        "type": "file_copy",
        "event_type": "file_copy",
        "user": user,
        "source": "agent",
        "context": {
            "user": user,
            "process_name": "explorer.exe",
            "active_window": "File Explorer",
            "window_title": "File Explorer"
        },
        "object": {
            "path": f"C:\\Users\\{user}\\Documents\\sensitive_file_{random.randint(1, 10)}.txt",
            "dst_path": "",
            "size_bytes": random.randint(10000, 1000000)
        },
        "operation": {
            "op_type": "copy"
        },
        "metrics": {
            "entropy": random.uniform(4.5, 7.5)  # High entropy (encrypted/sensitive)
        }
    }
    
    if anomaly_type == "bulk_copy_usb":
        # Copy to USB drive
        event["object"]["dst_path"] = f"F:\\stolen_data_{random.randint(1, 50)}.txt"
        event["object"]["size_bytes"] = random.randint(500000, 5000000)  # Large files
    
    elif anomaly_type == "paste_chatgpt":
        # Paste to ChatGPT
        event["type"] = "clipboard_paste"
        event["event_type"] = "clipboard_paste"
        event["clipboard"] = {
            "content_type": "Text",
            "content": f"API_KEY=sk-{random.randint(100000, 999999)}",
            "content_len": random.randint(100, 1000),
            "dest_app": "chrome.exe",
            "dest_domain": "chat.openai.com",
            "dest_window_title": "ChatGPT",
            "snapshot_linked": True
        }
        event["metrics"]["entropy"] = random.uniform(5.0, 7.0)  # High entropy (API keys)
    
    elif anomaly_type == "off_hours_bulk":
        # Bulk copy during off-hours
        event["object"]["dst_path"] = f"D:\\backup\\file_{random.randint(1, 100)}.txt"
        event["object"]["size_bytes"] = random.randint(100000, 2000000)
    
    elif anomaly_type == "encrypted_zip_copy":
        # Copy encrypted ZIP
        event["object"]["path"] = f"C:\\Users\\{user}\\Documents\\secret_{random.randint(1, 5)}.zip"
        event["object"]["dst_path"] = f"F:\\encrypted_{random.randint(1, 10)}.zip"
        event["metrics"]["entropy"] = 7.8  # Very high entropy (encrypted)
    
    return event


def generate_synthetic_dataset(
    output_path: Path,
    num_normal: int = 10000,
    num_anomalous: int = 50,
    start_date: Optional[datetime] = None
) -> None:
    """
    Generate synthetic dataset and save to JSONL
    
    Args:
        output_path: Path to output JSONL file
        num_normal: Number of normal events
        num_anomalous: Number of anomalous events
        start_date: Start date for events (default: 30 days ago)
    """
    if start_date is None:
        start_date = datetime.now(timezone.utc) - timedelta(days=30)
    
    users = [f"user{i:03d}" for i in range(1, 21)]  # 20 users
    
    events = []
    
    # Generate normal events
    print(f"Generating {num_normal} normal events...")
    for i in range(num_normal):
        user = random.choice(users)
        # Random date within last 30 days
        days_ago = random.randint(0, 30)
        event_time = start_date + timedelta(days=days_ago)
        event = generate_normal_event(event_time, user)
        events.append(event)
    
    # Generate anomalous events
    print(f"Generating {num_anomalous} anomalous events...")
    for i in range(num_anomalous):
        user = random.choice(users)
        # Random date within last 30 days
        days_ago = random.randint(0, 30)
        event_time = start_date + timedelta(days=days_ago)
        event = generate_anomalous_event(event_time, user)
        events.append(event)
    
    # Shuffle events
    random.shuffle(events)
    
    # Sort by timestamp
    events.sort(key=lambda e: e.get('ts', ''))
    
    # Write to JSONL
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        for event in events:
            f.write(json.dumps(event, ensure_ascii=False) + '\n')
    
    print(f"Generated {len(events)} events ({num_normal} normal, {num_anomalous} anomalous)")
    print(f"Saved to: {output_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate synthetic DLP events for UEBA training")
    parser.add_argument(
        "--output",
        type=str,
        default="synthetic_events.jsonl",
        help="Output JSONL file path"
    )
    parser.add_argument(
        "--normal",
        type=int,
        default=10000,
        help="Number of normal events (default: 10000)"
    )
    parser.add_argument(
        "--anomalous",
        type=int,
        default=50,
        help="Number of anomalous events (default: 50)"
    )
    
    args = parser.parse_args()
    
    output_path = Path(args.output)
    generate_synthetic_dataset(
        output_path,
        num_normal=args.normal,
        num_anomalous=args.anomalous
    )
