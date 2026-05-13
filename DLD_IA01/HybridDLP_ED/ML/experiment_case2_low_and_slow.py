import json
import logging
import os
os.environ["ML_ANOMALY_RISK_BOOST_FACTOR"] = "1.0"
from datetime import datetime, timedelta, timezone
from pathlib import Path
from ML.behavioral_ml_analyzer import BehavioralMLAnalyzer

def suppress_logs():
    logging.getLogger("behavioral_ml_analyzer").setLevel(logging.ERROR)

def clear_ueba_profiles(analyzer):
    if analyzer._profile_path.exists():
        try:
            os.remove(analyzer._profile_path)
        except Exception:
            pass
    analyzer._profiles = {}
    analyzer._accumulator = {}
    analyzer._profile_last_save_ts = 0.0

def generate_fragmented_exfil_events():
    base_time = datetime.now(timezone.utc).replace(hour=10, minute=5, second=0, microsecond=0)
    
    # Kịch bản fragment
    fragments = [
        {"time": 10, "content": "Nguyễn Văn A"},
        {"time": 15, "content": "SĐT: 0987xxxxxx"},
        {"time": 20, "content": "Email: nguyenvana@"},
        {"time": 30, "content": "...gmail.com"},
        {"time": 40, "content": "07920300"},
        {"time": 50, "content": "1234"},
    ]
    
    events = []
    
    for i, frag in enumerate(fragments):
        event_time = base_time + timedelta(minutes=frag["time"])
        content = frag["content"]
        
        event = {
            "ts": event_time.isoformat(),
            "timestamp": event_time.isoformat(),
            "type": "clipboard_paste",
            "event_type": "clipboard_paste",
            "user": "test_attacker",
            "source": "agent",
            "context": {
                "user": "test_attacker",
                "process_name": "chrome.exe",  # Risky app / external destination
                "dest_domain": "chat.openai.com"
            },
            "clipboard": {
                "content_type": "Text",
                "content": content,
                "content_len": len(content),
                "dest_app": "chrome.exe",
                "dest_window_title": "ChatGPT - Chrome"
            },
            "operation": {
                "op_type": "paste"
            },
            "object": {
                "size_bytes": len(content.encode('utf-8'))
            }
        }
        events.append(event)
        
    return events

def generate_fragmented_file_exfil_events():
    base_time = datetime.now(timezone.utc).replace(hour=11, minute=5, second=0, microsecond=0)
    
    # Kịch bản fragment qua file (USB)
    fragments = [
        {"time": 10, "content": "File part 1: Name"},
        {"time": 20, "content": "File part 2: Phone"},
        {"time": 30, "content": "File part 3: Email"},
        {"time": 40, "content": "File part 4: ID"},
        {"time": 50, "content": "File part 5: Auth"},
    ]
    
    events = []
    for i, frag in enumerate(fragments):
        event_time = base_time + timedelta(minutes=frag["time"])
        content = frag["content"]
        
        event = {
            "ts": event_time.isoformat(),
            "timestamp": event_time.isoformat(),
            "type": "file_created",
            "event_type": "file_created",
            "user": "test_attacker",
            "source": "agent",
            "context": {
                "user": "test_attacker",
                "process_name": "explorer.exe",
            },
            "object": {
                "path": f"C:\\temp\\frag{i}.txt",
                "dst_path": f"E:\\USB\\frag{i}.txt", # external path
                "size_bytes": len(content.encode('utf-8'))
            },
            "operation": {
                "op_type": "create"
            }
        }
        events.append(event)
        
    return events

def run_test():
    suppress_logs()
    
    analyzer = BehavioralMLAnalyzer()
    clear_ueba_profiles(analyzer)
    
    events_clip = generate_fragmented_exfil_events()
    events_file = generate_fragmented_file_exfil_events()
    
    with open("report.log", "w", encoding="utf-8") as f:
        f.write("="*60 + "\n")
        f.write(" SIMULATING SCENARIO A: Clipboard Paste (Chrome/ChatGPT)\n")
        f.write("="*60 + "\n")
        f.write(f"{'Time':<8} | {'Content':<18} | {'Size':<5} | {'Profile':<8} | {'Slow Burn':<10} | {'Total Score':<12} | Alert\n")
        f.write("-" * 80 + "\n")
        
        threshold = 7.0
        triggered_clip = False
        event_history = []
        
        for idx, e in enumerate(events_clip):
            dt = datetime.fromisoformat(e["ts"])
            time_str = dt.strftime("%H:%M")
            content = e["clipboard"]["content"]
            size = e["clipboard"]["content_len"]
            
            res = analyzer.predict(e, event_history)
            event_history.append(e)
            
            total_score = res.get("anomaly_score", 0.0)
            alert = "ALERT" if total_score >= threshold else "  "
            f.write(f"{time_str:<8} | {content:<18} | {size:<5} | {res.get('profile_score'):<8.2f} | {res.get('slow_burn_score'):<10.2f} | {total_score:<12.2f} | {alert}\n")
            if total_score >= threshold: triggered_clip = True
            if res.get("profile_reasons"): f.write("         > Reasons: " + ", ".join(res["profile_reasons"]) + "\n")
        
        # Scenario B
        clear_ueba_profiles(analyzer)
        event_history = []
        f.write("\n" + "="*60 + "\n")
        f.write(" SIMULATING SCENARIO B: File Creation (USB Drive)\n")
        f.write("="*60 + "\n")
        f.write(f"{'Time':<8} | {'Event Type':<18} | {'Size':<5} | {'Profile':<8} | {'Slow Burn':<10} | {'Total Score':<12} | Alert\n")
        f.write("-" * 80 + "\n")
        
        triggered_file = False
        for idx, e in enumerate(events_file):
            dt = datetime.fromisoformat(e["ts"])
            time_str = dt.strftime("%H:%M")
            content = f"frag{idx}.txt"
            size = e["object"]["size_bytes"]
            
            res = analyzer.predict(e, event_history)
            event_history.append(e)
            
            total_score = res.get("anomaly_score", 0.0)
            alert = "ALERT" if total_score >= threshold else "  "
            f.write(f"{time_str:<8} | {content:<18} | {size:<5} | {res.get('profile_score'):<8.2f} | {res.get('slow_burn_score'):<10.2f} | {total_score:<12.2f} | {alert}\n")
            if total_score >= threshold: triggered_file = True
            if res.get("profile_reasons"): f.write("         > Reasons: " + ", ".join(res["profile_reasons"]) + "\n")
            
        f.write("-" * 80 + "\n")
        if triggered_clip and triggered_file:
            f.write("SUCCESS: ML Model triggered Alert on both clipboard and file fragments!\n")
        else:
            f.write("FAILED: ML Model did not reach threshold for one or both scenarios.\n")

if __name__ == "__main__":
    run_test()
