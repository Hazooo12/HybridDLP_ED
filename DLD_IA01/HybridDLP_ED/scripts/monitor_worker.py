"""
Script monitor Worker processing và verify results
"""
import time
import sqlite3
import json
from pathlib import Path
from datetime import datetime

BASE_DIR = Path(__file__).parent.parent
AGENT_RUNTIME = BASE_DIR / "agent" / "runtime"
EVENTS_DB = AGENT_RUNTIME / "events.db"


def check_events():
    """Check events in database"""
    if not EVENTS_DB.exists():
        print("Database not found!")
        return
    
    conn = sqlite3.connect(str(EVENTS_DB))
    cursor = conn.cursor()
    
    # Get recent file events
    cursor.execute("""
        SELECT id, type, ts, payload_json
        FROM events
        WHERE type LIKE '%file%'
        ORDER BY id DESC
        LIMIT 10
    """)
    
    rows = cursor.fetchall()
    print(f"\nRecent file events: {len(rows)}")
    for row in rows:
        try:
            payload = json.loads(row[3])
            file_path = payload.get('object', {}).get('path', 'N/A')
            print(f"  ID {row[0]}: {row[1]} - {Path(file_path).name if file_path != 'N/A' else 'N/A'}")
        except:
            print(f"  ID {row[0]}: {row[1]}")
    
    conn.close()


def monitor_worker_logs():
    """Monitor worker logs for processing"""
    print("\n" + "=" * 60)
    print("Monitoring Worker Processing")
    print("=" * 60)
    print("\nCheck Docker logs:")
    print("  docker-compose logs -f worker")
    print("\nLook for:")
    print("  - YARA matches")
    print("  - Risk scores")
    print("  - Actions taken")
    print("  - File processing")


def verify_results():
    """Verify test results"""
    print("\n" + "=" * 60)
    print("Expected Results")
    print("=" * 60)
    
    expected = {
        "credit_card_info.txt": {
            "yara_rules": ["credit_card"],
            "risk_score": "High (should be > 50)",
            "action": "Alert or Block"
        },
        "vietnam_id_info.txt": {
            "yara_rules": ["vietnam_id", "phone_number", "email"],
            "risk_score": "High (should be > 50)",
            "action": "Alert or Block"
        },
        "financial_report.txt": {
            "yara_rules": ["financial_data"],
            "risk_score": "Medium-High (should be > 50)",
            "action": "Alert"
        },
        "hr_employee_list.txt": {
            "yara_rules": ["hr_data", "vietnam_id", "email"],
            "risk_score": "High (should be > 50)",
            "action": "Alert or Block"
        },
        "normal_document.txt": {
            "yara_rules": [],
            "risk_score": "Low (should be < 50)",
            "action": "Log only"
        }
    }
    
    print("\nExpected YARA matches:")
    for filename, details in expected.items():
        print(f"\n{filename}:")
        print(f"  YARA Rules: {', '.join(details['yara_rules']) if details['yara_rules'] else 'None'}")
        print(f"  Risk Score: {details['risk_score']}")
        print(f"  Action: {details['action']}")


def main():
    """Main monitoring function"""
    print("=" * 60)
    print("Worker Monitoring Tool")
    print("=" * 60)
    
    check_events()
    verify_results()
    monitor_worker_logs()
    
    print("\n" + "=" * 60)
    print("Monitoring Complete")
    print("=" * 60)


if __name__ == "__main__":
    main()
