import sqlite3
import json

db_path = "c:\\PRJ\\ProjectIA\\DLD_IA01\\HybridDLP_ED\\worker\\database\\processed_events.db"

conn = sqlite3.connect(db_path)
cur = conn.cursor()
cur.execute("SELECT event_id, event_payload FROM processed_events WHERE event_type='proc_end' ORDER BY id DESC LIMIT 10")
for row in cur.fetchall():
    try:
        p = json.loads(row[1])
        print(f"event_id: {row[0]} | ts: {p.get('ts')} | pid: {p.get('process', {}).get('pid')} | file: {p.get('process', {}).get('exe')}")
    except: pass
conn.close()
