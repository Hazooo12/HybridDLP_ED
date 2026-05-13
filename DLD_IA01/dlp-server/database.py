"""
database.py — SQLite storage cho DLP events
Schema khớp hoàn toàn với alerts.json hiện tại
"""
import sqlite3
import json
from datetime import datetime, timezone, timedelta
from typing import Optional

DB_PATH = "dlp_events.db"

# Timezone UTC+7 (Việt Nam)
TZ_VN = timezone(timedelta(hours=7))

def now_vn():
    """Trả về datetime hiện tại theo múi giờ Việt Nam (UTC+7)"""
    return datetime.now(tz=TZ_VN)


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Tạo bảng nếu chưa có — an toàn khi gọi nhiều lần"""
    conn = get_conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id                      INTEGER PRIMARY KEY AUTOINCREMENT,
            machine_name            TEXT    NOT NULL DEFAULT 'unknown',
            received_at             TEXT    NOT NULL,

            -- Các field cơ bản từ alerts.json
            timestamp               TEXT,
            risk_score              REAL,
            action                  TEXT,
            file_path               TEXT,
            file_name               TEXT,
            keywords                TEXT,   -- JSON array string
            window_title            TEXT,
            process_name            TEXT,
            user                    TEXT,
            source                  TEXT,
            is_clipboard            INTEGER,

            -- Chi tiết Match từ Detection Engine (mới)
            yara_matches_count      INTEGER DEFAULT 0,
            behavioral_matches_count INTEGER DEFAULT 0,
            yara_rules_matched      TEXT,   -- JSON array: [{"rule": "name", "strings": [...]}]
            behavioral_rules_matched TEXT,  -- JSON array: [{"rule": "name", "score": 0.5}]
            
            -- Chi tiết Risk Scoring
            risk_score_breakdown    TEXT,   -- JSON: {"keyword_score": 0.5, "behavioral_score": 0.3, ...}
            action_reason           TEXT,   -- Lý do chọn action này
            
            -- Metadata chi tiết
            event_type              TEXT,   -- clipboard, file, process, etc.
            content_size            INTEGER,-- Size of content checked
            check_duration_ms       INTEGER -- Thời gian xử lý (ms)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS agents (
            api_key      TEXT    PRIMARY KEY,
            machine_name TEXT    NOT NULL,
            display_name TEXT    NOT NULL,
            status       TEXT    NOT NULL DEFAULT 'active',
            created_at   TEXT    NOT NULL,
            last_connection TEXT
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_received  ON events(received_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_action    ON events(action)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_risk      ON events(risk_score)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_machine   ON events(machine_name)")
    conn.commit()
    conn.close()
    print("[DB] Initialized:", DB_PATH)


def insert_event(machine_name: str, event: dict) -> int:
    """Lưu 1 event vào DB. Trả về id mới."""
    conn = get_conn()
    cur = conn.execute("""
        INSERT INTO events (
            machine_name, received_at,
            timestamp, risk_score, action,
            file_path, file_name, keywords,
            window_title, process_name,
            user, source, is_clipboard,
            yara_matches_count, behavioral_matches_count,
            yara_rules_matched, behavioral_rules_matched,
            risk_score_breakdown, action_reason,
            event_type, content_size, check_duration_ms
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        machine_name,
        now_vn().isoformat(),
        event.get("timestamp"),
        event.get("risk_score", 0),
        (event.get("action") or "").lower(),
        event.get("file_path"),
        event.get("file_name"),
        json.dumps(event.get("keywords") or []),
        event.get("window_title"),
        event.get("process_name"),
        event.get("user"),
        event.get("source"),
        1 if event.get("is_clipboard") else 0,
        # Chi tiết match
        event.get("yara_matches_count", 0),
        event.get("behavioral_matches_count", 0),
        json.dumps(event.get("yara_rules_matched") or []),
        json.dumps(event.get("behavioral_rules_matched") or []),
        json.dumps(event.get("risk_score_breakdown") or {}),
        event.get("action_reason", ""),
        event.get("event_type", "unknown"),
        event.get("content_size", 0),
        event.get("check_duration_ms", 0),
    ))
    new_id = cur.lastrowid
    conn.commit()
    conn.close()
    return new_id


def insert_batch(machine_name: str, events: list) -> int:
    """Lưu nhiều events cùng lúc. Trả về số lượng đã lưu."""
    if not events:
        return 0
    conn = get_conn()
    now = now_vn().isoformat()
    rows = [(
        machine_name, now,
        e.get("timestamp"),
        e.get("risk_score", 0),
        (e.get("action") or "").lower(),
        e.get("file_path"),
        e.get("file_name"),
        json.dumps(e.get("keywords") or []),
        e.get("window_title"),
        e.get("process_name"),
        e.get("user"),
        e.get("source"),
        1 if e.get("is_clipboard") else 0,
        e.get("yara_matches_count", 0),
        e.get("behavioral_matches_count", 0),
        json.dumps(e.get("yara_rules_matched") or []),
        json.dumps(e.get("behavioral_rules_matched") or []),
        json.dumps(e.get("risk_score_breakdown") or {}),
        e.get("action_reason", ""),
        e.get("event_type", "unknown"),
        e.get("content_size", 0),
        e.get("check_duration_ms", 0),
    ) for e in events]

    conn.executemany("""
        INSERT INTO events (
            machine_name, received_at,
            timestamp, risk_score, action,
            file_path, file_name, keywords,
            window_title, process_name,
            user, source, is_clipboard,
            yara_matches_count, behavioral_matches_count,
            yara_rules_matched, behavioral_rules_matched,
            risk_score_breakdown, action_reason,
            event_type, content_size, check_duration_ms
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, rows)
    conn.commit()
    conn.close()
    return len(rows)


def query_events(
    limit: int = 500,
    action: Optional[str] = None,
    min_risk: float = 0,
    max_risk: float = 10,
    machine: Optional[str] = None,
) -> list[dict]:
    """Truy vấn events với filter. Trả về list dict."""
    conn = get_conn()
    sql = """
        SELECT * FROM events
        WHERE risk_score BETWEEN ? AND ?
    """
    params: list = [min_risk, max_risk]

    if action:
        sql += " AND action = ?"
        params.append(action.lower())
    if machine:
        sql += " AND machine_name = ?"
        params.append(machine)

    sql += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    rows = conn.execute(sql, params).fetchall()
    conn.close()

    result = []
    for r in rows:
        d = dict(r)
        d["keywords"] = json.loads(d["keywords"] or "[]")
        d["is_clipboard"] = bool(d["is_clipboard"])
        # Parse JSON fields (mới)
        d["yara_rules_matched"] = json.loads(d["yara_rules_matched"] or "[]")
        d["behavioral_rules_matched"] = json.loads(d["behavioral_rules_matched"] or "[]")
        d["risk_score_breakdown"] = json.loads(d["risk_score_breakdown"] or "{}")
        result.append(d)
    return result


def get_stats() -> dict:
    """Thống kê tổng hợp cho KPI cards."""
    conn = get_conn()

    total       = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    total_high  = conn.execute("SELECT COUNT(*) FROM events WHERE risk_score >= 7").fetchone()[0]
    total_alert = conn.execute("SELECT COUNT(*) FROM events WHERE action = 'alerted'").fetchone()[0]
    total_block = conn.execute("SELECT COUNT(*) FROM events WHERE action = 'blocked'").fetchone()[0]

    machines = conn.execute(
        "SELECT machine_name, COUNT(*) as cnt FROM events GROUP BY machine_name"
    ).fetchall()

    # Top keywords
    kw_rows = conn.execute(
        "SELECT keywords FROM events WHERE keywords != '[]' ORDER BY id DESC LIMIT 1000"
    ).fetchall()
    kw_count: dict = {}
    for row in kw_rows:
        for kw in json.loads(row[0] or "[]"):
            kw_count[kw] = kw_count.get(kw, 0) + 1
    top_kw = sorted(kw_count.items(), key=lambda x: -x[1])[:10]

    conn.close()
    return {
        "total": total,
        "high_plus": total_high,
        "alerted": total_alert,
        "blocked": total_block,
        "machines": [{"name": r[0], "count": r[1]} for r in machines],
        "top_keywords": [{"keyword": k, "count": v} for k, v in top_kw],
    }


def get_machines() -> list[str]:
    conn = get_conn()
    rows = conn.execute("SELECT DISTINCT machine_name FROM events ORDER BY machine_name").fetchall()
    conn.close()
    return [r[0] for r in rows]


# ============================================================
# AGENT MANAGEMENT
# ============================================================

def insert_agent(api_key: str, machine_name: str, display_name: str) -> bool:
    """Thêm agent mới. Trả về True nếu thêm thành công."""
    try:
        conn = get_conn()
        conn.execute("""
            INSERT INTO agents (api_key, machine_name, display_name, status, created_at)
            VALUES (?, ?, ?, 'active', ?)
        """, (api_key, machine_name, display_name, now_vn().isoformat()))
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        return False


def get_agents() -> list[dict]:
    """Lấy danh sách tất cả agents."""
    conn = get_conn()
    rows = conn.execute("""
        SELECT api_key, machine_name, display_name, status, created_at, last_connection
        FROM agents ORDER BY display_name
    """).fetchall()
    conn.close()
    
    result = []
    for r in rows:
        is_online = is_agent_online(r[5])  # check last_connection
        result.append({
            "api_key": r[0],
            "machine_name": r[1],
            "display_name": r[2],
            "status": r[3],
            "created_at": r[4],
            "last_connection": r[5],
            "is_online": is_online,
        })
    return result


def get_agent(api_key: str) -> Optional[dict]:
    """Lấy thông tin agent theo key."""
    conn = get_conn()
    row = conn.execute("""
        SELECT api_key, machine_name, display_name, status, created_at, last_connection
        FROM agents WHERE api_key = ?
    """, (api_key,)).fetchone()
    conn.close()
    
    if not row:
        return None
    
    is_online = is_agent_online(row[5])
    return {
        "api_key": row[0],
        "machine_name": row[1],
        "display_name": row[2],
        "status": row[3],
        "created_at": row[4],
        "last_connection": row[5],
        "is_online": is_online,
    }


def update_agent_last_connection(api_key: str):
    """Cập nhật thời gian kết nối cuối cùng cho agent."""
    conn = get_conn()
    conn.execute("""
        UPDATE agents SET last_connection = ? WHERE api_key = ?
    """, (now_vn().isoformat(), api_key))
    conn.commit()
    conn.close()


def delete_agent(api_key: str) -> bool:
    """Xóa agent. Trả về True nếu tồn tại và đã xóa."""
    conn = get_conn()
    cursor = conn.execute("DELETE FROM agents WHERE api_key = ?", (api_key,))
    conn.commit()
    success = cursor.rowcount > 0
    conn.close()
    return success


def is_agent_online(last_connection: Optional[str], timeout_seconds: int = 60) -> bool:
    """Kiểm tra agent còn online không (kết nối trong vòng timeout_seconds)."""
    if not last_connection:
        return False
    try:
        last_ts = datetime.fromisoformat(last_connection)
        now = now_vn()
        delta = (now - last_ts).total_seconds()
        return delta < timeout_seconds
    except:
        return False
