import sqlite3
import json
import time
from pathlib import Path
from typing import Dict, Any, List, Optional
from loguru import logger

class ProcessedEventsDB:
    def __init__(self, db_dir: Path):
        self.db_path = db_dir / "processed_events.db"
        self._init_schema()

    def _get_conn(self):
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False, timeout=30.0)
        # Bật WAL để hiệu năng cao hơn và tránh thread locking
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def _init_schema(self):
        try:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            with self._get_conn() as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS processed_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_id TEXT NOT NULL,
                        event_type TEXT,
                        risk_score REAL,
                        matched_rules TEXT,
                        event_payload TEXT,
                        processed_at REAL NOT NULL
                    )
                """)
                # Tạo index hỗ trợ truy vấn báo cáo theo event_id hoặc thời gian nếu cần
                conn.execute("CREATE INDEX IF NOT EXISTS idx_pe_event_id ON processed_events(event_id)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_pe_processed_at ON processed_events(processed_at)")
                conn.commit()
        except Exception as e:
            logger.error(f"Error initializing ProcessedEventsDB schema: {e}")

    def insert_event(
        self,
        event_id: str,
        event_type: str,
        risk_score: float,
        matched_rules: List[str],
        event_payload: Dict[str, Any]
    ) -> bool:
        """
        Lưu event đã xử lý vào database.
        :param event_id: ID của event từ agent.
        :param event_type: Loại event (vd: proc_start, clipboard_paste, file_copy...).
        :param risk_score: Tổng rủi ro (total_score) sau khi check.
        :param matched_rules: Danh sách tên rules trúng (YARA, Behavioral...).
        :param event_payload: Raw payload của event.
        :return: True nếu lưu thành công.
        """
        try:
            rules_json = json.dumps(matched_rules, ensure_ascii=False)
            payload_json = json.dumps(event_payload, ensure_ascii=False)
            now = time.time()
            
            with self._get_conn() as conn:
                conn.execute(
                    """
                    INSERT INTO processed_events
                    (event_id, event_type, risk_score, matched_rules, event_payload, processed_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (event_id, event_type, risk_score, rules_json, payload_json, now)
                )
                conn.commit()
            return True
        except Exception as e:
            logger.error(f"Error inserting processed event {event_id} into DB: {e}", exc_info=True)
            return False
