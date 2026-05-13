"""
L1/L2 — fila SQLite persistente para o Worker (L3) consumir.

Noteupdate: Sensor só emite eventos; a queue durável fica no runtime do **agent**,
não num pacote paralelo `shared/`.

Producer (processo Sensor): enqueue após canonicalize.
Consumer (processo Worker): lease_next / ack / fail.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple


def get_runtime_dir() -> Path:
    """Diretório `agent/runtime` (events, state, agent_store.db)."""
    override = os.getenv("DLP_RUNTIME_DIR", "").strip()
    if override:
        return Path(override)
    return Path(__file__).resolve().parent / "runtime"


def get_agent_store_db_path() -> Path:
    """SQLite: event_queue + agent_state (+ audit scan_results)."""
    override = os.getenv("DLP_AGENT_STORE_DB", "").strip()
    if override:
        return Path(override)
    return get_runtime_dir() / "agent_store.db"


class PersistentEventQueue:
    """
    Queue bền vững: crash không mất event (đã commit).
    Một worker đơn lẻ: lease một dòng pending → processing → ack (xóa).

    Producer tối ưu: gom nhiều INSERT trong một transaction (ít commit hơn → ít khóa WAL
    với worker đang lease/ack). Tắt bằng DLP_QUEUE_ENQUEUE_BATCH_SIZE=1.
    """

    def __init__(self, db_path: Optional[Any] = None):
        self.db_path = db_path or get_agent_store_db_path()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn: Optional[sqlite3.Connection] = None
        self._buf: list[tuple[str, float]] = []
        self._buf_deadline: float = 0.0
        try:
            self._batch_size = max(1, int(os.getenv("DLP_QUEUE_ENQUEUE_BATCH_SIZE", "25")))
        except ValueError:
            self._batch_size = 25
        try:
            self._flush_interval = float(os.getenv("DLP_QUEUE_ENQUEUE_FLUSH_SEC", "0.05"))
        except ValueError:
            self._flush_interval = 0.05
        self._init_schema()

    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False, timeout=30.0)
            self._conn.execute("PRAGMA journal_mode=WAL;")
            self._conn.execute("PRAGMA synchronous=NORMAL;")
        return self._conn

    def _init_schema(self) -> None:
        conn = self._get_conn()
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS event_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                payload_json TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                created_ts REAL NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                last_error TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_event_queue_status_id
                ON event_queue(status, id);

            CREATE TABLE IF NOT EXISTS agent_state (
                key TEXT PRIMARY KEY,
                value_json TEXT NOT NULL,
                updated_ts REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_ref TEXT,
                file_hash TEXT,
                risk_score REAL,
                scan_summary TEXT,
                payload_json TEXT,
                created_ts REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_scan_results_hash ON scan_results(file_hash);
            """
        )
        conn.commit()

    def close(self) -> None:
        with self._lock:
            try:
                self._flush_unlocked()
            except Exception:
                pass
            if self._conn is not None:
                try:
                    self._conn.close()
                except Exception:
                    pass
                self._conn = None

    def _flush_unlocked(self) -> int:
        """Ghi buffer ra DB. Phải giữ self._lock. Trả về lastrowid cuối hoặc -1."""
        if not self._buf:
            return -1
        conn = self._get_conn()
        last_id = -1
        for payload, ts in self._buf:
            cur = conn.execute(
                "INSERT INTO event_queue (payload_json, status, created_ts, attempts) VALUES (?, 'pending', ?, 0)",
                (payload, ts),
            )
            if cur.lastrowid is not None:
                last_id = int(cur.lastrowid)
        self._buf.clear()
        conn.commit()
        return last_id

    def flush(self) -> None:
        """Đẩy hết event trong buffer (shutdown / kiểm thử)."""
        with self._lock:
            self._flush_unlocked()

    def maybe_flush(self) -> None:
        """Ghi buffer nếu đủ batch hoặc đã quá hạn (gọi từ consumer khi idle)."""
        now = time.time()
        with self._lock:
            if not self._buf:
                return
            if len(self._buf) >= self._batch_size:
                self._flush_unlocked()
                return
            if self._flush_interval <= 0:
                self._flush_unlocked()
                return
            if now >= self._buf_deadline:
                self._flush_unlocked()

    def enqueue(self, event: Dict[str, Any]) -> int:
        """Thêm event (JSON). Trả về id hàng (hoặc -1 nếu còn nằm trong buffer tạm)."""
        payload = json.dumps(event, ensure_ascii=False)
        now = time.time()
        with self._lock:
            if not self._buf:
                self._buf_deadline = now + (self._flush_interval if self._flush_interval > 0 else 0.0)
            self._buf.append((payload, now))
            flush_now = (
                len(self._buf) >= self._batch_size
                or self._flush_interval <= 0
                or now >= self._buf_deadline
            )
            if flush_now:
                return self._flush_unlocked()
            return -1

    def pending_count(self) -> int:
        with self._lock:
            conn = self._get_conn()
            row = conn.execute(
                "SELECT COUNT(*) FROM event_queue WHERE status IN ('pending','processing')"
            ).fetchone()
            return int(row[0]) if row else 0

    def set_state(self, key: str, value: Any) -> None:
        payload = json.dumps(value, ensure_ascii=False)
        now = time.time()
        with self._lock:
            conn = self._get_conn()
            conn.execute("DELETE FROM agent_state WHERE key=?", (key,))
            conn.execute(
                "INSERT INTO agent_state(key, value_json, updated_ts) VALUES (?, ?, ?)",
                (key, payload, now),
            )
            conn.commit()

    def get_state(self, key: str) -> Optional[Any]:
        with self._lock:
            conn = self._get_conn()
            row = conn.execute("SELECT value_json FROM agent_state WHERE key=?", (key,)).fetchone()
            if not row:
                return None
            try:
                return json.loads(row[0])
            except Exception:
                return None

    def insert_scan_result(
        self,
        *,
        event_ref: str = "",
        file_hash: str = "",
        risk_score: Optional[float] = None,
        scan_summary: str = "",
        payload: Optional[Dict[str, Any]] = None,
    ) -> None:
        now = time.time()
        pj = json.dumps(payload or {}, ensure_ascii=False)
        with self._lock:
            conn = self._get_conn()
            conn.execute(
                """
                INSERT INTO scan_results (event_ref, file_hash, risk_score, scan_summary, payload_json, created_ts)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (event_ref, file_hash, risk_score, scan_summary, pj, now),
            )
            conn.commit()

    def lease_next(self) -> Optional[Tuple[int, Dict[str, Any]]]:
        """
        Lấy một event pending, chuyển sang processing. Trả về (id, event_dict) hoặc None.

        Khi hàng rỗng: chỉ SELECT (shared lock), không BEGIN IMMEDIATE — tránh chặn
        agent đang batch INSERT (producer).
        """
        with self._lock:
            conn = self._get_conn()
            row = conn.execute(
                "SELECT id, payload_json FROM event_queue WHERE status='pending' ORDER BY id LIMIT 1"
            ).fetchone()
            if not row:
                return None
            qid = int(row[0])
            raw = row[1]
            try:
                payload = json.loads(raw)
            except Exception:
                conn.execute("BEGIN IMMEDIATE")
                try:
                    conn.execute("DELETE FROM event_queue WHERE id=?", (qid,))
                    conn.execute("COMMIT")
                except Exception:
                    try:
                        conn.execute("ROLLBACK")
                    except Exception:
                        pass
                return None
            conn.execute("BEGIN IMMEDIATE")
            try:
                cur = conn.execute(
                    "UPDATE event_queue SET status='processing' WHERE id=? AND status='pending'",
                    (qid,),
                )
                if cur.rowcount != 1:
                    conn.execute("ROLLBACK")
                    return None
                conn.execute("COMMIT")
            except Exception:
                try:
                    conn.execute("ROLLBACK")
                except Exception:
                    pass
                raise
            return qid, payload

    def ack(self, queue_id: int) -> None:
        with self._lock:
            conn = self._get_conn()
            conn.execute("DELETE FROM event_queue WHERE id=?", (queue_id,))
            conn.commit()

    def fail(self, queue_id: int, error: str, max_attempts: int = 5) -> None:
        """Tăng attempts; nếu < max thì pending lại, không thì failed."""
        err_short = (error or "")[:2000]
        with self._lock:
            conn = self._get_conn()
            row = conn.execute(
                "SELECT attempts FROM event_queue WHERE id=?", (queue_id,)
            ).fetchone()
            if not row:
                conn.commit()
                return
            attempts = int(row[0]) + 1
            if attempts >= max_attempts:
                conn.execute(
                    "UPDATE event_queue SET status='failed', last_error=?, attempts=? WHERE id=?",
                    (err_short, attempts, queue_id),
                )
            else:
                conn.execute(
                    "UPDATE event_queue SET status='pending', last_error=?, attempts=? WHERE id=?",
                    (err_short, attempts, queue_id),
                )
            conn.commit()
