"""
Queue Consumer - Đọc events từ SQLite với Overload Protection
"""
import time
import json
import sqlite3
import os
from typing import Optional, Dict, Any
from pathlib import Path
from datetime import datetime, timedelta, timezone
from loguru import logger

import sys
from pathlib import Path
# Add parent directory to path để import config
sys.path.insert(0, str(Path(__file__).parent.parent))
from config import WorkerConfig


class QueueConsumer:
    """Consumer cho SQLite Queue với Overload Protection"""
    
    def __init__(self, lookback_hours: int = 1):
        """ 
        Initialize QueueConsumer
        
        Args:
            lookback_hours: Chỉ quét events từ N giờ trước (default: 1 hours)
        """
        self.panic_mode = False
        self.queue_size = 0
        self.events_db_path = WorkerConfig.EVENTS_DB_PATH
        self.last_processed_id = 0
        self.pid = os.getpid()
        self.lookback_hours = lookback_hours
        
        # Log database path and check
        logger.info(f"[PID={self.pid}] Initializing QueueConsumer (lookback: {lookback_hours} hours)")
        logger.info(f"[PID={self.pid}] Database path: {self.events_db_path}")
        logger.info(f"[PID={self.pid}] Database exists: {self.events_db_path.exists()}")
        logger.info(f"[PID={self.pid}] Database absolute path: {self.events_db_path.resolve()}")
        
        # Check permissions and initialize last_processed_id
        if self.events_db_path.exists():
            try:
                # Try to open database
                test_conn = sqlite3.connect(str(self.events_db_path), timeout=1.0)
                test_conn.execute("SELECT 1")
                test_conn.close()
                logger.info(f"[PID={self.pid}] Database is accessible")
                
                # Find starting event_id from 7 hours ago
                self._initialize_starting_id()
            except Exception as e:
                logger.error(f"[PID={self.pid}] Database access error: {e}")
        else:
            logger.warning(f"[PID={self.pid}] Events database not found: {self.events_db_path}")
            logger.warning(f"[PID={self.pid}] Parent directory exists: {self.events_db_path.parent.exists()}")
            if self.events_db_path.parent.exists():
                logger.warning(f"[PID={self.pid}] Parent directory: {self.events_db_path.parent}")
                logger.warning(f"[PID={self.pid}] Files in parent: {list(self.events_db_path.parent.glob('*'))[:10]}")
    
    def _initialize_starting_id(self):
        """
        Tìm event_id của event từ 7 giờ trước để bắt đầu quét từ đó
        Không quét lại từ đầu
        """
        try:
            # Calculate timestamp 7 hours ago
            now = datetime.now(timezone.utc)
            lookback_time = now - timedelta(hours=self.lookback_hours)
            lookback_ts = lookback_time.isoformat()
            
            logger.info(
                f"[PID={self.pid}] Finding starting event from {self.lookback_hours} hours ago "
                f"(since {lookback_ts})"
            )
            
            # Connect to database with WAL mode
            conn = sqlite3.connect(str(self.events_db_path), timeout=10.0)
            try:
                conn.execute("PRAGMA journal_mode=WAL;")
                conn.execute("PRAGMA read_uncommitted=1;")
            except Exception:
                pass
            
            cursor = conn.cursor()
            
            # Find event_id của event gần nhất từ 7 giờ trước
            # Tìm event có ts >= lookback_ts, lấy id nhỏ nhất
            cursor.execute("""
                SELECT MIN(id) as min_id
                FROM events
                WHERE ts >= ?
            """, (lookback_ts,))
            
            result = cursor.fetchone()
            conn.close()
            
            if result and result[0] is not None:
                self.last_processed_id = result[0] - 1  # Start from event before this
                logger.info(
                    f"[PID={self.pid}] Starting from event_id={self.last_processed_id + 1} "
                    f"(from {self.lookback_hours} hours ago)"
                )
            else:
                # No events from 7 hours ago, start from latest event
                conn = sqlite3.connect(str(self.events_db_path), timeout=10.0)
                try:
                    conn.execute("PRAGMA journal_mode=WAL;")
                    conn.execute("PRAGMA read_uncommitted=1;")
                except Exception:
                    pass
                cursor = conn.cursor()
                cursor.execute("SELECT MAX(id) as max_id FROM events")
                result = cursor.fetchone()
                conn.close()
                
                if result and result[0] is not None:
                    self.last_processed_id = result[0]
                    logger.info(
                        f"[PID={self.pid}] No events from {self.lookback_hours} hours ago. "
                        f"Starting from latest event_id={self.last_processed_id}"
                    )
                else:
                    # No events at all
                    self.last_processed_id = 0
                    logger.info(
                        f"[PID={self.pid}] No events in database. Starting from event_id=0"
                    )
        except Exception as e:
            logger.error(
                f"[PID={self.pid}] Error initializing starting ID: {e}. "
                f"Will start from beginning (event_id=0)"
            )
            self.last_processed_id = 0
    
    def get_queue_size(self) -> int:
        """Lấy kích thước queue (excluding heartbeat events)"""
        try:
            # Đếm số events chưa processed trong SQLite (excluding heartbeat)
            conn = sqlite3.connect(str(self.events_db_path), timeout=5.0)
            
            # Enable WAL mode
            try:
                conn.execute("PRAGMA journal_mode=WAL;")
                conn.execute("PRAGMA read_uncommitted=1;")
            except Exception:
                pass
            
            cursor = conn.cursor()
            cursor.execute(
                "SELECT COUNT(*) FROM events WHERE id > ? AND type != 'heartbeat'", 
                (self.last_processed_id,)
            )
            count = cursor.fetchone()[0]
            conn.close()
            return count
        except sqlite3.OperationalError as e:
            # Don't spam log for I/O/lock errors in queue size check
            return 0
        except Exception as e:
            # Only log occasionally
            if not hasattr(self, '_queue_size_error_count'):
                self._queue_size_error_count = 0
            self._queue_size_error_count += 1
            if self._queue_size_error_count % 50 == 1:
                logger.debug(f"Error getting queue size (count: {self._queue_size_error_count}): {e}")
            return 0
    
    def check_panic_mode(self) -> bool:
        """Kiểm tra và kích hoạt Panic Mode"""
        self.queue_size = self.get_queue_size()
        
        if self.queue_size > WorkerConfig.PANIC_MODE_THRESHOLD:
            if not self.panic_mode:
                self.panic_mode = True
                logger.warning(
                    f"PANIC MODE ACTIVATED: Queue size = {self.queue_size} "
                    f"(threshold: {WorkerConfig.PANIC_MODE_THRESHOLD})"
                )
            return True
        elif self.queue_size < WorkerConfig.PANIC_MODE_DISABLE_THRESHOLD:
            if self.panic_mode:
                self.panic_mode = False
                logger.info(
                    f"PANIC MODE DEACTIVATED: Queue size = {self.queue_size} "
                    f"(disable threshold: {WorkerConfig.PANIC_MODE_DISABLE_THRESHOLD})"
                )
            return False
        
        return self.panic_mode
    
    def get_event(self, timeout: int = 1) -> Optional[Dict[str, Any]]:
        """Lấy event từ SQLite queue với retry logic"""
        max_retries = 3
        retry_delay = 0.5
        
        for attempt in range(max_retries):
            try:
                # Check database exists
                if not self.events_db_path.exists():
                    logger.debug(f"[PID={self.pid}] Database not found, waiting...")
                    time.sleep(timeout)
                    return None
                
                # Đọc từ SQLite events table với timeout
                # Enable WAL mode để tránh lock conflicts với agent (agent cũng dùng WAL)
                # Filter heartbeat ở database level để giảm I/O và tránh đọc không cần thiết
                # Increase timeout to 30s for better handling of concurrent access
                conn = sqlite3.connect(
                    str(self.events_db_path),
                    timeout=30.0,
                    check_same_thread=False  # Allow connection from different threads
                )
                
                # Enable WAL mode để có thể đọc khi agent đang ghi
                try:
                    conn.execute("PRAGMA journal_mode=WAL;")
                except Exception:
                    pass  # Ignore if WAL not supported
                
                # Set read uncommitted để có thể đọc ngay cả khi agent đang commit
                try:
                    conn.execute("PRAGMA read_uncommitted=1;")
                except Exception:
                    pass
                
                # Set busy timeout để chờ lock được release
                try:
                    conn.execute("PRAGMA busy_timeout=30000;")  # 30 seconds
                except Exception:
                    pass
                
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                # Lấy event tiếp theo chưa processed, SKIP heartbeat events
                # SQLite sẽ tự động skip heartbeat events, last_processed_id sẽ được update với event_id của non-heartbeat event
                cursor.execute("""
                    SELECT id, ts, type, severity, source, payload_json
                    FROM events
                    WHERE id > ? AND type != 'heartbeat'
                    ORDER BY id ASC
                    LIMIT 1
                """, (self.last_processed_id,))
                
                row = cursor.fetchone()
                conn.close()

                if row:
                    try:
                        event_id = row['id']
                        event_type = row['type']

                        # Parse payload_json
                        payload = json.loads(row['payload_json']) if row['payload_json'] else {}

                        # Build event từ row
                        # Đảm bảo 'type' luôn có giá trị (từ row hoặc payload)
                        event_type = payload.get('type') or event_type

                        # Double check: Skip heartbeat even if it passed SQL filter
                        if event_type and event_type.lower() == 'heartbeat':
                            # Mark as processed but skip
                            self.last_processed_id = event_id
                            logger.debug(f"[PID={self.pid}] Skipping heartbeat event_id={event_id}")
                            return None

                        event = {
                            'event_id': event_id,
                            'timestamp': row['ts'],
                            'type': event_type,  # Use 'type' for consistency
                            'event_type': event_type,  # Also keep 'event_type' for compatibility
                            'ts': row['ts'],  # Also keep 'ts' for compatibility
                            'severity': row['severity'],
                            'source': row['source'],
                            **payload  # Merge payload vào event (may override above fields)
                        }

                        # Ensure 'type' is always set (payload may not have it)
                        if 'type' not in event or not event.get('type'):
                            event['type'] = event_type

                        # Final check: Skip heartbeat
                        if event.get('type', '').lower() == 'heartbeat':
                            self.last_processed_id = event_id
                            logger.debug(f"[PID={self.pid}] Skipping heartbeat event_id={event_id} (from payload)")
                            return None

                        self.last_processed_id = event_id

                        # Log event details
                        logger.info(
                            f"[PID={self.pid}] Received event: "
                            f"event_id={event_id}, type={event_type}, "
                            f"source={row['source']}"
                        )

                        return event
                    except json.JSONDecodeError as e:
                        logger.error(f"[PID={self.pid}] Invalid JSON in payload for event_id={row['id']}: {e}")
                        return None

                # Không có event mới, sleep
                time.sleep(timeout)
                return None
            except sqlite3.OperationalError as e:
                error_msg = str(e)
                
                # If this is not the last attempt, retry
                if attempt < max_retries - 1:
                    if "disk I/O error" in error_msg.lower() or "database is locked" in error_msg.lower():
                        # Wait before retry with exponential backoff
                        wait_time = retry_delay * (2 ** attempt)
                        logger.debug(
                            f"[PID={self.pid}] Database lock/I/O error (attempt {attempt + 1}/{max_retries}): "
                            f"{error_msg}. Retrying in {wait_time:.2f}s..."
                        )
                        time.sleep(wait_time)
                        continue  # Retry
                    elif "unable to open database file" in error_msg.lower():
                        wait_time = retry_delay * (2 ** attempt)
                        logger.debug(
                            f"[PID={self.pid}] Database file error (attempt {attempt + 1}/{max_retries}): "
                            f"{error_msg}. Retrying in {wait_time:.2f}s..."
                        )
                        time.sleep(wait_time)
                        continue  # Retry
                
                # Last attempt failed - log and handle
                if "unable to open database file" in error_msg.lower():
                    # Reduce log spam - only log every 20th error
                    if not hasattr(self, '_open_error_count'):
                        self._open_error_count = 0
                    self._open_error_count += 1
                    
                    if self._open_error_count % 20 == 1:
                        logger.error(
                            f"[PID={self.pid}] Database file error (count: {self._open_error_count}): {error_msg} | "
                            f"Path: {self.events_db_path} | "
                            f"Exists: {self.events_db_path.exists()} | "
                            f"Absolute: {self.events_db_path.resolve()}"
                        )
                    time.sleep(min(10, self._open_error_count * 0.3))  # Exponential backoff, max 10s
                elif "disk I/O error" in error_msg.lower() or "database is locked" in error_msg.lower():
                    # Reduce log spam for I/O/lock errors - only log every 20th error
                    if not hasattr(self, '_io_error_count'):
                        self._io_error_count = 0
                    self._io_error_count += 1
                    
                    if self._io_error_count % 20 == 1:
                        logger.warning(
                            f"[PID={self.pid}] Database lock/I/O error (count: {self._io_error_count}): {error_msg} | "
                            f"Path: {self.events_db_path} | "
                            f"May be locked by agent. Will retry on next call..."
                        )
                    time.sleep(min(10, self._io_error_count * 0.3))  # Exponential backoff, max 10s
                else:
                    # Other SQLite errors - log every 10th
                    if not hasattr(self, '_other_error_count'):
                        self._other_error_count = 0
                    self._other_error_count += 1
                    
                    if self._other_error_count % 10 == 1:
                        logger.error(f"[PID={self.pid}] SQLite error (count: {self._other_error_count}): {error_msg}")
                    time.sleep(min(5, self._other_error_count * 0.2))
                return None
            except Exception as e:
                # If this is not the last attempt, retry
                if attempt < max_retries - 1:
                    wait_time = retry_delay * (2 ** attempt)
                    logger.debug(
                        f"[PID={self.pid}] Error getting event (attempt {attempt + 1}/{max_retries}): {e}. "
                        f"Retrying in {wait_time:.2f}s..."
                    )
                    time.sleep(wait_time)
                    continue  # Retry
                
                # Last attempt failed
                logger.error(f"[PID={self.pid}] Error getting event from queue: {e}", exc_info=True)
                time.sleep(1)  # Wait before retry
                return None
        
        # All retries failed
        return None
    
    def is_panic_mode(self) -> bool:
        """Kiểm tra trạng thái Panic Mode"""
        return self.panic_mode
    
    def get_stats(self) -> Dict[str, Any]:
        """Lấy thống kê queue"""
        return {
            'queue_size': self.queue_size,
            'panic_mode': self.panic_mode,
            'queue_type': 'sqlite',
            'last_processed_id': self.last_processed_id
        }
