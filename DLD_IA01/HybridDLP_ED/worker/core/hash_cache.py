"""
Hash Cache Manager — SHA-256 por chunk, scan_cache com versões (Noteupdate).
Bổ sung chữ ký ssdeep (fuzzy hash) để khớp nội dung gần giống khi SHA khác nhau.
"""
import sqlite3
import hashlib
import time
from pathlib import Path
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone
from loguru import logger
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))
from config import WorkerConfig


def _fuzzy_hash_from_file(path_str: str) -> str:
    """ssdeep (libfuzzy) nếu có; không thì ppdeep (cùng thuật toán spamsum, thuần Python)."""
    for mod_name in ("ssdeep", "ppdeep"):
        try:
            mod = __import__(mod_name)
            fn = getattr(mod, "hash_from_file", None)
            if callable(fn):
                out = fn(path_str)
                return (out or "").strip()
        except Exception:
            continue
    return ""


def _fuzzy_compare(sig_a: str, sig_b: str) -> int:
    if not sig_a or not sig_b:
        return 0
    for mod_name in ("ssdeep", "ppdeep"):
        try:
            mod = __import__(mod_name)
            fn = getattr(mod, "compare", None)
            if callable(fn):
                return int(fn(sig_a, sig_b))
        except Exception:
            continue
    return 0


class HashCacheManager:
    """Quản lý Hash Cache để skip file đã scan (invalidação theo policy/engine version)."""

    def __init__(self, db_path: Path = None):
        self.db_path = db_path or WorkerConfig.CACHE_DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_database()

    def _migrate_columns(self, conn: sqlite3.Connection) -> None:
        cur = conn.cursor()
        cur.execute("PRAGMA table_info(file_cache)")
        cols = {row[1] for row in cur.fetchall()}
        alters = []
        if "scan_engine_version" not in cols:
            alters.append("ALTER TABLE file_cache ADD COLUMN scan_engine_version TEXT DEFAULT ''")
        if "policy_version" not in cols:
            alters.append("ALTER TABLE file_cache ADD COLUMN policy_version TEXT DEFAULT ''")
        if "first_seen" not in cols:
            alters.append("ALTER TABLE file_cache ADD COLUMN first_seen TEXT")
        if "last_seen" not in cols:
            alters.append("ALTER TABLE file_cache ADD COLUMN last_seen TEXT")
        if "ssdeep_sig" not in cols:
            alters.append("ALTER TABLE file_cache ADD COLUMN ssdeep_sig TEXT DEFAULT ''")
        for sql in alters:
            try:
                conn.execute(sql)
            except sqlite3.OperationalError:
                pass
        conn.commit()

    def _init_database(self):
        try:
            conn = sqlite3.connect(self.db_path)
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS file_cache (
                    file_hash TEXT PRIMARY KEY,
                    file_path TEXT,
                    file_size INTEGER,
                    scan_result TEXT,
                    risk_score REAL,
                    action_taken TEXT,
                    last_scan TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    scan_count INTEGER DEFAULT 1
                )
            """
            )
            conn.commit()
            self._migrate_columns(conn)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_file_path ON file_cache(file_path)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_last_scan ON file_cache(last_scan)")
            conn.commit()
            conn.close()
            logger.info(f"Hash cache database initialized: {self.db_path}")
        except Exception as e:
            logger.error(f"Error initializing database: {e}")

    def calculate_hash(self, file_path: Path) -> str:
        """SHA-256 (hoặc HASH_ALGORITHM) đọc theo chunk — không load cả file vào RAM."""
        algo_name = getattr(WorkerConfig, "HASH_ALGORITHM", "sha256")
        chunk_sz = max(4096, int(getattr(WorkerConfig, "HASH_READ_CHUNK_BYTES", 262144)))
        retries = max(1, int(getattr(WorkerConfig, "HASH_COMPUTE_RETRIES", 3)))

        for attempt in range(retries):
            try:
                hash_algo = getattr(hashlib, algo_name)()
                with open(file_path, "rb") as f:
                    while True:
                        chunk = f.read(chunk_sz)
                        if not chunk:
                            break
                        hash_algo.update(chunk)
                return hash_algo.hexdigest()
            except PermissionError:
                logger.warning(f"Permission denied: {file_path}")
                return ""
            except OSError as e:
                logger.warning(f"Hash attempt {attempt + 1}/{retries} failed for {file_path}: {e}")
                if attempt + 1 >= retries:
                    logger.error(f"Error calculating hash for {file_path}: {e}")
                    return ""
                time.sleep(0.1 * (attempt + 1))
            except Exception as e:
                logger.error(f"Error calculating hash for {file_path}: {e}")
                return ""
        return ""

    def calculate_ssdeep(self, file_path: Path) -> str:
        """
        Chữ ký fuzzy ssdeep/spamsum (ưu tiên package `ssdeep`, fallback `ppdeep` thuần Python).
        Thất bại → "" (worker vẫn chạy chỉ với SHA-256).
        """
        if not getattr(WorkerConfig, "SSDEEP_ENABLED", True):
            return ""
        try:
            max_mb = float(getattr(WorkerConfig, "SSDEEP_MAX_FILE_MB", 512.0) or 512.0)
            sz = file_path.stat().st_size
            if max_mb > 0 and sz > int(max_mb * 1024 * 1024):
                logger.debug(f"ssdeep skipped (file too large): {file_path.name}")
                return ""
        except OSError:
            return ""
        sig = _fuzzy_hash_from_file(str(file_path))
        if not sig:
            logger.debug(f"fuzzy hash (ssdeep/ppdeep) unavailable or failed for {file_path}")
        return sig

    def find_fuzzy_safe_match(self, ssdeep_sig: str, file_size: int) -> Optional[Dict[str, Any]]:
        """
        Nếu đã có bản ghi safe (cùng engine/policy) với ssdeep gần khớp → coi như cache hit,
        không cần quét lại (demo: file copy nhẹ metadata, SHA khác nhưng nội dung giống).
        """
        if not ssdeep_sig or not getattr(WorkerConfig, "SSDEEP_ENABLED", True):
            return None
        try:
            __import__("ssdeep")
        except ImportError:
            try:
                __import__("ppdeep")
            except ImportError:
                return None

        thr = int(getattr(WorkerConfig, "SSDEEP_MATCH_THRESHOLD", 90))
        thr = max(0, min(100, thr))
        eng = getattr(WorkerConfig, "SCAN_ENGINE_VERSION", "1.0.0")
        pol = getattr(WorkerConfig, "POLICY_VERSION", "1.0.0")
        lim = max(10, int(getattr(WorkerConfig, "SSDEEP_SAFE_CANDIDATES_LIMIT", 400)))

        lo = max(0, int(file_size * 0.85))
        hi = int(file_size * 1.15) + 1

        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute(
                """
                SELECT file_hash, scan_result, risk_score, action_taken, last_scan,
                       scan_engine_version, policy_version, scan_count, first_seen, last_seen,
                       ssdeep_sig, file_size
                FROM file_cache
                WHERE scan_result = 'safe'
                  AND scan_engine_version = ?
                  AND policy_version = ?
                  AND ssdeep_sig IS NOT NULL AND TRIM(ssdeep_sig) != ''
                  AND file_size BETWEEN ? AND ?
                ORDER BY last_scan DESC
                LIMIT ?
                """,
                (eng, pol, lo, hi, lim),
            )
            rows: List[sqlite3.Row] = cur.fetchall()
            conn.close()
        except Exception as e:
            logger.error(f"Error fuzzy cache query: {e}")
            return None

        for row in rows:
            other = (row["ssdeep_sig"] or "").strip()
            if not other:
                continue
            score = _fuzzy_compare(ssdeep_sig, other)
            if score <= 0:
                continue
            if score >= thr:
                return {
                    "file_hash": row["file_hash"],
                    "scan_result": row["scan_result"],
                    "risk_score": row["risk_score"],
                    "action_taken": row["action_taken"],
                    "last_scan": row["last_scan"],
                    "scan_count": row["scan_count"],
                    "first_seen": row["first_seen"],
                    "last_seen": row["last_seen"],
                    "ssdeep_matched_score": score,
                }
        return None

    def get_cached_result(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Cache hit apenas se engine_version e policy_version coincidirem (Noteupdate §14)."""
        if not file_hash:
            return None

        eng = getattr(WorkerConfig, "SCAN_ENGINE_VERSION", "1.0.0")
        pol = getattr(WorkerConfig, "POLICY_VERSION", "1.0.0")

        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT file_hash, scan_result, risk_score, action_taken, last_scan,
                       scan_engine_version, policy_version, scan_count, first_seen, last_seen
                FROM file_cache
                WHERE file_hash = ?
                """,
                (file_hash,),
            )

            row = cursor.fetchone()
            conn.close()

            if not row:
                return None

            row_eng = (row["scan_engine_version"] or "").strip()
            row_pol = (row["policy_version"] or "").strip()
            # Bản ghi cũ (rỗng) hoặc version khác → miss — buộc scan lại (Noteupdate §14)
            if (row_eng or "") != eng:
                logger.debug(f"Cache miss (scan_engine_version): {file_hash[:12]}… {row_eng!r} != {eng!r}")
                return None
            if (row_pol or "") != pol:
                logger.debug(f"Cache miss (policy_version): {file_hash[:12]}… {row_pol!r} != {pol!r}")
                return None

            return {
                "file_hash": row["file_hash"],
                "scan_result": row["scan_result"],
                "risk_score": row["risk_score"],
                "action_taken": row["action_taken"],
                "last_scan": row["last_scan"],
                "scan_count": row["scan_count"],
                "first_seen": row["first_seen"],
                "last_seen": row["last_seen"],
            }
        except Exception as e:
            logger.error(f"Error querying cache: {e}")
            return None

    def save_result(
        self,
        file_hash: str,
        file_path: str,
        file_size: int,
        scan_result: str,
        risk_score: float,
        action_taken: str,
        ssdeep_sig: str = "",
    ):
        if not file_hash:
            return

        eng = getattr(WorkerConfig, "SCAN_ENGINE_VERSION", "1.0.0")
        pol = getattr(WorkerConfig, "POLICY_VERSION", "1.0.0")
        now_iso = datetime.now(timezone.utc).isoformat()

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT scan_count, first_seen FROM file_cache WHERE file_hash = ?",
                (file_hash,),
            )
            existing = cursor.fetchone()
            if existing:
                scan_count = int(existing[0] or 0) + 1
                first_seen = existing[1] or now_iso
            else:
                scan_count = 1
                first_seen = now_iso

            sig = (ssdeep_sig or "").strip()
            cursor.execute(
                """
                INSERT INTO file_cache (
                    file_hash, file_path, file_size, scan_result, risk_score, action_taken,
                    last_scan, scan_count, scan_engine_version, policy_version, first_seen, last_seen,
                    ssdeep_sig
                )
                VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(file_hash) DO UPDATE SET
                    file_path = excluded.file_path,
                    file_size = excluded.file_size,
                    scan_result = excluded.scan_result,
                    risk_score = excluded.risk_score,
                    action_taken = excluded.action_taken,
                    last_scan = CURRENT_TIMESTAMP,
                    scan_count = excluded.scan_count,
                    scan_engine_version = excluded.scan_engine_version,
                    policy_version = excluded.policy_version,
                    last_seen = excluded.last_seen,
                    ssdeep_sig = CASE
                        WHEN excluded.ssdeep_sig IS NOT NULL AND TRIM(excluded.ssdeep_sig) != ''
                        THEN excluded.ssdeep_sig
                        ELSE file_cache.ssdeep_sig
                    END
                """,
                (
                    file_hash,
                    file_path,
                    file_size,
                    scan_result,
                    risk_score,
                    action_taken,
                    scan_count,
                    eng,
                    pol,
                    first_seen,
                    now_iso,
                    sig,
                ),
            )

            conn.commit()
            conn.close()
            logger.debug(f"Cached result for hash: {file_hash[:16]}...")
        except Exception as e:
            logger.error(f"Error saving to cache: {e}")

    def cleanup_old_entries(self, days: int = None):
        days = days or WorkerConfig.CACHE_CLEANUP_DAYS
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute(
                """
                DELETE FROM file_cache
                WHERE last_scan < datetime('now', '-' || ? || ' days')
                """,
                (days,),
            )

            deleted = cursor.rowcount
            conn.commit()
            conn.close()

            if deleted > 0:
                logger.info(f"Cleaned up {deleted} old cache entries")
        except Exception as e:
            logger.error(f"Error cleaning cache: {e}")

    def get_cache_stats(self) -> Dict[str, Any]:
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute("SELECT COUNT(*) FROM file_cache")
            total = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM file_cache WHERE scan_result = 'safe'")
            safe = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM file_cache WHERE scan_result = 'malicious'")
            malicious = cursor.fetchone()[0]

            conn.close()

            return {
                "total": total,
                "safe": safe,
                "malicious": malicious,
                "other": total - safe - malicious,
            }
        except Exception as e:
            logger.error(f"Error getting cache stats: {e}")
            return {"total": 0, "safe": 0, "malicious": 0, "other": 0}
