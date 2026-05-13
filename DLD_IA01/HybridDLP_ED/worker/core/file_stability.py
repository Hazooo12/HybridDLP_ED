"""
Debounce / estabilidade antes de SHA-256 (Noteupdate §7, §17).
Evita hash de ficheiro ainda a ser escrito ou bloqueado.
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Optional, Tuple

from loguru import logger


def _stat_key(path: Path) -> Optional[Tuple[int, int]]:
    try:
        st = path.stat()
        return (st.st_size, getattr(st, "st_mtime_ns", int(st.st_mtime * 1e9)))
    except OSError:
        return None


def wait_until_file_stable(
    path: Path,
    *,
    interval_sec: float = 0.15,
    max_wait_sec: float = 3.0,
) -> bool:
    """
    Duas leituras consecutivas com (size, mtime_ns) iguais → ficheiro estável.
    Retorna False se desaparecer ou exceder max_wait_sec.
    """
    deadline = time.time() + max(0.1, max_wait_sec)
    prev: Optional[Tuple[int, int]] = None

    while time.time() < deadline:
        if not path.is_file():
            logger.debug(f"file_stability: not a regular file or missing: {path}")
            return False
        cur = _stat_key(path)
        if cur is None:
            return False
        if prev is not None and cur == prev:
            return True
        prev = cur
        time.sleep(max(0.02, interval_sec))

    logger.debug(f"file_stability: timeout waiting stable: {path}")
    return False
