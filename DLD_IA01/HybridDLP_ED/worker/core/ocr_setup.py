"""
ocr_setup.py — Tự động phát hiện và cài Tesseract OCR khi worker khởi động.

Logic:
1. Kiểm tra Tesseract đã có chưa (shutil.which + common install paths)
2. Nếu chưa → chạy silent install từ file .exe trong thư mục ORC/ (bundled offline)
3. Trả về đường dẫn tuyệt đối đến tesseract.exe (hoặc None nếu cài thất bại)
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path
from loguru import logger

# Đường dẫn thư mục ORC chứa installer (relative to project root)
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_ORC_DIR = _PROJECT_ROOT / "ORC"

# Các đường dẫn cài đặt mặc định trên Windows
_COMMON_PATHS = [
    r"C:\Program Files\Tesseract-OCR\tesseract.exe",
    r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
    r"C:\Users\Public\Tesseract-OCR\tesseract.exe",
]


def _find_existing_tesseract() -> str | None:
    """Tìm Tesseract đã được cài sẵn. Trả về path hoặc None."""
    # 1. Ưu tiên env var
    env_cmd = os.getenv("TESSERACT_CMD", "").strip()
    if env_cmd and Path(env_cmd).is_file():
        return env_cmd

    # 2. shutil.which (PATH)
    found = shutil.which("tesseract")
    if found:
        return found

    # 3. Common install paths
    for p in _COMMON_PATHS:
        if Path(p).is_file():
            return p

    return None


def _find_installer() -> Path | None:
    """Tìm file installer .exe trong thư mục ORC/."""
    if not _ORC_DIR.exists():
        return None
    for f in sorted(_ORC_DIR.glob("tesseract-ocr-*.exe")):
        if f.is_file():
            return f
    return None


def _run_silent_install(installer: Path) -> bool:
    """
    Chạy installer Tesseract ở chế độ silent (không hiện UI).
    NSIS installer hỗ trợ flag /S /D=<install_dir>
    """
    install_dir = Path(r"C:\Program Files\Tesseract-OCR")
    logger.info(f"[OCR Setup] Cài Tesseract từ: {installer.name}")
    logger.info(f"[OCR Setup] Thư mục đích: {install_dir}")

    try:
        cmd = [str(installer), "/S", f"/D={install_dir}"]
        result = subprocess.run(
            cmd,
            timeout=120,
            capture_output=True,
        )
        if result.returncode == 0:
            logger.info("[OCR Setup] Cài Tesseract thành công!")
            return True
        else:
            stderr = result.stderr.decode("utf-8", errors="replace")
            logger.warning(f"[OCR Setup] Installer exit code {result.returncode}: {stderr[:200]}")
            return False
    except subprocess.TimeoutExpired:
        logger.error("[OCR Setup] Installer timeout sau 120 giây")
        return False
    except PermissionError:
        logger.error(
            "[OCR Setup] Không đủ quyền admin để cài vào Program Files. "
            "Hãy chạy worker với quyền Administrator."
        )
        return False
    except Exception as e:
        logger.error(f"[OCR Setup] Lỗi khi chạy installer: {e}")
        return False


def ensure_tesseract() -> str | None:
    """
    Entry point chính — gọi khi worker khởi động.

    Returns:
        str: đường dẫn đến tesseract.exe nếu sẵn sàng
        None: nếu không tìm thấy và cài thất bại
    """
    # Bước 1: Kiểm tra đã có chưa
    existing = _find_existing_tesseract()
    if existing:
        logger.info(f"[OCR Setup] Tesseract đã được cài: {existing}")
        _configure_pytesseract(existing)
        return existing

    # Bước 2: Chưa có → tìm installer
    logger.warning("[OCR Setup] Tesseract chưa được cài — tìm installer trong ORC/...")
    installer = _find_installer()
    if not installer:
        logger.error(
            f"[OCR Setup] Không tìm thấy installer trong {_ORC_DIR}. "
            "Đặt file tesseract-ocr-*.exe vào thư mục đó để cài tự động."
        )
        return None

    # Bước 3: Silent install
    success = _run_silent_install(installer)
    if not success:
        return None

    # Bước 4: Verify sau khi cài
    installed = _find_existing_tesseract()
    if installed:
        logger.info(f"[OCR Setup] Verify thành công: {installed}")
        _configure_pytesseract(installed)
        return installed
    else:
        logger.error("[OCR Setup] Cài xong nhưng không tìm thấy tesseract.exe — restart worker.")
        return None


def _configure_pytesseract(tess_path: str) -> None:
    """Set pytesseract.tesseract_cmd nếu thư viện đã được import."""
    try:
        import pytesseract
        pytesseract.pytesseract.tesseract_cmd = tess_path
    except ImportError:
        pass  # pytesseract chưa import, sẽ được set lại trong _lazy_load_tesseract
