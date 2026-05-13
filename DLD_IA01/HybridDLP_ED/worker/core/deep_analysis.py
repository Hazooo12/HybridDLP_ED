"""
Deep Analysis Module - OCR và ML Classification với Lazy Loading
"""
import psutil
from pathlib import Path
from typing import Dict, Optional, Any
from loguru import logger
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from config import WorkerConfig
from core.content_pipeline import ContentProcessor


class OCRProcessor:
    """OCR Processor với điều kiện"""
    
    def __init__(self):
        self.tesseract_loaded = False
        self.pytesseract = None
        self.Image = None
        self.cv2 = None
    
    def _lazy_load_tesseract(self):
        """Lazy load Tesseract chỉ khi cần — tự động tìm path nếu không có trong PATH"""
        if not self.tesseract_loaded:
            try:
                import pytesseract
                from PIL import Image
                import cv2
                import os

                # 1. Ưu tiên env var TESSERACT_CMD
                tess_cmd = os.getenv("TESSERACT_CMD", "").strip()

                # 2. Nếu không có env var, thử tìm ở các đường dẫn cài mặc định
                if not tess_cmd:
                    _common_paths = [
                        r"C:\Program Files\Tesseract-OCR\tesseract.exe",
                        r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
                        r"C:\Users\Public\Tesseract-OCR\tesseract.exe",
                        r"C:\tesseract\tesseract.exe",
                        "/usr/bin/tesseract",
                        "/usr/local/bin/tesseract",
                    ]
                    import shutil
                    tess_cmd = shutil.which("tesseract") or ""
                    if not tess_cmd:
                        for p in _common_paths:
                            if os.path.isfile(p):
                                tess_cmd = p
                                break

                if tess_cmd:
                    pytesseract.pytesseract.tesseract_cmd = tess_cmd
                    logger.info(f"Tesseract path configured: {tess_cmd}")
                else:
                    logger.warning(
                        "Tesseract executable not found. Set env var TESSERACT_CMD=<path> "
                        "or install via: choco install tesseract"
                    )

                self.pytesseract = pytesseract
                self.Image = Image
                self.cv2 = cv2
                self.tesseract_loaded = True
                logger.info("Tesseract OCR loaded (lazy)")
                return True
            except ImportError as e:
                logger.error(f"Failed to load OCR libraries: {e}")
                return False
        return True
    
    def should_ocr(self, file_path: Path) -> Dict[str, Any]:
        """
        Kiểm tra điều kiện OCR
        
        Returns:
            {
                'should_ocr': True/False,
                'reason': '...',
                'file_size_mb': 2.5,
                'cpu_percent': 45.2
            }
        """
        result = {
            'should_ocr': False,
            'reason': '',
            'file_size_mb': 0,
            'cpu_percent': 0
        }
        
        if not WorkerConfig.OCR_ENABLED:
            result['reason'] = "OCR disabled in config"
            return result
        
        try:
            # Check file size
            file_size = file_path.stat().st_size
            file_size_mb = file_size / (1024 * 1024)
            result['file_size_mb'] = file_size_mb
            
            if file_size_mb > WorkerConfig.OCR_MAX_FILE_SIZE_MB:
                result['reason'] = f"File too large: {file_size_mb:.2f}MB > {WorkerConfig.OCR_MAX_FILE_SIZE_MB}MB"
                return result
            
            # Check CPU usage
            cpu_percent = psutil.cpu_percent(interval=0.1)
            result['cpu_percent'] = cpu_percent
            
            if cpu_percent > WorkerConfig.OCR_MAX_CPU_PERCENT:
                result['reason'] = f"CPU too high: {cpu_percent:.1f}% > {WorkerConfig.OCR_MAX_CPU_PERCENT}%"
                return result
            
            # Check file type
            if not self._is_image_file(file_path):
                result['reason'] = "Not an image file"
                return result
            
            result['should_ocr'] = True
            result['reason'] = "All conditions met"
            
        except Exception as e:
            logger.error(f"Error checking OCR conditions: {e}")
            result['reason'] = f"Error: {e}"
        
        return result
    
    def _is_image_file(self, file_path: Path) -> bool:
        """Kiểm tra ảnh/PDF scan bằng signature bytes, không dựa extension."""
        try:
            with open(file_path, 'rb') as f:
                header = f.read(8)
            if header.startswith(b'%PDF'):
                return True
            # JPEG: FF D8 FF
            if header[:3] == b'\xff\xd8\xff':
                return True
            # PNG: 89 50 4E 47
            if header[:4] == b'\x89PNG':
                return True
            # GIF: GIF87a or GIF89a
            if header[:6] in (b'GIF87a', b'GIF89a'):
                return True
            return False
        except Exception as e:
            logger.debug(f"Error checking file type: {e}")
            return False
    
    def extract_text(self, file_path: Path) -> Optional[str]:
        """Extract text từ ảnh bằng OCR"""
        if not self._lazy_load_tesseract():
            return None
        
        decision = self.should_ocr(file_path)
        if not decision['should_ocr']:
            logger.debug(f"Skipping OCR: {decision['reason']}")
            return None
        
        try:
            # Handle scanned/image PDFs when pdf2image + Poppler are available.
            with open(file_path, "rb") as f:
                header = f.read(4)
            if header.startswith(b"%PDF"):
                try:
                    from pdf2image import convert_from_path  # type: ignore

                    pages = convert_from_path(str(file_path), first_page=1, last_page=3, dpi=200)
                    texts = []
                    for idx, page in enumerate(pages, start=1):
                        text = self.pytesseract.image_to_string(page, lang='vie+eng')
                        if text and text.strip():
                            texts.append(text.strip())
                            logger.debug(
                                f"PDF OCR extracted {len(text.strip())} characters "
                                f"from {file_path.name} page {idx}"
                            )
                    return "\n".join(texts).strip() or None
                except Exception as e:
                    logger.warning(
                        f"PDF OCR unavailable for {file_path.name}: {e}. "
                        "Install Poppler and ensure it is on PATH for scanned PDFs."
                    )
                    return None
            
            # Load image
            image = self.Image.open(file_path)
            
            # OCR với Vietnamese language
            text = self.pytesseract.image_to_string(
                image,
                lang='vie+eng'  # Vietnamese + English
            )
            
            if text.strip():
                logger.debug(f"OCR extracted {len(text)} characters from {file_path.name}")
                return text.strip()
            else:
                logger.debug(f"No text extracted from {file_path.name}")
                return None
            
        except Exception as e:
            logger.error(f"OCR error for {file_path}: {e}")
            return None


class DeepAnalysisEngine:
    """Deep Analysis Engine với Lazy Loading"""
    
    def __init__(self):
        self.ocr_processor = OCRProcessor()
        self.content_processor = ContentProcessor(max_text_length=WorkerConfig.ML_MAX_TEXT_LENGTH)
        # ML Classifier sẽ được import lazy
        self.ml_classifier = None
    
    def _lazy_load_ml(self):
        """Lazy load ML classifier"""
        if self.ml_classifier is None:
            try:
                import sys
                from pathlib import Path
                sys.path.insert(0, str(Path(__file__).parent.parent))
                from models.ml_classifier import MLClassifier
                self.ml_classifier = MLClassifier()
            except ImportError as e:
                logger.warning(f"ML Classifier not available: {e}")
                return False
        return True
    
    def analyze(self, file_path: Path, file_type: str, 
                panic_mode: bool = False) -> Dict[str, Any]:
        """
        Deep Analysis: OCR + ML
        
        Args:
            file_path: Đường dẫn file
            file_type: MIME type của file
            panic_mode: Nếu True, skip deep analysis
        
        Returns:
            {
                'ocr_text': '...',
                'ml_result': {...},
                'is_sensitive': True/False
            }
        """
        result = {
            'ocr_text': None,
            'ml_result': None,
            'is_sensitive': False,
            'detected_type': None,
            'detected_group': None,
            'detected_by': None,
            'extraction': None,
        }
        
        # Skip deep analysis nếu panic mode
        if panic_mode:
            logger.debug("Skipping deep analysis (panic mode)")
            return result
        
        try:
            detected = self.content_processor.detect_file_type(file_path)
            # If fast-scan provided file_type, keep it as a hint but prioritize real detector.
            if file_type and not detected.mime_type:
                detected.mime_type = file_type

            result['detected_type'] = detected.mime_type
            result['detected_group'] = detected.group
            result['detected_by'] = detected.source

            extraction = self.content_processor.extract_content(file_path, detected)
            result['extraction'] = {
                'parser': extraction.parser,
                'confidence': extraction.confidence,
                'needs_ocr': extraction.needs_ocr,
                'encrypted': extraction.encrypted,
                'truncated': extraction.truncated,
                'error': extraction.error,
                'metadata': extraction.metadata,
            }

            # OCR only when extraction says it is needed (image/pdf scan, etc.)
            if extraction.needs_ocr:
                result['ocr_text'] = self.ocr_processor.extract_text(file_path)

            # 2. ML Classification from extracted content (or OCR fallback)
            text_to_classify = result['ocr_text'] or extraction.text
            if text_to_classify and self._lazy_load_ml():
                result['ml_result'] = self.ml_classifier.classify(text_to_classify)
                if result['ml_result']:
                    result['is_sensitive'] = result['ml_result'].get('is_sensitive', False)
        
        except Exception as e:
            logger.error(f"Deep analysis error: {e}")
        
        return result
