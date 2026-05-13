"""
Fast Scan Module - YARA + real content-type detection (magic/container-aware).
"""
import yara
from pathlib import Path
from typing import Dict, List, Any, Optional
from loguru import logger
import tempfile
import zipfile
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from config import WorkerConfig
from core.content_pipeline import ContentProcessor
from core.deep_analysis import OCRProcessor

try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False
    logger.warning("python-magic not available, file type detection limited")


class FastScanEngine:
    """Fast Scan với YARA và detection theo content thật"""
    
    def __init__(self):
        self.yara_rules = None
        self.mime = None
        self.content_processor = ContentProcessor(max_text_length=WorkerConfig.ML_MAX_TEXT_LENGTH)
        self.ocr_processor = OCRProcessor()
        self._load_yara_rules()
        self._init_file_type_detection()
    
    def _load_yara_rules(self):
        """Load YARA rules"""
        try:
            rule_files = WorkerConfig.load_yara_rules()
            if rule_files:
                # Filter chỉ lấy file tồn tại
                existing_rules = {k: v for k, v in rule_files.items() if Path(v).exists()}
                
                if existing_rules:
                    valid_rules = {}
                    invalid_rules = {}
                    for rule_name, rule_path in existing_rules.items():
                        try:
                            # Validate each rule independently so one bad file
                            # does not disable the entire YARA bundle.
                            yara.compile(filepath=str(rule_path))
                            valid_rules[rule_name] = rule_path
                        except yara.Error as e:
                            invalid_rules[rule_name] = str(e)
                            logger.error(f"Invalid YARA rule skipped: {rule_path} | {e}")

                    if valid_rules:
                        self.yara_rules = yara.compile(filepaths=valid_rules)
                        logger.info(
                            f"Loaded {len(valid_rules)}/{len(existing_rules)} YARA rule files: "
                            f"{list(valid_rules.keys())}"
                        )
                        if invalid_rules:
                            logger.warning(
                                f"Skipped {len(invalid_rules)} invalid YARA rules: "
                                f"{list(invalid_rules.keys())}"
                            )
                    else:
                        logger.error("No valid YARA rules available after validation")
                        self.yara_rules = None
                else:
                    logger.warning("No YARA rule files found")
                    self.yara_rules = None
            else:
                logger.warning("No YARA rules configured")
                self.yara_rules = None
        except yara.Error as e:
            logger.error(f"Error loading YARA rules: {e}")
            self.yara_rules = None
        except Exception as e:
            logger.error(f"Unexpected error loading YARA rules: {e}")
            self.yara_rules = None
    
    def _init_file_type_detection(self):
        """Khởi tạo file type detection"""
        if MAGIC_AVAILABLE:
            try:
                self.mime = magic.Magic(mime=True)
            except Exception as e:
                logger.warning(f"Error initializing magic: {e}")
                self.mime = None
        else:
            self.mime = None
    
    def scan_file(self, file_path: Path, panic_mode: bool = False, force_extract: bool = False) -> Dict[str, Any]:
        """
        Scan file với YARA và Header Check
        
        Args:
            file_path: Đường dẫn file cần scan
            panic_mode: Nếu True, chỉ chạy YARA nhanh, skip các check phức tạp
            force_extract: Nếu True, bắt buộc bóc text + YARA trên nội dung
                           (dùng cho external transfer >= ngưỡng kích thước)
        
        Returns:
            {
                'yara_matches': [...],
                'file_type': 'image/jpeg',
                'is_encrypted_zip': False,
                'is_suspicious': False,
                'scan_time_ms': 5.2
            }
        """
        import time
        start_time = time.time()
        
        result = {
            'yara_matches': [],
            'file_type': None,
            'is_encrypted_zip': False,
            'is_suspicious': False,
            'scan_time_ms': 0,
            'extraction_parser': '',
            'extracted_text_len': 0,
            'extraction_error': '',
            'archive_scanned': False,
            'archive_entries': 0,
            'archive_scanned_files': 0,
            'archive_skipped_files': 0,
            'archive_sensitive_hits': [],
            'archive_scan_error': '',
        }
        
        if not file_path.exists():
            logger.warning(f"File not found: {file_path}")
            return result
        
        try:
            # 1. YARA Scan (luôn chạy, kể cả panic mode)
            if self.yara_rules:
                try:
                    matches = self.yara_rules.match(str(file_path), timeout=10)
                    result['yara_matches'] = [
                        {
                            'rule': match.rule,
                            'tags': list(match.tags),
                            'strings': [str(s) for s in match.strings[:5]]  # Limit strings
                        }
                        for match in matches
                    ]
                    
                    if matches:
                        result['is_suspicious'] = True
                        logger.debug(f"YARA match in {file_path.name}: {[m.rule for m in matches]}")
                except yara.TimeoutError:
                    logger.warning(f"YARA scan timeout for {file_path}")
                except Exception as e:
                    logger.warning(f"YARA scan error for {file_path}: {e}")
            
            # 2. Header Check (File Type Detection) - Skip nếu panic mode
            if not panic_mode:
                detected = self.content_processor.detect_file_type(file_path)
                result['file_type'] = detected.mime_type
                result['detected_group'] = detected.group
                result['detected_by'] = detected.source
                result['detection_confidence'] = detected.confidence
                
                # 3. Encrypted Zip Detection
                result['is_encrypted_zip'] = self._check_encrypted_zip(file_path)
                if result['is_encrypted_zip']:
                    result['is_suspicious'] = True
                    logger.warning(f"Encrypted ZIP detected: {file_path.name}")
                elif file_path.suffix.lower() == '.zip':
                    self._scan_zip_contents(file_path, result, panic_mode=panic_mode)
                 
                # 4. Text Extraction + YARA on text content
                # Chạy nếu: file thuộc nhóm tài liệu/ảnh, HOẶC force_extract=True (external transfer >= ngưỡng KB)
                should_extract = detected.group in ['docx', 'xlsx', 'pdf', 'text', 'image'] or force_extract
                if should_extract:
                    try:
                        extraction = self.content_processor.extract_content(file_path, detected)
                        text_to_scan = extraction.text if extraction.text else ""
                        result['extraction_parser'] = extraction.parser
                        result['extracted_text_len'] = len(text_to_scan)
                        result['extraction_error'] = extraction.error
                        
                        # Perform OCR if needed (e.g., images or short PDFs)
                        if extraction.needs_ocr:
                            ocr_text = self.ocr_processor.extract_text(file_path)
                            if ocr_text:
                                text_to_scan += "\n" + ocr_text
                                result['extracted_text_len'] = len(text_to_scan)

                        if text_to_scan and text_to_scan.strip():
                            # Run YARA trên text đã bóc
                            text_scan_result = self.scan_text_content(text_to_scan, panic_mode=True)
                            
                            # Merge YARA matches (deduplicate by rule name)
                            new_matches = text_scan_result.get('yara_matches', [])
                            if new_matches:
                                existing_rules = {m['rule'] for m in result['yara_matches']}
                                for m in new_matches:
                                    if m['rule'] not in existing_rules:
                                        result['yara_matches'].append(m)
                                        existing_rules.add(m['rule'])
                                        
                                result['is_suspicious'] = True
                                logger.debug(f"YARA match via text extraction in {file_path.name}: {[m['rule'] for m in new_matches]}")
                        
                        if force_extract:
                            result['force_extract_applied'] = True
                    except Exception as e:
                        result['extraction_error'] = str(e)
                        logger.warning(f"Failed to extract text for fast scan on {file_path.name}: {e}")
        
    
            result['scan_time_ms'] = (time.time() - start_time) * 1000
            
        except Exception as e:
            logger.error(f"Fast scan error for {file_path}: {e}")
            result['scan_time_ms'] = (time.time() - start_time) * 1000
        
        return result
    
    def _check_encrypted_zip(self, file_path: Path) -> bool:
        """Kiểm tra file ZIP có mật khẩu không"""
        try:
            import zipfile
            
            if not file_path.suffix.lower() == '.zip':
                return False
            
            with zipfile.ZipFile(file_path, 'r') as zip_file:
                # Kiểm tra xem có file nào được encrypt không
                for info in zip_file.infolist():
                    if info.flag_bits & 0x1:  # Bit 0 = encrypted
                        return True
            return False
        except zipfile.BadZipFile:
            return False
        except Exception as e:
            logger.debug(f"Error checking encrypted zip: {e}")
            return False

    def _scan_zip_contents(self, file_path: Path, result: Dict[str, Any], panic_mode: bool = False) -> None:
        """Scan text-bearing files inside a non-encrypted ZIP with bounded extraction."""
        if panic_mode:
            return

        max_files = int(getattr(WorkerConfig, "ZIP_SCAN_MAX_FILES", 25))
        max_member_bytes = int(getattr(WorkerConfig, "ZIP_SCAN_MAX_MEMBER_BYTES", 2 * 1024 * 1024))
        max_total_bytes = int(getattr(WorkerConfig, "ZIP_SCAN_MAX_TOTAL_BYTES", 10 * 1024 * 1024))
        supported_exts = {
            ".txt", ".csv", ".log", ".md", ".json", ".xml",
            ".docx", ".xlsx", ".pdf",
        }

        try:
            with zipfile.ZipFile(file_path, "r") as zf:
                infos = [info for info in zf.infolist() if not info.is_dir()]
                result["archive_entries"] = len(infos)
                result["archive_scanned"] = True

                scanned = 0
                skipped = 0
                total_bytes = 0
                existing_rules = {m.get("rule") for m in result.get("yara_matches", [])}

                with tempfile.TemporaryDirectory(prefix="dlp_zip_scan_") as tmp_dir:
                    tmp_root = Path(tmp_dir)
                    for info in infos:
                        if scanned >= max_files or total_bytes >= max_total_bytes:
                            skipped += 1
                            continue
                        if info.flag_bits & 0x1:
                            result["is_encrypted_zip"] = True
                            result["is_suspicious"] = True
                            skipped += 1
                            continue
                        if info.file_size <= 0 or info.file_size > max_member_bytes:
                            skipped += 1
                            continue

                        inner_name = info.filename.replace("\\", "/")
                        suffix = Path(inner_name).suffix.lower()
                        if suffix not in supported_exts:
                            skipped += 1
                            continue

                        total_bytes += int(info.file_size)
                        safe_name = Path(inner_name).name or "member.bin"
                        tmp_path = tmp_root / safe_name
                        try:
                            with zf.open(info, "r") as src, open(tmp_path, "wb") as dst:
                                remaining = max_member_bytes + 1
                                while remaining > 0:
                                    chunk = src.read(min(65536, remaining))
                                    if not chunk:
                                        break
                                    dst.write(chunk)
                                    remaining -= len(chunk)

                            detected = self.content_processor.detect_file_type(tmp_path)
                            extraction = self.content_processor.extract_content(tmp_path, detected)
                            text_to_scan = extraction.text or ""
                            if text_to_scan.strip():
                                text_scan_result = self.scan_text_content(text_to_scan, panic_mode=True)
                                for match in text_scan_result.get("yara_matches", []):
                                    rule = match.get("rule")
                                    if rule not in existing_rules:
                                        match = dict(match)
                                        match["archive_member"] = inner_name
                                        result["yara_matches"].append(match)
                                        existing_rules.add(rule)
                                    result["archive_sensitive_hits"].append({
                                        "member": inner_name,
                                        "rule": rule,
                                    })
                                if text_scan_result.get("is_suspicious"):
                                    result["is_suspicious"] = True
                            scanned += 1
                        except Exception as e:
                            skipped += 1
                            logger.debug(f"ZIP member scan failed: {file_path.name}!{inner_name}: {e}")
                        finally:
                            try:
                                tmp_path.unlink(missing_ok=True)
                            except Exception:
                                pass

                result["archive_scanned_files"] = scanned
                result["archive_skipped_files"] = skipped
                if result["archive_sensitive_hits"]:
                    logger.info(
                        f"ZIP content sensitive hits in {file_path.name}: "
                        f"{result['archive_sensitive_hits'][:5]}"
                    )
                else:
                    logger.info(
                        f"ZIP content scan clean: {file_path.name} "
                        f"entries={result['archive_entries']} scanned={scanned} skipped={skipped}"
                    )
        except zipfile.BadZipFile as e:
            result["archive_scan_error"] = f"bad_zip:{e}"
            logger.warning(f"Bad ZIP file, cannot scan contents: {file_path.name}")
        except Exception as e:
            result["archive_scan_error"] = str(e)
            logger.warning(f"Failed to scan ZIP contents for {file_path.name}: {e}")
    
    def scan_text_content(self, text_content: str, panic_mode: bool = False) -> Dict[str, Any]:
        """
        Scan text content với YARA rules (cho clipboard, OCR text, etc.)
        
        Args:
            text_content: Text content cần scan
            panic_mode: Nếu True, chỉ chạy YARA nhanh
        
        Returns:
            {
                'yara_matches': [...],
                'is_suspicious': False,
                'scan_time_ms': 5.2
            }
        """
        import time
        import tempfile
        start_time = time.time()
        
        result = {
            'yara_matches': [],
            'is_suspicious': False,
            'scan_time_ms': 0
        }
        
        if not text_content or not text_content.strip():
            return result
        
        try:
            # YARA cần scan từ file hoặc memory
            # Tạo temp file để scan
            with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', suffix='.txt', delete=False) as tmp_file:
                tmp_file.write(text_content)
                tmp_path = tmp_file.name
            
            try:
                # 1. YARA Scan
                if self.yara_rules:
                    try:
                        matches = self.yara_rules.match(tmp_path, timeout=10)
                        result['yara_matches'] = [
                            {
                                'rule': match.rule,
                                'tags': list(match.tags),
                                'strings': [str(s) for s in match.strings[:5]]  # Limit strings
                            }
                            for match in matches
                        ]
                        
                        if matches:
                            result['is_suspicious'] = True
                            logger.debug(f"YARA match in text content: {[m.rule for m in matches]}")
                    except yara.TimeoutError:
                        logger.warning(f"YARA scan timeout for text content")
                    except Exception as e:
                        logger.warning(f"YARA scan error for text content: {e}")
            finally:
                # Cleanup temp file
                try:
                    Path(tmp_path).unlink()
                except Exception:
                    pass
            
            result['scan_time_ms'] = (time.time() - start_time) * 1000
            
        except Exception as e:
            logger.error(f"Fast scan text content error: {e}")
            result['scan_time_ms'] = (time.time() - start_time) * 1000
        
        return result
