"""
CERT Insider Threat Dataset Loader
Load và convert CERT dataset sang Agent event format
"""
import pandas as pd
import numpy as np
from pathlib import Path
from typing import List, Dict, Any, Optional, Iterator
from datetime import datetime
import logging
import re
import random
from urllib.parse import urlparse

# Setup logging
logger = logging.getLogger(__name__)


class CERTDatasetLoader:
    """
    Load và convert CERT Insider Threat Dataset sang agent event format
    
    Dataset structure thực tế:
    - file.csv: id,date,user,pc,filename,activity,to_removable_media,from_removable_media,content
    - email.csv: id,date,user,pc,to,cc,bcc,from,activity,size,attachments,content
    - http.csv: id,date,user,pc,url,activity,content
    """
    
    def __init__(self, cert_data_dir: Path):
        """
        Initialize CERT dataset loader
        
        Args:
            cert_data_dir: Directory chứa CERT dataset files
                Expected structure:
                - Dataset/file.csv/file.csv
                - Dataset/email.csv/email.csv
                - Dataset/http.csv/http.csv
        """
        self.cert_data_dir = Path(cert_data_dir)
    
    def load_cert_events(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Load CERT dataset và convert sang agent event format
        
        Args:
            limit: Maximum number of events to load (None = all)
        
        Returns:
            List of events in agent format
        """
        events = []
        
        # Check CERT files (có thể ở subfolder)
        file_file = self._find_file("file.csv")
        email_file = self._find_file("email.csv")
        http_file = self._find_file("http.csv")
        
        if not any([file_file, email_file, http_file]):
            logger.warning(f"CERT dataset files not found in {self.cert_data_dir}")
            logger.info("Expected: file.csv, email.csv, http.csv (có thể ở subfolder)")
            return events
        
        # Load file events (most relevant for DLP) - TOÀN BỘ
        if file_file:
            try:
                if limit:
                    df = pd.read_csv(file_file, nrows=limit)
                    logger.info(f"Loading {len(df):,} file events from CERT dataset (limited to {limit:,})")
                else:
                    logger.info(f"Loading TOÀN BỘ file events from CERT dataset (no limit)...")
                    # Read in chunks for large files
                    chunk_size = 100000
                    chunk_list = []
                    for chunk in pd.read_csv(file_file, chunksize=chunk_size):
                        chunk_list.append(chunk)
                        if len(chunk_list) % 10 == 0:
                            logger.info(f"  Read {len(chunk_list) * chunk_size:,} rows...")
                    df = pd.concat(chunk_list, ignore_index=True)
                    logger.info(f"  Total rows loaded: {len(df):,}")
                
                logger.info(f"Converting {len(df):,} file events to agent format...")
                for i, (_, row) in enumerate(df.iterrows()):
                    if (i + 1) % 50000 == 0:
                        logger.info(f"  Converted {i + 1:,}/{len(df):,} file events...")
                    event = self._convert_cert_file_event(row)
                    if event:
                        events.append(event)
                logger.info(f"[OK] Converted {len([e for e in events if e.get('source') == 'cert_dataset' and 'file' in str(e.get('type', '')).lower()]):,} file events")
            except Exception as e:
                logger.error(f"Error loading CERT file.csv: {e}")
        
        # Load email events (for exfiltration detection) - TOÀN BỘ
        if email_file:
            try:
                if limit:
                    df = pd.read_csv(email_file, nrows=limit)
                    logger.info(f"Loading {len(df):,} email events from CERT dataset (limited to {limit:,})")
                else:
                    logger.info(f"Loading TOÀN BỘ email events from CERT dataset (no limit)...")
                    chunk_size = 100000
                    chunk_list = []
                    for chunk in pd.read_csv(email_file, chunksize=chunk_size):
                        chunk_list.append(chunk)
                        if len(chunk_list) % 10 == 0:
                            logger.info(f"  Read {len(chunk_list) * chunk_size:,} rows...")
                    df = pd.concat(chunk_list, ignore_index=True)
                    logger.info(f"  Total rows loaded: {len(df):,}")
                
                logger.info(f"Converting {len(df):,} email events to agent format...")
                email_count = 0
                for i, (_, row) in enumerate(df.iterrows()):
                    if (i + 1) % 50000 == 0:
                        logger.info(f"  Converted {i + 1:,}/{len(df):,} email events...")
                    event = self._convert_cert_email_event(row)
                    if event:
                        events.append(event)
                        email_count += 1
                logger.info(f"[OK] Converted {email_count:,} email events")
            except Exception as e:
                logger.error(f"Error loading CERT email.csv: {e}")
        
        # Load HTTP events (for network upload detection) - TOÀN BỘ
        if http_file:
            try:
                if limit:
                    df = pd.read_csv(http_file, nrows=limit)
                    logger.info(f"Loading {len(df):,} HTTP events from CERT dataset (limited to {limit:,})")
                else:
                    logger.info(f"Loading TOÀN BỘ HTTP events from CERT dataset (no limit)...")
                    chunk_size = 100000
                    chunk_list = []
                    for chunk in pd.read_csv(http_file, chunksize=chunk_size):
                        chunk_list.append(chunk)
                        if len(chunk_list) % 10 == 0:
                            logger.info(f"  Read {len(chunk_list) * chunk_size:,} rows...")
                    df = pd.concat(chunk_list, ignore_index=True)
                    logger.info(f"  Total rows loaded: {len(df):,}")
                
                logger.info(f"Converting {len(df):,} HTTP events to agent format...")
                http_count = 0
                for i, (_, row) in enumerate(df.iterrows()):
                    if (i + 1) % 50000 == 0:
                        logger.info(f"  Converted {i + 1:,}/{len(df):,} HTTP events...")
                    event = self._convert_cert_http_event(row)
                    if event:
                        events.append(event)
                        http_count += 1
                logger.info(f"[OK] Converted {http_count:,} HTTP events")
            except Exception as e:
                logger.error(f"Error loading CERT http.csv: {e}")
        
        logger.info(f"Total CERT events loaded: {len(events)}")
        return events
    
    def load_cert_events_streaming(
        self, 
        limit: Optional[int] = None, 
        chunk_size: int = 10000,
        sample_ratio: Optional[float] = None
    ) -> Iterator[Dict[str, Any]]:
        """
        Load CERT dataset in streaming mode (memory efficient)
        Yields events one by one instead of loading all into memory
        
        Args:
            limit: Maximum number of events per file (None = all)
            chunk_size: Chunk size for reading CSV
            sample_ratio: Sample ratio (0.1 = 10%, None = no sampling)
        """
        # Check CERT files
        file_file = self._find_file("file.csv")
        email_file = self._find_file("email.csv")
        http_file = self._find_file("http.csv")
        
        if not any([file_file, email_file, http_file]):
            logger.warning(f"CERT dataset files not found in {self.cert_data_dir}")
            return
        
        if sample_ratio:
            logger.info(f"Using sampling ratio: {sample_ratio*100:.1f}%")
        
        # Stream file events
        if file_file:
            logger.info(f"Streaming file events from: {file_file}")
            count = 0
            for event in self._stream_csv_events(file_file, self._convert_cert_file_event, limit, chunk_size, sample_ratio):
                yield event
                count += 1
                if count % 50000 == 0:
                    logger.info(f"  Streamed {count:,} file events...")
            logger.info(f"[OK] Streamed {count:,} file events")
        
        # Stream email events
        if email_file:
            logger.info(f"Streaming email events from: {email_file}")
            count = 0
            for event in self._stream_csv_events(email_file, self._convert_cert_email_event, limit, chunk_size, sample_ratio):
                yield event
                count += 1
                if count % 50000 == 0:
                    logger.info(f"  Streamed {count:,} email events...")
            logger.info(f"[OK] Streamed {count:,} email events")
        
        # Stream HTTP events
        if http_file:
            logger.info(f"Streaming HTTP events from: {http_file}")
            count = 0
            for event in self._stream_csv_events(http_file, self._convert_cert_http_event, limit, chunk_size, sample_ratio):
                yield event
                count += 1
                if count % 50000 == 0:
                    logger.info(f"  Streamed {count:,} HTTP events...")
            logger.info(f"[OK] Streamed {count:,} HTTP events")
    
    def _stream_csv_events(
        self, 
        csv_file: Path, 
        converter_func, 
        limit: Optional[int], 
        chunk_size: int,
        sample_ratio: Optional[float]
    ) -> Iterator[Dict[str, Any]]:
        """Stream CSV events in chunks"""
        count = 0
        
        try:
            # Read in chunks
            for chunk_df in pd.read_csv(csv_file, chunksize=chunk_size):
                for _, row in chunk_df.iterrows():
                    if limit and count >= limit:
                        return
                    
                    # Apply sampling
                    if sample_ratio and random.random() > sample_ratio:
                        continue
                    
                    event = converter_func(row)
                    if event:
                        yield event
                        count += 1
        except Exception as e:
            logger.error(f"Error streaming CSV {csv_file}: {e}")
    
    def _find_file(self, filename: str) -> Optional[Path]:
        """Tìm file trong cert_data_dir hoặc subfolder"""
        # Try direct path
        direct_path = self.cert_data_dir / filename
        if direct_path.exists():
            return direct_path
        
        # Try subfolder (Dataset/file.csv/file.csv)
        subfolder_path = self.cert_data_dir / filename.replace('.csv', '') / filename
        if subfolder_path.exists():
            return subfolder_path
        
        # Try recursive search
        for path in self.cert_data_dir.rglob(filename):
            return path
        
        return None
    
    def _convert_cert_file_event(self, row: pd.Series) -> Optional[Dict[str, Any]]:
        """Convert CERT file.csv row to agent event format"""
        try:
            # CERT format thực tế: id,date,user,pc,filename,activity,to_removable_media,from_removable_media,content
            user = str(row.get('user', 'unknown'))
            date_str = str(row.get('date', ''))
            filename = str(row.get('filename', ''))
            activity = str(row.get('activity', '')).lower()
            to_removable = bool(row.get('to_removable_media', False))
            from_removable = bool(row.get('from_removable_media', False))
            content = str(row.get('content', ''))
            pc = str(row.get('pc', ''))
            
            # Parse datetime (format: "01/02/2010 07:19:41")
            dt = self._parse_datetime(date_str)
            
            # Determine event type và operation
            if 'open' in activity:
                event_type = "file_copy"
                op_type = "read"
            elif 'write' in activity:
                event_type = "file_copy"
                op_type = "write"
            elif 'copy' in activity:
                event_type = "file_copy"
                op_type = "copy"
            else:
                event_type = "file_copy"
                op_type = "read"
            
            # Check if USB operation
            if to_removable or from_removable:
                event_type = "usb_copy" if to_removable else "file_copy"
            
            # Calculate entropy from content if available
            entropy = 3.5  # Default
            if content:
                entropy = self._calculate_entropy(content)
            
            event = {
                "ts": dt.isoformat(),
                "timestamp": dt.isoformat(),
                "type": event_type,
                "event_type": event_type,
                "user": user,
                "source": "cert_dataset",
                "device": {
                    "host_name": pc if pc else None
                },
                "context": {
                    "user": user,
                    "process_name": "explorer.exe",
                    "active_window": "File Explorer"
                },
                "object": {
                    "path": filename,
                    "dst_path": filename if to_removable else None,
                    "size_bytes": len(content.encode('utf-8')) if content else 0
                },
                "operation": {
                    "op_type": op_type
                },
                "metrics": {
                    "entropy": entropy
                },
                "usb": {
                    "to_removable": to_removable,
                    "from_removable": from_removable
                } if (to_removable or from_removable) else {}
            }
            
            return event
        except Exception as e:
            logger.debug(f"Error converting CERT file event: {e}")
            return None
    
    def _convert_cert_email_event(self, row: pd.Series) -> Optional[Dict[str, Any]]:
        """Convert CERT email.csv row to agent event format"""
        try:
            # CERT format thực tế: id,date,user,pc,to,cc,bcc,from,activity,size,attachments,content
            user = str(row.get('user', 'unknown'))
            date_str = str(row.get('date', ''))
            to_email = str(row.get('to', ''))
            size = int(row.get('size', 0))
            attachments = str(row.get('attachments', ''))
            activity = str(row.get('activity', '')).lower()
            content = str(row.get('content', ''))
            pc = str(row.get('pc', ''))
            
            # Extract domain from email address
            dest_domain = ''
            if '@' in to_email:
                dest_domain = to_email.split('@')[1].lower()
            elif to_email:
                dest_domain = to_email.lower()
            
            # Parse datetime
            dt = self._parse_datetime(date_str)
            
            # Only process "Send" activity (not "View")
            if 'send' not in activity:
                return None  # Skip view events
            
            # Calculate entropy
            entropy = 4.0  # Default
            if content:
                entropy = self._calculate_entropy(content)
            
            event = {
                "ts": dt.isoformat(),
                "timestamp": dt.isoformat(),
                "type": "clipboard_paste",  # Email send = external paste
                "event_type": "clipboard_paste",
                "user": user,
                "source": "cert_dataset",
                "device": {
                    "host_name": pc if pc else None
                },
                "context": {
                    "user": user,
                    "process_name": "outlook.exe",
                    "active_window": "Outlook",
                    "dest_domain": dest_domain
                },
                "clipboard": {
                    "content_type": "Text",
                    "content": content[:10000] if content else f"Email content {size} bytes",  # Limit size
                    "content_len": size,
                    "dest_app": "outlook.exe",
                    "dest_domain": dest_domain,
                    "snapshot_linked": True
                },
                "object": {
                    "path": attachments if attachments else None,
                    "size_bytes": size
                },
                "operation": {
                    "op_type": "paste"
                },
                "metrics": {
                    "entropy": entropy
                }
            }
            
            return event
        except Exception as e:
            logger.debug(f"Error converting CERT email event: {e}")
            return None
    
    def _convert_cert_http_event(self, row: pd.Series) -> Optional[Dict[str, Any]]:
        """Convert CERT http.csv row to agent event format"""
        try:
            # CERT format thực tế: id,date,user,pc,url,activity,content
            user = str(row.get('user', 'unknown'))
            date_str = str(row.get('date', ''))
            url = str(row.get('url', ''))
            activity = str(row.get('activity', '')).lower()
            content = str(row.get('content', ''))
            pc = str(row.get('pc', ''))
            
            # Extract domain from URL
            dest_domain = ''
            try:
                parsed = urlparse(url)
                dest_domain = parsed.netloc.lower() if parsed.netloc else ''
            except:
                # Fallback: extract domain manually
                if '://' in url:
                    dest_domain = url.split('://')[1].split('/')[0].lower()
            
            # Determine if upload (POST) or download (GET)
            is_upload = any(keyword in url.lower() or keyword in activity.lower() 
                          for keyword in ['upload', 'post', 'send', 'submit'])
            op_type = "upload" if is_upload else "download"
            
            # Parse datetime
            dt = self._parse_datetime(date_str)
            
            # Calculate entropy
            entropy = 4.5  # Default
            if content:
                entropy = self._calculate_entropy(content)
            
            event = {
                "ts": dt.isoformat(),
                "timestamp": dt.isoformat(),
                "type": "network_upload" if is_upload else "network_download",
                "event_type": "network_upload" if is_upload else "network_download",
                "user": user,
                "source": "cert_dataset",
                "device": {
                    "host_name": pc if pc else None
                },
                "context": {
                    "user": user,
                    "process_name": "chrome.exe",
                    "active_window": "Browser",
                    "dest_domain": dest_domain
                },
                "object": {
                    "path": url,
                    "dst_path": url
                },
                "network": {
                    "dest_url": url,
                    "dest_domain": dest_domain,
                    "method": "POST" if is_upload else "GET",
                    "external_dst": True if dest_domain and not dest_domain.endswith('.dtaa.com') else False
                },
                "content": {
                    "sample": content[:1000] if content else None,  # Limit sample size
                    "sample_len": len(content) if content else 0
                },
                "operation": {
                    "op_type": op_type
                },
                "metrics": {
                    "entropy": entropy
                }
            }
            
            return event
        except Exception as e:
            logger.debug(f"Error converting CERT http event: {e}")
            return None
    
    def _parse_datetime(self, date_str: str) -> datetime:
        """Parse CERT datetime string (format: "01/02/2010 07:19:41")"""
        try:
            # Format: "01/02/2010 07:19:41"
            dt = datetime.strptime(date_str.strip(), "%m/%d/%Y %H:%M:%S")
            dt = dt.replace(tzinfo=datetime.now().astimezone().tzinfo)
            return dt
        except Exception as e:
            logger.debug(f"Error parsing datetime '{date_str}': {e}")
            return datetime.now()
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text"""
        if not text or len(text) == 0:
            return 0.0
        
        # Count character frequencies
        char_counts = {}
        for char in text:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        text_len = len(text)
        for count in char_counts.values():
            p = count / text_len
            if p > 0:
                entropy -= p * np.log2(p)
        
        return entropy
