"""
GenTrainDataset — Synthetic DLP Event Generator for AI Training
=============================================================
Tạo dataset huấn luyện AI matching đúng schema event thực tế từ agent sensor.

Output: JSONL file  đúng event schema của HybridDLP Agent
Schema reference: HybridDLP_ED/agent/event_schema.py

Usage:
  python gen_train_dataset.py                    # 500 normal + 500 anomalous
  python gen_train_dataset.py --total 2000      # custom total
  python gen_train_dataset.py --out my_data.jsonl
  python gen_train_dataset.py --ratio 0.8        # 80% anomalous
  python gen_train_dataset.py --seed 42         # reproducible
"""

from __future__ import annotations

import argparse
import json
import random
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# ── base paths ───────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent
OUT_DIR = BASE_DIR
DEFAULT_OUT = OUT_DIR / "train_dataset.jsonl"


# ── helpers ──────────────────────────────────────────────────────────────────

def ts(base: datetime, offset_sec: float = 0.0) -> str:
    """ISO-8601 timestamp string."""
    return (base + timedelta(seconds=offset_sec)).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "+00:00")


def uid() -> str:
    return str(uuid.uuid4())


def pick(lst: List[Any]) -> Any:
    return random.choice(lst)


def rand_int(lo: int, hi: int) -> int:
    return random.randint(lo, hi)


def rand_float(lo: float, hi: float) -> float:
    return random.uniform(lo, hi)


def maybe(d: Dict[str, Any], prob: float = 0.7) -> Dict[str, Any]:
    """Return d with probability prob, else empty dict."""
    return d if random.random() < prob else {}


# ── entity pools ─────────────────────────────────────────────────────────────

USERS = [
    "thien", "huy.nguyen", "tram.le", "khanh.pham",
    "dat.tran", "lan.ho", "minh.nguyen", "hoa.nguyen",
]
HOSTNAMES = ["FNKX", "DESKTOP-7K3M2P1", "WIN-WS01", "FNKX-LAPTOP"]
DEVICE_IDS = [
    "c5770605020849c0a646b822edd9f01a",
    "a1234567890abcdef1234567890abcdef",
    "b9876543210fedcba9876543210fedcba",
]
SESSIONS = [
    "19d47e7d6e7",
    "19d47f8a8b8",
    "19d4801c9c9",
]

OFFICE_APPS = [
    "WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE",
    "wps.exe", "et.exe", "wpp.exe",
]
BROWSERS = ["chrome.exe", "msedge.exe", "firefox.exe"]
SYSTEM_APPS = ["explorer.exe", "cmd.exe", "powershell.exe"]
SCRIPT_TOOLS = ["python.exe", "node.exe", "powershell.exe", "cmd.exe"]
REMOTE_TOOLS = ["mstsc.exe", "ssh.exe", "putty.exe", "filezilla.exe"]
STORAGE_APPS = ["OneDrive.exe", "Dropbox.exe", "GoogleDrive.exe"]

SAFE_EXTENSIONS = [".txt", ".jpg", ".png", ".mp4", ".pdf", ".docx", ".xlsx"]
RISK_EXTENSIONS = [".csv", ".docx", ".xlsx", ".pdf", ".doc", ".pptx", ".txt"]
SENSITIVE_EXTENSIONS = [".csv", ".docx", ".xlsx", ".pdf"]

SENSITIVE_FILENAMES = [
    "bangluong_thang{n}_{y}.csv",
    "baocaotaichinhQ{n}_{y}.csv",
    "danhsachcongnoQ{n}_{y}.csv",
    "danhsachkhachhang_Q{n}_{y}.csv",
    "hopdongdichvu_Q{n}_{y}.docx",
    "hosokiemtoan_Q{n}_{y}.docx",
    "tailieuchienluoc_Q{n}_{y}.docx",
    "danhmucbosungvattu_{m}_{y}.csv",
    "listnhanvienmoi_{y}.docx",
    "phieudenghibosungvanphongpham_{y}.docx",
    "kehoachdaotaonoibo_{m}_{y}.docx",
    "thongtinvanhanhthuongki_{m}_{y}.docx",
]
NORMAL_FILENAMES = [
    "report_quy{n}_{y}.xlsx",
    "bai_tap_thuc_hanh_{n}.docx",
    "slide_bai_giang_{n}.pptx",
    "logo_cong_ty.png",
    "anh_san_pham_{n}.jpg",
    "video_gioi_thieu.mp4",
    "huong_dan_su_dung.pdf",
    "lich_lam_viec.xlsx",
    "nhiem_vu_thang{n}.docx",
    "thu_moi_hop_{n}.pdf",
]

SENSITIVE_FOLDERS = [
    "C:\\Users\\{u}\\Documents\\Finance",
    "C:\\Users\\{u}\\Documents\\HR",
    "C:\\Users\\{u}\\Documents\\Legal",
    "C:\\Users\\{u}\\Documents\\Strategy",
    "C:\\Users\\{u}\\Downloads\\BoHoSoTest",
    "C:\\PRJ\\SEB\\",
]
NORMAL_FOLDERS = [
    "C:\\Users\\{u}\\Documents",
    "C:\\Users\\{u}\\Downloads",
    "C:\\Users\\{u}\\Videos",
    "C:\\Users\\{u}\\Pictures",
]

USB_DRIVE_LETTERS = ["D:", "E:", "F:"]
CLOUD_DOMAINS = [
    "drive.google.com",
    "dropbox.com",
    "onedrive.live.com",
    "mega.nz",
    "wetransfer.com",
    "mediafire.com",
    "sendgb.com",
]
NETWORK_AI_DOMAINS = [
    "chat.openai.com",
    "copilot.microsoft.com",
    "claude.ai",
    "gemini.google.com",
    "poe.com",
]
NETWORK_SOCIAL_DOMAINS = [
    "facebook.com",
    "twitter.com",
    "zalo.me",
    "telegram.org",
]

PII_SAMPLES = [
    "Nguyễn Văn A, 0123456789, nguyenvana@mail.com",
    "Trần Thị B, 0987654321, tranb@gmail.com",
    "0312776451 - Công ty Cổ phần Logistics Đông Nam",
    "MST: 0312776451 | STK: 0071002945689 | Vietcombank",
    "Bảng lương tháng 02/2026: 15 nhân viên, tổng 450 triệu",
    "HĐDV/2026/019 - Công ty TNHH Giải pháp Số Đại Nam",
]
SAFE_SAMPLES = [
    "Cảm ơn bạn đã quan tâm đến sản phẩm của chúng tôi.",
    "Lịch họp phòng nhân sự ngày 15/04/2026",
    "Nội dung email: Xin chào, hy vọng bạn khỏe mạnh.",
    "Báo cáo công việc tuần 14 năm 2026",
    "Kế hoạch du lịch team building tháng 5/2026",
]


# ── scenario definitions ──────────────────────────────────────────────────────
# label:  0=normal  1=anomaly  2=critical
SCENARIOS_NORMAL = [
    # name, weight, builder
    ("office_file_open", 3, lambda u, b, d: _build_office_file(u, b, d, safe=True)),
    ("browser_normal", 3, lambda u, b, d: _build_browser_normal(u, b, d)),
    ("system_app", 2, lambda u, b, d: _build_system_app(u, b, d)),
    ("clipboard_text", 2, lambda u, b, d: _build_clipboard_text(u, b, d)),
    ("usb_safe", 1, lambda u, b, d: _build_usb_safe(u, b, d)),
]

SCENARIOS_ANOMALY = [
    ("file_copy_to_usb_sensitive", 3, lambda u, b, d: _build_copy_to_usb(u, b, d, sensitive=True)),
    ("file_copy_to_cloud", 2, lambda u, b, d: _build_copy_to_cloud(u, b, d)),
    ("clipboard_pii", 3, lambda u, b, d: _build_clipboard_pii(u, b, d)),
    ("bulk_file_export", 2, lambda u, b, d: _build_bulk_export(u, b, d)),
    ("off_hours_access", 2, lambda u, b, d: _build_offhours_access(u, b, d)),
    ("remote_access_file", 2, lambda u, b, d: _build_remote_access(u, b, d)),
    ("script_tool_sensitive", 2, lambda u, b, d: _build_script_sensitive(u, b, d)),
    ("usb_large_copy", 2, lambda u, b, d: _build_usb_large(u, b, d)),
    ("cloud_sync_sensitive", 1, lambda u, b, d: _build_cloud_sync(u, b, d)),
    ("browser_upload_sensitive", 1, lambda u, b, d: _build_browser_upload(u, b, d)),
]


# ── per-scenario builders ────────────────────────────────────────────────────

def _ctx(u: str, pid: int, proc: str, hwnd: int, session: str, biz: bool = True) -> Dict[str, Any]:
    ts_ = datetime.now(timezone.utc).replace(hour=rand_int(9, 17) if biz else rand_int(20, 23))
    return {
        "user": u,
        "fg_app": proc,
        "fg_process": proc,
        "fg_pid": pid,
        "fg_cmdline": f"C:\\Windows\\{proc}",
        "fg_exe_path": f"C:\\Windows\\{proc}",
        "fg_hwnd": hwnd,
        "session": session,
        "outside_working_hours": not biz,
    }


def _device(h: str, did: str) -> Dict[str, Any]:
    return {"host_name": h, "device_id": did}


def _actor(u: str, pid: int, ppid: int, proc: str, session: str) -> Dict[str, Any]:
    return {
        "user": f"{u}",
        "username": f"{u}",
        "pid": pid,
        "ppid": ppid,
        "process": proc.lower(),
        "exe": f"C:\\Windows\\{proc}",
        "cmdline": f"{proc}.exe",
        "username": f"FNKX\\{u}",
    }


def _proc(pid: int, ppid: int, proc: str, cmd: str, session: str) -> Dict[str, Any]:
    return {
        "pid": pid,
        "ppid": ppid,
        "name": proc.lower(),
        "exe": f"C:\\Windows\\{proc}",
        "cmdline": cmd,
        "create_time": time.time(),
        "username": f"FNKX\\thien",
        "parent_name": "explorer.exe",
    }


# ── NORMAL builders ──────────────────────────────────────────────────────────

def _build_office_file(u: str, base: datetime, d: Dict) -> Dict:
    app = pick(OFFICE_APPS)
    pid = rand_int(10000, 60000)
    ppid = rand_int(1000, 9999)
    ext = pick(SAFE_EXTENSIONS)
    folder = pick(NORMAL_FOLDERS).format(u=u)
    fname = f"report_{rand_int(1,999)}{ext}"
    fpath = f"{folder}\\{fname}"
    h = pick(HOSTNAMES)
    did = pick(DEVICE_IDS)
    sess = pick(SESSIONS)
    off_h = random.random() < 0.85  # business hours
    hour = rand_int(9, 17) if off_h else rand_int(18, 22)
    event_time = base.replace(hour=hour, minute=rand_int(0, 59))
    return {
        "event_id": uid(),
        "ts": ts(event_time),
        "type": pick(["file_modified", "file_created"]),
        "source": "file",
        "severity": 30,
        "tags": [],
        "device": _device(h, did),
        "actor": _actor(u, pid, ppid, app, sess),
        "process": _proc(pid, ppid, app, f'"{app}.exe" "{fpath}"', sess),
        "operation": {
            "op_type": pick(["file_modify", "file_create"]),
            "tool": app.lower(),
            "raw_fs_kind": "modified",
            "dest_volume_type": "Fixed",
            "dlp_semantic_hint": "local",
            "hash_kind": "partial",
            "hash_source": "fresh_read",
        },
        "object": {
            "path": fpath, "name": fname, "ext": ext,
            "size": rand_int(1024, 512000),
            "mtime": time.time(),
            "exists": True,
            "drive": "C:", "volume_type": "Fixed",
            "dest_drive": "C:", "dest_volume_type": "Fixed",
            "hash_sha256": uid().replace("-", "")[:64],
            "sensitivity": "Normal",
        },
        "context": _ctx(u, pid, app.lower(), rand_int(100000, 2000000), sess, biz=off_h),
        "metrics": {"file_count": 1},
        "decision": {"stage": "L1"},
        "schema_ver": 1,
        "ioc_hits": [],
    }


def _build_browser_normal(u: str, base: datetime, d: Dict) -> Dict:
    browser = pick(BROWSERS)
    pid = rand_int(10000, 60000)
    ppid = rand_int(1000, 9999)
    h = pick(HOSTNAMES)
    did = pick(DEVICE_IDS)
    sess = pick(SESSIONS)
    off_h = random.random() < 0.9
    hour = rand_int(9, 17) if off_h else rand_int(18, 22)
    event_time = base.replace(hour=hour, minute=rand_int(0, 59))
    domain = pick(["google.com", "microsoft.com", "vnexpress.net", "shopee.vn"])
    return {
        "event_id": uid(),
        "ts": ts(event_time),
        "type": pick(["proc_start", "network_request"]),
        "source": pick(["process", "network"]),
        "severity": 30,
        "tags": ["browser"],
        "device": _device(h, did),
        "actor": _actor(u, pid, ppid, browser, sess),
        "process": _proc(pid, ppid, browser, f'"{browser}.exe" --new-tab', sess),
        "operation": {"op_type": pick(["proc_start", "network_out"]), "tool": browser.lower()},
        "object": {"name": browser.lower()},
        "context": {
            **_ctx(u, pid, browser.lower(), rand_int(100000, 2000000), sess, biz=off_h),
            "domain": domain,
            "dest_domain": domain,
            "resolved_domain": domain,
        },
        "network": {
            "dest_domain": domain,
            "resolved_domain": domain,
            "dest_url": f"https://{domain}",
            "bytes_sent": rand_int(100, 8000),
            "bytes_recv": rand_int(500, 50000),
        },
        "decision": {"stage": "L1"},
        "schema_ver": 1,
        "ioc_hits": [],
    }


def _build_system_app(u: str, base: datetime, d: Dict) -> Dict:
    app = pick(SYSTEM_APPS)
    pid = rand_int(10000, 60000)
    ppid = rand_int(1000, 9999)
    h = pick(HOSTNAMES)
    did = pick(DEVICE_IDS)
    sess = pick(SESSIONS)
    hour = rand_int(9, 17)
    event_time = base.replace(hour=hour, minute=rand_int(0, 59))
    return {
        "event_id": uid(),
        "ts": ts(event_time),
        "type": pick(["proc_start", "proc_end"]),
        "source": "process",
        "severity": 30,
        "tags": [],
        "device": _device(h, did),
        "actor": _actor(u, pid, ppid, app, sess),
        "process": _proc(pid, ppid, app, app, sess),
        "operation": {"op_type": pick(["proc_start", "proc_end"]), "tool": app.lower()},
        "object": {"name": app.lower(), "path": f"C:\\Windows\\System32\\{app}"},
        "context": _ctx(u, pid, app.lower(), rand_int(100000, 2000000), sess),
        "decision": {"stage": "L1"},
        "schema_ver": 1,
        "ioc_hits": [],
    }


def _build_clipboard_text(u: str, base: datetime, d: Dict) -> Dict:
    pid = rand_int(10000, 60000)
    ppid = rand_int(1000, 9999)
    app = pick(OFFICE_APPS)
    h = pick(HOSTNAMES)
    did = pick(DEVICE_IDS)
    sess = pick(SESSIONS)
    sample = pick(SAFE_SAMPLES)
    return {
        "event_id": uid(),
        "ts": ts(base.replace(hour=rand_int(9, 17))),
        "type": "clipboard_paste",
        "source": "clipboard",
        "severity": 30,
        "tags": [],
        "device": _device(h, did),
        "actor": _actor(u, pid, ppid, app, sess),
        "process": _proc(pid, ppid, app, f'"{app}.exe"', sess),
        "operation": {"op_type": "clipboard_paste", "tool": app.lower()},
        "context": _ctx(u, pid, app.lower(), rand_int(100000, 2000000), sess),
        "clipboard": {
            "content_type": "Text",
            "text_content": sample,
            "dest_app": app.lower(),
            "dest_window_title": f"{app} - Document",
            "snapshot_linked": True,
        },
        "content": {"sample": sample, "sample_len": len(sample)},
        "decision": {"stage": "L1"},
        "schema_ver": 1,
        "ioc_hits": [],
    }


def _build_usb_safe(u: str, base: datetime, d: Dict) -> Dict:
    letter = pick(USB_DRIVE_LETTERS)
    pid = rand_int(10000, 60000)
    ppid = rand_int(1000, 9999)
    h = pick(HOSTNAMES)
    did = pick(DEVICE_IDS)
    sess = pick(SESSIONS)
    event_time = base.replace(hour=rand_int(9, 17), minute=rand_int(0, 59))
    return {
        "event_id": uid(),
        "ts": ts(event_time),
        "type": pick(["usb_connected", "volume_mounted"]),
        "source": pick(["usb", "file"]),
        "severity": 30,
        "tags": ["removable_media"],
        "device": _device(h, did),
        "actor": _actor(u, pid, ppid, "explorer.exe", sess),
        "process": _proc(pid, ppid, "explorer.exe", "explorer.exe", sess),
        "operation": {"op_type": pick(["usb_connect", "volume_mounted"]), "tool": "usb"},
        "object": {
            "path": f"{letter}\\", "name": f"{letter}\\",
            "drive": letter, "volume_type": "Removable",
            "dest_drive": letter, "dest_volume_type": "Removable",
        },
        "context": _ctx(u, pid, "explorer.exe", rand_int(100000, 2000000), sess),
        "metrics": {"file_count": 0},
        "usb": {
            "device_id": uid().replace("-", "")[:24],
            "device_name": f"{letter}\\",
            "device_type": "USB Storage",
            "connection_type": "USB Mass Storage",
            "trust_status": pick(["Trusted", "Known"]),
            "first_seen": time.time(),
            "mount_time": time.time(),
            "file_copy_volume": 0,
            "file_count_to_device": 0,
            "sensitive_file_count": 0,
            "drive": letter,
            "fs_type": pick(["FAT32", "exFAT", "NTFS"]),
        },
        "decision": {"stage": "L1"},
        "schema_ver": 1,
        "ioc_hits": [],
    }


# ── ANOMALY builders ─────────────────────────────────────────────────────────

def _build_copy_to_usb(u: str, base: datetime, d: Dict, sensitive: bool = True) -> Dict:
    letter = pick(USB_DRIVE_LETTERS)
    pid = rand_int(10000, 60000)
    ppid = rand_int(1000, 9999)
    h = pick(HOSTNAMES)
    did = pick(DEVICE_IDS)
    sess = pick(SESSIONS)
    tpl = pick(SENSITIVE_FILENAMES)
    y = rand_int(2025, 2026)
    m = f"{rand_int(1,12):02d}"
    n = rand_int(1, 4)
    fname = tpl.format(y=y, m=m, n=n)
    ext = Path(fname).suffix or ".csv"
    src_folder = pick(SENSITIVE_FOLDERS).format(u=u)
    fpath = f"{src_folder}\\{fname}"
    off_h = random.random() < 0.4
    hour = rand_int(18, 23) if off_h else rand_int(9, 17)
    event_time = base.replace(hour=hour, minute=rand_int(0, 59))
    file_size = rand_int(5000, 80000)
    sha = uid().replace("-", "")[:64]
    return {
        "event_id": uid(),
        "ts": ts(event_time),
        "type": "file_created",
        "source": "file",
        "severity": 70,
        "tags": ["removable_media"],
        "device": _device(h, did),
        "actor": _actor(u, pid, ppid, "explorer.exe", sess),
        "process": _proc(pid, ppid, "explorer.exe", "explorer.exe", sess),
        "operation": {
            "op_type": "file_copy_external",
            "tool": "explorer.exe",
            "copy_move_verdict": "copy_not_move",
            "copy_move_evidence": "reconcile_source_path_still_exists",
            "raw_fs_kind": "created",
            "correlation": {"layer_b": "flush_single"},
            "dest_volume_type": "Removable",
            "semantic_action": "copy_to_removable",
            "dlp_semantic_hint": "external_transfer",
            "hash_kind": "partial",
            "hash_source": "fresh_read",
        },
        "object": {
            "path": f"{letter}\\{fname}",
            "name": fname,
            "ext": ext,
            "size": file_size,
            "mtime": time.time(),
            "exists": True,
            "drive": letter,
            "volume_type": "Removable",
            "dest_drive": letter,
            "dest_volume_type": "Removable",
            "signature": pick(["csv", "docx", "xlsx"]),
            "hash_sha256": sha,
            "hash_sha256_partial": sha,
            "sensitivity": "Sensitive",
            "hash_after": sha,
        },
        "context": {
            **_ctx(u, pid, "explorer.exe", rand_int(100000, 2000000), sess, biz=not off_h),
            "window_title": f"USB Drive ({letter}) - File Explorer",
            "window_title_lc": f"usb drive ({letter}) - file explorer",
        },
        "metrics": {"file_count": rand_int(1, 5)},
        "content": {
            "sample": pick(PII_SAMPLES) if sensitive else pick(SAFE_SAMPLES),
            "sample_len": rand_int(100, 500),
        },
        "decision": {"stage": "L1"},
        "schema_ver": 1,
        "tags": [],
        "ioc_hits": [],
    }


def _build_copy_to_cloud(u: str, base: datetime, d: Dict) -> Dict:
    pid = rand_int(10000, 60000)
    ppid = rand_int(1000, 9999)
    h = pick(HOSTNAMES)
    did = pick(DEVICE_IDS)
    sess = pick(SESSIONS)
    domain = pick(CLOUD_DOMAINS)
    fname = pick(SENSITIVE_FILENAMES).format(y=rand_int(2025, 2026), m=f"{rand_int(1,12):02d}", n=rand_int(1,4))
    ext = Path(fname).suffix or ".csv"
    sha = uid().replace("-", "")[:64]
    off_h = random.random() < 0.3
    hour = rand_int(18, 23) if off_h else rand_int(9, 17)
    event_time = base.replace(hour=hour, minute=rand_int(0, 59))
    return {
        "event_id": uid(),
        "ts": ts(event_time),
        "type": "file_created",
        "source": "file",
        "severity": 70,
        "tags": ["cloud_sync"],
        "device": _device(h, did),
        "actor": _actor(u, pid, ppid, "explorer.exe", sess),
        "process": _proc(pid, ppid, "OneDrive.exe", "OneDrive.exe", sess),
        "operation": {
            "op_type": "file_sync_cloud",
            "tool": "onedrive.exe",
            "dest_volume_type": "Network",
            "semantic_action": "upload_to_cloud",
            "dlp_semantic_hint": "external_transfer",
            "hash_kind": "partial",
            "hash_source": "fresh_read",
        },
        "object": {
            "path": f"C:\\Users\\{u}\\{domain}\\{fname}",
            "name": fname,
            "ext": ext,
            "size": rand_int(5000, 80000),
            "mtime": time.time(),
            "exists": True,
            "drive": "C:",
            "volume_type": "Fixed",
            "dest_drive": "C:",
            "dest_volume_type": "Network",
            "hash_sha256": sha,
            "sensitivity": "Sensitive",
        },
        "context": {
            **_ctx(u, pid, "onedrive.exe", rand_int(100000, 2000000), sess, biz=not off_h),
            "domain": domain,
            "dest_domain": domain,
        },
        "network": {
            "dest_domain": domain,
            "dest_url": f"https://{domain}/upload",
            "bytes_sent": rand_int(5000, 80000),
        },
        "content": {"sample": pick(PII_SAMPLES), "sample_len": rand_int(100, 500)},
        "decision": {"stage": "L1"},
        "schema_ver": 1,
        "ioc_hits": [],
    }


def _build_clipboard_pii(u: str, base: datetime, d: Dict) -> Dict:
    pid = rand_int(10000, 60000)
    ppid = rand_int(1000, 9999)
    app = pick(OFFICE_APPS)
    h = pick(HOSTNAMES)
    did = pick(DEVICE_IDS)
    sess = pick(SESSIONS)
    off_h = random.random() < 0.4
    event_time = base.replace(hour=rand_int(18, 23) if off_h else rand_int(9, 17))
    sample = pick(PII_SAMPLES)
    return {
        "event_id": uid(),
        "ts": ts(event_time),
        "type": "clipboard_paste",
        "source": "clipboard",
        "severity": 70,
        "tags": [],
        "device": _device(h, did),
        "actor": _actor(u, pid, ppid, app, sess),
        "process": _proc(pid, ppid, app, f'"{app}.exe"', sess),
        "operation": {"op_type": "clipboard_paste", "tool": app.lower()},
        "context": {
            **_ctx(u, pid, app.lower(), rand_int(100000, 2000000), sess, biz=not off_h),
            "dest_domain": pick(CLOUD_DOMAINS + ["chat.openai.com"]),
        },
        "clipboard": {
            "content_type": "Text",
            "text_content": sample,
            "dest_app": app.lower(),
            "dest_window_title": f"{app} - Document",
            "snapshot_linked": True,
        },
        "content": {"sample": sample, "sample_len": len(sample)},
        "decision": {"stage": "L1"},
        "schema_ver": 1,
        "ioc_hits": [],
    }


def _build_bulk_export(u: str, base: datetime, d: Dict) -> Dict:
    pid = rand_int(10000, 60000)
    ppid = rand_int(1000, 9999)
    h = pick(HOSTNAMES)
    did = pick(DEVICE_IDS)
    sess = pick(SESSIONS)
    letter = pick(USB_DRIVE_LETTERS)
    count = rand_int(5, 20)
    off_h = random.random() < 0.5
    hour = rand_int(18, 23) if off_h else rand_int(9, 17)
    event_time = base.replace(hour=hour, minute=rand_int(0, 59))
    sha = uid().replace("-", "")[:64]
    return {
        "event_id": uid(),
        "ts": ts(event_time),
        "type": "file_created",
        "source": "file",
        "severity": 70,
        "tags": ["removable_media", "bulk_operation"],
        "device": _device(h, did),
        "actor": _actor(u, pid, ppid, "explorer.exe", sess),
        "process": _proc(pid, ppid, "explorer.exe", "explorer.exe", sess),
        "operation": {
            "op_type": "file_copy_external",
            "tool": "explorer.exe",
            "dest_volume_type": "Removable",
            "semantic_action": "copy_to_removable",
            "dlp_semantic_hint": "external_transfer",
            "hash_kind": "partial",
        },
        "object": {
            "path": f"{letter}\\export_batch_{rand_int(1,999)}.zip",
            "name": f"export_batch_{rand_int(1,999)}.zip",
            "ext": ".zip",
            "size": rand_int(100000, 5000000),
            "mtime": time.time(),
            "exists": True,
            "drive": letter,
            "volume_type": "Removable",
            "dest_drive": letter,
            "dest_volume_type": "Removable",
            "hash_sha256": sha,
            "sensitivity": "Sensitive",
        },
        "context": {
            **_ctx(u, pid, "explorer.exe", rand_int(100000, 2000000), sess, biz=not off_h),
            "window_title": f"USB Drive ({letter}) - File Explorer",
        },
        "metrics": {"file_count": count},
        "content": {
            "sample": pick(PII_SAMPLES),
            "sample_len": rand_int(200, 800),
        },
        "decision": {"stage": "L1"},
        "schema_ver": 1,
        "ioc_hits": [],
    }


def _build_offhours_access(u: str, base: datetime, d: Dict) -> Dict:
    pid = rand_int(10000, 60000)
    ppid = rand_int(1000, 9999)
    h = pick(HOSTNAMES)
    did = pick(DEVICE_IDS)
    sess = pick(SESSIONS)
    tpl = pick(SENSITIVE_FILENAMES)
    fname = tpl.format(y=rand_int(2025, 2026), m=f"{rand_int(1,12):02d}", n=rand_int(1,4))
    ext = Path(fname).suffix or ".csv"
    folder = pick(SENSITIVE_FOLDERS).format(u=u)
    fpath = f"{folder}\\{fname}"
    sha = uid().replace("-", "")[:64]
    event_time = base.replace(hour=rand_int(22, 23), minute=rand_int(0, 59))
    return {
        "event_id": uid(),
        "ts": ts(event_time),
        "type": pick(["file_created", "file_modified"]),
        "source": "file",
        "severity": 70,
        "tags": ["after_hours"],
        "device": _device(h, did),
        "actor": _actor(u, pid, ppid, pick(OFFICE_APPS), sess),
        "process": _proc(pid, ppid, "WINWORD.EXE", f'"{fpath}"', sess),
        "operation": {
            "op_type": pick(["file_create", "file_modify"]),
            "tool": "winword.exe",
            "dest_volume_type": "Fixed",
            "dlp_semantic_hint": "local",
            "hash_kind": "partial",
            "hash_source": "fresh_read",
        },
        "object": {
            "path": fpath,
            "name": fname,
            "ext": ext,
            "size": rand_int(5000, 80000),
            "mtime": time.time(),
            "exists": True,
            "drive": "C:",
            "volume_type": "Fixed",
            "hash_sha256": sha,
            "sensitivity": "Sensitive",
        },
        "context": {
            **_ctx(u, pid, "winword.exe", rand_int(100000, 2000000), sess, biz=False),
        },
        "content": {"sample": pick(PII_SAMPLES), "sample_len": rand_int(100, 500)},
        "decision": {"stage": "L1"},
        "schema_ver": 1,
        "ioc_hits": [],
    }


def _build_remote_access(u: str, base: datetime, d: Dict) -> Dict:
    pid = rand_int(10000, 60000)
    ppid = rand_int(1000, 9999)
    h = pick(HOSTNAMES)
    did = pick(DEVICE_IDS)
    sess = pick(SESSIONS)
    tool = pick(REMOTE_TOOLS)
    sha = uid().replace("-", "")[:64]
    fname = pick(SENSITIVE_FILENAMES).format(y=rand_int(2025, 2026), m=f"{rand_int(1,12):02d}", n=rand_int(1,4))
    event_time = base.replace(hour=rand_int(18, 22))
    return {
        "event_id": uid(),
        "ts": ts(event_time),
        "type": "file_created",
        "source": "file",
        "severity": 70,
        "tags": ["remote_access"],
        "device": _device(h, did),
        "actor": _actor(u, pid, ppid, tool, sess),
        "process": _proc(pid, ppid, tool, tool, sess),
        "operation": {
            "op_type": "file_copy_external",
            "tool": tool.lower(),
            "dest_volume_type": "Network",
            "semantic_action": "remote_transfer",
            "dlp_semantic_hint": "external_transfer",
            "hash_kind": "partial",
        },
        "object": {
            "path": f"C:\\Users\\{u}\\Documents\\RemoteTransfer\\{fname}",
            "name": fname,
            "ext": ".csv",
            "size": rand_int(5000, 80000),
            "mtime": time.time(),
            "exists": True,
            "volume_type": "Fixed",
            "dest_volume_type": "Network",
            "hash_sha256": sha,
            "sensitivity": "Sensitive",
        },
        "context": _ctx(u, pid, tool.lower(), rand_int(100000, 2000000), sess, biz=False),
        "content": {"sample": pick(PII_SAMPLES), "sample_len": rand_int(100, 500)},
        "decision": {"stage": "L1"},
        "schema_ver": 1,
        "ioc_hits": [],
    }


def _build_script_sensitive(u: str, base: datetime, d: Dict) -> Dict:
    pid = rand_int(10000, 60000)
    ppid = rand_int(1000, 9999)
    h = pick(HOSTNAMES)
    did = pick(DEVICE_IDS)
    sess = pick(SESSIONS)
    tool = pick(SCRIPT_TOOLS)
    sha = uid().replace("-", "")[:64]
    fname = f"sensitive_export_{rand_int(1,999)}.csv"
    event_time = base.replace(hour=rand_int(18, 23))
    return {
        "event_id": uid(),
        "ts": ts(event_time),
        "type": "file_created",
        "source": "file",
        "severity": 70,
        "tags": ["script_engine"],
        "device": _device(h, did),
        "actor": _actor(u, pid, ppid, tool, sess),
        "process": _proc(pid, ppid, tool, f'python.exe export.py', sess),
        "operation": {
            "op_type": "file_create",
            "tool": tool.lower(),
            "dest_volume_type": "Removable",
            "semantic_action": "script_export",
            "hash_kind": "partial",
        },
        "object": {
            "path": f"D:\\{fname}",
            "name": fname,
            "ext": ".csv",
            "size": rand_int(5000, 100000),
            "mtime": time.time(),
            "exists": True,
            "drive": "D:",
            "volume_type": "Removable",
            "hash_sha256": sha,
            "sensitivity": "Sensitive",
        },
        "context": {
            **_ctx(u, pid, tool.lower(), rand_int(100000, 2000000), sess, biz=False),
            "window_title": f"USB Drive (D:) - File Explorer",
        },
        "content": {"sample": pick(PII_SAMPLES), "sample_len": rand_int(100, 500)},
        "decision": {"stage": "L1"},
        "schema_ver": 1,
        "ioc_hits": [],
    }


def _build_usb_large(u: str, base: datetime, d: Dict) -> Dict:
    letter = pick(USB_DRIVE_LETTERS)
    pid = rand_int(10000, 60000)
    ppid = rand_int(1000, 9999)
    h = pick(HOSTNAMES)
    did = pick(DEVICE_IDS)
    sess = pick(SESSIONS)
    sha = uid().replace("-", "")[:64]
    event_time = base.replace(hour=rand_int(18, 22))
    return {
        "event_id": uid(),
        "ts": ts(event_time),
        "type": "file_created",
        "source": "file",
        "severity": 70,
        "tags": ["removable_media", "large_transfer"],
        "device": _device(h, did),
        "actor": _actor(u, pid, ppid, "explorer.exe", sess),
        "process": _proc(pid, ppid, "explorer.exe", "explorer.exe", sess),
        "operation": {
            "op_type": "file_copy_external",
            "tool": "explorer.exe",
            "dest_volume_type": "Removable",
            "semantic_action": "copy_to_removable",
            "dlp_semantic_hint": "external_transfer",
            "hash_kind": "partial",
        },
        "object": {
            "path": f"{letter}\\full_backup_{rand_int(1,9)}.zip",
            "name": f"full_backup_{rand_int(1,9)}.zip",
            "ext": ".zip",
            "size": rand_int(50000000, 500000000),
            "mtime": time.time(),
            "exists": True,
            "drive": letter,
            "volume_type": "Removable",
            "hash_sha256": sha,
            "sensitivity": "Sensitive",
        },
        "context": {
            **_ctx(u, pid, "explorer.exe", rand_int(100000, 2000000), sess, biz=False),
            "window_title": f"USB Drive ({letter}) - File Explorer",
        },
        "metrics": {"file_count": rand_int(20, 100)},
        "decision": {"stage": "L1"},
        "schema_ver": 1,
        "ioc_hits": [],
    }


def _build_cloud_sync(u: str, base: datetime, d: Dict) -> Dict:
    pid = rand_int(10000, 60000)
    ppid = rand_int(1000, 9999)
    h = pick(HOSTNAMES)
    did = pick(DEVICE_IDS)
    sess = pick(SESSIONS)
    app = pick(STORAGE_APPS)
    sha = uid().replace("-", "")[:64]
    fname = pick(SENSITIVE_FILENAMES).format(y=rand_int(2025,2026), m=f"{rand_int(1,12):02d}", n=rand_int(1,4))
    event_time = base.replace(hour=rand_int(18, 22))
    return {
        "event_id": uid(),
        "ts": ts(event_time),
        "type": "file_created",
        "source": "file",
        "severity": 70,
        "tags": ["cloud_sync"],
        "device": _device(h, did),
        "actor": _actor(u, pid, ppid, app, sess),
        "process": _proc(pid, ppid, app, app, sess),
        "operation": {
            "op_type": "file_sync_cloud",
            "tool": app.lower(),
            "dest_volume_type": "Network",
            "semantic_action": "upload_to_cloud",
            "dlp_semantic_hint": "external_transfer",
            "hash_kind": "partial",
        },
        "object": {
            "path": f"C:\\Users\\{u}\\{app}\\{fname}",
            "name": fname,
            "ext": ".csv",
            "size": rand_int(5000, 80000),
            "mtime": time.time(),
            "exists": True,
            "volume_type": "Fixed",
            "dest_volume_type": "Network",
            "hash_sha256": sha,
            "sensitivity": "Sensitive",
        },
        "context": _ctx(u, pid, app.lower(), rand_int(100000, 2000000), sess, biz=False),
        "content": {"sample": pick(PII_SAMPLES), "sample_len": rand_int(100, 500)},
        "decision": {"stage": "L1"},
        "schema_ver": 1,
        "ioc_hits": [],
    }


def _build_browser_upload(u: str, base: datetime, d: Dict) -> Dict:
    pid = rand_int(10000, 60000)
    ppid = rand_int(1000, 9999)
    h = pick(HOSTNAMES)
    did = pick(DEVICE_IDS)
    sess = pick(SESSIONS)
    browser = pick(BROWSERS)
    domain = pick(CLOUD_DOMAINS)
    sha = uid().replace("-", "")[:64]
    fname = pick(SENSITIVE_FILENAMES).format(y=rand_int(2025,2026), m=f"{rand_int(1,12):02d}", n=rand_int(1,4))
    event_time = base.replace(hour=rand_int(18, 22))
    return {
        "event_id": uid(),
        "ts": ts(event_time),
        "type": "browser_upload",
        "source": "browser",
        "severity": 70,
        "tags": ["browser_upload", "cloud"],
        "device": _device(h, did),
        "actor": _actor(u, pid, ppid, browser, sess),
        "process": _proc(pid, ppid, browser, f'"{browser}.exe"', sess),
        "operation": {
            "op_type": "browser_upload",
            "tool": browser.lower(),
            "dest_volume_type": "Network",
            "semantic_action": "upload_to_cloud",
            "dlp_semantic_hint": "external_transfer",
        },
        "object": {
            "path": f"https://{domain}/upload/{fname}",
            "name": fname,
            "ext": ".csv",
            "size": rand_int(5000, 80000),
            "mtime": time.time(),
            "hash_sha256": sha,
            "sensitivity": "Sensitive",
        },
        "context": {
            **_ctx(u, pid, browser.lower(), rand_int(100000, 2000000), sess, biz=False),
            "domain": domain,
            "dest_domain": domain,
        },
        "network": {
            "dest_domain": domain,
            "dest_url": f"https://{domain}/upload",
            "bytes_sent": rand_int(5000, 80000),
        },
        "content": {"sample": pick(PII_SAMPLES), "sample_len": rand_int(100, 500)},
        "decision": {"stage": "L1"},
        "schema_ver": 1,
        "ioc_hits": [],
    }


# ── label helper ──────────────────────────────────────────────────────────────

def label_for(event: Dict) -> int:
    """
    Auto-label based on event characteristics:
    0 = normal
    1 = anomaly (policy violation)
    2 = critical (high-risk data exfil)
    """
    tags = set(str(t).lower() for t in event.get("tags", []))
    severity = event.get("severity", 30)
    op = event.get("operation", {})
    obj = event.get("object", {})
    dest_vol = str(op.get("dest_volume_type") or obj.get("dest_volume_type") or "").lower()
    content_sample = (event.get("content") or {}).get("sample", "")
    ext = str(obj.get("ext") or "").lower()
    fname = str(obj.get("name") or "").lower()

    # Sensitive filename keywords
    sensitive_keywords = ["bangluong", "baocao", "congno", "khachhang",
                          "hopdong", "hoso", "chiendich", "tonghop"]
    is_sensitive_name = any(k in fname for k in sensitive_keywords)

    # High-risk: sensitive file to removable / cloud
    if (ext in [".csv", ".docx", ".xlsx", ".pdf"] and
        dest_vol in ["removable", "network"] and
            is_sensitive_name):
        return 2

    # Anomaly: any sensitive file / off-hours / large transfer
    if (severity == 70 or
        "after_hours" in tags or
        "bulk_operation" in tags or
        "removable_media" in tags or
        "cloud_sync" in tags or
        "script_engine" in tags or
        dest_vol in ["removable", "network"]):
        return 1

    return 0


# ── main generator ───────────────────────────────────────────────────────────

def build_scenario_pool() -> List:
    """Return weighted (weight, builder) list for normal + anomaly."""
    pool = []
    for name, weight, builder in SCENARIOS_NORMAL:
        for _ in range(weight):
            pool.append((0, name, builder))
    for name, weight, builder in SCENARIOS_ANOMALY:
        for _ in range(weight):
            pool.append((1, name, builder))
    return pool


def generate(
    total: int = 1000,
    anomaly_ratio: float = 0.5,
    seed: int | None = None,
    out_path: str | None = None,
) -> List[Dict]:
    """
    Generate `total` events.
    anomaly_ratio=0.5 → 50% normal, 50% anomaly.
    """
    if seed is not None:
        random.seed(seed)

    out_path = Path(out_path or DEFAULT_OUT)
    pool = build_scenario_pool()

    # determine counts
    n_normal = int(total * (1 - anomaly_ratio))
    n_anomaly = total - n_normal

    events: List[Dict] = []
    base_date = datetime(2026, 4, 1, 8, 0, 0, tzinfo=timezone.utc)

    def generate_batch(count: int, want_anomaly: bool) -> List[Dict]:
        batch = []
        attempts = 0
        while len(batch) < count and attempts < count * 6:
            attempts += 1
            # pick random scenario of correct type
            candidates = [(a, n, b) for a, n, b in pool if a == (1 if want_anomaly else 0)]
            if not candidates:
                continue
            _, name, builder = pick(candidates)
            u = pick(USERS)
            day_offset = rand_int(0, 30)
            base = base_date + timedelta(days=day_offset)
            try:
                ev = builder(u, base, {})
                ev["_meta"] = {
                    "scenario": name,
                    "want_anomaly": want_anomaly,
                }
                batch.append(ev)
            except Exception:
                pass
        return batch

    normal_events = generate_batch(n_normal, want_anomaly=False)
    anomaly_events = generate_batch(n_anomaly, want_anomaly=True)
    events = normal_events + anomaly_events
    random.shuffle(events)

    # label + write
    for ev in events:
        ev["label"] = label_for(ev)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        for ev in events:
            f.write(json.dumps(ev, ensure_ascii=False) + "\n")

    # stats
    counts = {0: 0, 1: 0, 2: 0}
    for ev in events:
        counts[ev["label"]] = counts.get(ev["label"], 0) + 1

    print(f"\n{'='*60}")
    print(f"  GenTrainDataset — Synthetic DLP Event Generator")
    print(f"{'='*60}")
    print(f"  Output : {out_path}")
    print(f"  Total  : {len(events)}")
    print(f"  Normal (label=0) : {counts[0]}")
    print(f"  Anomaly (label=1): {counts[1]}")
    print(f"  Critical (label=2): {counts[2]}")
    print(f"{'='*60}\n")
    return events


# ── CLI ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    ap = argparse.ArgumentParser(
        description="Generate synthetic DLP events for AI training.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("--total", type=int, default=1000,
                     help="Total events to generate (default: 1000)")
    ap.add_argument("--ratio", type=float, default=0.5,
                     help="Fraction of anomalous events (0.0-1.0, default: 0.5)")
    ap.add_argument("--seed", type=int, default=None,
                     help="Random seed for reproducibility")
    ap.add_argument("--out", type=str, default=None,
                     help="Output JSONL path (default: Dataset/train_dataset.jsonl)")
    args = ap.parse_args()

    generate(
        total=args.total,
        anomaly_ratio=args.ratio,
        seed=args.seed,
        out_path=args.out,
    )
