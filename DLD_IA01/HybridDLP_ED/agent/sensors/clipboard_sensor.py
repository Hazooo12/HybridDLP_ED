from __future__ import annotations

import ctypes
import hashlib
import os
import re
import threading
import time
import uuid
from collections import deque
from ctypes import wintypes
from typing import Any, Deque, Dict, List, Optional, Set, Tuple

# =========================
# WinAPI type aliases (portable across Python builds)
# =========================
if hasattr(wintypes, "ULONG_PTR"):
    ULONG_PTR = wintypes.ULONG_PTR  # type: ignore
else:
    ULONG_PTR = ctypes.c_uint64 if ctypes.sizeof(ctypes.c_void_p) == 8 else ctypes.c_uint32

if hasattr(wintypes, "LRESULT"):
    LRESULT = wintypes.LRESULT  # type: ignore
else:
    LRESULT = ctypes.c_int64 if ctypes.sizeof(ctypes.c_void_p) == 8 else ctypes.c_int32

if hasattr(wintypes, "WPARAM"):
    WPARAM = wintypes.WPARAM  # type: ignore
else:
    WPARAM = ULONG_PTR

if hasattr(wintypes, "LPARAM"):
    LPARAM = wintypes.LPARAM  # type: ignore
else:
    LPARAM = ctypes.c_int64 if ctypes.sizeof(ctypes.c_void_p) == 8 else ctypes.c_int32


# =========================
# WinAPI setup
# =========================
user32 = ctypes.WinDLL("user32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
shell32 = ctypes.WinDLL("shell32", use_last_error=True)
psapi = ctypes.WinDLL("psapi", use_last_error=True)

CF_UNICODETEXT = 13
CF_HDROP = 15  # file drop list
CF_DIB = 8    # device-independent bitmap (screenshot stays in clipboard as DIB)
CF_BITMAP = 2  # raw bitmap handle

# clipboard
user32.GetClipboardSequenceNumber.restype = wintypes.DWORD

user32.OpenClipboard.argtypes = [wintypes.HWND]
user32.OpenClipboard.restype = wintypes.BOOL

user32.CloseClipboard.argtypes = []
user32.CloseClipboard.restype = wintypes.BOOL

user32.GetClipboardData.argtypes = [wintypes.UINT]
user32.GetClipboardData.restype = wintypes.HANDLE

user32.IsClipboardFormatAvailable.argtypes = [wintypes.UINT]
user32.IsClipboardFormatAvailable.restype = wintypes.BOOL

kernel32.GlobalLock.argtypes = [wintypes.HGLOBAL]
kernel32.GlobalLock.restype = wintypes.LPVOID

kernel32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
kernel32.GlobalUnlock.restype = wintypes.BOOL

kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
kernel32.GetModuleHandleW.restype = wintypes.HMODULE

# DragQueryFileW (HDROP)
shell32.DragQueryFileW.argtypes = [wintypes.HANDLE, wintypes.UINT, wintypes.LPWSTR, wintypes.UINT]
shell32.DragQueryFileW.restype = wintypes.UINT

# foreground window / title / process
user32.GetForegroundWindow.argtypes = []
user32.GetForegroundWindow.restype = wintypes.HWND

user32.GetWindowTextLengthW.argtypes = [wintypes.HWND]
user32.GetWindowTextLengthW.restype = ctypes.c_int

user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
user32.GetWindowTextW.restype = ctypes.c_int

user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
user32.GetWindowThreadProcessId.restype = wintypes.DWORD

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_VM_READ = 0x0010

kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE

kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL

kernel32.QueryFullProcessImageNameW.argtypes = [
    wintypes.HANDLE,
    wintypes.DWORD,
    wintypes.LPWSTR,
    ctypes.POINTER(wintypes.DWORD),
]
kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL

psapi.GetModuleBaseNameW.argtypes = [wintypes.HANDLE, wintypes.HMODULE, wintypes.LPWSTR, wintypes.DWORD]
psapi.GetModuleBaseNameW.restype = wintypes.DWORD

# keyboard hook
WH_KEYBOARD_LL = 13
WM_KEYDOWN = 0x0100
WM_SYSKEYDOWN = 0x0104

VK_CONTROL = 0x11
VK_LCONTROL = 0xA2
VK_RCONTROL = 0xA3

VK_C = 0x43
VK_V = 0x56
VK_X = 0x58
VK_INSERT = 0x2D
VK_DELETE = 0x2E
VK_SHIFT = 0x10


class KBDLLHOOKSTRUCT(ctypes.Structure):
    _fields_ = [
        ("vkCode", wintypes.DWORD),
        ("scanCode", wintypes.DWORD),
        ("flags", wintypes.DWORD),
        ("time", wintypes.DWORD),
        ("dwExtraInfo", ULONG_PTR),
    ]


LPKBDLLHOOKSTRUCT = ctypes.POINTER(KBDLLHOOKSTRUCT)

HOOKPROC = ctypes.WINFUNCTYPE(LRESULT, ctypes.c_int, WPARAM, LPARAM)

user32.SetWindowsHookExW.argtypes = [wintypes.INT, HOOKPROC, wintypes.HINSTANCE, wintypes.DWORD]
user32.SetWindowsHookExW.restype = wintypes.HHOOK

user32.UnhookWindowsHookEx.argtypes = [wintypes.HHOOK]
user32.UnhookWindowsHookEx.restype = wintypes.BOOL

user32.CallNextHookEx.argtypes = [wintypes.HHOOK, ctypes.c_int, WPARAM, LPARAM]
user32.CallNextHookEx.restype = LRESULT

user32.GetKeyState.argtypes = [wintypes.INT]
user32.GetKeyState.restype = wintypes.SHORT
user32.GetAsyncKeyState.argtypes = [wintypes.INT]
user32.GetAsyncKeyState.restype = wintypes.SHORT


class MSG(ctypes.Structure):
    _fields_ = [
        ("hwnd", wintypes.HWND),
        ("message", wintypes.UINT),
        ("wParam", wintypes.WPARAM),
        ("lParam", wintypes.LPARAM),
        ("time", wintypes.DWORD),
        ("pt", wintypes.POINT),
    ]


user32.PeekMessageW.argtypes = [ctypes.POINTER(MSG), wintypes.HWND, wintypes.UINT, wintypes.UINT, wintypes.UINT]
user32.PeekMessageW.restype = wintypes.BOOL

PM_REMOVE = 0x0001


# =========================
# Light patterns (L1 only)
# =========================
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
URL_RE = re.compile(r"\bhttps?://\S+|\bwww\.\S+", re.IGNORECASE)
CC_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")  # rough hint only
CRED_KW_RE = re.compile(r"(?i)\b(password|passwd|pwd|token|apikey|api_key|secret|bearer)\b")
JSON_HINT_RE = re.compile(r"^\s*[\{\[]")
BASE64_HINT_RE = re.compile(r"^[A-Za-z0-9+/=\r\n]{80,}$")

DOMAIN_RE = re.compile(
    r"\b(?:https?://)?(?:www\.)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(?:[:/ ]|$)",
    re.IGNORECASE,
)

KNOWN_TITLE_DOMAIN_HINTS = {
    "chatgpt": "chatgpt.com",
    "openai": "chat.openai.com",
    "claude": "claude.ai",
    "gemini": "gemini.google.com",
    "bard": "bard.google.com",
    "perplexity": "perplexity.ai",
    "copilot": "copilot.microsoft.com",
    "gmail": "mail.google.com",
    "outlook": "outlook.office.com",
    "google drive": "drive.google.com",
    "drive": "drive.google.com",
    "dropbox": "dropbox.com",
    "onedrive": "onedrive.live.com",
    "discord": "discord.com",
    "slack": "slack.com",
    "teams": "teams.microsoft.com",
    "telegram": "web.telegram.org",
    "whatsapp": "web.whatsapp.com",
    "zalo": "chat.zalo.me",
    "facebook": "facebook.com",
    "messenger": "messenger.com",
    "instagram": "instagram.com",
    "linkedin": "linkedin.com",
    "reddit": "reddit.com",
    "x": "x.com",
    "twitter": "twitter.com",
    "tiktok": "tiktok.com",
    "pastebin": "pastebin.com",
    "github gist": "gist.github.com",
    "gitlab": "gitlab.com",
    "bitbucket": "bitbucket.org",
    "replit": "replit.com",
}

_BROWSER_EXES = {
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
    "brave.exe",
    "opera.exe",
    "vivaldi.exe",
    "iexplore.exe",
}

_MESSAGING_EXES = {
    "teams.exe",
    "slack.exe",
    "discord.exe",
    "telegram.exe",
    "whatsapp.exe",
    "line.exe",
    "signal.exe",
    "skype.exe",
    "zalo.exe",
    "outlook.exe",
}


# =========================
# Utils
# =========================
def _sha256_text(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", errors="ignore")).hexdigest()


def _safe_preview(s: str, n: int) -> str:
    s = s.replace("\r", "").replace("\t", " ")
    s = re.sub(r"\s+", " ", s).strip()
    return s[:n]


def _entropy_text(s: str) -> float:
    if not s:
        return 0.0
    from math import log2

    freq: Dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    ent = 0.0
    for c in freq.values():
        p = c / n
        ent -= p * log2(p)
    return float(ent)


def _mk_ioc_hits(text: str) -> List[Dict[str, str]]:
    hits: List[Dict[str, str]] = []
    m = EMAIL_RE.search(text)
    if m:
        hits.append({"tag": "email", "match": m.group(0)[:120]})
    m = URL_RE.search(text)
    if m:
        hits.append({"tag": "url", "match": m.group(0)[:200]})
    if CC_RE.search(text):
        hits.append({"tag": "possible_cc", "match": "digits_13_19"})
    m = CRED_KW_RE.search(text)
    if m:
        hits.append({"tag": "credential_keyword", "match": m.group(0).lower()})
    return hits


def _infer_text_signature(text: str) -> str:
    t = text.strip()
    if not t:
        return "empty"
    if URL_RE.search(t):
        return "looks_like_url"
    if EMAIL_RE.search(t):
        return "looks_like_email"
    if JSON_HINT_RE.match(t):
        return "looks_like_json"
    if BASE64_HINT_RE.match(t) and len(t) >= 120:
        return "looks_like_base64"
    if CC_RE.search(t):
        return "looks_like_digits_13_19"
    return "plain_text"


def _classify_sensitivity(text: str, entropy: Optional[float], ioc_hits: List[Dict[str, str]]) -> str:
    L = len(text)
    tags = {h.get("tag") for h in ioc_hits}

    if "credential_keyword" in tags and L >= 30:
        return "Highly Sensitive"
    if "possible_cc" in tags and L >= 60:
        return "Highly Sensitive"
    if entropy is not None and entropy >= 4.3 and L >= 80:
        return "Highly Sensitive"

    if "email" in tags or "url" in tags:
        return "Sensitive"
    if entropy is not None and entropy >= 3.7 and L >= 60:
        return "Sensitive"
    if L >= 500:
        return "Sensitive"

    return "Normal"


def _severity_from_sensitivity(s: str) -> str:
    if s == "Highly Sensitive":
        return "high"
    if s == "Sensitive":
        return "warn"
    return "info"


def _utc_iso(ts_unix: float) -> str:
    from datetime import datetime, timezone

    return datetime.fromtimestamp(ts_unix, tz=timezone.utc).isoformat()


def _norm_path(p: str) -> str:
    try:
        p2 = os.path.expandvars(os.path.expanduser(p))
        return str(os.path.normpath(p2))
    except Exception:
        return p


def _safe_lower(v: Any) -> str:
    try:
        return str(v or "").strip().lower()
    except Exception:
        return ""


def _coalesce_str(*vals: Any) -> Optional[str]:
    for v in vals:
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None


def _coalesce_int(*vals: Any) -> Optional[int]:
    for v in vals:
        try:
            if v is None or v == "":
                continue
            return int(v)
        except Exception:
            continue
    return None


def _extract_domain_from_text(s: str) -> Optional[str]:
    if not s:
        return None
    m = DOMAIN_RE.search(s)
    if m:
        return m.group(1).lower()

    low = s.lower()
    for k, v in KNOWN_TITLE_DOMAIN_HINTS.items():
        if k in low:
            return v
    return None


def _basename_lower(path_or_name: Optional[str]) -> Optional[str]:
    if not path_or_name:
        return None
    try:
        return os.path.basename(path_or_name).lower()
    except Exception:
        return str(path_or_name).lower()


def _get_window_text(hwnd: int) -> str:
    if not hwnd:
        return ""
    try:
        length = int(user32.GetWindowTextLengthW(hwnd) or 0)
        if length <= 0:
            return ""
        buf = ctypes.create_unicode_buffer(length + 1)
        n = int(user32.GetWindowTextW(hwnd, buf, length + 1) or 0)
        if n <= 0:
            return ""
        return buf.value.strip()
    except Exception:
        return ""


def _query_process_image(handle: int) -> str:
    try:
        size = wintypes.DWORD(32768)
        buf = ctypes.create_unicode_buffer(size.value)
        ok = kernel32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size))
        if ok:
            return buf.value
    except Exception:
        pass
    return ""


def _query_process_basename(handle: int) -> str:
    try:
        buf = ctypes.create_unicode_buffer(1024)
        n = int(psapi.GetModuleBaseNameW(handle, None, buf, 1024) or 0)
        if n > 0:
            return buf.value
    except Exception:
        pass
    return ""


def _get_foreground_process_info() -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "hwnd": None,
        "window_title": None,
        "fg_pid": None,
        "fg_process": None,
        "fg_app": None,
        "fg_exe_path": None,
        "fg_cmdline": None,  # not reliably available here
    }

    hwnd = user32.GetForegroundWindow()
    if not hwnd:
        return out

    out["hwnd"] = int(hwnd)
    out["window_title"] = _get_window_text(hwnd) or None

    pid = wintypes.DWORD(0)
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    pid_int = int(pid.value or 0)
    if pid_int <= 0:
        return out

    out["fg_pid"] = pid_int

    access = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ
    hproc = kernel32.OpenProcess(access, False, pid_int)
    if not hproc:
        return out

    try:
        full_path = _query_process_image(hproc) or ""
        base_name = _query_process_basename(hproc) or ""
        exe_name = _basename_lower(full_path) or _basename_lower(base_name)

        out["fg_exe_path"] = full_path or None
        out["fg_process"] = exe_name or None
        out["fg_app"] = exe_name or None
    finally:
        try:
            kernel32.CloseHandle(hproc)
        except Exception:
            pass

    return out


# =========================
# Clipboard read (robust)
# =========================
def _open_clipboard_retry(timeout_ms: int = 120) -> Optional[int]:
    deadline = time.time() + (timeout_ms / 1000.0)
    last_err: Optional[int] = None
    while time.time() < deadline:
        if user32.OpenClipboard(None):
            return None
        last_err = ctypes.get_last_error()
        time.sleep(0.005)
    return last_err


def _read_clipboard_text(timeout_ms: int = 120) -> Tuple[Optional[str], Optional[int]]:
    err = _open_clipboard_retry(timeout_ms=timeout_ms)
    if err is not None:
        return None, err
    try:
        if not user32.IsClipboardFormatAvailable(CF_UNICODETEXT):
            return None, 0

        handle = user32.GetClipboardData(CF_UNICODETEXT)
        if not handle:
            return None, ctypes.get_last_error()

        ptr = kernel32.GlobalLock(handle)
        if not ptr:
            return None, ctypes.get_last_error()

        try:
            return ctypes.wstring_at(ptr), None
        finally:
            kernel32.GlobalUnlock(handle)
    finally:
        user32.CloseClipboard()


def _read_clipboard_file_list(timeout_ms: int = 120, max_files: int = 50) -> Tuple[Optional[List[str]], Optional[int]]:
    err = _open_clipboard_retry(timeout_ms=timeout_ms)
    if err is not None:
        return None, err
    try:
        if not user32.IsClipboardFormatAvailable(CF_HDROP):
            return None, 0

        hdrop = user32.GetClipboardData(CF_HDROP)
        if not hdrop:
            return None, ctypes.get_last_error()

        count = int(shell32.DragQueryFileW(hdrop, 0xFFFFFFFF, None, 0))
        count = min(count, max_files)

        out: List[str] = []
        for i in range(count):
            n = int(shell32.DragQueryFileW(hdrop, i, None, 0))
            if n <= 0:
                continue
            buf = ctypes.create_unicode_buffer(n + 1)
            shell32.DragQueryFileW(hdrop, i, buf, n + 1)
            out.append(_norm_path(buf.value))
        return out, None
    finally:
        user32.CloseClipboard()


# =========================
# Screenshot helpers (Clipboard Image)
# =========================
def _read_clipboard_image_pil():
    """
    Kiểm tra clipboard có chứa ảnh không và trả về PIL.Image object.
    Dùng ImageGrab.grabclipboard() của Pillow — đơn giản và đáng tin cậy trên Windows.
    Trả về (Image | None, err_str | None)
    """
    try:
        from PIL import ImageGrab
        img = ImageGrab.grabclipboard()
        if img is None:
            return None, None  # clipboard không có ảnh
        # grabclipboard() có thể trả về list[str] (file list) — bỏ qua
        from PIL import Image
        if isinstance(img, list):
            return None, None
        if not isinstance(img, Image.Image):
            return None, None
        return img, None
    except ImportError:
        return None, "Pillow not installed"
    except Exception as e:
        return None, str(e)


def _get_screenshot_dir() -> Optional[str]:
    """Lấy thư mục lưu screenshot từ WorkerConfig (dynamic, machine-independent)."""
    try:
        import sys as _sys
        from pathlib import Path as _Path
        # Worker config shares the same base path
        _agent_dir = _Path(__file__).parent.parent
        _screenshot_dir = _agent_dir / "runtime" / "screenshots"
        _screenshot_dir.mkdir(parents=True, exist_ok=True)
        return str(_screenshot_dir)
    except Exception:
        # Fallback: same dir as this file
        try:
            import tempfile
            return tempfile.gettempdir()
        except Exception:
            return None


def _save_screenshot(img) -> Optional[str]:
    """
    Lưu ảnh từ PIL.Image vào thư mục screenshots.
    Trả về đường dẫn file đã lưu hoặc None nếu thất bại.
    """
    try:
        import uuid as _uuid
        from pathlib import Path as _Path
        scr_dir = _get_screenshot_dir()
        if not scr_dir:
            return None
        filename = f"screenshot_{_uuid.uuid4().hex[:12]}.png"
        file_path = str(_Path(scr_dir) / filename)
        img.save(file_path, format="PNG")
        return file_path
    except Exception:
        return None


# =========================
# Sensor
# =========================
class ClipboardSensor:
    """
    L1 Clipboard Sensor (text + file-list aware)

    Emits:
      - clipboard_copy : when clipboard content changes
      - clipboard_paste: when paste hotkeys detected (best-effort)

    Fixes included:
      - enrich foreground context even when ctx_provider is sparse/null
      - fill clipboard dest/source fields with WinAPI fallback
      - infer dest_domain from context/window title where possible
      - keep canonical fields used by worker rules
    """

    def __init__(
        self,
        queue_manager,
        poll_interval_sec: float = 0.15,
        min_len: int = 1,
        max_capture_len: int = 20000,
        preview_len: int = 120,
        cooldown_sec: float = 0.10,
        ignore_exact: Optional[Set[str]] = None,
        source: str = "clipboard",
        window_sec: float = 60.0,
        enable_text_file: bool = True,
        text_file_max_chars: int = 1200,
        bulk_paste_chars: int = 3000,
        hotkey_link_window_sec: float = 0.5,
        max_files: int = 50,
        paste_attach_last: bool = True,
    ):
        self.qm = queue_manager
        self.poll_interval_sec = float(poll_interval_sec)
        self.min_len = int(min_len)
        self.max_capture_len = int(max_capture_len)
        self.preview_len = int(preview_len)
        self.cooldown_sec = float(cooldown_sec)
        self.source = str(source)

        self.window_sec = float(window_sec)
        self.enable_text_file = bool(enable_text_file)
        self.text_file_max_chars = int(text_file_max_chars)
        self.bulk_paste_chars = int(bulk_paste_chars)
        self.hotkey_link_window_sec = float(hotkey_link_window_sec)

        self.max_files = int(max_files)
        self.paste_attach_last = bool(paste_attach_last)

        self.ignore_exact = set(x.strip().lower() for x in (ignore_exact or set()))
        self.ignore_exact.update({"ok", "oke", "done", "copy", "paste", "test", "123", "1234", "12345"})

        self._last_seq = int(user32.GetClipboardSequenceNumber() or 0)
        self._last_emit_ts = 0.0
        self._last_hash: Optional[str] = None

        self._copy_ts: Deque[float] = deque(maxlen=10000)
        self._paste_ts: Deque[float] = deque(maxlen=10000)
        self._total_volume_window: Deque[Tuple[float, int]] = deque(maxlen=20000)

        self._last_copy_snapshot: Dict[str, Any] = {}

        self._lock = threading.Lock()
        self._paste_requested: bool = False
        self._last_hotkey_copy_ts: float = 0.0
        self._last_hotkey_cut_ts: float = 0.0

        self._hook_thread: Optional[threading.Thread] = None
        self._hook_h: Optional[int] = None
        self._hook_ready: bool = False
        self._hook_stop = threading.Event()
        self._kbd_proc: Optional[Any] = None
        self._fallback_prev_ctrl_v: bool = False
        self._fallback_prev_shift_insert: bool = False

        self._last_err_emit = 0.0

    # ---------- helpers ----------
    def _emit(self, evt: Dict[str, Any]) -> None:
        try:
            self.qm.enqueue_event(evt)
        except Exception:
            pass

    def _merge_context(self, base: Dict[str, Any], overlay: Dict[str, Any]) -> Dict[str, Any]:
        out = dict(base or {})
        for k, v in (overlay or {}).items():
            if k not in out or out.get(k) in (None, "", 0):
                out[k] = v
        return out

    def _ctx_snapshot(self, ctx_provider: Optional[Any]) -> Dict[str, Any]:
        ctx: Dict[str, Any] = {}
        if ctx_provider:
            try:
                if hasattr(ctx_provider, "snapshot"):
                    got = ctx_provider.snapshot() or {}
                    if isinstance(got, dict):
                        ctx = got
            except Exception:
                ctx = {}

        # WinAPI fallback / enrichment
        fg = _get_foreground_process_info()

        enriched = dict(ctx)
        enriched = self._merge_context(enriched, fg)

        # Normalize aliases so downstream rules do not see nulls
        fg_proc = _coalesce_str(
            enriched.get("fg_process"),
            enriched.get("fg_app"),
            enriched.get("process"),
            enriched.get("app"),
        )
        fg_app = _coalesce_str(
            enriched.get("fg_app"),
            enriched.get("fg_process"),
            enriched.get("app"),
            enriched.get("process"),
        )
        window_title = _coalesce_str(
            enriched.get("window_title"),
            enriched.get("title"),
            enriched.get("active_window_title"),
        )
        fg_pid = _coalesce_int(
            enriched.get("fg_pid"),
            enriched.get("pid"),
        )

        enriched["fg_process"] = fg_proc
        enriched["fg_app"] = fg_app
        enriched["window_title"] = window_title
        enriched["fg_pid"] = fg_pid

        # best-effort dest domain
        dest_domain = self._infer_dest_domain_from_ctx(enriched)
        if dest_domain:
            enriched["dest_domain"] = dest_domain
            enriched["domain"] = enriched.get("domain") or dest_domain

        return enriched

    def _trim_window(self, dq: Deque[float], now: float) -> None:
        cutoff = now - self.window_sec
        while dq and dq[0] < cutoff:
            dq.popleft()

    def _trim_volume(self, now: float) -> int:
        cutoff = now - self.window_sec
        while self._total_volume_window and self._total_volume_window[0][0] < cutoff:
            self._total_volume_window.popleft()
        return sum(v for _, v in self._total_volume_window)

    def _emit_error(self, msg: str, ctx: Dict[str, Any], extra: Optional[Dict[str, Any]] = None) -> None:
        now = time.time()
        if now - self._last_err_emit < 3.0:
            return
        self._last_err_emit = now

        evt: Dict[str, Any] = {
            "type": "clipboard_sensor_error",
            "source": self.source,
            "severity": "warn",
            "ts": _utc_iso(now),
            "timestamp": _utc_iso(now),
            "context": ctx,
            "actor": self._actor_from_ctx(ctx),
            "operation": {
                "op_type": "control",
                "tool": (ctx.get("fg_app") or ctx.get("fg_process") or "clipboard"),
            },
            "message": msg[:500],
        }
        if extra:
            evt["extra"] = extra
        self._emit(evt)

    def _calc_freq(self, dq: Deque[float], now: float) -> Optional[str]:
        self._trim_window(dq, now)
        if self.window_sec <= 0:
            return None
        per_min = (len(dq) / self.window_sec) * 60.0
        return f"{per_min:.2f}/min"

    def _calc_freq_value(self, dq: Deque[float], now: float) -> Optional[float]:
        self._trim_window(dq, now)
        if self.window_sec <= 0:
            return None
        return float((len(dq) / self.window_sec) * 60.0)

    def _severity_for_paste(self, snap: Dict[str, Any], bulk_paste: bool) -> str:
        sens = snap.get("sensitivity") or "Normal"
        if sens == "Highly Sensitive":
            return "high"
        if sens == "Sensitive":
            return "warn"
        if bulk_paste:
            return "warn"
        return "info"

    def _infer_dest_domain_from_ctx(self, ctx: Dict[str, Any]) -> Optional[str]:
        # direct structured fields first
        for k in ("dest_domain", "domain", "url_domain", "host", "website_domain"):
            v = ctx.get(k)
            if isinstance(v, str) and v.strip():
                return v.strip().lower()

        # try URL-like fields if any
        for k in ("url", "page_url", "active_url", "website", "address"):
            v = ctx.get(k)
            if isinstance(v, str) and v.strip():
                domain = _extract_domain_from_text(v)
                if domain:
                    return domain

        # try title/window title
        for k in ("window_title", "title", "active_window_title"):
            v = ctx.get(k)
            if isinstance(v, str) and v.strip():
                domain = _extract_domain_from_text(v)
                if domain:
                    return domain

        return None

    def _actor_from_ctx(self, ctx: Dict[str, Any]) -> Dict[str, Any]:
        process_name = _coalesce_str(
            ctx.get("fg_process"),
            ctx.get("fg_app"),
            ctx.get("process"),
            ctx.get("app"),
        )
        return {
            "user": ctx.get("user"),
            "pid": _coalesce_int(ctx.get("fg_pid"), ctx.get("pid")),
            "process": process_name,
            "cmdline": _coalesce_str(ctx.get("fg_cmdline"), ctx.get("cmdline")),
            "exe_path": _coalesce_str(ctx.get("fg_exe_path"), ctx.get("exe_path")),
        }

    def _object_from_snapshot(self, snap: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "path": None,
            "dst_path": None,
            "drive": None,
            "volume_type": None,
            "sensitivity": snap.get("sensitivity"),
        }

    def _typed_hash(self, kind: str, content_hash: Optional[str]) -> Optional[str]:
        if not content_hash:
            return None
        return f"{kind}:{content_hash}"

    def _build_context_for_event(self, ctx: Dict[str, Any], dest_domain: Optional[str]) -> Dict[str, Any]:
        out = dict(ctx or {})
        out["fg_app"] = _coalesce_str(out.get("fg_app"), out.get("fg_process"))
        out["fg_process"] = _coalesce_str(out.get("fg_process"), out.get("fg_app"))
        out["window_title"] = _coalesce_str(out.get("window_title"), out.get("active_window_title"))
        out["fg_pid"] = _coalesce_int(out.get("fg_pid"), out.get("pid"))
        if dest_domain and not out.get("dest_domain"):
            out["dest_domain"] = dest_domain
        return out

    # =========================
    # Keyboard hook
    # =========================
    def _poll_paste_hotkey_fallback(self) -> None:
        """
        Fallback detector for paste hotkeys when low-level keyboard hook is unavailable.
        Detects key DOWN edge for Ctrl+V and Shift+Insert.
        """
        try:
            ctrl_down = bool(user32.GetAsyncKeyState(VK_CONTROL) & 0x8000)
            shift_down = bool(user32.GetAsyncKeyState(VK_SHIFT) & 0x8000)
            v_down = bool(user32.GetAsyncKeyState(VK_V) & 0x8000)
            ins_down = bool(user32.GetAsyncKeyState(VK_INSERT) & 0x8000)

            now_ctrl_v = bool(ctrl_down and v_down)
            now_shift_insert = bool(shift_down and ins_down)

            if (now_ctrl_v and not self._fallback_prev_ctrl_v) or (
                now_shift_insert and not self._fallback_prev_shift_insert
            ):
                with self._lock:
                    self._paste_requested = True

            self._fallback_prev_ctrl_v = now_ctrl_v
            self._fallback_prev_shift_insert = now_shift_insert
        except Exception:
            pass

    def _start_hook(self) -> None:
        if self._hook_thread and self._hook_thread.is_alive():
            return
        self._hook_stop.clear()
        t = threading.Thread(target=self._hook_loop, name="clipboard_kbd_hook", daemon=True)
        self._hook_thread = t
        t.start()

    def _hook_loop(self) -> None:
        @HOOKPROC
        def _proc(nCode, wParam, lParam):
            try:
                if nCode == 0 and (wParam == WM_KEYDOWN or wParam == WM_SYSKEYDOWN):
                    kb = ctypes.cast(lParam, LPKBDLLHOOKSTRUCT).contents
                    vk = int(kb.vkCode)

                    ctrl_down = bool(user32.GetKeyState(VK_CONTROL) & 0x8000)
                    shift_down = bool(user32.GetKeyState(VK_SHIFT) & 0x8000)
                    now = time.time()

                    with self._lock:
                        if (ctrl_down and vk == VK_V) or (shift_down and vk == VK_INSERT):
                            self._paste_requested = True

                        if (ctrl_down and vk == VK_C) or (ctrl_down and vk == VK_INSERT):
                            self._last_hotkey_copy_ts = now

                        if (ctrl_down and vk == VK_X) or (shift_down and vk == VK_DELETE):
                            self._last_hotkey_cut_ts = now
            except Exception:
                pass

            return user32.CallNextHookEx(self._hook_h or 0, nCode, wParam, lParam)

        self._kbd_proc = _proc

        hmod = kernel32.GetModuleHandleW(None)
        hhook = user32.SetWindowsHookExW(WH_KEYBOARD_LL, self._kbd_proc, hmod, 0)
        self._hook_h = int(hhook) if hhook else None
        self._hook_ready = bool(self._hook_h)
        if not self._hook_ready:
            return

        msg = MSG()
        while not self._hook_stop.is_set():
            user32.PeekMessageW(ctypes.byref(msg), None, 0, 0, PM_REMOVE)
            time.sleep(0.01)

        if self._hook_h:
            try:
                user32.UnhookWindowsHookEx(self._hook_h)
            except Exception:
                pass
        self._hook_h = None

    # =========================
    # Snapshot builders
    # =========================
    def _make_snapshot_from_text(self, ctx: Dict[str, Any], now: float, event_type: str, text: str) -> Dict[str, Any]:
        text = text.strip()
        if len(text) > self.max_capture_len:
            text = text[: self.max_capture_len]

        content_len = len(text)
        self._total_volume_window.append((now, int(content_len * 2)))
        total_vol = self._trim_volume(now)

        try:
            entropy = _entropy_text(text[:4096])
        except Exception:
            entropy = None

        ioc_hits = _mk_ioc_hits(text)
        signature = _infer_text_signature(text)
        sensitivity = _classify_sensitivity(text, entropy, ioc_hits)

        sample = _safe_preview(text, self.preview_len) if self.preview_len > 0 else None
        sample_len = len(sample) if sample is not None else None
        text_file = text[: self.text_file_max_chars] if self.enable_text_file else None

        copy_freq = self._calc_freq(self._copy_ts, now)
        copy_freq_value = self._calc_freq_value(self._copy_ts, now)

        return {
            "copy_ts": _utc_iso(now),
            "content_hash": _sha256_text(text),
            "content_len": content_len,
            "content_type": "Text",
            "entropy": entropy,
            "ioc_hits": ioc_hits,
            "sample": sample,
            "sample_len": sample_len,
            "text_file": text_file,
            "content": text_file,
            "files": None,
            "source_app": _coalesce_str(ctx.get("fg_app"), ctx.get("fg_process")),
            "source_process": _coalesce_str(ctx.get("fg_process"), ctx.get("fg_app")),
            "source_window_title": _coalesce_str(ctx.get("window_title")),
            "copy_frequency": copy_freq,
            "copy_frequency_value": copy_freq_value,
            "copy_frequency_window_sec": self.window_sec,
            "total_volume": total_vol,
            "original_format": "Plain Text",
            "converted_format": "Plain Text",
            "sensitivity": sensitivity,
            "signature": signature,
            "event_type": event_type,
        }

    def _make_snapshot_from_files(self, ctx: Dict[str, Any], now: float, event_type: str, files: List[str]) -> Dict[str, Any]:
        files = [f for f in files if f]
        joined = "\n".join(files[: self.max_files])
        content_hash = _sha256_text(joined)

        content_len = len(files)
        self._total_volume_window.append((now, int(len(joined) * 2)))
        total_vol = self._trim_volume(now)

        sensitivity = "Sensitive" if len(files) >= 1 else "Normal"
        ioc_hits: List[Dict[str, str]] = []
        sample = _safe_preview(joined, self.preview_len) if self.preview_len > 0 else None
        sample_len = len(sample) if sample is not None else None

        copy_freq = self._calc_freq(self._copy_ts, now)
        copy_freq_value = self._calc_freq_value(self._copy_ts, now)

        return {
            "copy_ts": _utc_iso(now),
            "content_hash": content_hash,
            "content_len": content_len,
            "content_type": "FileList",
            "entropy": None,
            "ioc_hits": ioc_hits,
            "sample": sample,
            "sample_len": sample_len,
            "text_file": None,
            "content": None,
            "files": files[: self.max_files],
            "source_app": _coalesce_str(ctx.get("fg_app"), ctx.get("fg_process")),
            "source_process": _coalesce_str(ctx.get("fg_process"), ctx.get("fg_app")),
            "source_window_title": _coalesce_str(ctx.get("window_title")),
            "copy_frequency": copy_freq,
            "copy_frequency_value": copy_freq_value,
            "copy_frequency_window_sec": self.window_sec,
            "total_volume": total_vol,
            "original_format": "File Drop List",
            "converted_format": "File Drop List",
            "sensitivity": sensitivity,
            "signature": "cf_hdrop_file_list",
            "event_type": event_type,
        }

    # =========================
    # Event builders
    # =========================
    def _build_copy_event(self, ctx: Dict[str, Any], now: float, event_type: str, snap: Dict[str, Any]) -> Dict[str, Any]:
        file_count = len(snap.get("files") or []) if snap.get("content_type") == "FileList" else None
        dest_domain = self._infer_dest_domain_from_ctx(ctx)
        norm_ctx = self._build_context_for_event(ctx, dest_domain)

        source_app = _coalesce_str(snap.get("source_app"), norm_ctx.get("fg_app"), norm_ctx.get("fg_process"))
        source_process = _coalesce_str(snap.get("source_process"), norm_ctx.get("fg_process"), norm_ctx.get("fg_app"))
        source_window_title = _coalesce_str(snap.get("source_window_title"), norm_ctx.get("window_title"))

        evt = {
            "type": "clipboard_copy",
            "source": self.source,
            "severity": _severity_from_sensitivity(snap.get("sensitivity") or "Normal"),
            "ts": _utc_iso(now),
            "timestamp": _utc_iso(now),
            "context": norm_ctx,
            "actor": self._actor_from_ctx(norm_ctx),
            "operation": {
                "op_type": "clipboard_copy",
                "tool": _coalesce_str(norm_ctx.get("fg_app"), norm_ctx.get("fg_process"), "clipboard"),
            },
            "object": self._object_from_snapshot(snap),
            "ioc_hits": snap.get("ioc_hits") or [],
            "clipboard": {
                "event_type": event_type,
                "clipboard_id": str(uuid.uuid4()),
                "copy_ts": snap.get("copy_ts"),
                "paste_ts": None,
                "content_hash": snap.get("content_hash"),
                "content_len": snap.get("content_len"),
                "text_len": snap.get("content_len") if snap.get("content_type") == "Text" else None,
                "content_type": snap.get("content_type"),
                "source_app": source_app,
                "source_process": source_process,
                "source_window_title": source_window_title,
                "dest_app": _coalesce_str(norm_ctx.get("fg_app"), norm_ctx.get("fg_process")),
                "dest_process": _coalesce_str(norm_ctx.get("fg_process"), norm_ctx.get("fg_app")),
                "active_window_title": _coalesce_str(norm_ctx.get("window_title")),
                "dest_window_title": _coalesce_str(norm_ctx.get("window_title")),
                "dest_domain": dest_domain,
                "window_process_name": _coalesce_str(norm_ctx.get("fg_process"), norm_ctx.get("fg_app")),
                "snapshot_linked": True,
                "copy_frequency": snap.get("copy_frequency"),
                "copy_frequency_value": snap.get("copy_frequency_value"),
                "copy_frequency_window_sec": snap.get("copy_frequency_window_sec"),
                "paste_frequency": None,
                "paste_frequency_value": None,
                "paste_frequency_window_sec": self.window_sec,
                "total_volume": snap.get("total_volume"),
                "bulk_paste_event": False,
                "original_format": snap.get("original_format"),
                "converted_format": snap.get("converted_format"),
                "text_file": snap.get("text_file"),
                "content": snap.get("content"),
                "file_list": snap.get("files"),
                "file_count": file_count,
                "signature": snap.get("signature"),
            },
            "metrics": {
                "file_count": file_count,
                "row_count": None,
                "entropy": snap.get("entropy"),
            },
            "flags": {"password_protected": None},
            "content": {
                "sample": snap.get("sample"),
                "sample_len": snap.get("sample_len"),
            },
        }
        return evt

    def _build_paste_event(self, ctx: Dict[str, Any], now: float, snap: Dict[str, Any]) -> Dict[str, Any]:
        ctype = snap.get("content_type") or "Unknown"
        bulk_paste = False
        if ctype == "Text":
            L = snap.get("content_len")
            bulk_paste = bool(isinstance(L, int) and L >= self.bulk_paste_chars)
        elif ctype == "FileList":
            L = snap.get("content_len")
            bulk_paste = bool(isinstance(L, int) and L >= 10)

        file_count = len(snap.get("files") or []) if ctype == "FileList" else None
        paste_freq = self._calc_freq(self._paste_ts, now)
        paste_freq_value = self._calc_freq_value(self._paste_ts, now)
        dest_domain = self._infer_dest_domain_from_ctx(ctx)
        norm_ctx = self._build_context_for_event(ctx, dest_domain)

        snapshot_linked = bool(snap and snap.get("copy_ts") and snap.get("content_hash"))
        source_app = _coalesce_str(snap.get("source_app"))
        source_process = _coalesce_str(snap.get("source_process"))
        source_window_title = _coalesce_str(snap.get("source_window_title"))

        dest_app = _coalesce_str(norm_ctx.get("fg_app"), norm_ctx.get("fg_process"))
        dest_process = _coalesce_str(norm_ctx.get("fg_process"), norm_ctx.get("fg_app"))
        dest_window_title = _coalesce_str(norm_ctx.get("window_title"))

        evt = {
            "type": "clipboard_paste",
            "source": self.source,
            "severity": self._severity_for_paste(snap, bulk_paste),
            "ts": _utc_iso(now),
            "timestamp": _utc_iso(now),
            "context": norm_ctx,
            "actor": self._actor_from_ctx(norm_ctx),
            "operation": {
                "op_type": "clipboard_paste",
                "tool": _coalesce_str(dest_app, dest_process, "clipboard"),
            },
            "object": self._object_from_snapshot(snap),
            "ioc_hits": snap.get("ioc_hits") or [],
            "clipboard": {
                "event_type": "Paste",
                "copy_ts": snap.get("copy_ts"),
                "paste_ts": _utc_iso(now),
                "content_hash": snap.get("content_hash"),
                "content_len": snap.get("content_len"),
                "text_len": snap.get("content_len") if ctype == "Text" else None,
                "content_type": ctype,
                "source_app": source_app,
                "source_process": source_process,
                "source_window_title": source_window_title,
                "dest_app": dest_app,
                "dest_process": dest_process,
                "active_window_title": dest_window_title,
                "dest_window_title": dest_window_title,
                "dest_domain": dest_domain,
                "window_process_name": dest_process or dest_app,
                "snapshot_linked": snapshot_linked,
                "copy_frequency": snap.get("copy_frequency"),
                "copy_frequency_value": snap.get("copy_frequency_value"),
                "copy_frequency_window_sec": snap.get("copy_frequency_window_sec"),
                "paste_frequency": paste_freq,
                "paste_frequency_value": paste_freq_value,
                "paste_frequency_window_sec": self.window_sec,
                "total_volume": snap.get("total_volume"),
                "bulk_paste_event": bulk_paste,
                "original_format": snap.get("original_format"),
                "converted_format": snap.get("converted_format"),
                "text_file": snap.get("text_file"),
                "content": snap.get("content"),
                "file_list": snap.get("files"),
                "file_count": file_count,
                "signature": snap.get("signature"),
            },
            "metrics": {
                "file_count": file_count,
                "row_count": None,
                "entropy": snap.get("entropy"),
            },
            "flags": {"password_protected": None},
            "content": {
                "sample": snap.get("sample"),
                "sample_len": snap.get("sample_len"),
            },
        }
        return evt

    # =========================
    # Main run loop
    # =========================
    def run_loop(self, stop_event, ctx_provider: Optional[Any] = None) -> None:
        try:
            self._start_hook()
        except Exception:
            pass

        while not stop_event.is_set():
            now = time.time()
            ctx = self._ctx_snapshot(ctx_provider)

            try:
                # fallback key polling helps when WH_KEYBOARD_LL cannot be installed
                self._poll_paste_hotkey_fallback()

                # ---------- paste inference ----------
                paste_req = False
                with self._lock:
                    if self._paste_requested:
                        paste_req = True
                        self._paste_requested = False

                if paste_req:
                    # refresh context again at paste time for most accurate dest window/process
                    paste_ctx = self._ctx_snapshot(ctx_provider)

                    self._paste_ts.append(now)
                    self._trim_window(self._paste_ts, now)

                    snap = dict(self._last_copy_snapshot) if (
                        self.paste_attach_last and isinstance(self._last_copy_snapshot, dict)
                    ) else {}

                    evt_paste = self._build_paste_event(paste_ctx, now, snap)
                    self._emit(evt_paste)

                # ---------- clipboard change detection ----------
                seq = int(user32.GetClipboardSequenceNumber() or 0)
                if seq == self._last_seq:
                    time.sleep(self.poll_interval_sec)
                    continue
                self._last_seq = seq

                if (now - self._last_emit_ts) < self.cooldown_sec:
                    time.sleep(self.poll_interval_sec)
                    continue

                # refresh context again right when sequence changes
                copy_ctx = self._ctx_snapshot(ctx_provider)

                event_type = "Copy"
                with self._lock:
                    if (now - self._last_hotkey_cut_ts) <= self.hotkey_link_window_sec:
                        event_type = "Cut"
                    elif (now - self._last_hotkey_copy_ts) <= self.hotkey_link_window_sec:
                        event_type = "Copy"

                # Try file-list first
                files, ferr = _read_clipboard_file_list(timeout_ms=120, max_files=self.max_files)
                if files is not None and ferr is None:
                    if not files:
                        time.sleep(self.poll_interval_sec)
                        continue

                    snap = self._make_snapshot_from_files(copy_ctx, now, event_type, files)
                    typed_hash = self._typed_hash("files", snap.get("content_hash"))
                    if typed_hash == self._last_hash:
                        time.sleep(self.poll_interval_sec)
                        continue

                    self._copy_ts.append(now)
                    self._trim_window(self._copy_ts, now)

                    self._last_copy_snapshot = snap
                    self._last_hash = typed_hash

                    evt_copy = self._build_copy_event(copy_ctx, now, event_type, snap)
                    self._emit(evt_copy)
                    self._last_emit_ts = now
                    time.sleep(self.poll_interval_sec)
                    continue

                # ---- screenshot (bitmap image in clipboard) ----
                # Phát hiện ảnh trong clipboard (Snipping Tool / PrtSc / Win+Shift+S)
                _img, _img_err = _read_clipboard_image_pil()
                if _img is not None:
                    saved_path = _save_screenshot(_img)
                    if saved_path:
                        # Xác định source (cửa sổ nào đang active khi chụp)
                        _fg = _get_foreground_process_info()
                        _fg_app = _coalesce_str(_fg.get("fg_app"), _fg.get("fg_process")) or "unknown"
                        _win_title = _coalesce_str(_fg.get("window_title")) or ""
                        # Nhận dạng nguồn: Snipping Tool hay PrintScreen
                        _source_hint = "SnippingTool" if any(
                            k in _win_title.lower()
                            for k in ("snip", "snipping", "screenshot", "capture", "snipingtool")
                        ) else "PrintScreen"
                        _scrn_evt: Dict[str, Any] = {
                            "type": "screenshot",
                            "source": self.source,
                            "severity": "info",
                            "ts": _utc_iso(now),
                            "timestamp": _utc_iso(now),
                            "file_path": saved_path,
                            "screenshot": {
                                "file_path": saved_path,
                                "source": _source_hint,
                                "width": _img.width,
                                "height": _img.height,
                            },
                            "context": copy_ctx,
                            "actor": self._actor_from_ctx(copy_ctx),
                            "operation": {
                                "op_type": "screenshot",
                                "tool": _fg_app,
                            },
                        }
                        self._emit(_scrn_evt)
                        self._last_emit_ts = now
                        # Không reset _last_seq — ta vẫn muốn xử lý text nếu có
                        # nhưng tránh emit lại screenshot giống nhau
                        typed_hash_img = self._typed_hash("image", f"{_img.width}x{_img.height}:{_img.tobytes()[:64].hex()}")
                        if typed_hash_img == self._last_hash:
                            time.sleep(self.poll_interval_sec)
                            continue
                        self._last_hash = typed_hash_img
                        time.sleep(self.poll_interval_sec)
                        continue

                # Try text
                text, terr = _read_clipboard_text(timeout_ms=120)
                if text is None:
                    if terr not in (None, 0):
                        self._emit_error("clipboard read failed", copy_ctx, {"win32_last_error": int(terr)})
                    time.sleep(self.poll_interval_sec)
                    continue

                text = text.strip()
                if len(text) < self.min_len:
                    time.sleep(self.poll_interval_sec)
                    continue

                if text.lower() in self.ignore_exact:
                    time.sleep(self.poll_interval_sec)
                    continue

                candidate_hash = _sha256_text(text[: self.max_capture_len])
                typed_hash = self._typed_hash("text", candidate_hash)
                if typed_hash == self._last_hash:
                    time.sleep(self.poll_interval_sec)
                    continue

                self._copy_ts.append(now)
                self._trim_window(self._copy_ts, now)

                snap = self._make_snapshot_from_text(copy_ctx, now, event_type, text)
                self._last_copy_snapshot = snap
                self._last_hash = self._typed_hash("text", snap.get("content_hash"))

                evt_copy = self._build_copy_event(copy_ctx, now, event_type, snap)
                self._emit(evt_copy)
                self._last_emit_ts = now

            except Exception as e:
                self._emit_error("clipboard sensor exception", ctx, {"err": str(e)[:300]})
                time.sleep(self.poll_interval_sec)

        self._hook_stop.set()