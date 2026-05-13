from __future__ import annotations

import ctypes
import getpass
import os
import re
import time
from ctypes import wintypes
from typing import Any, Dict, Optional, List, Tuple

try:
    import psutil  # type: ignore
except Exception:
    psutil = None

user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32


# -----------------------
# Lightweight helpers
# -----------------------
def _now() -> float:
    return time.time()


def _iso_utc(ts: float) -> str:
    from datetime import datetime, timezone
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def _safe_str(v: Any, max_len: int = 512) -> Optional[str]:
    if v is None:
        return None
    try:
        s = str(v)
        if len(s) > max_len:
            s = s[:max_len]
        return s
    except Exception:
        return None


def _safe_lower(v: Any) -> str:
    try:
        return str(v or "").strip().lower()
    except Exception:
        return ""


def _coalesce_str(*vals: Any, max_len: int = 1024) -> Optional[str]:
    for v in vals:
        if v is None:
            continue
        try:
            s = str(v).strip()
            if s:
                return s[:max_len]
        except Exception:
            continue
    return None


def _norm_domain(s: Optional[str]) -> Optional[str]:
    if not s:
        return None
    x = s.strip().lower()
    x = x.replace("https://", "").replace("http://", "")
    x = x.split("/", 1)[0].strip()
    x = x.strip("[](){}<>;:,'\" ")
    if ":" in x and x.count(":") == 1:
        host, port = x.split(":", 1)
        if port.isdigit():
            x = host.strip()
    return x or None


def _is_ip_literal(s: Optional[str]) -> bool:
    if not s:
        return False
    t = s.strip()
    return bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", t))


def _looks_like_filename(s: Optional[str]) -> bool:
    if not s:
        return False
    t = s.strip().lower()
    # common local file-like names that must NOT become domains
    return bool(
        re.fullmatch(
            r".+\.(txt|log|csv|tsv|json|xml|yaml|yml|ini|conf|cfg|doc|docx|xls|xlsx|ppt|pptx|pdf|zip|7z|rar|jpg|jpeg|png|gif|bmp|sql|ps1|py|js|ts|java|cpp|c|h)$",
            t,
        )
    )


def _is_probable_domain(s: Optional[str]) -> bool:
    if not s:
        return False
    x = _norm_domain(s)
    if not x:
        return False
    if _is_ip_literal(x):
        return False
    if _looks_like_filename(x):
        return False
    if x in {"localhost", "local", "intranet"}:
        return False
    # Must contain at least one dot and plausible TLD-ish suffix
    if "." not in x:
        return False
    return bool(re.fullmatch(r"(?:[a-z0-9-]+\.)+[a-z]{2,24}", x))


def _is_portable_path(exe_path: Optional[str]) -> bool:
    """
    Portable browser/app thường chạy từ:
      - Removable drive (E:\, F:\,...)
      - Temp folder
      - Downloads
    """
    if not exe_path:
        return False
    p = exe_path.lower()
    if len(p) >= 2 and p[1] == ":" and p[0] not in ("c", "d"):
        return True
    if "\\appdata\\local\\temp\\" in p or "\\temp\\" in p:
        return True
    if "\\downloads\\" in p:
        return True
    return False


def _tag_process(pname: Optional[str], exe_path: Optional[str]) -> List[str]:
    """
    Very light rule-based tags (L1 only).
    """
    tags: List[str] = []
    n = (pname or "").lower()

    if n in ("powershell.exe", "pwsh.exe", "python.exe", "pythonw.exe", "wscript.exe", "cscript.exe", "cmd.exe"):
        tags.append("script_engine")

    if n in ("autohotkey.exe", "macrorecorder.exe", "pulover.exe", "uiautomation.exe"):
        tags.append("automation_tool")

    if n in ("chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "vivaldi.exe"):
        if _is_portable_path(exe_path):
            tags.append("portable_browser")
        else:
            tags.append("browser")

    if n in ("teams.exe", "slack.exe", "discord.exe", "telegram.exe", "whatsapp.exe", "line.exe", "signal.exe", "skype.exe", "zalo.exe", "outlook.exe"):
        tags.append("messaging_or_collab")

    if n in ("snippingtool.exe", "screenclippinghost.exe", "obs64.exe", "obs32.exe", "camtasia.exe", "zoom.exe"):
        tags.append("screen_capture_or_recording")

    if n in ("mstsc.exe", "teamviewer.exe", "anydesk.exe"):
        tags.append("remote_session_hint")

    return tags


_DOMAIN_RE = re.compile(
    r"(?i)\b((?:[a-z0-9-]+\.)+(?:com|net|org|io|ai|co|app|dev|vn|edu|gov|cloud|me|ly|gg|info|biz))\b"
)

_URL_RE = re.compile(
    r"(?i)\bhttps?://[^\s|]+"
)

KNOWN_TITLE_DOMAIN_HINTS: Dict[str, str] = {
    "chatgpt": "chatgpt.com",
    "openai": "chat.openai.com",
    "claude": "claude.ai",
    "gemini": "gemini.google.com",
    "bard": "bard.google.com",
    "perplexity": "perplexity.ai",
    "copilot": "copilot.microsoft.com",
    "gmail": "mail.google.com",
    "google mail": "mail.google.com",
    "google drive": "drive.google.com",
    "drive": "drive.google.com",
    "dropbox": "dropbox.com",
    "onedrive": "onedrive.live.com",
    "slack": "slack.com",
    "discord": "discord.com",
    "telegram": "web.telegram.org",
    "teams": "teams.microsoft.com",
    "outlook": "outlook.office.com",
    "github": "github.com",
    "gitlab": "gitlab.com",
    "zalo": "chat.zalo.me",
    "whatsapp": "web.whatsapp.com",
    "messenger": "messenger.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "reddit": "reddit.com",
    "linkedin": "linkedin.com",
    "tiktok": "tiktok.com",
    "pastebin": "pastebin.com",
    "gist": "gist.github.com",
    "wetransfer": "wetransfer.com",
}


def _extract_domain_from_window_title(title: Optional[str]) -> Optional[str]:
    """
    Heuristic only, but safer:
      - accepts real URLs/domains
      - maps well-known app/site keywords
      - rejects file names like test1.txt
      - rejects IPs/local names
    """
    if not title:
        return None

    t = title.strip()
    tl = t.lower()

    # 1) URL first
    m = _URL_RE.search(t)
    if m:
        url = m.group(0)
        d = _norm_domain(url)
        if _is_probable_domain(d):
            return d

    # 2) Explicit domain token in title
    m = _DOMAIN_RE.search(t)
    if m:
        d = _norm_domain(m.group(1))
        if _is_probable_domain(d):
            return d

    # 3) Keyword mapping
    for k, v in KNOWN_TITLE_DOMAIN_HINTS.items():
        if k in tl:
            return v

    return None


# -----------------------
# WinAPI: foreground window/process
# -----------------------
class ContextProvider:
    """
    Sensor Layer context snapshot (VERY lightweight)

    Always:
      - user
      - window_title
      - fg_pid
      - fg_process
      - fg_app
      - fg_exe_path
      - session

    Optional:
      - fg_cmdline
      - net_snapshot

    Extra best-effort fields added:
      - fg_hwnd
      - fg_tid
      - window_title_lc
      - fg_domain
      - fg_url_hint
    """

    def __init__(
        self,
        cache_ttl_sec: float = 0.5,
        include_session: bool = True,
        include_exe_path: bool = True,
        include_cmdline: bool = True,
        include_net_snapshot: bool = False,
        working_hours: Optional[Tuple[int, int]] = (8, 18),
    ):
        self.cache_ttl_sec = float(cache_ttl_sec)
        self.include_session = bool(include_session)
        self.include_exe_path = bool(include_exe_path)
        self.include_cmdline = bool(include_cmdline)
        self.include_net_snapshot = bool(include_net_snapshot)
        self.working_hours = working_hours

        self._last_ts = 0.0
        self._cached: Dict[str, Any] = {}
        self._session_id = self._make_session_id() if self.include_session else None

    def _make_session_id(self) -> str:
        return hex(int(time.time() * 1000))[2:]

    def _get_foreground_hwnd(self) -> Optional[int]:
        try:
            hwnd = user32.GetForegroundWindow()
            if hwnd:
                return int(hwnd)
        except Exception:
            pass
        return None

    def _get_window_title(self, hwnd: Optional[int] = None) -> str:
        try:
            if not hwnd:
                hwnd = self._get_foreground_hwnd()
            if not hwnd:
                return ""
            length = int(user32.GetWindowTextLengthW(hwnd) or 0)
            if length <= 0:
                return ""
            buf = ctypes.create_unicode_buffer(length + 1)
            user32.GetWindowTextW(hwnd, buf, length + 1)
            return buf.value or ""
        except Exception:
            return ""

    def _get_foreground_pid_tid(self, hwnd: Optional[int] = None) -> Tuple[Optional[int], Optional[int]]:
        try:
            if not hwnd:
                hwnd = self._get_foreground_hwnd()
            if not hwnd:
                return None, None

            pid = wintypes.DWORD(0)
            tid = user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            return int(pid.value) if pid.value else None, int(tid) if tid else None
        except Exception:
            return None, None

    def _get_process_path(self, pid: int) -> Optional[str]:
        """
        Best-effort get full exe path via QueryFullProcessImageNameW.
        """
        if not pid:
            return None

        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        h = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not h:
            return None

        try:
            QueryFullProcessImageNameW = getattr(kernel32, "QueryFullProcessImageNameW", None)
            if not QueryFullProcessImageNameW:
                return None

            QueryFullProcessImageNameW.argtypes = [
                wintypes.HANDLE,
                wintypes.DWORD,
                wintypes.LPWSTR,
                ctypes.POINTER(wintypes.DWORD),
            ]
            QueryFullProcessImageNameW.restype = wintypes.BOOL

            buf_len = wintypes.DWORD(2048)
            buf = ctypes.create_unicode_buffer(buf_len.value)

            ok = QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(buf_len))
            if ok:
                return buf.value or None
            return None
        except Exception:
            return None
        finally:
            try:
                kernel32.CloseHandle(h)
            except Exception:
                pass

    def _get_process_name(self, pid: int, exe_path: Optional[str] = None) -> Optional[str]:
        try:
            if exe_path:
                base = os.path.basename(exe_path)
                if base:
                    return base
        except Exception:
            pass

        try:
            if psutil is not None and pid:
                return psutil.Process(pid).name()
        except Exception:
            pass

        return None

    def _get_cmdline_light(self, pid: int) -> Optional[str]:
        """
        psutil-based command line (best-effort).
        """
        if not pid or psutil is None:
            return None

        try:
            p = psutil.Process(pid)
            cmd = p.cmdline()
            if isinstance(cmd, list) and cmd:
                s = " ".join(str(x) for x in cmd)
            else:
                s = str(cmd or "")
            return _safe_str(s, 1000)
        except Exception:
            return None

    # -----------------------
    # Optional: network summary (VERY light)
    # -----------------------
    def _net_snapshot_tcp(self, pid_filter: Optional[int] = None) -> Dict[str, Any]:
        """
        Very light TCP outbound summary using GetExtendedTcpTable.
        - NO domain resolution
        - NO DPI
        - Returns counts by remote port
        """
        out = {
            "tcp_conn_count": None,
            "tcp_top_remote_ports": None,
        }

        try:
            AF_INET = 2
            TCP_TABLE_OWNER_PID_ALL = 5

            GetExtendedTcpTable = getattr(ctypes.windll.iphlpapi, "GetExtendedTcpTable", None)
            if not GetExtendedTcpTable:
                return out

            size = wintypes.DWORD(0)
            GetExtendedTcpTable(None, ctypes.byref(size), False, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
            if size.value <= 0:
                return out

            buf = ctypes.create_string_buffer(size.value)
            ret = GetExtendedTcpTable(buf, ctypes.byref(size), False, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
            if ret != 0:
                return out

            import struct

            offset = 0
            dwNumEntries = struct.unpack_from("<I", buf, offset)[0]
            offset += 4

            ports: Dict[int, int] = {}
            total = 0

            row_size = 24
            for _i in range(int(dwNumEntries)):
                if offset + row_size > len(buf):
                    break
                state, laddr, lport, raddr, rport, opid = struct.unpack_from("<6I", buf, offset)
                offset += row_size

                if pid_filter is not None and int(opid) != int(pid_filter):
                    continue

                rp = int(((rport & 0xFF) << 8) | ((rport >> 8) & 0xFF))
                ports[rp] = ports.get(rp, 0) + 1
                total += 1

            out["tcp_conn_count"] = total
            out["tcp_top_remote_ports"] = sorted(ports.items(), key=lambda x: x[1], reverse=True)[:5]
            return out

        except Exception:
            return out

    def _outside_hours_hint(self) -> Optional[bool]:
        if not self.working_hours:
            return None
        try:
            start_h, end_h = self.working_hours
            h = time.localtime().tm_hour
            return bool(h < start_h or h >= end_h)
        except Exception:
            return None

    # -----------------------
    def snapshot(self) -> Dict[str, Any]:
        current_ts = _now()
        if current_ts - self._last_ts < self.cache_ttl_sec:
            return dict(self._cached)

        hwnd: Optional[int] = None
        pid: Optional[int] = None
        tid: Optional[int] = None
        exe_path: Optional[str] = None
        pname: Optional[str] = None
        window_title: str = ""

        ctx: Dict[str, Any] = {
            "ts": current_ts,
            "Timestamp": _iso_utc(current_ts),

            "user": getpass.getuser(),
            "window_title": "",
            "window_title_lc": "",

            "fg_hwnd": None,
            "fg_tid": None,
            "fg_pid": None,
            "fg_process": None,
            "fg_app": None,
            "fg_exe_path": None,
            "fg_cmdline": None,

            "fg_domain": None,
            "domain": None,
            "dest_domain": None,
            "fg_url_hint": None,

            "session": self._session_id if self.include_session else None,
            "process_tags": [],
            "outside_working_hours": self._outside_hours_hint(),

            "net_snapshot": None,
        }

        try:
            hwnd = self._get_foreground_hwnd()
            window_title = self._get_window_title(hwnd)
            pid, tid = self._get_foreground_pid_tid(hwnd)

            ctx["fg_hwnd"] = hwnd
            ctx["window_title"] = window_title
            ctx["window_title_lc"] = window_title.lower() if window_title else ""
            ctx["fg_pid"] = pid
            ctx["fg_tid"] = tid

            if self.include_exe_path and pid:
                exe_path = self._get_process_path(pid)
                ctx["fg_exe_path"] = _safe_str(exe_path, 1024)

            pname = self._get_process_name(pid or 0, exe_path=exe_path)
            pname = _coalesce_str(pname)
            ctx["fg_process"] = pname
            ctx["fg_app"] = pname

            if self.include_cmdline and pid:
                cmdline = self._get_cmdline_light(pid)
                ctx["fg_cmdline"] = _safe_str(cmdline, 1000)

            ctx["process_tags"] = _tag_process(pname, exe_path)

            # Safer domain extraction from title only
            domain = _extract_domain_from_window_title(window_title)

            # Final sanitize
            if not _is_probable_domain(domain):
                domain = None

            ctx["fg_domain"] = domain
            ctx["domain"] = domain
            ctx["dest_domain"] = domain
            ctx["fg_url_hint"] = domain

            if self.include_net_snapshot and pid:
                ctx["net_snapshot"] = self._net_snapshot_tcp(pid_filter=pid)

        except Exception:
            pass

        # Final normalization so behavior rules see stable fields
        ctx["fg_process"] = _coalesce_str(ctx.get("fg_process"), ctx.get("fg_app"))
        ctx["fg_app"] = _coalesce_str(ctx.get("fg_app"), ctx.get("fg_process"))
        ctx["window_title"] = _coalesce_str(ctx.get("window_title"), "") or ""
        ctx["window_title_lc"] = ctx["window_title"].lower() if ctx["window_title"] else ""
        ctx["fg_domain"] = _norm_domain(ctx.get("fg_domain"))
        if not _is_probable_domain(ctx["fg_domain"]):
            ctx["fg_domain"] = None
        ctx["domain"] = ctx["fg_domain"]
        ctx["dest_domain"] = ctx["fg_domain"]
        ctx["fg_url_hint"] = ctx["fg_domain"]

        self._cached = ctx
        self._last_ts = current_ts
        return dict(ctx)