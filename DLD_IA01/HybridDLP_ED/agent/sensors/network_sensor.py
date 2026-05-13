from __future__ import annotations

import ipaddress
import socket
import struct
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Tuple

try:
    import psutil
except Exception:
    psutil = None

try:
    import pydivert
except Exception:
    pydivert = None


# =========================================================
# Utilities
# =========================================================

def now() -> float:
    return time.time()


def iso_utc(ts: float) -> str:
    from datetime import datetime, timezone
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def is_private(ip: str) -> bool:
    try:
        obj = ipaddress.ip_address(ip)
        return (
            obj.is_private
            or obj.is_loopback
            or obj.is_link_local
            or obj.is_multicast
            or obj.is_reserved
        )
    except Exception:
        return True


def infer_outbound(packet, src_ip: str, dst_ip: str) -> bool:
    try:
        flag = getattr(packet, "is_outbound", None)
        if flag is not None:
            return bool(flag)
    except Exception:
        pass

    try:
        if is_private(src_ip) and not is_private(dst_ip):
            return True
    except Exception:
        pass

    return False


def _safe_lower(v: Any) -> str:
    try:
        return str(v or "").strip().lower()
    except Exception:
        return ""


def _looks_ip(v: Any) -> bool:
    try:
        ipaddress.ip_address(str(v).strip())
        return True
    except Exception:
        return False


def _norm_domain(v: Any) -> Optional[str]:
    if v is None:
        return None
    try:
        s = str(v).strip().lower()
        if not s:
            return None

        s = s.replace("https://", "").replace("http://", "")
        s = s.split("/", 1)[0].strip()
        s = s.strip("[](){}<>;,'\" ")

        # host:port
        if ":" in s and s.count(":") == 1:
            host, port = s.rsplit(":", 1)
            if port.isdigit():
                s = host.strip()

        return s or None
    except Exception:
        return None


def _norm_url(v: Any) -> Optional[str]:
    if v is None:
        return None
    try:
        s = str(v).strip()
        return s[:1024] if s else None
    except Exception:
        return None


def _clean_host(v: str) -> str:
    s = _norm_domain(v) or ""
    return s.strip(".").lower()


def _extract_host_from_url(url: Optional[str]) -> Optional[str]:
    if not url:
        return None
    return _norm_domain(url)


def _ensure_url(proto: str, dst_port: int, host_or_url: Optional[str]) -> Optional[str]:
    s = str(host_or_url or "").strip()
    if not s:
        return None
    if s.startswith("http://") or s.startswith("https://"):
        return s

    host = _norm_domain(s)
    if not host:
        return None

    if proto == "TCP" and dst_port == 443:
        return f"https://{host}"
    if proto == "UDP" and dst_port == 443:
        return f"https://{host}"
    if proto == "TCP" and dst_port in {80, 8080, 8000}:
        return f"http://{host}"

    return host


def _extract_host_from_cmdline(cmdline: Optional[str]) -> Optional[str]:
    s = str(cmdline or "").strip()
    if not s:
        return None

    tokens = s.replace('"', " ").replace("'", " ").split()
    for tok in tokens:
        t = tok.strip()
        if t.startswith("http://") or t.startswith("https://"):
            host = _extract_host_from_url(t)
            if host:
                return host

    lowered = s.lower()
    hints = [
        "chatgpt.com",
        "chat.openai.com",
        "api.openai.com",
        "openai.com",
        "github.com",
        "api.github.com",
        "marketplace.visualstudio.com",
    ]
    for h in hints:
        if h in lowered:
            return h

    return None


# =========================================================
# Minimal DNS parser
# =========================================================

def _read_name(buf: bytes, offset: int, depth: int = 0) -> Tuple[str, int]:
    if depth > 8:
        return "", offset

    labels = []
    pos = offset
    jumped = False
    end_pos = offset

    try:
        while pos < len(buf):
            ln = buf[pos]
            if ln == 0:
                if not jumped:
                    end_pos = pos + 1
                pos += 1
                break

            if (ln & 0xC0) == 0xC0:
                if pos + 1 >= len(buf):
                    break
                ptr = ((ln & 0x3F) << 8) | buf[pos + 1]
                sub, _ = _read_name(buf, ptr, depth + 1)
                if sub:
                    labels.append(sub)
                if not jumped:
                    end_pos = pos + 2
                pos += 2
                jumped = True
                break

            pos += 1
            if pos + ln > len(buf):
                break
            labels.append(buf[pos:pos + ln].decode("utf-8", errors="ignore"))
            pos += ln

        if not jumped:
            end_pos = pos

        return ".".join([x for x in labels if x]), end_pos
    except Exception:
        return "", offset


def parse_dns_response(payload: bytes) -> Dict[str, Any]:
    result = {"qname": None, "answers": []}

    try:
        if not payload or len(payload) < 12:
            return result

        _id, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", payload[:12])
        is_response = (flags & 0x8000) != 0
        if not is_response:
            return result

        pos = 12
        qname = None

        for _ in range(qdcount):
            qname, pos = _read_name(payload, pos)
            if pos + 4 > len(payload):
                return result
            pos += 4

        result["qname"] = _clean_host(qname) if qname else None

        answers = []
        for _ in range(ancount):
            name, pos = _read_name(payload, pos)
            if pos + 10 > len(payload):
                break

            rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", payload[pos:pos + 10])
            pos += 10
            if pos + rdlen > len(payload):
                break

            rdata = payload[pos:pos + rdlen]
            pos += rdlen

            item = {
                "name": _clean_host(name) if name else result["qname"],
                "ttl": int(ttl),
                "type": None,
                "value": None,
            }

            if rclass != 1:
                continue

            if rtype == 1 and rdlen == 4:
                item["type"] = "A"
                item["value"] = socket.inet_ntoa(rdata)
                answers.append(item)
            elif rtype == 28 and rdlen == 16:
                item["type"] = "AAAA"
                item["value"] = socket.inet_ntop(socket.AF_INET6, rdata)
                answers.append(item)
            elif rtype == 5:
                cname, _ = _read_name(payload, pos - rdlen)
                item["type"] = "CNAME"
                item["value"] = _clean_host(cname)
                answers.append(item)

        result["answers"] = answers
        return result
    except Exception:
        return result


# =========================================================
# Constants
# =========================================================

HTTP_PORTS = {80, 8080, 8000}
HTTPS_PORTS = {443}
DNS_PORTS = {53}

UPLOAD_TCP_PORTS = HTTP_PORTS | HTTPS_PORTS
UPLOAD_UDP_PORTS = {443}

BROWSER_PROCESSES = {
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
    "brave.exe",
    "opera.exe",
    "vivaldi.exe",
}

SCRIPT_OR_TOOL_PROCESSES = {
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "python.exe",
    "pythonw.exe",
    "curl.exe",
    "wget.exe",
    "bitsadmin.exe",
    "certutil.exe",
    "rclone.exe",
    "scp.exe",
    "sftp.exe",
    "ftp.exe",
    "winscp.exe",
    "filezilla.exe",
    "code.exe",
}

MESSAGING_OR_SYNC_PROCESSES = {
    "slack.exe",
    "teams.exe",
    "discord.exe",
    "outlook.exe",
    "onedrive.exe",
    "dropbox.exe",
    "zalo.exe",
    "telegram.exe",
    "whatsapp.exe",
}

UPLOAD_RELATED_PROCESSES = (
    BROWSER_PROCESSES
    | SCRIPT_OR_TOOL_PROCESSES
    | MESSAGING_OR_SYNC_PROCESSES
)

CLOUD_DOMAINS = [
    "dropbox",
    "drive.google",
    "docs.google",
    "googleusercontent",
    "onedrive",
    "sharepoint",
    "mega.nz",
    "transfer.sh",
    "discord",
    "slack",
    "box",
    "icloud",
    "chatgpt",
    "openai",
    "claude",
    "anthropic",
    "gemini",
    "copilot",
    "perplexity",
    "gmail",
    "outlook",
    "teams.microsoft",
    "zalo",
    "github",
    "gitlab",
    "bitbucket",
    "wetransfer",
    "mediafire",
    "leagueoflegends",
    "visualstudio",
    "vscode",
]

GPT_DOMAIN_HINTS = [
    "chatgpt",
    "openai",
    "oaistatic",
]

FLOW_IDLE_TIMEOUT_SEC = 12
FLOW_CLEANUP_INTERVAL_SEC = 2
DNS_CACHE_TTL_SEC = 900
EVENT_DEDUP_WINDOW_SEC = 45.0

MIN_UPLOAD_BYTES_BROWSER = 64 * 1024
MIN_UPLOAD_BYTES_TOOL = 32 * 1024
MIN_UPLOAD_BYTES_DEFAULT = 128 * 1024
MIN_UPLOAD_BYTES_QUIC = 64 * 1024
MIN_UPLOAD_PACKETS = 4


# =========================================================
# Flow stats
# =========================================================

FlowKey = Tuple[str, int, str, int, str]


@dataclass
class Flow:
    first_ts: float
    last_ts: float
    pid: Optional[int]

    bytes_out: int = 0
    bytes_in: int = 0
    packets_out: int = 0
    packets_in: int = 0

    first_ctx: Optional[Dict[str, Any]] = None
    last_ctx: Optional[Dict[str, Any]] = None

    emitted: bool = False
    history: Deque[float] = None
    gate_state: str = "unknown"  # unknown | allow | block
    gate_decided_ts: Optional[float] = None
    pending_packets: Deque[Any] = None
    source_paths_hint: List[str] = None

    def __post_init__(self) -> None:
        if self.history is None:
            self.history = deque(maxlen=64)
        if self.pending_packets is None:
            self.pending_packets = deque(maxlen=64)
        if self.source_paths_hint is None:
            self.source_paths_hint = []

    def add(self, ts: float, size: int, outbound: bool) -> None:
        self.last_ts = ts
        self.history.append(ts)
        if outbound:
            self.bytes_out += size
            self.packets_out += 1
        else:
            self.bytes_in += size
            self.packets_in += 1

    def duration(self) -> float:
        return max(0.0, self.last_ts - self.first_ts)

    def packets_total(self) -> int:
        return self.packets_out + self.packets_in


# =========================================================
# Sensor
# =========================================================

class NetworkSensor:
    def __init__(
        self,
        queue_manager,
        win_divert_filter: str = (
            "ip and ("
            "(tcp and ("
            "tcp.DstPort == 80 or tcp.DstPort == 443 or tcp.DstPort == 8080 or tcp.DstPort == 8000 or "
            "tcp.DstPort == 53 or tcp.SrcPort == 53"
            ")) or "
            "(udp and ("
            "udp.DstPort == 443 or udp.DstPort == 53 or udp.SrcPort == 53"
            "))"
            ")"
        ),
        **kwargs,
    ):
        if pydivert is None:
            raise RuntimeError("pydivert not installed")

        self.qm = queue_manager
        self.filter = win_divert_filter

        self.flows: Dict[FlowKey, Flow] = {}
        self.proc_cache: Dict[int, Dict[str, Optional[str]]] = {}
        self.last_cleanup_ts = 0.0

        self.dns_ip_cache: Dict[str, Dict[str, Any]] = {}
        self.dns_name_cache: Dict[str, Dict[str, Any]] = {}

        self.only_upload_processes = bool(kwargs.get("only_upload_processes", False))
        self.prefer_sniff = bool(kwargs.get("prefer_sniff", True))
        self.debug = bool(kwargs.get("debug", False))

        self.min_upload_bytes_browser = int(
            kwargs.get("min_upload_bytes_browser", MIN_UPLOAD_BYTES_BROWSER)
        )
        self.min_upload_bytes_tool = int(
            kwargs.get("min_upload_bytes_tool", MIN_UPLOAD_BYTES_TOOL)
        )
        self.min_upload_bytes_default = int(
            kwargs.get("min_upload_bytes_default", MIN_UPLOAD_BYTES_DEFAULT)
        )
        self.min_upload_bytes_quic = int(
            kwargs.get("min_upload_bytes_quic", MIN_UPLOAD_BYTES_QUIC)
        )
        self.min_upload_packets = int(
            kwargs.get("min_upload_packets", MIN_UPLOAD_PACKETS)
        )
        self.enforce_upload_gate = bool(kwargs.get("enforce_upload_gate", False))
        self.gate_hold_sec = float(kwargs.get("gate_hold_sec", 1.2))
        self.gate_max_buffer_packets = int(kwargs.get("gate_max_buffer_packets", 32))
        self.gate_sensitive_exts = {
            ".doc", ".docx", ".pdf", ".xls", ".xlsx", ".csv", ".sql", ".zip", ".7z", ".env"
        }
        self.gate_sensitive_keywords = {
            "payroll", "salary", "finance", "customer", "secret", "confidential", "hr", "employee"
        }
        self._summary_dedup_window_sec = float(kwargs.get("summary_dedup_window_sec", EVENT_DEDUP_WINDOW_SEC))
        self._recent_summary_keys: Dict[str, float] = {}
        # Debug FLOW noise controls (only affects _dbg prints, not emitted events)
        self.flow_debug_min_interval_sec = float(kwargs.get("flow_debug_min_interval_sec", 2.0))
        self.flow_debug_min_bytes_delta = int(kwargs.get("flow_debug_min_bytes_delta", 64 * 1024))
        self.flow_debug_min_packets_delta = int(kwargs.get("flow_debug_min_packets_delta", 50))
        self._flow_debug_state: Dict[FlowKey, Dict[str, Any]] = {}
        self._noisy_processes = {
            "svchost.exe",
            "runtimebroker.exe",
            "backgroundtaskhost.exe",
            "searchhost.exe",
            "searchindexer.exe",
            "widgets.exe",
            "widgetservice.exe",
            "msedgewebview2.exe",
            "onedrivestandaloneupdater.exe",
            "mousocoreworker.exe",
            "tiworker.exe",
            "trustedinstaller.exe",
        }
        self._noisy_domain_tokens = (
            "windowsupdate",
            "delivery.mp.microsoft.com",
            "msftconnecttest",
            "msedge.api",
            "officecdn.microsoft.com",
            "gvt1.com",
            "googleapis.com",
            "telemetry",
            "sentry.io",
            "crashlytics",
        )

    # -----------------------------------------------------
    # Core helpers
    # -----------------------------------------------------

    def emit(self, evt: Dict[str, Any]) -> None:
        try:
            self.qm.enqueue_event(evt)
        except Exception:
            pass

    def _cleanup_recent_summary_keys(self, ts: float) -> None:
        cutoff = ts - self._summary_dedup_window_sec
        stale = [k for k, last_ts in self._recent_summary_keys.items() if last_ts < cutoff]
        for k in stale:
            self._recent_summary_keys.pop(k, None)

    def _should_suppress_network_noise(self, proc_name: Optional[str], domain: Optional[str]) -> bool:
        pn = _safe_lower(proc_name)
        dm = _safe_lower(domain)
        if pn in self._noisy_processes:
            return True
        if dm and any(tok in dm for tok in self._noisy_domain_tokens):
            return True
        return False

    def _summary_dedup_key(self, proc_name: Optional[str], domain: Optional[str], dst_ip: str, dst_port: int, proto: str) -> str:
        return "|".join(
            [
                _safe_lower(proc_name),
                _safe_lower(domain) or _safe_lower(dst_ip),
                str(dst_port),
                _safe_lower(proto),
            ]
        )

    def _dbg(self, *args) -> None:
        if self.debug:
            try:
                print("[NetworkSensor]", *args)
            except Exception:
                pass

    def ctx_snapshot(self, ctx_provider: Optional[Any]) -> Dict[str, Any]:
        if not ctx_provider:
            return {}
        try:
            if hasattr(ctx_provider, "snapshot"):
                snap = ctx_provider.snapshot() or {}
                if isinstance(snap, dict):
                    return snap
        except Exception:
            pass
        return {}

    def get_proc_info(self, pid: Optional[int]) -> Dict[str, Optional[str]]:
        base = {
            "pid": pid,
            "process": None,
            "exe": None,
            "username": None,
            "cmdline": None,
            "parent_pid": None,
            "parent_name": None,
            "parent_cmdline": None,
        }
        if pid is None or psutil is None:
            return base

        if pid in self.proc_cache:
            return self.proc_cache[pid]

        try:
            p = psutil.Process(pid)
            cmdline = None
            try:
                parts = p.cmdline()
                if parts:
                    cmdline = " ".join(parts)[:1000]
            except Exception:
                cmdline = None

            parent_pid = None
            parent_name = None
            parent_cmdline = None
            try:
                parent = p.parent()
                if parent is not None:
                    parent_pid = parent.pid
                    parent_name = parent.name()
                    try:
                        pparts = parent.cmdline()
                        if pparts:
                            parent_cmdline = " ".join(pparts)[:1000]
                    except Exception:
                        parent_cmdline = None
            except Exception:
                pass

            info = {
                "pid": pid,
                "process": p.name(),
                "exe": p.exe(),
                "username": p.username(),
                "cmdline": cmdline,
                "parent_pid": parent_pid,
                "parent_name": parent_name,
                "parent_cmdline": parent_cmdline,
            }
        except Exception:
            info = base

        self.proc_cache[pid] = info
        return info

    # Extensions likely to be uploaded as attachments / media
    _UPLOADABLE_EXTS: frozenset = frozenset({
        # Images
        ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".tiff", ".heic", ".heif", ".svg",
        # Videos
        ".mp4", ".mov", ".avi", ".mkv", ".webm", ".3gp", ".wmv", ".flv",
        # Documents
        ".pdf", ".docx", ".doc", ".xlsx", ".xls", ".pptx", ".ppt",
        ".txt", ".csv", ".rtf", ".odt", ".ods",
        # Archives / compressed
        ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2",
        # Code / data
        ".json", ".xml", ".sql", ".env", ".py", ".js", ".ts",
    })

    def get_open_files_hint(self, pid: Optional[int]) -> List[str]:
        """
        Snapshot files currently open by `pid`, filtered to uploadable extensions.

        Not cached — open file list is volatile and must be queried at event time.
        Returns at most 8 paths sorted by relevance (media/docs first).
        """
        if pid is None or psutil is None:
            return []
        try:
            p = psutil.Process(pid)
            media: List[str] = []
            docs: List[str] = []
            for f in p.open_files():
                fp = getattr(f, "path", None)
                if not fp:
                    continue
                ext = Path(fp).suffix.lower()
                if ext not in self._UPLOADABLE_EXTS:
                    continue
                if ext in {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp",
                           ".tiff", ".heic", ".mp4", ".mov", ".avi", ".mkv"}:
                    media.append(fp)
                else:
                    docs.append(fp)
            combined = media + docs
            return combined[:8]
        except Exception:
            return []

    def _update_flow_source_hints(self, flow: Flow, pid: Optional[int]) -> None:
        hints = self.get_open_files_hint(pid)
        if not hints:
            return
        existing = set(flow.source_paths_hint or [])
        for hp in hints:
            if hp and hp not in existing:
                flow.source_paths_hint.append(hp)
                existing.add(hp)
        if len(flow.source_paths_hint) > 16:
            flow.source_paths_hint = flow.source_paths_hint[:16]

    def _should_block_upload_flow(self, flow: Flow, domain: Optional[str], ctx: Dict[str, Any], proc_name: Optional[str]) -> bool:
        d = _safe_lower(domain)
        process_tags = [str(x).lower() for x in (ctx.get("process_tags") or [])]
        app = _safe_lower(ctx.get("fg_app") or proc_name)
        is_external_sink = bool(d) and (self.looks_cloud_domain(d) or "zalo" in d or "discord" in d or "slack" in d)
        is_messaging_sink = ("messaging_or_collab" in process_tags) or any(x in app for x in ["zalo", "discord", "telegram", "whatsapp", "slack", "teams"])
        if not (is_external_sink or is_messaging_sink):
            return False

        for p in flow.source_paths_hint or []:
            pl = str(p).lower()
            ext = Path(pl).suffix.lower()
            if ext in self.gate_sensitive_exts:
                return True
            if any(k in pl for k in self.gate_sensitive_keywords):
                return True
        return False

    def effective_proc_name(self, proc_name: Optional[str], ctx: Optional[Dict[str, Any]] = None) -> str:
        ctx = ctx or {}
        return _safe_lower(proc_name or ctx.get("fg_process") or ctx.get("fg_app"))

    # -----------------------------------------------------
    # DNS correlation
    # -----------------------------------------------------

    def _dns_cache_put(self, ip: str, domain: str, ts: Optional[float] = None, ttl: Optional[int] = None) -> None:
        ts = ts or now()
        if not ip or not domain:
            return
        domain = _clean_host(domain)
        if not domain:
            return

        expires_at = ts + min(max(int(ttl or 300), 60), DNS_CACHE_TTL_SEC)
        self.dns_ip_cache[ip] = {
            "domain": domain,
            "ts": ts,
            "expires_at": expires_at,
            "ttl": ttl or 300,
            "source": "dns_response",
        }
        self.dns_name_cache[domain] = {
            "ip": ip,
            "ts": ts,
            "expires_at": expires_at,
            "ttl": ttl or 300,
            "source": "dns_response",
        }

    def _dns_cache_get(self, ip: str) -> Optional[Dict[str, Any]]:
        item = self.dns_ip_cache.get(ip)
        if not item:
            return None
        if now() > float(item.get("expires_at", 0)):
            self.dns_ip_cache.pop(ip, None)
            return None
        return item

    def handle_dns_packet(self, packet) -> None:
        try:
            if not getattr(packet, "udp", None):
                return

            src_port = int(packet.udp.src_port)
            dst_port = int(packet.udp.dst_port)
            if src_port != 53 and dst_port != 53:
                return

            payload = getattr(packet, "payload", b"") or b""
            if not payload:
                return

            parsed = parse_dns_response(payload)
            qname = parsed.get("qname")
            answers = parsed.get("answers") or []
            ts = now()

            if qname:
                self._dbg("DNS", "qname=", qname)

            cname_target = None
            for ans in answers:
                if ans.get("type") == "CNAME" and ans.get("value"):
                    cname_target = _clean_host(ans["value"])

            for ans in answers:
                atype = ans.get("type")
                value = ans.get("value")
                ttl = ans.get("ttl") or 300
                name = _clean_host(ans.get("name") or qname or "")

                if atype in ("A", "AAAA") and value:
                    final_domain = cname_target or name or qname
                    if final_domain:
                        self._dns_cache_put(value, final_domain, ts=ts, ttl=ttl)
                        self._dbg("DNS-CACHE", value, "->", final_domain)
        except Exception as e:
            self._dbg("handle_dns_packet error:", repr(e))

    # -----------------------------------------------------
    # Domain/service resolution
    # -----------------------------------------------------

    def _preferred_context_domain(self, ctx: Dict[str, Any]) -> Optional[str]:
        ctx = ctx or {}
        candidates = [
            ctx.get("dest_domain"),
            ctx.get("fg_domain"),
            ctx.get("domain"),
            _extract_host_from_url(ctx.get("fg_url_hint")),
        ]
        for c in candidates:
            d = _norm_domain(c)
            if d and not _looks_ip(d):
                return d
        return None

    def infer_service_name(
        self,
        domain: Optional[str],
        proc: Dict[str, Optional[str]],
        ctx: Optional[Dict[str, Any]] = None,
    ) -> str:
        ctx = ctx or {}
        domain_l = _safe_lower(domain)
        cmd = _safe_lower(proc.get("cmdline") or ctx.get("fg_cmdline"))
        title = _safe_lower(ctx.get("window_title"))
        pname = self.effective_proc_name(proc.get("process"), ctx)

        if any(x in domain_l for x in ["chatgpt", "openai", "oaistatic"]) or "chatgpt" in title:
            return "chatgpt"
        if "github" in domain_l:
            return "github"
        if "dropbox" in domain_l:
            return "dropbox"
        if "drive.google" in domain_l or "docs.google" in domain_l:
            return "google-drive"
        if "onedrive" in domain_l or "sharepoint" in domain_l:
            return "onedrive-sharepoint"
        if "discord" in domain_l:
            return "discord"
        if "slack" in domain_l:
            return "slack"
        if "teams.microsoft" in domain_l or "teams" in pname:
            return "microsoft-teams"

        if pname == "code.exe":
            if "copilot" in title or "copilot" in cmd:
                return "vscode-copilot"
            return "vscode-network"
        if pname in BROWSER_PROCESSES:
            return "browser-web"
        if pname in SCRIPT_OR_TOOL_PROCESSES:
            return "tool-network"

        return "unknown-network-service"

    def infer_service_category(self, service_name: str, domain: Optional[str]) -> str:
        s = _safe_lower(service_name)
        d = _safe_lower(domain)

        if "chatgpt" in s or any(x in d for x in GPT_DOMAIN_HINTS):
            return "ai"
        if any(x in s for x in ["dropbox", "google-drive", "onedrive", "sharepoint", "github"]):
            return "cloud"
        if "vscode" in s:
            return "developer-tool"
        if "browser" in s:
            return "web"
        return "network"

    def choose_domain(self, ctx: Dict[str, Any], dst_ip: str, proc: Optional[Dict[str, Optional[str]]] = None) -> str:
        ctx = ctx or {}
        proc = proc or {}

        d = self._preferred_context_domain(ctx)
        if d:
            return d

        cmd_host = _extract_host_from_cmdline(proc.get("cmdline") or ctx.get("fg_cmdline"))
        if cmd_host and not _looks_ip(cmd_host):
            return cmd_host

        hit = self._dns_cache_get(dst_ip)
        if hit and hit.get("domain"):
            return str(hit["domain"])

        return dst_ip

    def choose_url_hint(
        self,
        ctx: Dict[str, Any],
        dst_ip: str,
        dst_port: int,
        proto: str,
        proc: Optional[Dict[str, Optional[str]]] = None,
    ) -> Optional[str]:
        ctx = ctx or {}
        proc = proc or {}

        raw = _norm_url(ctx.get("fg_url_hint"))
        if raw:
            fixed = _ensure_url(proto, dst_port, raw)
            if fixed:
                return fixed

        cmd_host = _extract_host_from_cmdline(proc.get("cmdline") or ctx.get("fg_cmdline"))
        if cmd_host:
            return self.infer_dest_url(proto, cmd_host, dst_ip, dst_port)

        host = self.choose_domain(ctx, dst_ip, proc=proc)
        return self.infer_dest_url(proto, host, dst_ip, dst_port)

    def is_upload_process(self, proc_name: Optional[str], ctx: Dict[str, Any]) -> bool:
        pname = self.effective_proc_name(proc_name, ctx)
        return pname in UPLOAD_RELATED_PROCESSES

    def looks_cloud_domain(self, domain: str) -> bool:
        d = _safe_lower(domain)
        return any(x in d for x in CLOUD_DOMAINS)

    def looks_gpt_domain(self, domain: str, url_hint: Optional[str], title: Optional[str]) -> bool:
        all_text = " ".join([
            _safe_lower(domain),
            _safe_lower(url_hint),
            _safe_lower(title),
        ])
        return any(h in all_text for h in GPT_DOMAIN_HINTS)

    def threshold_for(
        self,
        proc_name: Optional[str],
        proto: str,
        ctx: Optional[Dict[str, Any]] = None,
        domain: str = "",
    ) -> int:
        ctx = ctx or {}
        if proto == "UDP":
            return self.min_upload_bytes_quic

        effective_name = self.effective_proc_name(proc_name, ctx)
        title = _safe_lower(ctx.get("window_title"))
        url_hint = _safe_lower(ctx.get("fg_url_hint"))

        if effective_name in BROWSER_PROCESSES:
            return self.min_upload_bytes_browser
        if effective_name in SCRIPT_OR_TOOL_PROCESSES:
            return self.min_upload_bytes_tool
        if effective_name in MESSAGING_OR_SYNC_PROCESSES:
            return self.min_upload_bytes_tool
        if self.looks_cloud_domain(domain) or self.looks_gpt_domain(domain, url_hint, title):
            return min(self.min_upload_bytes_browser, self.min_upload_bytes_tool)
        return self.min_upload_bytes_default

    def is_likely_upload(
        self,
        flow: Flow,
        proc_name: Optional[str],
        domain: str,
        proto: str,
        ctx: Optional[Dict[str, Any]] = None,
    ) -> bool:
        ctx = ctx or {}
        threshold = self.threshold_for(proc_name, proto, ctx=ctx, domain=domain)
        if flow.bytes_out < threshold:
            return False

        effective_name = self.effective_proc_name(proc_name, ctx)
        title = _safe_lower(ctx.get("window_title"))
        url_hint = _safe_lower(ctx.get("fg_url_hint"))

        interesting_domain = self.looks_cloud_domain(domain) or self.looks_gpt_domain(domain, url_hint, title)
        interesting_proc = effective_name in UPLOAD_RELATED_PROCESSES

        if flow.packets_out < self.min_upload_packets and flow.bytes_out < (threshold * 2):
            return False

        if proto == "UDP":
            return (
                interesting_domain
                or effective_name in BROWSER_PROCESSES
                or flow.bytes_out >= self.min_upload_bytes_quic
            )

        if interesting_proc:
            return True
        if interesting_domain:
            return True
        return flow.bytes_out >= self.min_upload_bytes_default

    def infer_method(self, proto: str, dst_port: int, bytes_out: int) -> Optional[str]:
        if proto == "TCP" and dst_port in UPLOAD_TCP_PORTS and bytes_out >= 16 * 1024:
            return "POST"
        if proto == "UDP" and dst_port == 443 and bytes_out >= 16 * 1024:
            return "POST"
        return None

    def infer_content_type(self, proto: str, dst_port: int, bytes_out: int) -> Optional[str]:
        if proto == "TCP" and dst_port in UPLOAD_TCP_PORTS and bytes_out >= 16 * 1024:
            return "application/octet-stream"
        if proto == "UDP" and dst_port == 443 and bytes_out >= 16 * 1024:
            return "application/octet-stream"
        return None

    def infer_dest_url(self, proto: str, domain: str, dst_ip: str, dst_port: int) -> Optional[str]:
        host = domain if domain and domain != dst_ip else dst_ip
        if not host:
            return None

        if proto == "UDP" and dst_port == 443:
            return f"https://{host}"

        if proto == "TCP":
            if dst_port == 443:
                return f"https://{host}"
            if dst_port in HTTP_PORTS:
                return f"http://{host}"

        return None

    def infer_operation_type(
        self,
        domain: str,
        proc_name: Optional[str],
        proto: str,
        ctx: Optional[Dict[str, Any]] = None,
    ) -> str:
        ctx = ctx or {}
        title = ctx.get("window_title")
        url_hint = ctx.get("fg_url_hint")
        effective_name = self.effective_proc_name(proc_name, ctx)

        if self.looks_gpt_domain(domain, url_hint, title):
            return "gpt_upload"
        if self.looks_cloud_domain(domain):
            return "cloud_upload"
        if effective_name in BROWSER_PROCESSES:
            return "http_upload" if proto == "TCP" else "network_upload"
        return "network_upload"

    # -----------------------------------------------------
    # Event builders
    # -----------------------------------------------------

    def build_src_block(self, src_ip: str, src_port: int) -> Dict[str, Any]:
        return {
            "ip": src_ip,
            "port": src_port,
        }

    def build_actor_block(self, proc: Dict[str, Optional[str]], ctx: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        ctx = ctx or {}
        return {
            "pid": proc.get("pid") or ctx.get("fg_pid"),
            "process": proc.get("process") or ctx.get("fg_process") or ctx.get("fg_app"),
            "exe": proc.get("exe") or ctx.get("fg_exe_path"),
            "username": proc.get("username") or ctx.get("user"),
            "cmdline": proc.get("cmdline") or ctx.get("fg_cmdline"),
            "user": proc.get("username") or ctx.get("user"),
        }

    def merge_context_block(
        self,
        actor_block: Dict[str, Any],
        ctx: Dict[str, Any],
        domain: str,
        dst_ip: str,
        dst_port: int,
        proto: str,
        proc: Optional[Dict[str, Optional[str]]] = None,
    ) -> Dict[str, Any]:
        ctx = ctx or {}
        proc = proc or {}

        fg_app = ctx.get("fg_app") or ctx.get("fg_process") or actor_block.get("process")
        fg_process = ctx.get("fg_process") or ctx.get("fg_app") or actor_block.get("process")
        fg_pid = ctx.get("fg_pid") or actor_block.get("pid")
        fg_cmdline = ctx.get("fg_cmdline") or actor_block.get("cmdline")
        fg_exe_path = ctx.get("fg_exe_path") or actor_block.get("exe")
        fg_url_hint = self.choose_url_hint(ctx, dst_ip, dst_port, proto, proc=proc)

        service_name = self.infer_service_name(domain, proc=proc, ctx=ctx)
        service_category = self.infer_service_category(service_name, domain)

        resolved_from = (
            "context"
            if self._preferred_context_domain(ctx)
            else "cmdline"
            if _extract_host_from_cmdline(proc.get("cmdline") or ctx.get("fg_cmdline"))
            else "dns_cache"
            if self._dns_cache_get(dst_ip)
            else "ip_only"
        )

        return {
            "user": ctx.get("user") or actor_block.get("username"),
            "fg_app": fg_app,
            "fg_process": fg_process,
            "fg_pid": fg_pid,
            "fg_cmdline": fg_cmdline,
            "fg_exe_path": fg_exe_path,
            "fg_hwnd": ctx.get("fg_hwnd"),
            "fg_tid": ctx.get("fg_tid"),
            "window_title": ctx.get("window_title"),
            "window_title_lc": ctx.get("window_title_lc") or _safe_lower(ctx.get("window_title")),
            "session": ctx.get("session"),
            "process_tags": ctx.get("process_tags") or [],
            "outside_working_hours": ctx.get("outside_working_hours"),
            "fg_domain": _norm_domain(ctx.get("fg_domain")) or (domain if not _looks_ip(domain) else None),
            "domain": _norm_domain(ctx.get("domain")) or (domain if not _looks_ip(domain) else None),
            "dest_domain": domain,
            "resolved_domain": None if _looks_ip(domain) else domain,
            "resolved_from": resolved_from,
            "dest_ip": dst_ip,
            "fg_url_hint": fg_url_hint,
            "net_snapshot": ctx.get("net_snapshot"),
            "service_name": service_name,
            "service_category": service_category,
        }

    def build_network_block(
        self,
        proto: str,
        dst_ip: str,
        dst_port: int,
        domain: str,
        flow: Flow,
        ctx: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        bytes_out = flow.bytes_out
        method = self.infer_method(proto, dst_port, bytes_out)
        content_type = self.infer_content_type(proto, dst_port, bytes_out)
        dns_hit = self._dns_cache_get(dst_ip)

        return {
            "protocol_type": proto,
            "dest_ip": dst_ip,
            "dest_domain": domain,
            "resolved_domain": None if _looks_ip(domain) else domain,
            "dest_host_display": domain if domain else dst_ip,
            "dest_url": self.choose_url_hint(ctx or {}, dst_ip, dst_port, proto),
            "dst_port": dst_port,
            "external_dst": not is_private(dst_ip),
            "method": method,
            "content_type": content_type,
            "bytes_sent_total": bytes_out,
            "bytes_out_total": flow.bytes_out,
            "bytes_in_total": flow.bytes_in,
            "packets_total": flow.packets_total(),
            "packets_out_total": flow.packets_out,
            "packets_in_total": flow.packets_in,
            "session_duration_sec": flow.duration(),
            "dns_correlated": bool(dns_hit),
            "dns_cache_domain": dns_hit.get("domain") if dns_hit else None,
        }

    def build_metrics_block(self, flow: Flow) -> Dict[str, Any]:
        return {
            "bytes_out": flow.bytes_out,
            "bytes_in": flow.bytes_in,
            "packets_total": flow.packets_total(),
            "packets_out_total": flow.packets_out,
            "packets_in_total": flow.packets_in,
            "session_duration_sec": flow.duration(),
        }

    # -----------------------------------------------------
    # Emit
    # -----------------------------------------------------

    def emit_upload_summary(self, ts: float, key: FlowKey, flow: Flow, ctx_provider: Optional[Any] = None) -> None:
        if flow.emitted:
            return

        src_ip, src_port, dst_ip, dst_port, proto = key

        # FIX: ưu tiên context của flow, không lấy snapshot hiện tại trước
        ctx = flow.last_ctx or flow.first_ctx or self.ctx_snapshot(ctx_provider) or {}

        proc = self.get_proc_info(flow.pid)
        proc_name = proc.get("process")
        domain = self.choose_domain(ctx, dst_ip, proc=proc)
        if self._should_suppress_network_noise(proc_name, domain):
            return

        # Best-effort: snapshot open file handles of the uploading process
        open_files_hint: List[str] = self.get_open_files_hint(flow.pid)
        _primary_file: Optional[str] = open_files_hint[0] if open_files_hint else None
        _primary_name = Path(_primary_file).name if _primary_file else None
        _primary_ext = Path(_primary_file).suffix.lower() if _primary_file else None

        if not self.is_likely_upload(flow, proc_name, domain, proto, ctx=ctx):
            return

        self._cleanup_recent_summary_keys(ts)
        dedup_key = self._summary_dedup_key(proc_name, domain, dst_ip, dst_port, proto)
        last_emit = self._recent_summary_keys.get(dedup_key)
        if last_emit is not None and (ts - last_emit) < self._summary_dedup_window_sec:
            return

        actor_block = self.build_actor_block(proc, ctx=ctx)
        context_block = self.merge_context_block(actor_block, ctx, domain, dst_ip, dst_port, proto, proc=proc)
        network_block = self.build_network_block(proto, dst_ip, dst_port, domain, flow, ctx=context_block)
        src_block = self.build_src_block(src_ip, src_port)

        threshold_used = self.threshold_for(proc_name, proto, ctx=context_block, domain=domain)
        looks_gpt = self.looks_gpt_domain(domain, context_block.get("fg_url_hint"), context_block.get("window_title"))
        inferred_method = self.infer_method(proto, dst_port, flow.bytes_out)
        inferred_content_type = self.infer_content_type(proto, dst_port, flow.bytes_out)
        service_name = context_block.get("service_name")
        service_category = context_block.get("service_category")

        effective_name = self.effective_proc_name(proc_name, context_block)

        evt = {
            "ts": ts,
            "timestamp": iso_utc(ts),
            "type": "network_upload_summary",
            "source": "network",
            "severity": "high" if looks_gpt or flow.bytes_out >= max(3 * threshold_used, 256 * 1024) else "warn",
            "actor": actor_block,
            "process": {
                "pid": proc.get("pid") or context_block.get("fg_pid"),
                "ppid": proc.get("parent_pid"),
                "name": proc.get("process") or context_block.get("fg_process") or context_block.get("fg_app"),
                "exe": proc.get("exe") or context_block.get("fg_exe_path"),
                "cmdline": proc.get("cmdline") or context_block.get("fg_cmdline"),
                "username": proc.get("username") or context_block.get("user"),
                "parent_name": proc.get("parent_name"),
            },
            "context": context_block,
            "operation": {
                "op_type": self.infer_operation_type(domain, proc_name, proto, ctx=context_block),
                "tool": actor_block.get("process") or context_block.get("fg_app"),
                "service_name": service_name,
                "service_category": service_category,
            },
            "object": {
                "path": _primary_file,
                "dst_path": None,
                "name": _primary_name,
                "ext": _primary_ext,
                "size": None,
                "exists": True if _primary_file else None,
                "drive": None,
                "volume_type": None,
                "cloud_provider": "gpt" if looks_gpt else ("cloud" if self.looks_cloud_domain(domain) else None),
                "bytes": flow.bytes_out,
                "dest": domain or dst_ip,
                "dest_display": f"{service_name} ({domain})" if domain and not _looks_ip(domain) else service_name,
                "open_files_hint": open_files_hint if open_files_hint else None,
            },
            "network": network_block,
            "src": src_block,
            "metrics": self.build_metrics_block(flow),
            "flags": {
                "password_protected": None,
            },
            "debug": {
                "evidence": {
                    "flow_first_ts": iso_utc(flow.first_ts),
                    "flow_last_ts": iso_utc(flow.last_ts),
                    "flow_bytes_out": flow.bytes_out,
                    "flow_bytes_in": flow.bytes_in,
                    "flow_packets_out": flow.packets_out,
                    "flow_packets_in": flow.packets_in,
                    "flow_duration_sec": flow.duration(),
                    "threshold_used": threshold_used,
                    "threshold_family": (
                        "browser"
                        if effective_name in BROWSER_PROCESSES
                        else "tool"
                        if effective_name in SCRIPT_OR_TOOL_PROCESSES or effective_name in MESSAGING_OR_SYNC_PROCESSES
                        else "default"
                    ),
                    "is_browser_proc": effective_name in BROWSER_PROCESSES,
                    "is_upload_related_proc": self.is_upload_process(proc_name, context_block),
                    "is_cloud_domain": self.looks_cloud_domain(domain),
                    "is_gpt_domain": looks_gpt,
                    "proto": proto,
                    "packet_process_id": flow.pid,
                    "proc_name": proc.get("process"),
                    "proc_exe": proc.get("exe"),
                    "proc_cmdline": proc.get("cmdline"),
                    "parent_pid": proc.get("parent_pid"),
                    "parent_name": proc.get("parent_name"),
                    "parent_cmdline": proc.get("parent_cmdline"),
                    "ctx_fg_app": context_block.get("fg_app"),
                    "ctx_fg_process": context_block.get("fg_process"),
                    "ctx_fg_pid": context_block.get("fg_pid"),
                    "ctx_window_title": context_block.get("window_title"),
                    "ctx_fg_domain": context_block.get("fg_domain"),
                    "ctx_dest_domain": context_block.get("dest_domain"),
                    "ctx_fg_url_hint": context_block.get("fg_url_hint"),
                    "ctx_process_tags": context_block.get("process_tags") or [],
                    "service_name": service_name,
                    "service_category": service_category,
                    "resolved_from": context_block.get("resolved_from"),
                    "dns_cache_hit": bool(self._dns_cache_get(dst_ip)),
                    "method_inferred": inferred_method,
                    "content_type_inferred": inferred_content_type,
                    "method_is_inferred_only": True,
                    "content_type_is_inferred_only": True,
                    "open_files_hint": open_files_hint if open_files_hint else None,
                    "open_files_hint_count": len(open_files_hint),
                }
            },
        }

        flow.emitted = True
        self._recent_summary_keys[dedup_key] = ts
        self._dbg(
            "EMIT",
            evt["type"],
            network_block.get("dest_domain"),
            network_block.get("bytes_sent_total"),
            proto,
            "proc=",
            effective_name,
            "service=",
            service_name,
        )
        self.emit(evt)

    def cleanup_idle_flows(self, ts: float, ctx_provider: Optional[Any] = None) -> None:
        if ts - self.last_cleanup_ts < FLOW_CLEANUP_INTERVAL_SEC:
            return

        self.last_cleanup_ts = ts

        expired_ips = []
        for ip, item in self.dns_ip_cache.items():
            if ts > float(item.get("expires_at", 0)):
                expired_ips.append(ip)
        for ip in expired_ips:
            self.dns_ip_cache.pop(ip, None)

        expired_keys = []
        for key, flow in self.flows.items():
            if ts - flow.last_ts >= FLOW_IDLE_TIMEOUT_SEC:
                expired_keys.append(key)

        for key in expired_keys:
            flow = self.flows.pop(key, None)
            if flow is None:
                continue
            self.emit_upload_summary(ts, key, flow, ctx_provider=ctx_provider)

    # -----------------------------------------------------
    # WinDivert open
    # -----------------------------------------------------

    def _open_divert(self):
        if not self.prefer_sniff:
            return pydivert.WinDivert(self.filter)

        try:
            from pydivert.consts import Flag  # type: ignore
            return pydivert.WinDivert(self.filter, flags=Flag.SNIFF)
        except Exception:
            pass

        try:
            Flag = getattr(pydivert, "Flag", None)
            if Flag is not None:
                return pydivert.WinDivert(self.filter, flags=Flag.SNIFF)
        except Exception:
            pass

        try:
            return pydivert.WinDivert(self.filter, flags=1)
        except Exception:
            pass

        return pydivert.WinDivert(self.filter)

    # -----------------------------------------------------
    # Main loop
    # -----------------------------------------------------

    def run_loop(self, stop_event, ctx=None) -> None:
        with self._open_divert() as w:
            try:
                if hasattr(w, "set_param"):
                    try:
                        from pydivert.consts import Param  # type: ignore
                        w.set_param(Param.QUEUE_LEN, 4096)
                        w.set_param(Param.QUEUE_SIZE, 4 * 1024 * 1024)
                        w.set_param(Param.QUEUE_TIME, 256)
                    except Exception:
                        pass
            except Exception:
                pass

            for packet in w:
                if stop_event.is_set():
                    break

                try:
                    if not getattr(packet, "ip", None):
                        continue

                    # Bắt DNS trước để cache domain
                    try:
                        if getattr(packet, "udp", None):
                            sp = int(packet.udp.src_port)
                            dp = int(packet.udp.dst_port)
                            if sp == 53 or dp == 53:
                                self.handle_dns_packet(packet)
                    except Exception:
                        pass

                    reinject_mode = bool(self.enforce_upload_gate and not self.prefer_sniff)
                    blocked_now = False

                    proto = None
                    src_port = 0
                    dst_port = 0

                    if getattr(packet, "tcp", None):
                        proto = "TCP"
                        src_port = packet.tcp.src_port
                        dst_port = packet.tcp.dst_port
                        if dst_port not in UPLOAD_TCP_PORTS:
                            if reinject_mode:
                                w.send(packet)
                            continue
                    elif getattr(packet, "udp", None):
                        proto = "UDP"
                        src_port = packet.udp.src_port
                        dst_port = packet.udp.dst_port
                        if dst_port not in UPLOAD_UDP_PORTS:
                            if reinject_mode:
                                w.send(packet)
                            continue
                    else:
                        if reinject_mode:
                            w.send(packet)
                        continue

                    src_ip = packet.src_addr
                    dst_ip = packet.dst_addr

                    outbound = infer_outbound(packet, src_ip, dst_ip)
                    if not outbound:
                        if reinject_mode:
                            w.send(packet)
                        continue

                    if is_private(dst_ip):
                        if reinject_mode:
                            w.send(packet)
                        continue

                    try:
                        raw_data = getattr(packet, "raw", b"")
                        size = len(raw_data) if raw_data is not None else 0
                    except Exception:
                        size = 0

                    ts = now()
                    current_ctx = self.ctx_snapshot(ctx)

                    pid = getattr(packet, "process_id", None)
                    proc = self.get_proc_info(pid)
                    proc_name = proc.get("process")

                    if self.only_upload_processes and pid is not None and not self.is_upload_process(proc_name, current_ctx):
                        self.cleanup_idle_flows(ts, ctx_provider=ctx)
                        if reinject_mode:
                            w.send(packet)
                        continue

                    key = (src_ip, src_port, dst_ip, dst_port, proto)
                    flow = self.flows.get(key)

                    if flow is None:
                        flow = Flow(first_ts=ts, last_ts=ts, pid=pid)
                        flow.first_ctx = current_ctx or {}
                        self.flows[key] = flow
                    else:
                        # nếu flow chưa có pid mà packet mới có pid thì cập nhật
                        if flow.pid is None and pid is not None:
                            flow.pid = pid

                    flow.last_ctx = current_ctx or flow.last_ctx
                    flow.add(ts, size, outbound=True)

                    domain = self.choose_domain(current_ctx, dst_ip, proc=proc)
                    service_name = self.infer_service_name(domain, proc=proc, ctx=current_ctx)
                    self._update_flow_source_hints(flow, pid)

                    self._dbg(
                        "FLOW",
                        proto,
                        src_ip,
                        src_port,
                        "->",
                        dst_ip,
                        dst_port,
                        "pid=",
                        pid,
                        "proc=",
                        self.effective_proc_name(proc_name, current_ctx),
                        "bytes_out=",
                        flow.bytes_out,
                        "packets_out=",
                        flow.packets_out,
                        "domain=",
                        domain,
                        "service=",
                        service_name,
                        "title=",
                        current_ctx.get("window_title"),
                    )

                    if self.is_likely_upload(flow, proc_name, domain, proto, ctx=current_ctx):
                        self.emit_upload_summary(ts, key, flow, ctx_provider=ctx)

                    if reinject_mode:
                        # Hold first packets briefly so we can collect source-path hints before deciding.
                        if flow.gate_state == "unknown":
                            should_block = self._should_block_upload_flow(flow, domain, current_ctx, proc_name)
                            gate_timed_out = (ts - flow.first_ts) >= self.gate_hold_sec
                            if should_block:
                                flow.gate_state = "block"
                                flow.gate_decided_ts = ts
                            elif gate_timed_out:
                                flow.gate_state = "allow"
                                flow.gate_decided_ts = ts

                        if flow.gate_state == "unknown":
                            if len(flow.pending_packets) < self.gate_max_buffer_packets:
                                flow.pending_packets.append(packet)
                            else:
                                flow.gate_state = "allow"
                                flow.gate_decided_ts = ts

                        if flow.gate_state == "allow":
                            while flow.pending_packets:
                                try:
                                    w.send(flow.pending_packets.popleft())
                                except Exception:
                                    break
                            w.send(packet)
                        elif flow.gate_state == "block":
                            blocked_now = True

                    self.cleanup_idle_flows(ts, ctx_provider=ctx)

                    if reinject_mode and blocked_now:
                        continue

                except Exception as e:
                    self._dbg("loop error:", repr(e))
                    continue

        ts = now()
        for key, flow in list(self.flows.items()):
            if self.enforce_upload_gate and (not self.prefer_sniff):
                # On shutdown, fail-open for undecided flows to avoid stuck connections.
                flow.gate_state = flow.gate_state if flow.gate_state != "unknown" else "allow"
                if flow.gate_state == "allow":
                    while flow.pending_packets:
                        try:
                            w.send(flow.pending_packets.popleft())
                        except Exception:
                            break
            self.emit_upload_summary(ts, key, flow, ctx_provider=ctx)
        self.flows.clear()


NetworkUploadSensor = NetworkSensor