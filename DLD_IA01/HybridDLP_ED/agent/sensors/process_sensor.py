from __future__ import annotations

import time
import re
from pathlib import Path
from typing import Any, Dict, Optional, Set, List, Tuple

try:
    import psutil  # type: ignore
except Exception:
    psutil = None


def _now() -> float:
    return time.time()


def _iso_utc(ts: float) -> str:
    from datetime import datetime, timezone
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def _norm_name(name: Optional[str]) -> str:
    n = (name or "").strip().lower()
    if n.endswith(".exe"):
        n = n[:-4]
    return n


# =========================
# IOC / Commandline Rules (L1 metadata only)
# =========================
IOC_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"(?i)\b(certutil|bitsadmin|curl|wget)\b"), "native_download_tool"),
    (re.compile(r"(?i)\bcertutil(?:\.exe)?\b.*\s-(?:urlcache|encode|decode)\b"), "certutil_abuse"),
    (re.compile(r"(?i)\bbitsadmin(?:\.exe)?\b.*\s/transfer\b"), "bitsadmin_download"),

    (re.compile(r"(?i)\b(findstr)\b"), "data_discovery"),
    (re.compile(r"(?i)\bdir\b.*\s/s\b"), "data_discovery"),
    (re.compile(r"(?i)\b(get-childitem|gci)\b.*\s-recurse\b"), "data_discovery"),

    (re.compile(r"(?i)\b(7z|7za|rar|zip|tar|makecab)\b"), "archive_staging"),

    (re.compile(r"(?i)\b(get-clipboard)\b"), "clipboard_access"),
    (re.compile(r"(?i)\b(copyfromscreen)\b"), "screen_clipboard_capture"),

    (re.compile(r"(?i)\b(aws|gsutil|az|rclone)\b"), "cloud_exfiltration_tool"),

    (re.compile(r"(?i)\b(send-mailmessage)\b"), "email_exfiltration"),
    (re.compile(r"(?i)\bsmtp\b"), "email_exfiltration"),

    (re.compile(r"(?i)\b(token|api[_-]?key|secret|password|passwd)\b"), "credential_keyword"),
    (re.compile(r"(?i)\b-enc\b|\b-encodedcommand\b"), "encoded_command"),
]

SECRET_KV_RE = re.compile(r"(?i)\b(token|api[_-]?key|secret|password|passwd)\b\s*[:=]\s*([^\s\"']+)")
LONG_BASE64_RE = re.compile(r"(?i)\b[A-Za-z0-9+/]{120,}={0,2}\b")


def _sanitize_cmdline(cmd: str, max_len: int = 4096) -> str:
    """
    Keep cmdline useful but avoid logging secrets.
    - mask token/password=xxxx
    - mask long base64 blocks
    - remove full path of the executable but keep arguments
    """
    if not cmd:
        return ""

    cmd = cmd.strip()
    try:
        parts = cmd.split()
        if parts:
            parts[0] = Path(parts[0]).name
        cmd = " ".join(parts)
    except Exception:
        pass

    cmd = SECRET_KV_RE.sub(lambda m: f"{m.group(1)}=<redacted>", cmd)
    cmd = LONG_BASE64_RE.sub("<base64_redacted>", cmd)

    if len(cmd) > max_len:
        cmd = cmd[:max_len]

    return cmd


def _safe_match_text(m: str) -> str:
    s = (m or "").strip()
    if "=" in s:
        k = s.split("=", 1)[0].strip()
        return (k + "=")[:80]
    return s[:80]


def _cmdline_hits(cmdline: str) -> List[Dict[str, str]]:
    hits: List[Dict[str, str]] = []
    s = cmdline or ""
    for rx, tag in IOC_PATTERNS:
        m = rx.search(s)
        if not m:
            continue
        hits.append({"tag": tag, "match": _safe_match_text(m.group(0))})
    return hits


def _severity_from_hits(hits: List[Dict[str, str]], tags: Optional[List[str]] = None) -> str:
    tagset = {h.get("tag") for h in hits if isinstance(h, dict)}
    tags2 = set(tags or [])

    if "encoded_command" in tagset:
        return "high"
    if "cloud_exfiltration_tool" in tagset or "bitsadmin_download" in tagset:
        return "high"
    if "archive_staging" in tagset and ("script_engine" in tags2 or "file_transfer_tool" in tags2):
        return "high"
    if hits:
        return "warn"
    return "info"


def _tags_for_name_and_path(proc_name: Optional[str], exe_path: Optional[str]) -> List[str]:
    n = _norm_name(proc_name)
    tags: List[str] = []

    script_engines = {"powershell", "pwsh", "cmd", "wscript", "cscript", "python", "pythonw"}
    transfer_tools = {"curl", "wget", "rclone", "winscp", "filezilla", "pscp", "scp", "sftp", "robocopy"}
    screen_capture = {"snippingtool", "screenclippinghost", "obs64", "obs32", "camtasia", "greenshot", "lightshot"}
    archivers = {"7z", "7za", "winrar", "rar", "zip", "tar", "makecab"}
    browsers = {"chrome", "msedge", "firefox", "brave", "opera", "vivaldi"}
    remote_tools = {"mstsc", "teamviewer", "anydesk"}
    messaging = {"slack", "teams", "discord", "telegram", "whatsapp", "zalo", "outlook"}

    if n in script_engines:
        tags.append("script_engine")
    if n in transfer_tools:
        tags.append("file_transfer_tool")
    if n in screen_capture:
        tags.append("screen_capture_tool")
    if n in archivers:
        tags.append("archive_tool")
    if n in browsers:
        tags.append("browser")
    if n in remote_tools:
        tags.append("remote_tool")
    if n in messaging:
        tags.append("messaging_or_collab")

    if exe_path:
        p = exe_path.lower()
        if len(p) >= 2 and p[1] == ":" and p[0] not in ("c", "d"):
            tags.append("portable_exec")
        if "\\downloads\\" in p or "\\appdata\\local\\temp\\" in p:
            tags.append("user_space_exec")

    return tags


def _proc_sample(proc_payload: Dict[str, Any]) -> Optional[str]:
    cmd = proc_payload.get("cmdline")
    if isinstance(cmd, str) and cmd.strip():
        return cmd[:400]
    name = proc_payload.get("name")
    if isinstance(name, str) and name.strip():
        return name[:200]
    return None


class ProcessSensor:
    """
    L1 Process Sensor (poll-based, optimized)

    Emits:
      - proc_start
      - proc_end (optional)

    Canonical fields:
      - actor.*
      - process.*
      - operation.*
      - context.*
      - metrics.*
      - flags.*
      - content.*
    """

    def __init__(
        self,
        queue_manager,
        poll_interval_sec: float = 0.5,
        watch_names: Optional[Set[str]] = None,
        emit_end: bool = False,
        include_cmdline: bool = True,
        include_parent: bool = True,
        include_username: bool = True,
        max_new_per_tick: int = 500,
        max_known_pids: int = 25000,
    ):
        self.qm = queue_manager
        self.poll_interval_sec = float(poll_interval_sec)
        self.emit_end = bool(emit_end)

        self.include_cmdline = bool(include_cmdline)
        self.include_parent = bool(include_parent)
        self.include_username = bool(include_username)

        self.watch_names: Set[str] = {_norm_name(n) for n in (watch_names or set()) if str(n).strip()}

        self.max_new_per_tick = int(max_new_per_tick)
        self.max_known_pids = int(max_known_pids)

        self._known_pids: Dict[int, float] = {}
        self._proc_cache: Dict[int, Dict[str, Any]] = {}

    def _is_interesting(self, proc_name: Optional[str]) -> bool:
        if not self.watch_names:
            return True
        return _norm_name(proc_name) in self.watch_names

    def _ctx_snapshot(self, ctx_provider: Optional[Any]) -> Dict[str, Any]:
        if not ctx_provider:
            return {}
        try:
            return (ctx_provider.snapshot() or {}) if hasattr(ctx_provider, "snapshot") else {}
        except Exception:
            return {}

    def _emit(self, evt: Dict[str, Any]) -> None:
        try:
            self.qm.enqueue_event(evt)
        except Exception:
            pass

    def _build_actor(self, proc_payload: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "user": proc_payload.get("username") or context.get("user"),
            "pid": proc_payload.get("pid"),
            "ppid": proc_payload.get("ppid"),
            "process": proc_payload.get("name"),
            "cmdline": proc_payload.get("cmdline"),
            "exe_path": proc_payload.get("exe"),
        }

    def _build_context(self, context: Dict[str, Any], proc_payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Keep foreground context from ctx_provider, but also ensure process fields are usable
        for rule consumers.
        """
        ctx = dict(context or {})
        ctx["fg_app"] = ctx.get("fg_app") or proc_payload.get("name")
        ctx["fg_process"] = ctx.get("fg_process") or proc_payload.get("name")
        ctx["fg_pid"] = ctx.get("fg_pid") or proc_payload.get("pid")
        ctx["fg_cmdline"] = ctx.get("fg_cmdline") or proc_payload.get("cmdline")
        ctx["fg_exe_path"] = ctx.get("fg_exe_path") or proc_payload.get("exe")
        return ctx

    def _base_event(
        self,
        event_type: str,
        severity: str,
        ts: float,
        process_payload: Dict[str, Any],
        context: Dict[str, Any],
        tool: Optional[str],
        tags: Optional[List[str]] = None,
        ioc_hits: Optional[List[Dict[str, str]]] = None,
    ) -> Dict[str, Any]:
        sample = _proc_sample(process_payload)
        built_ctx = self._build_context(context, process_payload)

        evt = {
            "type": event_type,
            "severity": severity,
            "source": "process",
            "ts": ts,
            "timestamp": _iso_utc(ts),
            "Timestamp": _iso_utc(ts),

            "context": built_ctx,
            "actor": self._build_actor(process_payload, built_ctx),
            "process": process_payload,

            "operation": {
                # important for your behavioral rule
                "op_type": "proc_start" if event_type == "proc_start" else "proc_end" if event_type == "proc_end" else "control",
                "tool": tool,
            },

            "object": {
                "path": process_payload.get("exe"),
                "dst_path": None,
                "name": process_payload.get("name"),
                "ext": Path(process_payload["exe"]).suffix.lower() if process_payload.get("exe") else None,
                "size": None,
                "hash_sha256": None,
                "signature": None,
                "drive": None,
                "volume_type": None,
                "old_ext": None,
                "new_ext": None,
                "sensitivity": "Sensitive" if ioc_hits else None,
            },

            "metrics": {
                "file_count": None,
                "row_count": None,
                "entropy": None,
            },
            "flags": {
                "password_protected": None,
            },
            "content": {
                "sample": sample,
                "sample_len": len(sample) if sample else None,
            },

            "tags": tags or [],
            "ioc_hits": ioc_hits or [],

            # legacy compatibility
            "Event_Type": "ProcessStart" if event_type == "proc_start" else "ProcessEnd" if event_type == "proc_end" else "Control",
            "Process_Name": process_payload.get("name"),
            "Process_ID": process_payload.get("pid"),
            "Parent_Process_ID": process_payload.get("ppid"),
            "Parent_Process_Name": process_payload.get("parent_name"),
            "Command_Line": process_payload.get("cmdline"),
            "Executable_Path": process_payload.get("exe"),

            "debug": {
                "evidence": {
                    "has_ioc_hits": bool(ioc_hits),
                    "ioc_count": len(ioc_hits or []),
                    "tag_count": len(tags or []),
                    "is_script_engine": "script_engine" in (tags or []),
                    "is_transfer_tool": "file_transfer_tool" in (tags or []),
                    "is_archive_tool": "archive_tool" in (tags or []),
                    "is_browser": "browser" in (tags or []),
                    "is_messaging_or_collab": "messaging_or_collab" in (tags or []),
                }
            },
        }
        return evt

    def _enrich_process(self, p: "psutil.Process", base: Dict[str, Any]) -> Dict[str, Any]:
        info = dict(base)

        exe = None
        try:
            exe = p.exe()
        except Exception:
            exe = None
        info["exe"] = exe

        if self.include_cmdline:
            try:
                cmd = p.cmdline()
                if isinstance(cmd, list):
                    cmd_str = " ".join(str(x) for x in cmd)
                else:
                    cmd_str = str(cmd)
                info["cmdline"] = _sanitize_cmdline(cmd_str, 4096)
            except Exception:
                info["cmdline"] = "<cmdline_error>"
        else:
            info["cmdline"] = None

        if self.include_username:
            try:
                info["username"] = p.username()
            except Exception:
                info["username"] = None
        else:
            info["username"] = None

        if self.include_parent:
            try:
                ppid = info.get("ppid")
                if isinstance(ppid, int) and ppid > 0:
                    parent = psutil.Process(ppid)
                    info["parent_name"] = parent.name()
                else:
                    info["parent_name"] = None
            except Exception:
                info["parent_name"] = None
        else:
            info["parent_name"] = None

        return info

    def run_loop(self, stop_event, ctx_provider: Optional[Any] = None) -> None:
        if psutil is None:
            ts = _now()
            self._emit(
                {
                    "type": "proc_sensor_error",
                    "severity": "warn",
                    "source": "process",
                    "ts": ts,
                    "timestamp": _iso_utc(ts),
                    "Timestamp": _iso_utc(ts),
                    "message": "psutil not available; install psutil to enable ProcessSensor",
                    "context": self._ctx_snapshot(ctx_provider),
                    "actor": {
                        "user": None,
                        "pid": None,
                        "ppid": None,
                        "process": None,
                        "cmdline": None,
                        "exe_path": None,
                    },
                    "operation": {"op_type": "control", "tool": "process"},
                    "object": {
                        "path": None,
                        "dst_path": None,
                        "name": None,
                        "ext": None,
                        "size": None,
                        "hash_sha256": None,
                        "signature": None,
                        "drive": None,
                        "volume_type": None,
                        "old_ext": None,
                        "new_ext": None,
                        "sensitivity": None,
                    },
                    "metrics": {"file_count": None, "row_count": None, "entropy": None},
                    "flags": {"password_protected": None},
                    "content": {"sample": None, "sample_len": None},
                    "tags": [],
                    "ioc_hits": [],
                    "debug": {"evidence": {"psutil_missing": True}},
                }
            )
            while not stop_event.is_set():
                time.sleep(1.0)
            return

        while not stop_event.is_set():
            now = _now()
            context = self._ctx_snapshot(ctx_provider)

            current: Dict[int, Dict[str, Any]] = {}
            try:
                for p in psutil.process_iter(attrs=["pid", "name", "ppid", "create_time"]):
                    try:
                        info = p.info or {}
                        pid = int(info.get("pid") or 0)
                        if pid <= 0:
                            continue
                        current[pid] = {
                            "pid": pid,
                            "ppid": info.get("ppid"),
                            "name": info.get("name"),
                            "create_time": info.get("create_time"),
                        }
                    except Exception:
                        continue
            except Exception:
                time.sleep(self.poll_interval_sec)
                continue

            known_set = set(self._known_pids.keys())
            current_set = set(current.keys())

            # -------------------------
            # proc_end
            # -------------------------
            dead_pids = known_set - current_set
            if dead_pids:
                for pid in list(dead_pids):
                    first_seen = self._known_pids.pop(pid, None)
                    cached = self._proc_cache.pop(pid, None)

                    if not self.emit_end:
                        continue

                    proc_payload: Dict[str, Any] = {"pid": pid, "first_seen_ts": first_seen}
                    if isinstance(cached, dict) and cached:
                        proc_payload.update(
                            {
                                "ppid": cached.get("ppid"),
                                "name": cached.get("name"),
                                "cmdline": cached.get("cmdline"),
                                "exe": cached.get("exe"),
                                "create_time": cached.get("create_time"),
                                "username": cached.get("username"),
                                "parent_name": cached.get("parent_name"),
                            }
                        )

                    tool = proc_payload.get("name") or None
                    evt = self._base_event(
                        event_type="proc_end",
                        severity="info",
                        ts=now,
                        process_payload=proc_payload,
                        context=context,
                        tool=tool,
                        tags=[],
                        ioc_hits=[],
                    )
                    self._emit(evt)

            # -------------------------
            # proc_start
            # -------------------------
            new_pids = list(current_set - known_set)
            if new_pids:
                emitted = 0
                for pid in new_pids:
                    if emitted >= self.max_new_per_tick:
                        break

                    base = current.get(pid) or {}
                    name = base.get("name")

                    self._known_pids[pid] = now
                    interesting = self._is_interesting(name)

                    cached = dict(base)

                    if interesting:
                        try:
                            p = psutil.Process(pid)
                            cached = self._enrich_process(p, cached)
                        except Exception:
                            pass

                    self._proc_cache[pid] = cached

                    if not interesting:
                        continue

                    exe_path = cached.get("exe")
                    tags = _tags_for_name_and_path(name, exe_path)

                    cmdline = cached.get("cmdline") or ""
                    ioc_hits = _cmdline_hits(cmdline)
                    severity = _severity_from_hits(ioc_hits, tags=tags)
                    tool = cached.get("name") or None

                    evt = self._base_event(
                        event_type="proc_start",
                        severity=severity,
                        ts=now,
                        process_payload=cached,
                        context=context,
                        tool=tool,
                        tags=tags,
                        ioc_hits=ioc_hits,
                    )
                    self._emit(evt)
                    emitted += 1

            if len(self._known_pids) > self.max_known_pids:
                items = sorted(self._known_pids.items(), key=lambda kv: kv[1], reverse=True)[: self.max_known_pids]
                keep = {pid for pid, _ in items}
                self._known_pids = dict(items)
                self._proc_cache = {pid: self._proc_cache.get(pid, {}) for pid in keep if pid in self._proc_cache}

            time.sleep(self.poll_interval_sec)