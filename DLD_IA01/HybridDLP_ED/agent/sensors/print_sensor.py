# agent/sensors/print_sensor.py
from __future__ import annotations

import time
import re
from typing import Any, Dict, Optional, List, Tuple

try:
    import win32evtlog  # type: ignore
except Exception:
    win32evtlog = None


def _now() -> float:
    return time.time()


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


def _ctx_snapshot(ctx_provider: Optional[Any]) -> Dict[str, Any]:
    if not ctx_provider:
        return {}
    try:
        return (ctx_provider.snapshot() or {}) if hasattr(ctx_provider, "snapshot") else {}
    except Exception:
        return {}


# ---------- Printer type heuristics ----------
_VIRTUAL_PRINTER_HINTS = [
    "microsoft print to pdf",
    "microsoft xps",
    "onenote",
    "pdf",
    "cutePDF",
    "foxit",
    "doPDF",
]

def _printer_type(printer_name: Optional[str]) -> Optional[str]:
    if not printer_name:
        return None
    p = printer_name.lower()
    if any(h in p for h in _VIRTUAL_PRINTER_HINTS):
        return "Virtual"
    return "Physical"


# ---------- Parsing heuristics for Event ID 307 ----------
_INT_RE = re.compile(r"^\s*\d+\s*$")

def _try_pick_int(tokens: List[str]) -> Optional[int]:
    for t in tokens:
        if t and _INT_RE.match(t):
            try:
                return int(t.strip())
            except Exception:
                continue
    return None

def _looks_like_user(s: str) -> bool:
    # e.g. DOMAIN\User or COMPUTER\User
    return ("\\" in s) and (1 <= len(s) <= 128)

def _looks_like_path(s: str) -> bool:
    # best-effort Windows path
    s2 = s.strip()
    return (len(s2) >= 3 and s2[1] == ":" and ("\\" in s2))

def _parse_307_inserts(inserts: List[Any]) -> Dict[str, Any]:
    """
    Best-effort mapping for Event ID 307 (Document printed).
    Inserts differ by Windows/driver, so:
      - keep raw inserts (truncated)
      - heuristically pick: user, printer, document
      - try derive page count if present as integer token
      - try derive printed_file_path if any insert looks like a file path
    """
    ins = [(_safe_str(x, 1024) or "") for x in (inserts or [])]
    ins = ins[:24]

    user = None
    printer = None
    doc = None
    printed_path = None
    page_count = None

    # 1) find user candidate
    for s in ins:
        if s and user is None and _looks_like_user(s):
            user = s

    # 2) find printer candidate (many drivers include printer name)
    # prefer tokens with "Microsoft", "Canon", "HP" or "PDF"
    for s in ins:
        if not s:
            continue
        sl = s.lower()
        if printer is None and (
            "microsoft" in sl or "canon" in sl or "hp" in sl or "epson" in sl or "brother" in sl or "pdf" in sl or "printer" in sl
        ):
            printer = s

    # 3) find path candidate
    for s in ins:
        if s and _looks_like_path(s):
            printed_path = s
            break

    # 4) document name (fallback)
    for s in ins:
        if not s:
            continue
        if s == user or s == printer or s == printed_path:
            continue
        if doc is None:
            doc = s
            break

    # 5) page count candidate (if any token is numeric)
    page_count = _try_pick_int(ins)

    return {
        "event_id": 307,
        "inserts": ins,
        "document_name": doc,
        "printer_name": printer,
        "user_hint": user,
        "printed_file_path_hint": printed_path,
        "page_count_hint": page_count,
    }


class PrintSensor:
    """
    SCREENSHOT / PRINT SENSOR - Print part (L1)

    Scope:
      - Monitor PRINT events (incl. Print to PDF) via Windows Event Log
      - No file hashing (handled by FileSystemSensor)
      - No USB logic (handled by I/O sensor)
      - No clipboard logic (handled by ClipboardSensor)
      - No risk score (handled by correlator)

    Source log:
      Microsoft-Windows-PrintService/Operational
      NOTE: must be enabled in Event Viewer.

    Emits:
      - print_job
      - print_sensor_error
    """

    def __init__(
        self,
        queue_manager,
        poll_interval_sec: float = 1.0,
        channel: str = "Microsoft-Windows-PrintService/Operational",
        max_events_per_tick: int = 200,
        lookback_records: int = 2048,
        source: str = "print",
    ):
        self.qm = queue_manager
        self.poll_interval_sec = float(poll_interval_sec)
        self.channel = channel
        self.max_events_per_tick = int(max_events_per_tick)
        self.lookback_records = int(lookback_records)
        self.source = str(source)

        self._last_record_number: Optional[int] = None

    def _emit(self, evt: Dict[str, Any]) -> None:
        try:
            self.qm.enqueue_event(evt)
        except Exception:
            pass

    def run_loop(self, stop_event, ctx_provider: Optional[Any] = None) -> None:
        if win32evtlog is None:
            self._emit(
                {
                    "type": "print_sensor_error",
                    "severity": "warn",
                    "source": self.source,
                    "message": "pywin32 not available; install pywin32 to enable PrintSensor",
                    "ts": _now(),
                    "context": _ctx_snapshot(ctx_provider),
                    "operation": {"op_type": "control", "tool": None},
                }
            )
            while not stop_event.is_set():
                time.sleep(1.0)
            return

        server = "localhost"
        try:
            handle = win32evtlog.OpenEventLog(server, self.channel)
        except Exception:
            self._emit(
                {
                    "type": "print_sensor_error",
                    "severity": "warn",
                    "source": self.source,
                    "message": f"cannot open event log: {self.channel}. Enable 'PrintService/Operational' log in Event Viewer.",
                    "ts": _now(),
                    "context": _ctx_snapshot(ctx_provider),
                    "operation": {"op_type": "control", "tool": None},
                }
            )
            while not stop_event.is_set():
                time.sleep(2.0)
            return

        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

        while not stop_event.is_set():
            context = _ctx_snapshot(ctx_provider)

            try:
                batch = win32evtlog.ReadEventLog(handle, flags, 0) or []
            except Exception:
                time.sleep(self.poll_interval_sec)
                continue

            new_events: List[Any] = []
            max_rn = self._last_record_number or 0

            for ev in batch:
                try:
                    rn = int(ev.RecordNumber)
                except Exception:
                    continue

                if self._last_record_number is not None and rn <= self._last_record_number:
                    break

                if self._last_record_number is None and len(new_events) >= self.lookback_records:
                    break

                new_events.append(ev)
                if rn > max_rn:
                    max_rn = rn

                if len(new_events) >= self.max_events_per_tick:
                    break

            for ev in reversed(new_events):
                try:
                    eid = int(ev.EventID & 0xFFFF)
                    rn = int(ev.RecordNumber)
                except Exception:
                    continue

                if eid != 307:
                    continue

                try:
                    inserts = list(ev.StringInserts or [])
                except Exception:
                    inserts = []

                payload = _parse_307_inserts(inserts)
                payload["record_number"] = rn

                ts_gen_unix = None
                try:
                    ts_gen_unix = float(ev.TimeGenerated.timestamp())
                except Exception:
                    ts_gen_unix = None

                printer_name = _safe_str(payload.get("printer_name"), 256)
                printer_type = _printer_type(printer_name)

                # report fields (E. Print / Print to PDF)
                Print_Process = "spoolsv.exe"
                Application_Source = context.get("fg_app") or context.get("fg_process")
                Printer_Type = printer_type
                Printed_File_Path = payload.get("printed_file_path_hint")  # may be None
                Page_Count = payload.get("page_count_hint")
                Print_Timestamp = ts_gen_unix or _now()

                # Printed_Content_Sensit.: L1 can't OCR/inspect; leave None and let correlator/rule/ML fill later
                Printed_Content_Sensit = None

                event_out: Dict[str, Any] = {
                    # canonical-ish
                    "type": "print_job",
                    "severity": "warn",
                    "source": self.source,
                    "ts": _now(),  # time sensor emitted
                    "context": context,
                    "operation": {"op_type": "print_job", "tool": Print_Process},
                    "actor": {"user": payload.get("user_hint"), "pid": None, "ppid": None, "process": None, "cmdline": None},

                    # object bucket (print is not file hashing; no File_Hash here)
                    "object": {
                        "path": Printed_File_Path,  # best-effort
                        "dst_path": None,
                        "ext": None,
                        "size": None,
                        "mtime": None,
                        "exists": None,
                        "drive": None,
                        "volume_type": None,
                        "volume_label": None,
                        "old_ext": None,
                        "new_ext": None,
                        "signature": None,
                        "hash_sha256": None,
                    },

                    # metrics placeholders
                    "metrics": {"file_count": None, "row_count": None, "entropy": None},
                    "flags": {"password_protected": None},
                    "content": {"sample": None, "sample_len": None},

                    # ---- REPORT FIELDS: Print / Print to PDF (E) ----
                    "Print_Process": Print_Process,
                    "Application_Source": Application_Source,
                    "Printer_Type": Printer_Type,
                    "Printed_File_Path": Printed_File_Path,
                    "Printed_Content_Sensit.": Printed_Content_Sensit,
                    "Page_Count": Page_Count,
                    "Print_Timestamp": Print_Timestamp,

                    # forensic payload
                    "print": {
                        "event_id": payload.get("event_id"),
                        "record_number": payload.get("record_number"),
                        "document_name": payload.get("document_name"),
                        "printer_name": printer_name,
                        "printer_type": printer_type,
                        "ts_generated_unix": ts_gen_unix,
                        "raw_inserts": payload.get("inserts"),
                    },
                }

                self._emit(event_out)

            if max_rn > 0:
                self._last_record_number = max_rn

            time.sleep(self.poll_interval_sec)

        try:
            win32evtlog.CloseEventLog(handle)
        except Exception:
            pass