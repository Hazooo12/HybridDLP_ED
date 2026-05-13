from __future__ import annotations

from typing import Any, Dict, Optional
from datetime import datetime, timezone
import copy
import uuid
import re


# -----------------------------
# time parsing
# -----------------------------
def _to_unix(ts: Any) -> float:
    """
    Best-effort timestamp -> unix float seconds.
    Accept:
      - None
      - int/float
      - ISO 8601 string (with/without timezone, 'Z')
      - 'YYYY-MM-DD HH:MM:SS(.ms)' (report style)
    """
    if ts is None:
        return datetime.now(timezone.utc).timestamp()

    if isinstance(ts, (int, float)):
        try:
            return float(ts)
        except Exception:
            return datetime.now(timezone.utc).timestamp()

    s = str(ts).strip()
    if not s:
        return datetime.now(timezone.utc).timestamp()

    if s.endswith("Z"):
        s = s[:-1] + "+00:00"

    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except Exception:
        return datetime.now(timezone.utc).timestamp()


def _to_iso_utc(ts: Any) -> str:
    try:
        return datetime.fromtimestamp(_to_unix(ts), tz=timezone.utc).isoformat()
    except Exception:
        return datetime.now(timezone.utc).isoformat()


# -----------------------------
# severity normalization
# -----------------------------
def _sev_int_to_str(v: int) -> str:
    """
    Map 0..100 -> low/info/warn/high
      0..29   -> low
      30..59  -> info
      60..79  -> warn
      80..100 -> high
    """
    v = max(0, min(100, int(v)))
    if v >= 80:
        return "high"
    if v >= 60:
        return "warn"
    if v >= 30:
        return "info"
    return "low"


def _sev_to_str(sev: Any) -> str:
    """
    Accept:
      - int 0..100
      - strings: critical/crit/high/warn/info/low/debug/trace
    """
    if isinstance(sev, bool):
        return "info"

    if isinstance(sev, int):
        return _sev_int_to_str(sev)

    if isinstance(sev, float):
        try:
            return _sev_int_to_str(int(sev))
        except Exception:
            return "info"

    s = str(sev or "").strip().lower()
    if s in ("critical", "crit"):
        return "high"
    if s in ("high",):
        return "high"
    if s in ("warn", "warning", "medium"):
        return "warn"
    if s in ("info",):
        return "info"
    if s in ("low", "debug", "trace"):
        return "low"
    return "info"


def _sev_to_int(sev: Any) -> int:
    if isinstance(sev, bool):
        return 30
    if isinstance(sev, int):
        return max(0, min(100, sev))
    s = str(sev or "").strip().lower()
    if s in ("critical", "crit"):
        return 95
    if s in ("high",):
        return 85
    if s in ("warn", "warning", "medium"):
        return 70
    if s in ("info", "low"):
        return 30
    if s in ("debug", "trace"):
        return 10
    return 30


# -----------------------------
# lightweight helpers
# -----------------------------
def _as_dict(v: Any) -> Dict[str, Any]:
    return v if isinstance(v, dict) else {}


def _coalesce(*vals: Any) -> Any:
    for v in vals:
        if v is not None and v != "":
            return v
    return None


def _safe_int(v: Any) -> Optional[int]:
    try:
        if v is None or v == "":
            return None
        return int(v)
    except Exception:
        return None


def _safe_float(v: Any) -> Optional[float]:
    try:
        if v is None or v == "":
            return None
        return float(v)
    except Exception:
        return None


def _norm_str(v: Any, max_len: int = 2048) -> Optional[str]:
    if v is None:
        return None
    try:
        s = str(v).strip()
        if not s:
            return None
        if len(s) > max_len:
            s = s[:max_len]
        return s
    except Exception:
        return None


def _norm_domain(v: Any) -> Optional[str]:
    s = _norm_str(v, 512)
    if not s:
        return None
    s = s.lower()
    s = s.replace("https://", "").replace("http://", "")
    s = s.split("/", 1)[0].strip()
    s = s.strip("[](){}<>;:,'\" ")
    if ":" in s and s.count(":") == 1:
        host, port = s.split(":", 1)
        if port.isdigit():
            s = host.strip()
    if not s:
        return None
    return s


def _is_ip_literal(s: Optional[str]) -> bool:
    if not s:
        return False
    return bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", s))


def _ensure_block(e: Dict[str, Any], key: str) -> Dict[str, Any]:
    if not isinstance(e.get(key), dict):
        e[key] = {}
    return e[key]


def _derive_text_len(e: Dict[str, Any]) -> Optional[int]:
    clipboard = _as_dict(e.get("clipboard"))
    content = _as_dict(e.get("content"))
    obj = _as_dict(e.get("object"))

    return _coalesce(
        _safe_int(clipboard.get("text_len")),
        _safe_int(clipboard.get("content_len")) if clipboard.get("content_type") == "Text" else None,
        _safe_int(obj.get("text_len")),
        len(content.get("sample")) if isinstance(content.get("sample"), str) else None,
    )


def _derive_object_sensitivity(e: Dict[str, Any]) -> Optional[str]:
    obj = _as_dict(e.get("object"))
    if obj.get("sensitivity"):
        return _norm_str(obj.get("sensitivity"), 128)

    file_sens = e.get("File_Sensitivity")
    if file_sens:
        return _norm_str(file_sens, 128)

    clipboard = _as_dict(e.get("clipboard"))
    sig = _norm_str(clipboard.get("signature"), 128)
    ioc_hits = e.get("ioc_hits") or []
    entropy = _safe_float(_as_dict(e.get("metrics")).get("entropy"))
    content_len = _safe_int(clipboard.get("content_len"))

    if ioc_hits:
        return "Sensitive"
    if sig in {"looks_like_email", "looks_like_base64", "looks_like_digits_13_19"}:
        return "Sensitive"
    if entropy is not None and entropy >= 4.3 and (content_len or 0) >= 80:
        return "Highly Sensitive"
    if (content_len or 0) >= 500:
        return "Sensitive"
    return None


def _normalize_actor_context_operation(e: Dict[str, Any]) -> None:
    actor = _ensure_block(e, "actor")
    context = _ensure_block(e, "context")
    operation = _ensure_block(e, "operation")

    # actor
    actor["user"] = _coalesce(actor.get("user"), actor.get("username"), context.get("user"))
    actor["username"] = _coalesce(actor.get("username"), actor.get("user"))
    actor["pid"] = _coalesce(actor.get("pid"), context.get("fg_pid"))
    actor["process"] = _coalesce(
        actor.get("process"),
        context.get("fg_process"),
        context.get("fg_app"),
        operation.get("tool"),
    )
    actor["cmdline"] = _coalesce(actor.get("cmdline"), context.get("fg_cmdline"))
    actor["exe"] = _coalesce(actor.get("exe"), actor.get("exe_path"), context.get("fg_exe_path"))

    # context
    context["fg_app"] = _coalesce(context.get("fg_app"), context.get("fg_process"), actor.get("process"))
    context["fg_process"] = _coalesce(context.get("fg_process"), context.get("fg_app"), actor.get("process"))
    context["fg_pid"] = _coalesce(context.get("fg_pid"), actor.get("pid"))
    context["fg_cmdline"] = _coalesce(context.get("fg_cmdline"), actor.get("cmdline"))
    context["fg_exe_path"] = _coalesce(context.get("fg_exe_path"), actor.get("exe"), actor.get("exe_path"))

    # operation
    operation["op_type"] = _coalesce(operation.get("op_type"), e.get("type"), "unknown")
    operation["tool"] = _coalesce(operation.get("tool"), context.get("fg_app"), context.get("fg_process"), actor.get("process"))


def _normalize_domain_fields(e: Dict[str, Any]) -> None:
    context = _ensure_block(e, "context")
    clipboard = _ensure_block(e, "clipboard")
    network = _ensure_block(e, "network")

    # priority:
    #   clipboard.dest_domain
    #   network.dest_domain
    #   context.dest_domain
    #   context.fg_domain
    #   context.domain
    best = _coalesce(
        _norm_domain(clipboard.get("dest_domain")),
        _norm_domain(network.get("dest_domain")),
        _norm_domain(context.get("dest_domain")),
        _norm_domain(context.get("fg_domain")),
        _norm_domain(context.get("domain")),
        _norm_domain(context.get("fg_url_hint")),
    )

    # If "domain" is actually IP, keep dest_ip separate and avoid pretending it's a friendly domain
    if best and _is_ip_literal(best):
        if not network.get("dest_ip"):
            network["dest_ip"] = best

    context["fg_domain"] = _coalesce(_norm_domain(context.get("fg_domain")), best)
    context["domain"] = _coalesce(_norm_domain(context.get("domain")), best)
    context["dest_domain"] = _coalesce(_norm_domain(context.get("dest_domain")), best)
    context["fg_url_hint"] = _coalesce(_norm_domain(context.get("fg_url_hint")), best)

    clipboard["dest_domain"] = _coalesce(_norm_domain(clipboard.get("dest_domain")), context.get("dest_domain"), network.get("dest_domain"))
    network["dest_domain"] = _coalesce(_norm_domain(network.get("dest_domain")), clipboard.get("dest_domain"), context.get("dest_domain"))

    # normalize URL if present
    if network.get("dest_url"):
        network["dest_url"] = _norm_str(network.get("dest_url"), 2048)


def _normalize_clipboard_fields(e: Dict[str, Any]) -> None:
    clipboard = _ensure_block(e, "clipboard")
    context = _ensure_block(e, "context")
    actor = _ensure_block(e, "actor")
    obj = _ensure_block(e, "object")
    content = _ensure_block(e, "content")
    metrics = _ensure_block(e, "metrics")

    clipboard["content_type"] = _coalesce(clipboard.get("content_type"), "Unknown")
    clipboard["dest_app"] = _coalesce(clipboard.get("dest_app"), context.get("fg_app"), context.get("fg_process"), actor.get("process"))
    clipboard["dest_process"] = _coalesce(clipboard.get("dest_process"), context.get("fg_process"), context.get("fg_app"), actor.get("process"))
    clipboard["active_window_title"] = _coalesce(clipboard.get("active_window_title"), context.get("window_title"))
    clipboard["dest_window_title"] = _coalesce(clipboard.get("dest_window_title"), context.get("window_title"))
    clipboard["window_process_name"] = _coalesce(clipboard.get("window_process_name"), context.get("fg_process"), context.get("fg_app"), actor.get("process"))

    if clipboard.get("content_type") == "Text":
        clipboard["text_len"] = _coalesce(_safe_int(clipboard.get("text_len")), _safe_int(clipboard.get("content_len")))
    else:
        clipboard["text_len"] = _coalesce(_safe_int(clipboard.get("text_len")), None)

    # content fallback
    if not content.get("sample"):
        content["sample"] = _coalesce(clipboard.get("text_file"), clipboard.get("content"))
    if content.get("sample") is not None and content.get("sample_len") is None and isinstance(content.get("sample"), str):
        content["sample_len"] = len(content["sample"])

    # object.text_len
    obj["text_len"] = _coalesce(_safe_int(obj.get("text_len")), _derive_text_len(e))

    # metrics.entropy preserve if already there
    metrics["entropy"] = _coalesce(_safe_float(metrics.get("entropy")), None)

    # snapshot_linked normalize bool-ish
    if clipboard.get("snapshot_linked") is None:
        clipboard["snapshot_linked"] = bool(
            clipboard.get("copy_ts") and clipboard.get("content_hash")
        )


def _normalize_network_fields(e: Dict[str, Any]) -> None:
    network = _ensure_block(e, "network")
    metrics = _ensure_block(e, "metrics")

    network["protocol_type"] = _coalesce(network.get("protocol_type"), None)
    network["dest_ip"] = _coalesce(_norm_str(network.get("dest_ip"), 128), None)
    network["dest_domain"] = _coalesce(_norm_domain(network.get("dest_domain")), network.get("dest_ip"))
    network["dst_port"] = _coalesce(_safe_int(network.get("dst_port")), None)
    network["method"] = _coalesce(_norm_str(network.get("method"), 32), None)
    network["content_type"] = _coalesce(_norm_str(network.get("content_type"), 256), None)

    # bytes
    network["bytes_sent_total"] = _coalesce(_safe_int(network.get("bytes_sent_total")), _safe_int(metrics.get("bytes_out")))
    network["bytes_out_total"] = _coalesce(_safe_int(network.get("bytes_out_total")), _safe_int(network.get("bytes_sent_total")), _safe_int(metrics.get("bytes_out")))
    network["bytes_in_total"] = _coalesce(_safe_int(network.get("bytes_in_total")), _safe_int(metrics.get("bytes_in")))

    metrics["bytes_out"] = _coalesce(_safe_int(metrics.get("bytes_out")), _safe_int(network.get("bytes_out_total")))
    metrics["bytes_in"] = _coalesce(_safe_int(metrics.get("bytes_in")), _safe_int(network.get("bytes_in_total")))

    network["packets_total"] = _coalesce(_safe_int(network.get("packets_total")), _safe_int(metrics.get("packets_total")))
    network["packets_out_total"] = _coalesce(_safe_int(network.get("packets_out_total")), _safe_int(metrics.get("packets_out_total")))
    network["packets_in_total"] = _coalesce(_safe_int(network.get("packets_in_total")), _safe_int(metrics.get("packets_in_total")))
    network["session_duration_sec"] = _coalesce(_safe_float(network.get("session_duration_sec")), _safe_float(metrics.get("session_duration_sec")))

    if network.get("external_dst") is None:
        dip = _norm_str(network.get("dest_ip"), 128)
        dd = _norm_domain(network.get("dest_domain"))
        if dip or dd:
            network["external_dst"] = True


def _normalize_object_fields(e: Dict[str, Any]) -> None:
    obj = _ensure_block(e, "object")
    clipboard = _ensure_block(e, "clipboard")

    obj["path"] = _coalesce(_norm_str(obj.get("path"), 2048), _norm_str(e.get("file_path"), 2048))
    obj["dst_path"] = _coalesce(_norm_str(obj.get("dst_path"), 2048), _norm_str(e.get("dst_path"), 2048))
    obj["drive"] = _coalesce(_norm_str(obj.get("drive"), 64), _norm_str(obj.get("dest_drive"), 64))
    obj["volume_type"] = _coalesce(_norm_str(obj.get("volume_type"), 64), _norm_str(e.get("Dest_Volume_Type"), 64))
    obj["text_len"] = _coalesce(_safe_int(obj.get("text_len")), _safe_int(clipboard.get("text_len")))
    obj["sensitivity"] = _coalesce(_norm_str(obj.get("sensitivity"), 128), _derive_object_sensitivity(e))


def _backfill_legacy_aliases(e: Dict[str, Any]) -> None:
    """
    Keep old report/legacy fields aligned with canonical blocks so behavioral rules
    keep working even when a specific sensor only emits canonical structure.
    """
    obj = _ensure_block(e, "object")
    metrics = _ensure_block(e, "metrics")
    flags = _ensure_block(e, "flags")
    clipboard = _ensure_block(e, "clipboard")
    network = _ensure_block(e, "network")
    pr = _ensure_block(e, "print")
    operation = _ensure_block(e, "operation")

    # File/object aliases
    e["File_Path"] = _coalesce(e.get("File_Path"), obj.get("path"))
    e["Dest_Path"] = _coalesce(e.get("Dest_Path"), obj.get("dst_path"), e.get("dst_path"))
    e["File_Sensitivity"] = _coalesce(e.get("File_Sensitivity"), obj.get("sensitivity"))
    e["Old_Extension"] = _coalesce(e.get("Old_Extension"), obj.get("old_ext"))
    e["New_Extension"] = _coalesce(e.get("New_Extension"), obj.get("new_ext"))
    e["Dest_Volume_Type"] = _coalesce(e.get("Dest_Volume_Type"), obj.get("dest_volume_type"), obj.get("volume_type"))
    e["Source_Drive"] = _coalesce(e.get("Source_Drive"), obj.get("src_drive"), obj.get("drive"))
    e["Dest_Drive"] = _coalesce(e.get("Dest_Drive"), obj.get("dest_drive"), obj.get("drive"))

    # Generic metrics/flags aliases
    e["File_Count"] = _coalesce(e.get("File_Count"), metrics.get("file_count"))
    e["Password_Flag"] = _coalesce(e.get("Password_Flag"), flags.get("password_protected"))

    # Clipboard aliases used by some rules/reporters
    if e.get("content") is None or not isinstance(e.get("content"), dict):
        e["content"] = {}
    e["content"]["sample"] = _coalesce(e["content"].get("sample"), clipboard.get("text_file"), clipboard.get("content"))
    e["content"]["sample_len"] = _coalesce(
        e["content"].get("sample_len"),
        len(e["content"]["sample"]) if isinstance(e["content"].get("sample"), str) else None,
    )

    # Network aliases
    if "file_path" not in e or not e.get("file_path"):
        e["file_path"] = _coalesce(obj.get("path"), e.get("File_Path"))
    if "dest_domain" not in e or not e.get("dest_domain"):
        e["dest_domain"] = _coalesce(network.get("dest_domain"), _ensure_block(e, "context").get("dest_domain"))

    # Print aliases
    e["Printed_File_Path"] = _coalesce(e.get("Printed_File_Path"), pr.get("printed_file_path"), pr.get("printed_file_path_hint"), obj.get("path"))
    e["Printer_Type"] = _coalesce(e.get("Printer_Type"), pr.get("printer_type"))
    e["Application_Source"] = _coalesce(e.get("Application_Source"), operation.get("tool"))


def _normalize_top_level(e: Dict[str, Any]) -> None:
    if not e.get("event_id"):
        e["event_id"] = str(uuid.uuid4())

    e.setdefault("type", "unknown")
    e.setdefault("source", "unknown")
    e["ts"] = _to_unix(e.get("ts"))
    e["timestamp"] = _to_iso_utc(e.get("timestamp") or e.get("ts"))

    if "ioc_hits" not in e or not isinstance(e.get("ioc_hits"), list):
        e["ioc_hits"] = []

    if "tags" not in e or not isinstance(e.get("tags"), list):
        e["tags"] = []


def _ensure_schema_blocks(e: Dict[str, Any]) -> None:
    for k in (
        "device",
        "actor",
        "operation",
        "object",
        "context",
        "metrics",
        "flags",
        "content",
        "clipboard",
        "usb",
        "print",
        "network",
        "decision",
        "debug",
    ):
        _ensure_block(e, k)


# -----------------------------
# adapters
# -----------------------------
def adapt_for_queue(evt: Dict[str, Any]) -> Dict[str, Any]:
    """
    Adapter for QueueManager + behavioral rules:
      - ensure stable top-level fields
      - keep raw_original
      - normalize important subfields so rules don't miss due to naming/null drift
      - keep severity as string for queue uniformity
    """
    e = copy.deepcopy(evt) if isinstance(evt, dict) else {}

    # Preserve original before normalization
    if "raw_original" not in e:
        e["raw_original"] = copy.deepcopy(e)

    _normalize_top_level(e)
    _ensure_schema_blocks(e)

    _normalize_actor_context_operation(e)
    _normalize_domain_fields(e)
    _normalize_clipboard_fields(e)
    _normalize_network_fields(e)
    _normalize_object_fields(e)
    _backfill_legacy_aliases(e)

    e["severity"] = _sev_to_str(e.get("severity"))

    return e


def adapt_for_legacy_sinks(evt: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compatibility helper for old JSONL/SQLite sinks.
    """
    return adapt_for_queue(evt)


def adapt_severity_to_int(evt: Dict[str, Any]) -> Dict[str, Any]:
    """
    Optional utility: if you ever need to convert severity to int (0..100)
    before passing to canonicalize_event().
    """
    e = adapt_for_queue(evt)
    e["severity"] = _sev_to_int(e.get("severity"))
    return e