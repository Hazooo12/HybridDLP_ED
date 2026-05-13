from __future__ import annotations

from typing import Any, Dict, Optional
from datetime import datetime, timezone

from agent.event_schema import normalize_event, severity_to_int
from agent.device_info import get_device_info


def _iso(ts: Any) -> str:
    if ts is None:
        return datetime.now(timezone.utc).isoformat()
    if isinstance(ts, (int, float)):
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat()
    s = str(ts).strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    return s


def _pick_user(evt: Dict[str, Any]) -> Optional[str]:
    actor = evt.get("actor")
    if isinstance(actor, dict) and actor.get("user"):
        return str(actor["user"])

    ctx = evt.get("context")
    if isinstance(ctx, dict) and ctx.get("user"):
        return str(ctx["user"])

    proc = evt.get("process")
    if isinstance(proc, dict) and proc.get("username"):
        return str(proc["username"])

    return None


def _legacy_fg_app(ctx: Dict[str, Any]) -> Optional[str]:
    v = ctx.get("fg_app") or ctx.get("fg_process")
    return None if v is None else str(v)


def _first_non_empty(*values: Any) -> Any:
    for v in values:
        if v is None:
            continue
        if isinstance(v, str) and not v.strip():
            continue
        return v
    return None


def _ensure_device(evt: Dict[str, Any]) -> Dict[str, str]:
    d = evt.get("device") if isinstance(evt.get("device"), dict) else {}
    if not d.get("host_name") or not d.get("device_id"):
        d = get_device_info()
    return {
        "host_name": str(d.get("host_name") or "unknown"),
        "device_id": str(d.get("device_id") or "unknown-device"),
    }


def _derive_operation(etype: str, source: str, evt: Dict[str, Any]) -> Dict[str, Any]:
    """
    Important:
    - If sensor already emitted operation.*, preserve it.
    - Only derive when operation is missing/empty.
    """
    op = evt.get("operation") if isinstance(evt.get("operation"), dict) else {}
    if op and (op.get("op_type") is not None or op.get("tool") is not None):
        return {
            "op_type": op.get("op_type"),
            "tool": op.get("tool"),
        }

    tool = None
    legacy_proc = evt.get("process") if isinstance(evt.get("process"), dict) else {}
    actor = evt.get("actor") if isinstance(evt.get("actor"), dict) else {}
    ctx = evt.get("context") if isinstance(evt.get("context"), dict) else {}

    if actor.get("process"):
        tool = str(actor.get("process"))
    elif legacy_proc.get("name"):
        tool = str(legacy_proc.get("name"))
    elif ctx.get("fg_process") or ctx.get("fg_app"):
        tool = str(ctx.get("fg_process") or ctx.get("fg_app"))

    if etype == "proc_start":
        return {"op_type": "proc_start", "tool": tool}
    if etype == "proc_end":
        return {"op_type": "proc_end", "tool": tool}
    if etype in ("usb_connected", "usb_disconnected"):
        return {"op_type": "usb_connect" if etype == "usb_connected" else "usb_disconnect", "tool": "usb"}
    if etype in ("clipboard_copy", "clipboard_paste", "clipboard_text"):
        return {"op_type": etype, "tool": tool}
    if etype in ("network_flow_summary", "net_flow_summary"):
        return {"op_type": "network_flow", "tool": tool}
    if etype in (
        "network_upload_summary",
        "http_upload",
        "cloud_exfiltration",
        "data_exfiltration",
        "network_upload",
        "browser_upload",
        "file_upload",
    ):
        return {"op_type": etype, "tool": tool}
    if etype == "print_job":
        return {"op_type": "print_job", "tool": tool or "spoolsv.exe"}
    if etype == "heartbeat":
        return {"op_type": "control", "tool": None}
    if etype == "shutdown":
        return {"op_type": "control", "tool": None}

    return {"op_type": None, "tool": tool}


def canonicalize_event(evt: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert ANY L1 event (legacy or already-normalized) to canonical schema.
    - Keeps forensic originals in raw_original + raw_envelope
    - Tries hard to preserve all useful fields from sensors
    """
    if not isinstance(evt, dict):
        evt = {"type": "unknown", "source": "unknown", "ts": None}

    raw_original = dict(evt)
    evt = {k: v for k, v in evt.items() if not str(k).startswith("_")}

    etype = str(evt.get("type") or "unknown")
    source = str(evt.get("source") or "unknown")

    ts_iso = _iso(evt.get("ts"))
    sev_int = severity_to_int(evt.get("severity", 0), 0)

    device = _ensure_device(evt)

    legacy_ctx = evt.get("context") if isinstance(evt.get("context"), dict) else {}
    ctx = {
        "user": legacy_ctx.get("user"),
        "fg_app": _legacy_fg_app(legacy_ctx) if isinstance(legacy_ctx, dict) else None,
        "fg_process": legacy_ctx.get("fg_process") if isinstance(legacy_ctx, dict) else None,
        "fg_pid": legacy_ctx.get("fg_pid") if isinstance(legacy_ctx, dict) else None,
        "fg_cmdline": legacy_ctx.get("fg_cmdline") if isinstance(legacy_ctx, dict) else None,
        "fg_exe_path": legacy_ctx.get("fg_exe_path") if isinstance(legacy_ctx, dict) else None,
        "fg_hwnd": legacy_ctx.get("fg_hwnd") if isinstance(legacy_ctx, dict) else None,
        "fg_tid": legacy_ctx.get("fg_tid") if isinstance(legacy_ctx, dict) else None,
        "window_title": legacy_ctx.get("window_title") if isinstance(legacy_ctx, dict) else None,
        "window_title_lc": legacy_ctx.get("window_title_lc") if isinstance(legacy_ctx, dict) else None,
        "session": legacy_ctx.get("session") if isinstance(legacy_ctx, dict) else None,
        "process_tags": legacy_ctx.get("process_tags") if isinstance(legacy_ctx, dict) else None,
        "outside_working_hours": legacy_ctx.get("outside_working_hours") if isinstance(legacy_ctx, dict) else None,
        "fg_domain": legacy_ctx.get("fg_domain") if isinstance(legacy_ctx, dict) else None,
        "domain": legacy_ctx.get("domain") if isinstance(legacy_ctx, dict) else None,
        "dest_domain": legacy_ctx.get("dest_domain") if isinstance(legacy_ctx, dict) else None,
        "fg_url_hint": legacy_ctx.get("fg_url_hint") if isinstance(legacy_ctx, dict) else None,
        "net_snapshot": legacy_ctx.get("net_snapshot") if isinstance(legacy_ctx, dict) else None,
    }

    actor0 = evt.get("actor") if isinstance(evt.get("actor"), dict) else {}
    legacy_proc = evt.get("process") if isinstance(evt.get("process"), dict) else {}

    actor = {
        "user": actor0.get("user") or _pick_user(evt),
        "username": actor0.get("username") or actor0.get("user") or legacy_proc.get("username"),
        "pid": actor0.get("pid") or legacy_proc.get("pid") or ctx.get("fg_pid"),
        "ppid": actor0.get("ppid") or legacy_proc.get("ppid"),
        "process": actor0.get("process") or legacy_proc.get("name") or ctx.get("fg_process") or ctx.get("fg_app"),
        "exe": actor0.get("exe") or actor0.get("exe_path") or legacy_proc.get("exe") or ctx.get("fg_exe_path"),
        "cmdline": actor0.get("cmdline") or legacy_proc.get("cmdline") or ctx.get("fg_cmdline"),
    }

    derived_op = _derive_operation(etype, source, evt)
    op_sensor = evt.get("operation") if isinstance(evt.get("operation"), dict) else {}
    operation = dict(derived_op)
    for k, v in op_sensor.items():
        if v is not None:
            operation[k] = v
    if not operation.get("op_type"):
        operation["op_type"] = derived_op.get("op_type")
    if operation.get("tool") is None:
        operation["tool"] = derived_op.get("tool")

    legacy_file = evt.get("file") if isinstance(evt.get("file"), dict) else {}
    obj0 = evt.get("object") if isinstance(evt.get("object"), dict) else {}

    obj = {
        "path": evt.get("path") or evt.get("file_path") or legacy_file.get("path") or obj0.get("path") or evt.get("File_Path"),
        "dst_path": evt.get("dst_path") or legacy_file.get("dst_path") or obj0.get("dst_path") or evt.get("Dest_Path"),
        "name": obj0.get("name") or evt.get("File_Name"),
        "ext": evt.get("ext") or legacy_file.get("ext") or obj0.get("ext") or evt.get("File_Extension"),
        "size": evt.get("size") or legacy_file.get("size") or obj0.get("size") or evt.get("File_Size"),
        "mtime": evt.get("mtime") or legacy_file.get("mtime") or obj0.get("mtime"),
        "exists": evt.get("exists") if "exists" in evt else legacy_file.get("exists") if "exists" in legacy_file else obj0.get("exists"),
        "drive": evt.get("drive") or legacy_file.get("drive") or obj0.get("drive"),
        "volume_type": evt.get("volume_type") or legacy_file.get("volume_type") or obj0.get("volume_type") or evt.get("Dest_Volume_Type"),
        "volume_label": evt.get("volume_label") or legacy_file.get("volume_label") or obj0.get("volume_label"),

        "src_drive": obj0.get("src_drive") or evt.get("Source_Drive"),
        "src_volume_type": obj0.get("src_volume_type") or evt.get("Source_Volume_Type"),
        "dest_drive": obj0.get("dest_drive") or evt.get("Dest_Drive"),
        "dest_volume_type": obj0.get("dest_volume_type") or evt.get("Dest_Volume_Type"),

        "old_ext": evt.get("old_ext") or legacy_file.get("old_ext") or obj0.get("old_ext") or evt.get("Old_Extension"),
        "new_ext": evt.get("new_ext") or legacy_file.get("new_ext") or obj0.get("new_ext") or evt.get("New_Extension"),
        "signature": evt.get("signature") or legacy_file.get("signature") or obj0.get("signature") or evt.get("File_Signature"),
        "hash_sha256": evt.get("hash_sha256") or legacy_file.get("hash_sha256") or obj0.get("hash_sha256") or evt.get("File_Hash"),
        "hash_sha256_partial": obj0.get("hash_sha256_partial") or evt.get("File_Hash_Partial"),
        "hash_sha256_full": obj0.get("hash_sha256_full") or evt.get("File_Hash_Full"),

        "format": obj0.get("format"),
        "text_len": obj0.get("text_len") or evt.get("text_len"),
        "line_count": obj0.get("line_count"),
        "sensitivity": obj0.get("sensitivity") or evt.get("File_Sensitivity"),
        "hash_before": obj0.get("hash_before") or evt.get("File_Hash_Before"),
        "hash_after": obj0.get("hash_after") or evt.get("File_Hash_After"),
        "cloud_provider": obj0.get("cloud_provider") or evt.get("Cloud_Provider"),
        "bytes": _first_non_empty(obj0.get("bytes"), evt.get("bytes")),
        "dest": _first_non_empty(obj0.get("dest"), evt.get("dest")),
    }

    metrics0 = evt.get("metrics") if isinstance(evt.get("metrics"), dict) else {}
    flags0 = evt.get("flags") if isinstance(evt.get("flags"), dict) else {}
    content0 = evt.get("content") if isinstance(evt.get("content"), dict) else {}

    clipboard0 = evt.get("clipboard") if isinstance(evt.get("clipboard"), dict) else {}
    screenshot0 = evt.get("screenshot") if isinstance(evt.get("screenshot"), dict) else {}
    usb0 = evt.get("usb") if isinstance(evt.get("usb"), dict) else {}
    print0 = evt.get("print") if isinstance(evt.get("print"), dict) else {}
    network0 = evt.get("network") if isinstance(evt.get("network"), dict) else {}
    decision0 = evt.get("decision") if isinstance(evt.get("decision"), dict) else {}
    debug0 = evt.get("debug") if isinstance(evt.get("debug"), dict) else {}
    process0 = evt.get("process") if isinstance(evt.get("process"), dict) else {}
    browser_upload0 = evt.get("browser_upload") if isinstance(evt.get("browser_upload"), dict) else {}

    raw_envelope = {
        "type": etype,
        "source": source,
        "ts": ts_iso,
        "severity": sev_int,
        "tags": evt.get("tags", []),
        "ioc_hits": evt.get("ioc_hits", []),
        "drop_hint": evt.get("drop_hint"),

        "device": device,
        "actor": actor,
        "operation": operation,
        "object": obj,
        "context": ctx,

        "metrics": {
            "file_count": metrics0.get("file_count") if isinstance(metrics0, dict) else None,
            "row_count": metrics0.get("row_count") if isinstance(metrics0, dict) else None,
            "entropy": metrics0.get("entropy") if isinstance(metrics0, dict) else None,
            "bytes_out": _first_non_empty(
                metrics0.get("bytes_out") if isinstance(metrics0, dict) else None,
                network0.get("bytes_out_total") if isinstance(network0, dict) else None,
                network0.get("bytes_sent_total") if isinstance(network0, dict) else None,
            ),
            "bytes_in": _first_non_empty(
                metrics0.get("bytes_in") if isinstance(metrics0, dict) else None,
                network0.get("bytes_in_total") if isinstance(network0, dict) else None,
            ),
            "packets_total": _first_non_empty(
                metrics0.get("packets_total") if isinstance(metrics0, dict) else None,
                network0.get("packets_total") if isinstance(network0, dict) else None,
            ),
            "packets_out_total": _first_non_empty(
                metrics0.get("packets_out_total") if isinstance(metrics0, dict) else None,
                network0.get("packets_out_total") if isinstance(network0, dict) else None,
            ),
            "packets_in_total": _first_non_empty(
                metrics0.get("packets_in_total") if isinstance(metrics0, dict) else None,
                network0.get("packets_in_total") if isinstance(network0, dict) else None,
            ),
            "session_duration_sec": _first_non_empty(
                metrics0.get("session_duration_sec") if isinstance(metrics0, dict) else None,
                network0.get("session_duration_sec") if isinstance(network0, dict) else None,
            ),
        },
        "flags": {
            "password_protected": flags0.get("password_protected") if isinstance(flags0, dict) else None,
        },
        "content": {
            "sample": content0.get("sample") if isinstance(content0, dict) else None,
            "sample_len": content0.get("sample_len") if isinstance(content0, dict) else None,
        },

        "clipboard": clipboard0,
        "screenshot": screenshot0,
        "usb": usb0,
        "print": print0,
        "browser_upload": browser_upload0,
        "network": {
            **network0,
            "dest_domain": _first_non_empty(
                network0.get("dest_domain") if isinstance(network0, dict) else None,
                ctx.get("dest_domain"),
                ctx.get("domain"),
                ctx.get("fg_domain"),
            ),
            "dest_url": _first_non_empty(
                network0.get("dest_url") if isinstance(network0, dict) else None,
                ctx.get("fg_url_hint"),
            ),
            "bytes_sent_total": _first_non_empty(
                network0.get("bytes_sent_total") if isinstance(network0, dict) else None,
                network0.get("bytes_out_total") if isinstance(network0, dict) else None,
                metrics0.get("bytes_out") if isinstance(metrics0, dict) else None,
            ),
            "bytes_out_total": _first_non_empty(
                network0.get("bytes_out_total") if isinstance(network0, dict) else None,
                network0.get("bytes_sent_total") if isinstance(network0, dict) else None,
                metrics0.get("bytes_out") if isinstance(metrics0, dict) else None,
            ),
            "bytes_in_total": _first_non_empty(
                network0.get("bytes_in_total") if isinstance(network0, dict) else None,
                metrics0.get("bytes_in") if isinstance(metrics0, dict) else None,
            ),
        },
        "decision": decision0,
        "debug": debug0,
        "process": process0,
    }

    raw_envelope["raw_original"] = raw_original
    raw_envelope.pop("raw_envelope", None)

    return normalize_event({
        **raw_envelope,
        "raw_original": raw_original,
        "raw_envelope": raw_envelope,
    })