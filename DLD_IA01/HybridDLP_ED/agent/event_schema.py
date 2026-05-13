from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def ensure_list(v: Any) -> List[Any]:
    if v is None:
        return []
    if isinstance(v, list):
        return v
    return [v]


def ensure_dict(v: Any) -> Dict[str, Any]:
    return v if isinstance(v, dict) else {}


def as_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        return default


def to_iso_utc(v: Any) -> str:
    """
    Normalize timestamp to ISO8601 UTC string.
    Accept:
      - None
      - unix int/float
      - ISO string (with/without Z)
      - fallback: now
    """
    if v is None:
        return now_iso()

    if isinstance(v, (int, float)):
        try:
            return datetime.fromtimestamp(float(v), tz=timezone.utc).isoformat()
        except Exception:
            return now_iso()

    s = str(v).strip()
    if not s:
        return now_iso()

    try:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt.isoformat()
    except Exception:
        return now_iso()


def severity_to_int(v: Any, default: int = 0) -> int:
    """
    Accept both numeric and textual severities.
    """
    if isinstance(v, (int, float)):
        iv = int(v)
        return max(0, min(100, iv))

    s = str(v or "").strip().lower()
    mapping = {
        "critical": 95,
        "crit": 95,
        "high": 90,
        "warn": 70,
        "warning": 70,
        "medium": 70,
        "info": 30,
        "low": 30,
        "debug": 10,
        "": default,
        "none": default,
    }
    if s in mapping:
        return mapping[s]

    try:
        iv = int(s)
        return max(0, min(100, iv))
    except Exception:
        return default


def first_non_empty(*values: Any) -> Any:
    for v in values:
        if v is None:
            continue
        if isinstance(v, str) and not v.strip():
            continue
        return v
    return None


def empty_event() -> Dict[str, Any]:
    """
    Canonical event structure for Sensor Layer (L1).
    L1: metadata only (no deep analysis / no blocking).
    """
    return {
        "event_id": None,
        "ts": None,          # ISO8601 UTC string
        "type": None,        # file_modified, usb_connected, clipboard_copy, net_flow_violation, ...
        "source": None,      # file / usb / clipboard / process / print / network / l1 / correlator

        "severity": 0,       # 0..100
        "tags": [],
        "ioc_hits": [],
        "drop_hint": None,

        "device": {
            "host_name": None,
            "device_id": None,
        },

        "actor": {
            "user": None,
            "username": None,
            "pid": None,
            "ppid": None,
            "process": None,
            "exe": None,
            "cmdline": None,
        },

        "process": {
            "pid": None,
            "ppid": None,
            "name": None,
            "exe": None,
            "cmdline": None,
            "create_time": None,
            "username": None,
            "parent_name": None,
            "parent_cmdline": None,
        },

        "operation": {
            "op_type": None,
            "tool": None,
            "service_name": None,
            "service_category": None,
            # file_sensor: copy vs move to external (Removable/Network) from fixed-disk evidence
            "copy_move_verdict": None,
            "copy_move_evidence": None,
        },

        "object": {
            # file-like
            "path": None,
            "dst_path": None,
            "name": None,
            "ext": None,
            "size": None,
            "mtime": None,
            "exists": None,
            "drive": None,
            "volume_type": None,
            "volume_label": None,

            "src_drive": None,
            "src_volume_type": None,
            "dest_drive": None,
            "dest_volume_type": None,

            "old_ext": None,
            "new_ext": None,
            "signature": None,
            "hash_sha256": None,
            "hash_sha256_partial": None,
            "hash_sha256_full": None,

            # clipboard/file/process friendly optional extras
            "format": None,
            "text_len": None,
            "line_count": None,
            "sensitivity": None,
            "hash_before": None,
            "hash_after": None,
            "cloud_provider": None,
            "bytes": None,
            "dest": None,
            "dest_display": None,
            "metadata": {},
        },

        "context": {
            "user": None,
            "fg_app": None,
            "fg_process": None,
            "fg_pid": None,
            "fg_cmdline": None,
            "fg_exe_path": None,
            "fg_hwnd": None,
            "fg_tid": None,
            "window_title": None,
            "window_title_lc": None,
            "session": None,
            "process_tags": None,
            "outside_working_hours": None,
            "fg_domain": None,
            "domain": None,
            "dest_domain": None,
            "resolved_domain": None,
            "resolved_from": None,
            "dest_ip": None,
            "fg_url_hint": None,
            "net_snapshot": None,
            "service_name": None,
            "service_category": None,
        },

        "metrics": {
            "file_count": None,
            "row_count": None,
            "entropy": None,
            "bytes_out": None,
            "bytes_in": None,
            "packets_total": None,
            "packets_out_total": None,
            "packets_in_total": None,
            "session_duration_sec": None,
        },

        "flags": {
            "password_protected": None,
        },

        "content": {
            "sample": None,
            "sample_len": None,
        },

        # =========
        # L1 buckets
        # =========
        "clipboard": {
            "clipboard_id": None,
            "event_type": None,
            "copy_ts": None,
            "paste_ts": None,
            "content_hash": None,
            "content_len": None,
            "text_len": None,
            "content_type": None,

            "source_app": None,
            "source_process": None,
            "source_window_title": None,

            "dest_app": None,
            "dest_process": None,
            "active_window_title": None,
            "dest_window_title": None,
            "dest_domain": None,
            "window_process_name": None,

            "snapshot_linked": None,

            "copy_frequency": None,
            "copy_frequency_value": None,
            "copy_frequency_window_sec": None,

            "paste_frequency": None,
            "paste_frequency_value": None,
            "paste_frequency_window_sec": None,

            "aggregated_copy_pattern": None,
            "total_volume": None,
            "bulk_paste_event": None,

            "original_format": None,
            "converted_format": None,
            "conversion_application": None,
            "content_structure_change": None,

            "clipboard_manager_proc": None,
            "clipboard_history_access": None,
            "clipboard_history_size": None,

            "keystroke_pattern_meta": None,
            "text_input_length": None,
            "active_window_context": None,
            "sensitive_source_access": None,

            "text_file": None,
            "content": None,
            "file_list": None,
            "file_count": None,
            "signature": None,
        },

        "usb": {
            "device_id": None,
            "serial_number": None,
            "device_name": None,
            "device_vendor": None,
            "product_name": None,
            "device_type": None,

            "storage_capacity": None,
            "connection_type": None,
            "trust_status": None,
            "first_seen": None,

            "mount_time": None,
            "unmount_time": None,
            "session_duration": None,
            "session_duration_sec": None,

            "transfer_direction": None,
            "file_copy_volume": None,
            "copy_rate": None,
            "file_count_to_device": None,
            "sensitive_file_count": None,

            "drive": None,
            "fs_type": None,
            "volume_label": None,
        },

        "print": {
            "print_process": None,
            "application_source": None,
            "printer_type": None,
            "printer_name": None,
            "document_name": None,
            "printed_file_path": None,
            "printed_content_sensit": None,
            "page_count": None,
            "print_timestamp": None,

            "event_id": None,
            "record_number": None,
            "raw_inserts": None,
        },

        "network": {
            "rule_id": None,
            "action": None,
            "reason": None,

            "dest_ip": None,
            "dest_domain": None,
            "resolved_domain": None,
            "dest_url": None,
            "dest_host_display": None,
            "protocol_type": None,
            "dst_port": None,

            "method": None,
            "content_type": None,

            "dest_trust_level": None,
            "external_dst": None,
            "dns_correlated": None,
            "dns_cache_domain": None,

            "transfer_volume_window": None,
            "window_sec": None,
            "bytes_sent_total": None,
            "bytes_out_total": None,
            "bytes_in_total": None,

            "packets_total": None,
            "packets_out_total": None,
            "packets_in_total": None,

            "session_first_ts": None,
            "session_last_ts": None,
            "session_duration_sec": None,
        },

        "browser_upload": {
            "filename": None,
            "size": None,
            "tab_url": None,
            "destination": None,
            "trigger": None,
            "browser": None,
            "confidence_score": None,
            "local_path": None,
        },

        "decision": {
            "stage": "L1",
            "action": None,
            "score": None,
            "reason": None,
        },

        "debug": {
            "schema_error": None,
            "sensor_latency_ms": None,
            "evidence": None,
        },

        # forensic
        "raw_original": None,
        "raw_envelope": None,
    }


def validate_event(e: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    if not e.get("type"):
        return False, "missing type"
    if not e.get("source"):
        return False, "missing source"
    if not e.get("ts"):
        return False, "missing ts"

    sev = severity_to_int(e.get("severity", 0), 0)
    e["severity"] = max(0, min(100, sev))
    e["ts"] = to_iso_utc(e.get("ts"))
    return True, None


def normalize_event(raw: Dict[str, Any]) -> Dict[str, Any]:
    """
    Merge raw event into canonical schema, filling defaults.
    Never raises. If invalid -> attach debug.schema_error.
    """
    e = empty_event()
    raw = ensure_dict(raw)

    # top-level
    e["event_id"] = raw.get("event_id") or str(uuid.uuid4())
    e["ts"] = to_iso_utc(raw.get("ts"))
    e["type"] = raw.get("type")
    e["source"] = raw.get("source")

    e["severity"] = severity_to_int(raw.get("severity", 0), 0)
    e["tags"] = ensure_list(raw.get("tags"))
    e["ioc_hits"] = ensure_list(raw.get("ioc_hits"))
    e["drop_hint"] = raw.get("drop_hint")

    # forensic
    e["raw_original"] = raw.get("raw_original")
    e["raw_envelope"] = raw.get("raw_envelope")

    # nested buckets
    device = ensure_dict(raw.get("device"))
    actor = ensure_dict(raw.get("actor"))
    process = ensure_dict(raw.get("process"))
    operation = ensure_dict(raw.get("operation"))
    obj = ensure_dict(raw.get("object"))
    ctx = ensure_dict(raw.get("context"))
    metrics = ensure_dict(raw.get("metrics"))
    flags = ensure_dict(raw.get("flags"))
    content = ensure_dict(raw.get("content"))

    clipboard = ensure_dict(raw.get("clipboard"))
    usb = ensure_dict(raw.get("usb"))
    prn = ensure_dict(raw.get("print"))
    net = ensure_dict(raw.get("network"))
    browser_upload = ensure_dict(raw.get("browser_upload"))

    decision = ensure_dict(raw.get("decision"))
    debug = ensure_dict(raw.get("debug"))

    # device
    e["device"].update({
        "host_name": first_non_empty(device.get("host_name"), raw.get("host_name")),
        "device_id": first_non_empty(device.get("device_id"), raw.get("device_id")),
    })

    # actor
    e["actor"].update({
        "user": first_non_empty(actor.get("user"), actor.get("username")),
        "username": first_non_empty(actor.get("username"), actor.get("user")),
        "pid": actor.get("pid"),
        "ppid": actor.get("ppid"),
        "process": actor.get("process"),
        "exe": first_non_empty(actor.get("exe"), actor.get("exe_path")),
        "cmdline": actor.get("cmdline"),
    })

    # process
    e["process"].update({
        "pid": first_non_empty(process.get("pid"), actor.get("pid")),
        "ppid": first_non_empty(process.get("ppid"), actor.get("ppid")),
        "name": first_non_empty(process.get("name"), actor.get("process")),
        "exe": first_non_empty(process.get("exe"), actor.get("exe"), actor.get("exe_path")),
        "cmdline": first_non_empty(process.get("cmdline"), actor.get("cmdline")),
        "create_time": process.get("create_time"),
        "username": first_non_empty(process.get("username"), actor.get("username"), actor.get("user")),
        "parent_name": process.get("parent_name"),
        "parent_cmdline": process.get("parent_cmdline"),
    })

    # operation — preservar todas as chaves não nulas do sensor (hash_kind, correlation, …)
    op_patch = {k: v for k, v in operation.items() if v is not None}
    op_patch.setdefault("op_type", first_non_empty(operation.get("op_type"), raw.get("type")))
    if op_patch.get("tool") is None:
        op_patch["tool"] = operation.get("tool")
    e["operation"].update(op_patch)

    # object
    e["object"].update({
        "path": first_non_empty(obj.get("path"), raw.get("path")),
        "dst_path": first_non_empty(obj.get("dst_path"), raw.get("dst_path"), raw.get("Dest_Path")),
        "name": first_non_empty(obj.get("name"), raw.get("File_Name")),
        "ext": first_non_empty(obj.get("ext"), raw.get("ext"), raw.get("File_Extension")),
        "size": first_non_empty(obj.get("size"), raw.get("size"), raw.get("File_Size")),
        "mtime": first_non_empty(obj.get("mtime"), raw.get("mtime")),
        "exists": first_non_empty(obj.get("exists"), raw.get("exists")),
        "drive": first_non_empty(obj.get("drive"), raw.get("drive"), usb.get("drive")),
        "volume_type": first_non_empty(obj.get("volume_type"), raw.get("volume_type"), raw.get("Dest_Volume_Type")),
        "volume_label": first_non_empty(obj.get("volume_label"), raw.get("volume_label"), usb.get("volume_label")),

        "src_drive": first_non_empty(obj.get("src_drive"), raw.get("Source_Drive")),
        "src_volume_type": first_non_empty(obj.get("src_volume_type"), raw.get("Source_Volume_Type")),
        "dest_drive": first_non_empty(obj.get("dest_drive"), raw.get("Dest_Drive")),
        "dest_volume_type": first_non_empty(obj.get("dest_volume_type"), raw.get("Dest_Volume_Type")),

        "old_ext": first_non_empty(obj.get("old_ext"), raw.get("old_ext"), raw.get("Old_Extension")),
        "new_ext": first_non_empty(obj.get("new_ext"), raw.get("new_ext"), raw.get("New_Extension")),
        "signature": first_non_empty(obj.get("signature"), raw.get("signature"), raw.get("File_Signature")),
        "hash_sha256": first_non_empty(obj.get("hash_sha256"), raw.get("hash_sha256"), raw.get("File_Hash")),
        "hash_sha256_partial": first_non_empty(obj.get("hash_sha256_partial"), raw.get("File_Hash_Partial")),
        "hash_sha256_full": first_non_empty(obj.get("hash_sha256_full"), raw.get("File_Hash_Full")),

        "format": obj.get("format"),
        "text_len": first_non_empty(obj.get("text_len"), clipboard.get("text_len"), clipboard.get("content_len")),
        "line_count": obj.get("line_count"),
        "sensitivity": first_non_empty(obj.get("sensitivity"), raw.get("File_Sensitivity")),
        "hash_before": first_non_empty(obj.get("hash_before"), raw.get("File_Hash_Before")),
        "hash_after": first_non_empty(obj.get("hash_after"), raw.get("File_Hash_After")),
        "cloud_provider": first_non_empty(obj.get("cloud_provider"), raw.get("Cloud_Provider")),
        "bytes": first_non_empty(obj.get("bytes"), raw.get("bytes")),
        "dest": first_non_empty(obj.get("dest"), raw.get("dest")),
        "dest_display": first_non_empty(obj.get("dest_display"), raw.get("dest_display")),
    })
    if isinstance(obj.get("metadata"), dict):
        meta = {k: v for k, v in obj["metadata"].items() if v is not None}
        if meta:
            e["object"]["metadata"] = meta

    # context
    e["context"].update({
        "user": first_non_empty(ctx.get("user"), e["actor"]["user"]),
        "fg_app": ctx.get("fg_app"),
        "fg_process": ctx.get("fg_process"),
        "fg_pid": ctx.get("fg_pid"),
        "fg_cmdline": ctx.get("fg_cmdline"),
        "fg_exe_path": ctx.get("fg_exe_path"),
        "fg_hwnd": ctx.get("fg_hwnd"),
        "fg_tid": ctx.get("fg_tid"),
        "window_title": ctx.get("window_title"),
        "window_title_lc": ctx.get("window_title_lc"),
        "session": ctx.get("session"),
        "process_tags": ctx.get("process_tags"),
        "outside_working_hours": ctx.get("outside_working_hours"),
        "fg_domain": first_non_empty(ctx.get("fg_domain"), net.get("resolved_domain"), net.get("dest_domain"), clipboard.get("dest_domain")),
        "domain": first_non_empty(ctx.get("domain"), ctx.get("resolved_domain"), ctx.get("fg_domain"), net.get("resolved_domain"), net.get("dest_domain"), clipboard.get("dest_domain")),
        "dest_domain": first_non_empty(ctx.get("dest_domain"), ctx.get("resolved_domain"), net.get("resolved_domain"), net.get("dest_domain"), clipboard.get("dest_domain")),
        "resolved_domain": first_non_empty(ctx.get("resolved_domain"), net.get("resolved_domain"), net.get("dest_domain")),
        "resolved_from": ctx.get("resolved_from"),
        "dest_ip": first_non_empty(ctx.get("dest_ip"), net.get("dest_ip")),
        "fg_url_hint": first_non_empty(ctx.get("fg_url_hint"), net.get("dest_url"), clipboard.get("dest_domain")),
        "net_snapshot": ctx.get("net_snapshot"),
        "service_name": first_non_empty(ctx.get("service_name"), operation.get("service_name")),
        "service_category": first_non_empty(ctx.get("service_category"), operation.get("service_category")),
    })

    # metrics
    e["metrics"].update({
        "file_count": first_non_empty(metrics.get("file_count"), raw.get("File_Count"), clipboard.get("file_count")),
        "row_count": metrics.get("row_count"),
        "entropy": first_non_empty(metrics.get("entropy"), raw.get("Entropy_Value")),
        "bytes_out": first_non_empty(metrics.get("bytes_out"), net.get("bytes_out_total"), net.get("bytes_sent_total")),
        "bytes_in": first_non_empty(metrics.get("bytes_in"), net.get("bytes_in_total")),
        "packets_total": first_non_empty(metrics.get("packets_total"), net.get("packets_total")),
        "packets_out_total": first_non_empty(metrics.get("packets_out_total"), net.get("packets_out_total")),
        "packets_in_total": first_non_empty(metrics.get("packets_in_total"), net.get("packets_in_total")),
        "session_duration_sec": first_non_empty(metrics.get("session_duration_sec"), net.get("session_duration_sec")),
    })

    # flags
    e["flags"].update({
        "password_protected": first_non_empty(flags.get("password_protected"), raw.get("Password_Flag")),
    })

    # content
    e["content"].update({
        "sample": first_non_empty(content.get("sample"), clipboard.get("text_file"), clipboard.get("content")),
        "sample_len": first_non_empty(content.get("sample_len"), raw.get("sample_len")),
    })

    # clipboard bucket
    e["clipboard"].update({
        "event_type": clipboard.get("event_type"),
        "copy_ts": clipboard.get("copy_ts"),
        "paste_ts": clipboard.get("paste_ts"),
        "content_hash": clipboard.get("content_hash"),
        "content_len": clipboard.get("content_len"),
        "text_len": first_non_empty(clipboard.get("text_len"), clipboard.get("content_len")),
        "content_type": clipboard.get("content_type"),

        "source_app": clipboard.get("source_app"),
        "source_process": clipboard.get("source_process"),
        "source_window_title": clipboard.get("source_window_title"),

        "dest_app": clipboard.get("dest_app"),
        "dest_process": clipboard.get("dest_process"),
        "active_window_title": clipboard.get("active_window_title"),
        "dest_window_title": clipboard.get("dest_window_title"),
        "dest_domain": first_non_empty(clipboard.get("dest_domain"), ctx.get("dest_domain")),
        "window_process_name": clipboard.get("window_process_name"),

        "snapshot_linked": clipboard.get("snapshot_linked"),

        "copy_frequency": clipboard.get("copy_frequency"),
        "copy_frequency_value": clipboard.get("copy_frequency_value"),
        "copy_frequency_window_sec": clipboard.get("copy_frequency_window_sec"),

        "paste_frequency": clipboard.get("paste_frequency"),
        "paste_frequency_value": clipboard.get("paste_frequency_value"),
        "paste_frequency_window_sec": clipboard.get("paste_frequency_window_sec"),

        "aggregated_copy_pattern": clipboard.get("aggregated_copy_pattern"),
        "total_volume": clipboard.get("total_volume"),
        "bulk_paste_event": clipboard.get("bulk_paste_event"),

        "original_format": clipboard.get("original_format"),
        "converted_format": clipboard.get("converted_format"),
        "conversion_application": clipboard.get("conversion_application"),
        "content_structure_change": clipboard.get("content_structure_change"),

        "clipboard_manager_proc": clipboard.get("clipboard_manager_proc"),
        "clipboard_history_access": clipboard.get("clipboard_history_access"),
        "clipboard_history_size": clipboard.get("clipboard_history_size"),

        "keystroke_pattern_meta": clipboard.get("keystroke_pattern_meta"),
        "text_input_length": clipboard.get("text_input_length"),
        "active_window_context": clipboard.get("active_window_context"),
        "sensitive_source_access": clipboard.get("sensitive_source_access"),

        "text_file": clipboard.get("text_file"),
        "content": clipboard.get("content"),
        "file_list": clipboard.get("file_list"),
        "file_count": clipboard.get("file_count"),
        "signature": clipboard.get("signature"),
    })

    # usb bucket — accept canonical + legacy keys
    e["usb"].update({
        "device_id": first_non_empty(usb.get("device_id"), usb.get("Device_ID")),
        "serial_number": first_non_empty(usb.get("serial_number"), usb.get("Serial_Number")),
        "device_name": first_non_empty(usb.get("device_name"), usb.get("Device_Name")),
        "device_vendor": first_non_empty(usb.get("device_vendor"), usb.get("Device_Vendor")),
        "product_name": first_non_empty(usb.get("product_name"), usb.get("Product_Name")),
        "device_type": first_non_empty(usb.get("device_type"), usb.get("Device_Type")),

        "storage_capacity": first_non_empty(usb.get("storage_capacity"), usb.get("Storage_Capacity")),
        "connection_type": first_non_empty(usb.get("connection_type"), usb.get("Connection_Type")),
        "trust_status": first_non_empty(usb.get("trust_status"), usb.get("Device_Trust_Status")),
        "first_seen": first_non_empty(usb.get("first_seen"), usb.get("Device_First_Seen")),

        "mount_time": first_non_empty(usb.get("mount_time"), usb.get("Mount_Time")),
        "unmount_time": first_non_empty(usb.get("unmount_time"), usb.get("Unmount_Time")),
        "session_duration": first_non_empty(usb.get("session_duration"), usb.get("Session_Duration")),
        "session_duration_sec": first_non_empty(usb.get("session_duration_sec"), usb.get("session_duration"), usb.get("Session_Duration")),

        "transfer_direction": first_non_empty(usb.get("transfer_direction"), usb.get("Transfer_Direction")),
        "file_copy_volume": first_non_empty(usb.get("file_copy_volume"), usb.get("File_Copy_Volume")),
        "copy_rate": first_non_empty(usb.get("copy_rate"), usb.get("Copy_Rate")),
        "file_count_to_device": first_non_empty(usb.get("file_count_to_device"), usb.get("File_Count_To_Device")),
        "sensitive_file_count": first_non_empty(usb.get("sensitive_file_count"), usb.get("Sensitive_File_Count")),

        "drive": first_non_empty(usb.get("drive"), raw.get("drive")),
        "fs_type": first_non_empty(usb.get("fs_type"), usb.get("FS_Type")),
        "volume_label": first_non_empty(usb.get("volume_label"), usb.get("Volume_Label"), raw.get("volume_label")),
    })

    # print bucket — accept canonical + legacy keys
    e["print"].update({
        "print_process": first_non_empty(prn.get("print_process"), raw.get("Print_Process")),
        "application_source": first_non_empty(prn.get("application_source"), raw.get("Application_Source")),
        "printer_type": first_non_empty(prn.get("printer_type"), raw.get("Printer_Type")),
        "printer_name": prn.get("printer_name"),
        "document_name": prn.get("document_name"),
        "printed_file_path": first_non_empty(prn.get("printed_file_path"), raw.get("Printed_File_Path")),
        "printed_content_sensit": first_non_empty(prn.get("printed_content_sensit"), raw.get("Printed_Content_Sensit.")),
        "page_count": first_non_empty(prn.get("page_count"), raw.get("Page_Count")),
        "print_timestamp": first_non_empty(prn.get("print_timestamp"), raw.get("Print_Timestamp")),

        "event_id": prn.get("event_id"),
        "record_number": prn.get("record_number"),
        "raw_inserts": prn.get("raw_inserts"),
    })

    # network bucket
    e["network"].update({
        "rule_id": net.get("rule_id"),
        "action": net.get("action"),
        "reason": net.get("reason"),

        "dest_ip": first_non_empty(net.get("dest_ip"), ctx.get("dest_ip")),
        "dest_domain": first_non_empty(net.get("dest_domain"), net.get("resolved_domain"), ctx.get("resolved_domain"), ctx.get("dest_domain"), ctx.get("domain"), ctx.get("fg_domain")),
        "resolved_domain": first_non_empty(net.get("resolved_domain"), net.get("dest_domain"), ctx.get("resolved_domain"), ctx.get("dest_domain")),
        "dest_url": first_non_empty(net.get("dest_url"), ctx.get("fg_url_hint")),
        "dest_host_display": first_non_empty(net.get("dest_host_display")),
        "protocol_type": net.get("protocol_type"),
        "dst_port": net.get("dst_port"),

        "method": net.get("method"),
        "content_type": net.get("content_type"),

        "dest_trust_level": net.get("dest_trust_level"),
        "external_dst": net.get("external_dst"),
        "dns_correlated": net.get("dns_correlated"),
        "dns_cache_domain": net.get("dns_cache_domain"),

        "transfer_volume_window": net.get("transfer_volume_window"),
        "window_sec": net.get("window_sec"),
        "bytes_sent_total": first_non_empty(net.get("bytes_sent_total"), net.get("bytes_out_total"), metrics.get("bytes_out")),
        "bytes_out_total": first_non_empty(net.get("bytes_out_total"), net.get("bytes_sent_total"), metrics.get("bytes_out")),
        "bytes_in_total": first_non_empty(net.get("bytes_in_total"), metrics.get("bytes_in")),

        "packets_total": first_non_empty(net.get("packets_total"), metrics.get("packets_total")),
        "packets_out_total": first_non_empty(net.get("packets_out_total"), metrics.get("packets_out_total")),
        "packets_in_total": first_non_empty(net.get("packets_in_total"), metrics.get("packets_in_total")),

        "session_first_ts": net.get("session_first_ts"),
        "session_last_ts": net.get("session_last_ts"),
        "session_duration_sec": first_non_empty(net.get("session_duration_sec"), metrics.get("session_duration_sec")),
    })

    # browser_upload bucket
    e["browser_upload"].update({
        "filename": browser_upload.get("filename"),
        "size": browser_upload.get("size"),
        "tab_url": browser_upload.get("tab_url"),
        "destination": browser_upload.get("destination"),
        "trigger": browser_upload.get("trigger"),
        "browser": browser_upload.get("browser"),
        "confidence_score": browser_upload.get("confidence_score"),
        "local_path": browser_upload.get("local_path"),
    })

    # decision/debug
    e["decision"].update({
        "stage": decision.get("stage") or "L1",
        "action": decision.get("action"),
        "score": decision.get("score"),
        "reason": decision.get("reason"),
    })

    # preserve full debug payload as much as possible
    debug_out = dict(e["debug"])
    for k, v in debug.items():
        debug_out[k] = v
    if "schema_error" not in debug_out:
        debug_out["schema_error"] = None
    if "sensor_latency_ms" not in debug_out:
        debug_out["sensor_latency_ms"] = None
    e["debug"] = debug_out

    ok, err = validate_event(e)
    if not ok:
        e["debug"]["schema_error"] = err

    try:
        from agent.canonical_compact import finalize_storage_event

        e = finalize_storage_event(e)
    except Exception:
        pass

    return e