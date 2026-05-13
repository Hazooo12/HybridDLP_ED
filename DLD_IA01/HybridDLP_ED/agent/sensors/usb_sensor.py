from __future__ import annotations

import time
import ctypes
import hashlib
from ctypes import wintypes
from typing import Dict, Any, Set, Optional, Callable

DRIVE_REMOVABLE = 2


# -----------------------------
# Helpers
# -----------------------------
def _now() -> float:
    return time.time()


def _iso_utc(ts: float) -> str:
    from datetime import datetime, timezone
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def _norm_drive(d: str) -> str:
    d = (d or "").strip()
    if len(d) >= 2 and d[1] == ":":
        if not d.endswith("\\"):
            d += "\\"
        return d[0].upper() + d[1:]
    return d


def _list_removable_drives() -> Set[str]:
    """
    Return set like {"E:\\", "F:\\"} for removable drives on Windows.
    """
    drives: Set[str] = set()
    bitmask = ctypes.windll.kernel32.GetLogicalDrives()
    for i in range(26):
        if bitmask & (1 << i):
            letter = chr(ord("A") + i)
            path = f"{letter}:\\"
            dtype = ctypes.windll.kernel32.GetDriveTypeW(ctypes.c_wchar_p(path))
            if int(dtype) == DRIVE_REMOVABLE:
                drives.add(path)
    return drives


def _volume_type_windows(drive: str) -> Optional[str]:
    drive = _norm_drive(drive)
    if not drive:
        return None
    try:
        GetDriveTypeW = ctypes.windll.kernel32.GetDriveTypeW
        GetDriveTypeW.argtypes = [wintypes.LPCWSTR]
        GetDriveTypeW.restype = wintypes.UINT
        dtype = int(GetDriveTypeW(drive))
        mapping = {
            0: "Unknown",
            1: "NoRootDir",
            2: "Removable",
            3: "Fixed",
            4: "Network",
            5: "CDROM",
            6: "RAMDisk",
        }
        return mapping.get(dtype, "Unknown")
    except Exception:
        return None


def _get_volume_info(drive: str, include_serial: bool = False) -> Dict[str, Any]:
    """
    Best-effort volume metadata. Keep light.
    NOTE: serial can be sensitive (unique). Default disabled.
    """
    drive = _norm_drive(drive)
    out: Dict[str, Any] = {
        "volume_label": None,
        "fs_type": None,
        "serial_number": None,
    }
    try:
        GetVolumeInformationW = ctypes.windll.kernel32.GetVolumeInformationW
        GetVolumeInformationW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.LPWSTR,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            ctypes.POINTER(wintypes.DWORD),
            ctypes.POINTER(wintypes.DWORD),
            wintypes.LPWSTR,
            wintypes.DWORD,
        ]
        GetVolumeInformationW.restype = wintypes.BOOL

        vol_name_buf = ctypes.create_unicode_buffer(261)
        fs_name_buf = ctypes.create_unicode_buffer(261)
        serial = wintypes.DWORD(0)
        max_comp_len = wintypes.DWORD(0)
        fs_flags = wintypes.DWORD(0)

        ok = GetVolumeInformationW(
            drive,
            vol_name_buf,
            260,
            ctypes.byref(serial),
            ctypes.byref(max_comp_len),
            ctypes.byref(fs_flags),
            fs_name_buf,
            260,
        )
        if ok:
            out["volume_label"] = vol_name_buf.value or None
            out["fs_type"] = fs_name_buf.value or None
            if include_serial:
                out["serial_number"] = int(serial.value)
    except Exception:
        pass
    return out


def _get_storage_capacity_bytes(drive: str) -> Optional[int]:
    drive = _norm_drive(drive)
    if not drive:
        return None
    try:
        free_bytes_avail = ctypes.c_ulonglong(0)
        total_bytes = ctypes.c_ulonglong(0)
        total_free = ctypes.c_ulonglong(0)

        GetDiskFreeSpaceExW = ctypes.windll.kernel32.GetDiskFreeSpaceExW
        GetDiskFreeSpaceExW.argtypes = [
            wintypes.LPCWSTR,
            ctypes.POINTER(ctypes.c_ulonglong),
            ctypes.POINTER(ctypes.c_ulonglong),
            ctypes.POINTER(ctypes.c_ulonglong),
        ]
        GetDiskFreeSpaceExW.restype = wintypes.BOOL

        ok = GetDiskFreeSpaceExW(
            drive,
            ctypes.byref(free_bytes_avail),
            ctypes.byref(total_bytes),
            ctypes.byref(total_free),
        )
        if ok:
            return int(total_bytes.value)
    except Exception:
        pass
    return None


def _make_device_id(drive: str, vol_label: Optional[str], fs_type: Optional[str], serial: Optional[int]) -> str:
    """
    L1 lightweight Device_ID:
      - If serial available: hash(drive + serial) to avoid raw identifier leakage.
      - Else: hash(drive + label + fs)
    """
    base = f"{_norm_drive(drive)}|{vol_label or ''}|{fs_type or ''}|{serial or ''}"
    return hashlib.sha256(base.encode("utf-8", errors="ignore")).hexdigest()[:24]


def _trust_status(
    drive: str,
    vol_label: Optional[str],
    serial: Optional[int],
    whitelist_labels: Set[str],
    whitelist_drives: Set[str],
    whitelist_serials: Set[int],
    approved_devices: Set[str],
    dev_id: str,
) -> str:
    """
    Policy:
      - Whitelist: explicit allowlist match
      - Approved: known approved device_id from local store
      - Unknown: the rest
    """
    d = _norm_drive(drive)
    lbl = (vol_label or "").strip().lower()

    if d in whitelist_drives:
        return "Whitelist"
    if lbl and lbl in whitelist_labels:
        return "Whitelist"
    if serial is not None and serial in whitelist_serials:
        return "Whitelist"

    if dev_id in approved_devices:
        return "Approved"

    return "Unknown"


# -----------------------------
# USBSensor
# -----------------------------
class USBSensor:
    """
    USB / REMOVABLE DEVICE SENSOR (L1 - metadata only)

    Emits:
      - usb_connected
      - usb_disconnected

    Canonical fields:
      - actor.*
      - object.*
      - operation.*
      - context.*
      - metrics.*
      - flags.*
      - content.*

    Legacy:
      - drive
      - volume_type
      - volume_label
      - usb.*
    """

    def __init__(
        self,
        queue_manager,
        poll_interval_sec: float = 1.0,
        include_volume_info: bool = True,
        include_serial_number: bool = False,
        include_capacity: bool = True,
        source: str = "usb",
        whitelist_labels: Optional[Set[str]] = None,
        whitelist_drives: Optional[Set[str]] = None,
        whitelist_serials: Optional[Set[int]] = None,
        approved_devices_file: Optional[str] = "approved_devices.txt",
    ):
        self.qm = queue_manager
        self.poll_interval_sec = float(poll_interval_sec)
        self.include_volume_info = bool(include_volume_info)
        self.include_serial_number = bool(include_serial_number)
        self.include_capacity = bool(include_capacity)
        self.source = str(source)

        self._known: Set[str] = set()
        self._mount_ts: Dict[str, float] = {}
        self._first_seen: Dict[str, float] = {}

        self.approved_devices_file = approved_devices_file
        self.approved_devices = self._load_approved_devices(approved_devices_file)

        self.whitelist_labels = set((x or "").strip().lower() for x in (whitelist_labels or set()) if (x or "").strip())
        self.whitelist_drives = set(_norm_drive(x) for x in (whitelist_drives or set()) if (x or "").strip())
        self.whitelist_serials = set(int(x) for x in (whitelist_serials or set()))

    def _load_approved_devices(self, file_path: Optional[str]) -> Set[str]:
        approved_devices = set()
        if not file_path:
            return approved_devices

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                for line in f:
                    dev = (line or "").strip()
                    if dev:
                        approved_devices.add(dev)
        except FileNotFoundError:
            pass
        except Exception:
            pass
        return approved_devices

    def _save_approved_devices(self) -> None:
        if not self.approved_devices_file:
            return
        try:
            with open(self.approved_devices_file, "w", encoding="utf-8") as f:
                for device in sorted(self.approved_devices):
                    f.write(f"{device}\n")
        except Exception:
            pass

    def _ctx_snapshot(self, ctx_provider: Optional[Any]) -> Dict[str, Any]:
        if not ctx_provider:
            return {}
        try:
            return (ctx_provider.snapshot() or {}) if hasattr(ctx_provider, "snapshot") else {}
        except Exception:
            return {}

    def _build_actor(self, ctx: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "user": ctx.get("user"),
            "pid": ctx.get("fg_pid"),
            "ppid": None,
            "process": (ctx.get("fg_process") or ctx.get("fg_app")),
            "cmdline": ctx.get("fg_cmdline"),
            "exe_path": ctx.get("fg_exe_path"),
        }

    def _build_object(
        self,
        drive: str,
        volume_type: Optional[str],
        volume_label: Optional[str],
        sensitivity: Optional[str] = None,
    ) -> Dict[str, Any]:
        return {
            "path": drive,
            "dst_path": None,
            "name": volume_label or drive,
            "ext": None,
            "size": None,
            "hash_sha256": None,
            "signature": None,
            "drive": drive,
            "volume_type": volume_type,
            "src_drive": None,
            "src_volume_type": None,
            "dest_drive": drive,
            "dest_volume_type": volume_type,
            "old_ext": None,
            "new_ext": None,
            "sensitivity": sensitivity,
            "cloud_provider": None,
        }

    def _resolve_trust_status(self, dev_id: str, drive: str, vol_info: Dict[str, Any], serial: Optional[int]) -> str:
        trust = _trust_status(
            drive=drive,
            vol_label=vol_info.get("volume_label"),
            serial=serial,
            whitelist_labels=self.whitelist_labels,
            whitelist_drives=self.whitelist_drives,
            whitelist_serials=self.whitelist_serials,
            approved_devices=self.approved_devices,
            dev_id=dev_id,
        )

        # Nếu explicit whitelist thì lưu luôn như approved local knowledge
        if trust == "Whitelist" and dev_id not in self.approved_devices:
            self.approved_devices.add(dev_id)
            self._save_approved_devices()

        return trust

    def _event_severity(self, trust: str) -> str:
        if trust == "Unknown":
            return "warn"
        return "info"

    def _emit_connected(self, drive: str, ctx: Dict[str, Any]) -> None:
        drive = _norm_drive(drive)
        vol_type = _volume_type_windows(drive)

        vol_info: Dict[str, Any] = {"volume_label": None, "fs_type": None, "serial_number": None}
        if self.include_volume_info:
            vol_info = _get_volume_info(drive, include_serial=self.include_serial_number)

        cap = _get_storage_capacity_bytes(drive) if self.include_capacity else None
        serial = vol_info.get("serial_number")
        dev_id = _make_device_id(drive, vol_info.get("volume_label"), vol_info.get("fs_type"), serial)

        first_seen = self._first_seen.get(dev_id)
        if first_seen is None:
            first_seen = _now()
            self._first_seen[dev_id] = first_seen

        mount_time = _now()
        self._mount_ts[drive] = mount_time

        trust = self._resolve_trust_status(dev_id, drive, vol_info, serial)
        severity = self._event_severity(trust)

        evt: Dict[str, Any] = {
            "type": "usb_connected",
            "severity": severity,
            "source": self.source,
            "ts": mount_time,
            "timestamp": _iso_utc(mount_time),
            "Timestamp": _iso_utc(mount_time),

            "context": ctx,
            "actor": self._build_actor(ctx),
            "operation": {"op_type": "usb_connect", "tool": "usb"},
            "object": self._build_object(
                drive=drive,
                volume_type=vol_type,
                volume_label=vol_info.get("volume_label"),
                sensitivity=None,
            ),

            # legacy flat fields
            "drive": drive,
            "volume_type": vol_type,
            "volume_label": vol_info.get("volume_label"),

            "tags": ["removable_media"],
            "ioc_hits": [],

            "metrics": {
                "file_count": 0,
                "row_count": None,
                "entropy": None,
                "session_duration_sec": None,
            },
            "flags": {
                "password_protected": None,
            },
            "content": {
                "sample": None,
                "sample_len": None,
            },

            "usb": {
                # canonical / snake_case
                "device_id": dev_id,
                "serial_number": serial,
                "device_name": vol_info.get("volume_label") or drive,
                "device_vendor": None,
                "product_name": None,
                "device_type": "USB Storage",
                "storage_capacity": cap,
                "connection_type": "USB Mass Storage",
                "trust_status": trust,
                "first_seen": first_seen,
                "mount_time": mount_time,
                "unmount_time": None,
                "session_duration": None,
                "session_duration_sec": None,
                "transfer_direction": None,
                "file_copy_volume": 0,
                "copy_rate": None,
                "file_count_to_device": 0,
                "sensitive_file_count": 0,
                "drive": drive,
                "volume_label": vol_info.get("volume_label"),
                "fs_type": vol_info.get("fs_type"),

                # legacy / compatibility
                "Device_ID": dev_id,
                "Serial_Number": serial,
                "Device_Name": vol_info.get("volume_label") or drive,
                "Device_Vendor": None,
                "Product_Name": None,
                "Device_Type": "USB Storage",
                "Storage_Capacity": cap,
                "Connection_Type": "USB Mass Storage",
                "Device_Trust_Status": trust,
                "Device_First_Seen": first_seen,
                "Mount_Time": mount_time,
                "Unmount_Time": None,
                "Session_Duration": None,
                "Transfer_Direction": None,
                "File_Copy_Volume": 0,
                "Copy_Rate": None,
                "File_Count_To_Device": 0,
                "Sensitive_File_Count": 0,
                "Volume_Label": vol_info.get("volume_label"),
                "FS_Type": vol_info.get("fs_type"),
            },

            "debug": {
                "evidence": {
                    "volume_type": vol_type,
                    "trust_status": trust,
                    "whitelist_drive": drive in self.whitelist_drives,
                    "whitelist_label": (vol_info.get("volume_label") or "").strip().lower() in self.whitelist_labels if vol_info.get("volume_label") else False,
                    "approved_device": dev_id in self.approved_devices,
                }
            },
        }

        try:
            self.qm.enqueue_event(evt)
        except Exception:
            pass

    def _emit_disconnected(self, drive: str, ctx: Dict[str, Any]) -> None:
        drive = _norm_drive(drive)

        # Sau khi rút có thể không query được volume info nữa, nên best-effort
        vol_type = _volume_type_windows(drive)

        vol_info: Dict[str, Any] = {"volume_label": None, "fs_type": None, "serial_number": None}
        if self.include_volume_info:
            vol_info = _get_volume_info(drive, include_serial=self.include_serial_number)

        serial = vol_info.get("serial_number")
        dev_id = _make_device_id(drive, vol_info.get("volume_label"), vol_info.get("fs_type"), serial)

        unmount_time = _now()
        mount_time = self._mount_ts.pop(drive, None)
        duration = (unmount_time - mount_time) if mount_time else None

        trust = self._resolve_trust_status(dev_id, drive, vol_info, serial)
        severity = self._event_severity(trust)

        first_seen = self._first_seen.get(dev_id)
        if first_seen is None:
            first_seen = unmount_time
            self._first_seen[dev_id] = first_seen

        evt: Dict[str, Any] = {
            "type": "usb_disconnected",
            "severity": severity,
            "source": self.source,
            "ts": unmount_time,
            "timestamp": _iso_utc(unmount_time),
            "Timestamp": _iso_utc(unmount_time),

            "context": ctx,
            "actor": self._build_actor(ctx),
            "operation": {"op_type": "usb_disconnect", "tool": "usb"},
            "object": self._build_object(
                drive=drive,
                volume_type=vol_type,
                volume_label=vol_info.get("volume_label"),
                sensitivity=None,
            ),

            # legacy flat fields
            "drive": drive,
            "volume_type": vol_type,
            "volume_label": vol_info.get("volume_label"),

            "tags": ["removable_media"],
            "ioc_hits": [],

            "metrics": {
                "file_count": 0,
                "row_count": None,
                "entropy": None,
                "session_duration_sec": duration,
            },
            "flags": {
                "password_protected": None,
            },
            "content": {
                "sample": None,
                "sample_len": None,
            },

            "usb": {
                # canonical / snake_case
                "device_id": dev_id,
                "serial_number": serial,
                "device_name": vol_info.get("volume_label") or drive,
                "device_vendor": None,
                "product_name": None,
                "device_type": "USB Storage",
                "storage_capacity": _get_storage_capacity_bytes(drive) if self.include_capacity else None,
                "connection_type": "USB Mass Storage",
                "trust_status": trust,
                "first_seen": first_seen,
                "mount_time": mount_time,
                "unmount_time": unmount_time,
                "session_duration": duration,
                "session_duration_sec": duration,
                "transfer_direction": None,
                "file_copy_volume": 0,
                "copy_rate": None,
                "file_count_to_device": 0,
                "sensitive_file_count": 0,
                "drive": drive,
                "volume_label": vol_info.get("volume_label"),
                "fs_type": vol_info.get("fs_type"),

                # legacy / compatibility
                "Device_ID": dev_id,
                "Serial_Number": serial,
                "Device_Name": vol_info.get("volume_label") or drive,
                "Device_Vendor": None,
                "Product_Name": None,
                "Device_Type": "USB Storage",
                "Storage_Capacity": _get_storage_capacity_bytes(drive) if self.include_capacity else None,
                "Connection_Type": "USB Mass Storage",
                "Device_Trust_Status": trust,
                "Device_First_Seen": first_seen,
                "Mount_Time": mount_time,
                "Unmount_Time": unmount_time,
                "Session_Duration": duration,
                "Transfer_Direction": None,
                "File_Copy_Volume": 0,
                "Copy_Rate": None,
                "File_Count_To_Device": 0,
                "Sensitive_File_Count": 0,
                "Volume_Label": vol_info.get("volume_label"),
                "FS_Type": vol_info.get("fs_type"),
            },

            "debug": {
                "evidence": {
                    "volume_type": vol_type,
                    "trust_status": trust,
                    "session_duration_sec": duration,
                    "approved_device": dev_id in self.approved_devices,
                }
            },
        }

        try:
            self.qm.enqueue_event(evt)
        except Exception:
            pass

    def run_loop(
        self,
        stop_event,
        on_connected: Optional[Callable[[str], None]] = None,
        on_disconnected: Optional[Callable[[str], None]] = None,
        ctx_provider: Optional[Any] = None,
    ) -> None:
        """
        Callbacks:
          - on_connected(drive)
          - on_disconnected(drive)
        """
        self._known = _list_removable_drives()

        while not stop_event.is_set():
            cur = _list_removable_drives()
            added = cur - self._known
            removed = self._known - cur

            ctx = self._ctx_snapshot(ctx_provider)

            for d in sorted(added):
                self._emit_connected(d, ctx)
                if callable(on_connected):
                    try:
                        on_connected(_norm_drive(d))
                    except Exception:
                        pass

            for d in sorted(removed):
                self._emit_disconnected(d, ctx)
                if callable(on_disconnected):
                    try:
                        on_disconnected(_norm_drive(d))
                    except Exception:
                        pass

            self._known = cur
            time.sleep(self.poll_interval_sec)