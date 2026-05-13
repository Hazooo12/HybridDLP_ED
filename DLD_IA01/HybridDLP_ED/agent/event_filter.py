"""
Event Filter - Lọc event trước khi enqueue vào Worker queue
Được áp dụng ở SENSOR (L1/L2) trước khi persistent_queue.enqueue()

Tính năng:
- Lọc theo process name
- Lọc theo event type
- Lọc theo file path patterns
- Config qua environment variables hoặc file JSON
"""
from __future__ import annotations

import os
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


def get_event_filter_config_path() -> Path:
    """Lấy path của event filter config file."""
    override = os.getenv("DLP_EVENT_FILTER_CONFIG", "").strip()
    if override:
        return Path(override)
    # Mặc định: agent/runtime/config/event_filter.json
    return Path(__file__).resolve().parent / "runtime" / "config" / "event_filter.json"


class EventFilter:
    """Filter event dựa trên các rules cấu hình."""

    def __init__(self):
        """Khởi tạo filter từ config file + env vars."""
        self.excluded_processes: Set[str] = set()
        self.excluded_event_types: Set[str] = set()
        self.excluded_path_patterns: List[str] = []
        self.excluded_file_names: List[str] = []
        self.excluded_extensions: Set[str] = set()
        self.excluded_domains: Set[str] = set()
        self.enabled = True
        self.verbose = False

        self._load_config()

    def _load_config(self) -> None:
        """Tải config từ file JSON + env vars."""
        # Đọc từ file
        config_file = get_event_filter_config_path()
        file_config = {}
        if config_file.exists():
            try:
                with open(config_file, "r", encoding="utf-8") as f:
                    file_config = json.load(f) or {}
            except Exception as e:
                if self.verbose:
                    print(f"⚠️  Lỗi đọc event filter config: {e}")
                file_config = {}

        # Ghi đè bằng env vars
        env_config = self._load_env_config()

        # Merge file + env
        config = {**file_config, **env_config}

        # Parse excluded_processes
        if isinstance(config.get("excluded_processes"), list):
            self.excluded_processes = set(p.lower() for p in config["excluded_processes"] if p)
        else:
            processes_str = config.get("excluded_processes", "")
            if isinstance(processes_str, str) and processes_str.strip():
                self.excluded_processes = set(
                    p.lower() for p in processes_str.split("|") if p.strip()
                )

        # Parse excluded_event_types
        if isinstance(config.get("excluded_event_types"), list):
            self.excluded_event_types = set(t.lower() for t in config["excluded_event_types"] if t)
        else:
            types_str = config.get("excluded_event_types", "")
            if isinstance(types_str, str) and types_str.strip():
                self.excluded_event_types = set(
                    t.lower() for t in types_str.split("|") if t.strip()
                )

        # Parse excluded_path_patterns
        if isinstance(config.get("excluded_path_patterns"), list):
            self.excluded_path_patterns = [
                p.lower() for p in config["excluded_path_patterns"] if p
            ]
        else:
            patterns_str = config.get("excluded_path_patterns", "")
            if isinstance(patterns_str, str) and patterns_str.strip():
                self.excluded_path_patterns = [
                    p.lower() for p in patterns_str.split("|") if p.strip()
                ]

        # Parse excluded_file_names (e.g., "WiredTiger.turtle", "*.log", etc.)
        if isinstance(config.get("excluded_file_names"), list):
            self.excluded_file_names = [
                n.lower() for n in config["excluded_file_names"] if n
            ]
        else:
            names_str = config.get("excluded_file_names", "")
            if isinstance(names_str, str) and names_str.strip():
                self.excluded_file_names = [
                    n.lower() for n in names_str.split("|") if n.strip()
                ]

        # Parse excluded_extensions (e.g., ".mkv", ".log", etc.)
        if isinstance(config.get("excluded_extensions"), list):
            self.excluded_extensions = set(
                e.lower() for e in config["excluded_extensions"] if e
            )
        else:
            extensions_str = config.get("excluded_extensions", "")
            if isinstance(extensions_str, str) and extensions_str.strip():
                self.excluded_extensions = set(
                    e.lower() for e in extensions_str.split("|") if e.strip()
                )

        # Parse excluded_domains
        if isinstance(config.get("excluded_domains"), list):
            self.excluded_domains = set(d.lower() for d in config["excluded_domains"] if d)
        else:
            domains_str = config.get("excluded_domains", "")
            if isinstance(domains_str, str) and domains_str.strip():
                self.excluded_domains = set(
                    d.lower() for d in domains_str.split("|") if d.strip()
                )

        # Enable/disable
        enabled_str = config.get("enabled", "true")
        if isinstance(enabled_str, bool):
            self.enabled = enabled_str
        else:
            self.enabled = str(enabled_str).lower() in {"1", "true", "yes", "on"}

        # Verbose mode
        verbose_str = config.get("verbose", "false")
        if isinstance(verbose_str, bool):
            self.verbose = verbose_str
        else:
            self.verbose = str(verbose_str).lower() in {"1", "true", "yes", "on"}

    def _load_env_config(self) -> Dict[str, Any]:
        """Tải config từ environment variables."""
        config = {}

        # DLP_EVENT_FILTER_ENABLED: "1" hoặc "true"
        if os.getenv("DLP_EVENT_FILTER_ENABLED"):
            config["enabled"] = os.getenv("DLP_EVENT_FILTER_ENABLED").lower() in {
                "1", "true", "yes", "on"
            }

        # DLP_EVENT_FILTER_EXCLUDED_PROCESSES: "rundll32.exe|svchost.exe|..."
        if os.getenv("DLP_EVENT_FILTER_EXCLUDED_PROCESSES"):
            config["excluded_processes"] = os.getenv("DLP_EVENT_FILTER_EXCLUDED_PROCESSES")

        # DLP_EVENT_FILTER_EXCLUDED_EVENT_TYPES: "heartbeat|proc_start|..."
        if os.getenv("DLP_EVENT_FILTER_EXCLUDED_EVENT_TYPES"):
            config["excluded_event_types"] = os.getenv("DLP_EVENT_FILTER_EXCLUDED_EVENT_TYPES")

        # DLP_EVENT_FILTER_EXCLUDED_PATH_PATTERNS: "\\appdata\\|\\windows\\|..."
        if os.getenv("DLP_EVENT_FILTER_EXCLUDED_PATH_PATTERNS"):
            config["excluded_path_patterns"] = os.getenv("DLP_EVENT_FILTER_EXCLUDED_PATH_PATTERNS")

        # DLP_EVENT_FILTER_EXCLUDED_FILE_NAMES: "WiredTiger.turtle|*.log|..."
        if os.getenv("DLP_EVENT_FILTER_EXCLUDED_FILE_NAMES"):
            config["excluded_file_names"] = os.getenv("DLP_EVENT_FILTER_EXCLUDED_FILE_NAMES")

        # DLP_EVENT_FILTER_EXCLUDED_EXTENSIONS: ".mkv|.txt|..."
        if os.getenv("DLP_EVENT_FILTER_EXCLUDED_EXTENSIONS"):
            config["excluded_extensions"] = os.getenv("DLP_EVENT_FILTER_EXCLUDED_EXTENSIONS")

        # DLP_EVENT_FILTER_EXCLUDED_DOMAINS: "google.com|microsoft.com|..."
        if os.getenv("DLP_EVENT_FILTER_EXCLUDED_DOMAINS"):
            config["excluded_domains"] = os.getenv("DLP_EVENT_FILTER_EXCLUDED_DOMAINS")

        # DLP_EVENT_FILTER_VERBOSE
        if os.getenv("DLP_EVENT_FILTER_VERBOSE"):
            config["verbose"] = os.getenv("DLP_EVENT_FILTER_VERBOSE").lower() in {
                "1", "true", "yes", "on"
            }

        return config

    def _is_external_transfer_event(self, event: Dict[str, Any]) -> bool:
        """Keep USB/network transfer events even when the process is otherwise noisy."""
        operation = event.get("operation") if isinstance(event.get("operation"), dict) else {}
        obj = event.get("object") if isinstance(event.get("object"), dict) else {}
        op_type = str(operation.get("op_type") or event.get("type") or "").lower()
        semantic_hint = str(operation.get("dlp_semantic_hint") or "").lower()
        semantic_action = str(operation.get("semantic_action") or "").lower()
        dest_volume = str(
            operation.get("dest_volume_type")
            or obj.get("dest_volume_type")
            or obj.get("volume_type")
            or ""
        ).lower()

        if semantic_hint == "local" and "external" not in op_type and "copy_to_removable" not in semantic_action:
            return False
        return (
            "external" in op_type
            or "copy_to_removable" in semantic_action
            or "external_transfer" in semantic_hint
            or dest_volume in {"removable", "network"}
        )

    def should_drop(self, event: Dict[str, Any]) -> bool:
        """Kiểm tra xem event có nên bị drop hay không."""
        if not self.enabled:
            return False

        # Rule 1: Check event type
        event_type = str(event.get("type") or "").lower()
        if event_type in self.excluded_event_types:
            if self.verbose:
                print(f"[EVENT_FILTER] Drop: event type '{event_type}'")
            return True

        if self._is_external_transfer_event(event):
            return False

        # Rule 2: Check actor/process name
        actor = event.get("actor") if isinstance(event.get("actor"), dict) else {}
        process_name = str(actor.get("process") or "").lower()
        if process_name in self.excluded_processes:
            if self.verbose:
                print(f"[EVENT_FILTER] Drop: process '{process_name}'")
            return True

        # Rule 3: Check actor in process field (nested)
        process_dict = event.get("process") if isinstance(event.get("process"), dict) else {}
        process_name_alt = str(process_dict.get("name") or "").lower()
        if process_name_alt in self.excluded_processes:
            if self.verbose:
                print(f"[EVENT_FILTER] Drop: process (process.name) '{process_name_alt}'")
            return True

        # Rule 4: Check file path patterns
        obj = event.get("object") if isinstance(event.get("object"), dict) else {}
        file_path = str(obj.get("path") or "").lower()
        if file_path:
            for pattern in self.excluded_path_patterns:
                if pattern in file_path:
                    if self.verbose:
                        print(f"[EVENT_FILTER] Drop: file path pattern '{pattern}' in '{file_path}'")
                    return True

        # Rule 5: Check file name (object.name field)
        file_name = str(obj.get("name") or "").lower()
        if file_name:
            for name_pattern in self.excluded_file_names:
                # Support wildcard (* for "starts with" / "contains")
                if "*" in name_pattern:
                    # Simple wildcard handling: "*.log" or "WiredTiger*"
                    import fnmatch
                    if fnmatch.fnmatch(file_name, name_pattern):
                        if self.verbose:
                            print(f"[EVENT_FILTER] Drop: file name pattern '{name_pattern}' matches '{file_name}'")
                        return True
                elif name_pattern == file_name or name_pattern in file_name:
                    # Exact match or substring match
                    if self.verbose:
                        print(f"[EVENT_FILTER] Drop: file name '{name_pattern}' in '{file_name}'")
                    return True

        # Rule 5.5: Check file extension (object.ext field)
        file_ext = str(obj.get("ext") or "").lower()
        if file_ext and file_ext in self.excluded_extensions:
            if self.verbose:
                print(f"[EVENT_FILTER] Drop: file extension '{file_ext}'")
            return True

        # Rule 6: Check domain/network
        context = event.get("context") if isinstance(event.get("context"), dict) else {}
        fg_domain = str(context.get("fg_domain") or "").lower()
        if fg_domain in self.excluded_domains:
            if self.verbose:
                print(f"[EVENT_FILTER] Drop: domain '{fg_domain}'")
            return True

        # Network context
        network = event.get("network") if isinstance(event.get("network"), dict) else {}
        dest_domain = str(network.get("dest_domain") or "").lower()
        if dest_domain in self.excluded_domains:
            if self.verbose:
                print(f"[EVENT_FILTER] Drop: dest_domain '{dest_domain}'")
            return True

        return False

    def get_stats(self) -> Dict[str, Any]:
        """Lấy thông tin về filter hiện tại."""
        return {
            "enabled": self.enabled,
            "excluded_processes": list(self.excluded_processes),
            "excluded_event_types": list(self.excluded_event_types),
            "excluded_path_patterns": self.excluded_path_patterns,
            "excluded_file_names": self.excluded_file_names,
            "excluded_extensions": list(self.excluded_extensions),
            "excluded_domains": list(self.excluded_domains),
            "verbose": self.verbose,
        }


# Global instance
_event_filter_instance: Optional[EventFilter] = None


def get_event_filter() -> EventFilter:
    """Lấy global EventFilter instance."""
    global _event_filter_instance
    if _event_filter_instance is None:
        _event_filter_instance = EventFilter()
    return _event_filter_instance


def init_event_filter() -> EventFilter:
    """Khởi tạo lại filter instance (reload config)."""
    global _event_filter_instance
    _event_filter_instance = EventFilter()
    return _event_filter_instance


def save_default_config() -> None:
    """Tạo file config mặc định."""
    config_file = get_event_filter_config_path()
    config_file.parent.mkdir(parents=True, exist_ok=True)

    default = {
        "enabled": True,
        "verbose": False,
        "excluded_processes": [
            "rundll32.exe",
            "svchost.exe",
            "wmiprvse.exe",
            "backgroundtaskhost.exe",
            "searchhost.exe",
            "startmenuexperiencehost.exe",
            "msedgewebview2.exe",
        ],
        "excluded_event_types": [
            "heartbeat",
        ],
        "excluded_path_patterns": [
            "\\appdata\\local\\programs\\",
            "\\appdata\\local\\packages\\",
            "\\appdata\\local\\temp\\",
            "\\appdata\\local\\microsoft\\edge\\user data\\",
            "\\appdata\\local\\google\\chrome\\user data\\",
            "\\windows\\",
            "\\program files\\",
            "\\cache\\",
            "\\logs\\",
        ],
        "excluded_file_names": [],
        "excluded_domains": [],
    }

    try:
        with open(config_file, "w", encoding="utf-8") as f:
            json.dump(default, f, ensure_ascii=False, indent=2)
        print(f"✅ Tạo event filter config mặc định: {config_file}")
    except Exception as e:
        print(f"❌ Lỗi ghi event filter config: {e}")
