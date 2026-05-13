"""
install_host.py – Đăng ký DLP Native Messaging Host vào Windows Registry.

Chạy một lần sau khi deploy:
    python native_host/install_host.py

Để gỡ bỏ:
    python native_host/install_host.py --uninstall
"""
from __future__ import annotations

import argparse
import json
import os
import sys

# Key registry Chrome dùng để tìm native host
CHROME_REG_KEY = r"Software\Google\Chrome\NativeMessagingHosts\com.dlp.browser_upload"
EDGE_REG_KEY   = r"Software\Microsoft\Edge\NativeMessagingHosts\com.dlp.browser_upload"

HOST_NAME = "com.dlp.browser_upload"


def _manifest_path() -> str:
    """Absolute path đến native_host.json (cùng folder với script này)."""
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "native_host.json"))


def _update_manifest_path(manifest_path: str) -> None:
    """
    Cập nhật field 'path' trong native_host.json để trỏ đúng đến native_host.bat.
    Chrome cần absolute path.
    """
    bat_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "native_host.bat"))
    with open(manifest_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    data["path"] = bat_path
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"[install_host] Updated manifest path -> {bat_path}")


def install(browsers: list[str]) -> None:
    try:
        import winreg
    except ImportError:
        print("ERROR: This script only runs on Windows.", file=sys.stderr)
        sys.exit(1)

    manifest_path = _manifest_path()
    if not os.path.exists(manifest_path):
        print(f"ERROR: manifest not found at {manifest_path}", file=sys.stderr)
        sys.exit(1)

    _update_manifest_path(manifest_path)

    reg_keys = []
    if "chrome" in browsers:
        reg_keys.append(CHROME_REG_KEY)
    if "edge" in browsers:
        reg_keys.append(EDGE_REG_KEY)

    for reg_key in reg_keys:
        try:
            key = winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, reg_key, 0, winreg.KEY_WRITE)
            winreg.SetValueEx(key, "", 0, winreg.REG_SZ, manifest_path)
            winreg.CloseKey(key)
            print(f"[install_host] Registered: HKCU\\{reg_key}")
            print(f"               -> {manifest_path}")
        except PermissionError as exc:
            print(f"ERROR: Cannot write registry key ({exc}).", file=sys.stderr)
            sys.exit(1)

    print("\n[install_host] Done. Restart Chrome/Edge for changes to take effect.")
    print("IMPORTANT: Update 'allowed_origins' in native_host.json with your extension ID.")


def uninstall(browsers: list[str]) -> None:
    try:
        import winreg
    except ImportError:
        print("ERROR: Windows only.", file=sys.stderr)
        sys.exit(1)

    reg_keys = []
    if "chrome" in browsers:
        reg_keys.append(CHROME_REG_KEY)
    if "edge" in browsers:
        reg_keys.append(EDGE_REG_KEY)

    for reg_key in reg_keys:
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, reg_key)
            print(f"[install_host] Removed: HKCU\\{reg_key}")
        except FileNotFoundError:
            print(f"[install_host] Key not found (already removed?): {reg_key}")
        except PermissionError as exc:
            print(f"ERROR: Cannot delete registry key ({exc}).", file=sys.stderr)


def main() -> None:
    parser = argparse.ArgumentParser(description="Install/Uninstall DLP Native Messaging Host")
    parser.add_argument(
        "--uninstall", action="store_true", help="Remove registry entries"
    )
    parser.add_argument(
        "--browser",
        action="append",
        choices=["chrome", "edge"],
        default=None,
        dest="browsers",
        help="Target browser(s). Default: chrome + edge",
    )
    args = parser.parse_args()
    browsers = args.browsers or ["chrome", "edge"]

    if args.uninstall:
        uninstall(browsers)
    else:
        install(browsers)


if __name__ == "__main__":
    main()
