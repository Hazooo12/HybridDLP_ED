"""
DLP Native Messaging Host (TCP client mode)
============================================
Bridge giữa Chrome/Edge Extension và BrowserUploadSensor.

Kết nối dưới dạng:
  Chrome/Edge  ←─ stdio ─→  native_host.py  ─── TCP ──→  BrowserUploadSensor(:47266)

Cách chạy:
  Chrome tự động khởi động script này khi extension gọi
  chrome.runtime.connectNative("com.dlp.browser_upload").

Test thủ công (xem có gửi được token không):
  python native_host/native_host.py --test

Log file: native_host/native_host.log
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import socket
import struct
import sys
import time
from typing import Any, Dict, Optional

# ── Config ────────────────────────────────────────────────────────────────────
SENSOR_HOST = "127.0.0.1"
SENSOR_PORT = 47266
MAX_MESSAGE_BYTES = 1 * 1024 * 1024
CONNECT_TIMEOUT_SEC = 5.0
RECONNECT_DELAY_SEC = 1.0
MAX_RECONNECT_ATTEMPTS = 5

# ── Logging ───────────────────────────────────────────────────────────────────
LOG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "native_host.log")
logging.basicConfig(
    filename=LOG_PATH,
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)s %(name)s - %(message)s",
)
logger = logging.getLogger("dlp_native_host")


# ── TCP Forwarder ─────────────────────────────────────────────────────────────

class TCPForwarder:
    """Send newline-delimited JSON events to BrowserUploadSensor TCP server."""

    def __init__(self, host: str, port: int) -> None:
        self._host = host
        self._port = port
        self._sock: Optional[socket.socket] = None

    def _connect(self) -> None:
        for attempt in range(1, MAX_RECONNECT_ATTEMPTS + 1):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(CONNECT_TIMEOUT_SEC)
                s.connect((self._host, self._port))
                s.settimeout(None)  # blocking for sends
                self._sock = s
                logger.info("TCPForwarder connected to %s:%d", self._host, self._port)
                return
            except OSError as exc:
                logger.warning(
                    "TCPForwarder connect attempt %d/%d failed: %s",
                    attempt, MAX_RECONNECT_ATTEMPTS, exc,
                )
                time.sleep(RECONNECT_DELAY_SEC)
        raise OSError(
            f"Cannot connect to BrowserUploadSensor at {self._host}:{self._port} "
            f"after {MAX_RECONNECT_ATTEMPTS} attempts. "
            f"Is 'python -m sensor_system.runner --sensor browser_upload_sensor' running?"
        )

    def send(self, message: Dict[str, Any]) -> None:
        raw = (json.dumps(message, ensure_ascii=False) + "\n").encode("utf-8")
        for attempt in range(3):
            try:
                if self._sock is None:
                    self._connect()
                self._sock.sendall(raw)
                return
            except OSError as exc:
                logger.warning("TCPForwarder send error (attempt %d): %s", attempt + 1, exc)
                try:
                    self._sock.close()
                except Exception:
                    pass
                self._sock = None
                if attempt < 2:
                    time.sleep(RECONNECT_DELAY_SEC)
        logger.error("Failed to forward message after 3 attempts, dropping.")

    def close(self) -> None:
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None


# ── Chrome Native Messaging protocol ─────────────────────────────────────────

def _read_native_message() -> Optional[Dict]:
    stdin = sys.stdin.buffer
    raw_length = stdin.read(4)
    if not raw_length or len(raw_length) < 4:
        return None
    msg_length = struct.unpack("<I", raw_length)[0]
    if msg_length > MAX_MESSAGE_BYTES:
        logger.warning("Oversized message (%d bytes), skipping.", msg_length)
        stdin.read(msg_length)
        return None
    raw_msg = stdin.read(msg_length)
    if len(raw_msg) < msg_length:
        return None
    try:
        return json.loads(raw_msg.decode("utf-8"))
    except json.JSONDecodeError as exc:
        logger.warning("JSON decode error: %s", exc)
        return None


def _send_native_response(payload: Dict) -> None:
    stdout = sys.stdout.buffer
    raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    stdout.write(struct.pack("<I", len(raw)))
    stdout.write(raw)
    stdout.flush()


def _enrich(msg: Dict[str, Any]) -> Dict[str, Any]:
    import getpass
    enriched = dict(msg)
    enriched["host_ts"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    enriched["host_pid"] = os.getpid()
    try:
        enriched["host_user"] = getpass.getuser()
    except Exception:
        enriched["host_user"] = "unknown"
    return enriched


# ── Main loop ────────────────────────────────────────────────────────────────

def main() -> None:
    logger.info("DLP Native Host started (PID=%d)", os.getpid())
    forwarder = TCPForwarder(SENSOR_HOST, SENSOR_PORT)

    while True:
        msg = _read_native_message()
        if msg is None:
            logger.info("Browser disconnected, exiting.")
            break

        logger.debug("Received from browser: %s", json.dumps(msg)[:300])
        enriched = _enrich(msg)

        try:
            forwarder.send(enriched)
        except Exception as exc:
            logger.error("Forwarding error: %s", exc)

        _send_native_response({"status": "ok", "ts": enriched["host_ts"]})

    forwarder.close()
    logger.info("DLP Native Host exiting.")


# ── Self-test ─────────────────────────────────────────────────────────────────

def self_test() -> None:
    """Send a fake upload event to verify TCP connectivity."""
    import getpass
    test_event = {
        "browser": "chrome",
        "tab_url": "https://drive.google.com/drive/my-drive",
        "destination": "drive.google.com",
        "filename": "test_selftest.xlsx",
        "size": 204800,
        "trigger": "file_input",
        "confidence_score": 0.9,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "host_user": getpass.getuser(),
        "host_ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "host_pid": os.getpid(),
    }
    print(f"[self_test] Connecting to BrowserUploadSensor at {SENSOR_HOST}:{SENSOR_PORT}...")
    fwd = TCPForwarder(SENSOR_HOST, SENSOR_PORT)
    try:
        fwd.send(test_event)
        print("[self_test] [OK] Event sent successfully!")
        print(f"[self_test] Event: {json.dumps(test_event, indent=2)}")
    except OSError as exc:
        print(f"[self_test] [FAIL] FAILED: {exc}")
        print(
            "[self_test] Make sure the sensor is running:\n"
            "  python -m sensor_system.runner --sensor browser_upload_sensor"
        )
        sys.exit(1)
    finally:
        fwd.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--test", action="store_true", help="Send test event to sensor")
    args, _ = parser.parse_known_args()
    if args.test:
        self_test()
    else:
        main()
