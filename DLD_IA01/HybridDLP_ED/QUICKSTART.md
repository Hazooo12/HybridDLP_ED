# [START] HybridDLP Control System - Quickstart

## What is This?

Hệ thống quản lý HybridDLP với giao diện thân thiện:
- [OK] Lần đầu setup: Set mật khẩu → Server URL/Key → Khởi động services
- [OK] System Tray: Quản lý từ background
- [OK] Control Center: Dashboard quản lý services
- [OK] Bảo mật: Tất cả thao tác yêu cầu password

## [START] Getting Started (2 steps)

### Step 1: Install dependencies
```bash
cd agent
pip install -r requirements.txt
```

### Step 2: Run the system
```bash
# Windows
start_hybridlp.bat

# Or directly
python agent/boot.py
```

That's it! 

## [TARGET] First Run Experience

1. **Popup 1**: "Set Master Password" → Input password (≥4 chars)
2. **Popup 2**: "Server Configuration" → Input Server URL + API Key
3. **Popup 3**: "Start Services" → Choose Sensor/Worker to start
4. **System Tray**: Icon appears, click to manage

##  Control Center

Click system tray icon → Enter password → Dashboard

**Features:**
- ▶️ Start/Stop Sensor
- ▶️ Start/Stop Worker
- [SETTING] Edit Server Settings
-  Logout

##  Data Storage

```
agent/runtime/config/
├── password.json      (Password hash - PBKDF2 SHA256)
└── config.json        (Server URL + API Key)
```

##  Security Note

- Password stored as hash (not plain text)
- PBKDF2 SHA256 with 32-byte salt
- 100,000 iterations
- Requires authentication for all operations

##  Test Everything

```bash
python agent/test_system.py
```

Expected output:
```
[OK] ALL TESTS PASSED!
```

##  Full Documentation

See: `HYBRIDLP_SYSTEM_GUIDE.md`

## ⚡ Troubleshooting

### System Tray not showing?
```bash
pip install pystray pillow
```

### Reset configuration?
```bash
# Delete config folder to reset
rmdir /s agent\runtime\config
```

### View logs?
```
agent/runtime/events.jsonl
```

## [TARGET] What's Inside

| Component | Purpose |
|-----------|---------|
| `password_manager.py` | Secure password hashing |
| `config.py` | Server settings |
| `service_manager.py` | Sensor/Worker control |
| `setup_wizard.py` | First-time setup |
| `main_window.py` | Control dashboard |
| `system_tray_app.py` | Background icon |
| `boot.py` | Application entry |

##  Quick Links

- **Main entry:** `python agent/boot.py`
- **Setup again:** `python agent/setup_wizard.py`
- **Test system:** `python agent/test_system.py`
- **Docs:** `HYBRIDLP_SYSTEM_GUIDE.md`

---

**Ready?** Run: `start_hybridlp.bat` [START]
