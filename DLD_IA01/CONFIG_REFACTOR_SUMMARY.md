# Refactor Behavioral Rules Config - Tóm Tắt Thay Đổi

## 📋 Vấn Đề Gốc

Code ban đầu có nhiều **hardcoded lists** (danh sách):
- Ứng dụng trình duyệt (browser).exe
- Ứng dụng nhắn tin (teams, discord, slack, v.v.)
- Domains nhạy cảm (chat.openai.com, gmail.com, v.v.)
- Từ khóa tiêu đề cửa sổ (chatgpt, slack, zalo, v.v.)
- Ổ USB/Removable (E:, F:, G:, v.v.)

**Hạn chế:** Để cập nhật danh sách, phải sửa code → rebuild → redeploy

## ✅ Giải Pháp

Chuyển tất cả hardcoded lists sang **file config JSON động** mà admin có thể cập nhật mà không cần sửa code.

### Files Được Tạo/Sửa:

#### 1. **rules_config.json** (NEW)
- File cấu hình tập trung chứa tất cả lists
- Format: JSON, dễ đọc + dễ sửa
- Admin có thể cập nhật trực tiếp hoặc thông qua API

#### 2. **rules_config_manager.py** (NEW)
- Class `RulesConfigManager` để quản lý config
- **Tính năng:**
  - Load config từ file JSON
  - Reload config (khi admin cập nhật)
  - Add/Remove apps, domains, keywords, drives
  - Save config lại file
  - Global singleton instance
  
- **API:**
  ```python
  config_manager = get_config_manager()
  
  # Get methods
  browser_apps = config_manager.get_browser_apps()
  messaging_apps = config_manager.get_messaging_apps()
  sensitive_domains = config_manager.get_sensitive_domains()
  removable_drives = config_manager.get_removable_drives()
  
  # Modify methods
  config_manager.add_browser_app("opera.exe")
  config_manager.add_sensitive_domain("slack.com")
  config_manager.remove_app("telegram.exe")
  config_manager.save_config()
  ```

#### 3. **behavioral_rules.py** (MODIFIED)
- Thêm import: `from .rules_config_manager import get_config_manager`
- Class `ClipboardPasteToExternalAppRule.__init__()`:
  - Thay thế 140+ dòng hardcoded lists
  - Load từ `config_manager` thay vào
  
- Class `USBDataExfiltrationRule.check()`:
  - Load removable drives từ config
  - Thay vì hardcoded `['e:', 'f:', 'g:', ...]`

- Class `NetworkUploadRule.check()`:
  - Load upload_types, browser_apps, desktop_upload_apps, cli_tools, sensitive_domains từ config

#### 4. **CONFIG_GUIDE.md** (NEW)
- Hướng dẫn cách sử dụng config system cho dev + admin
- Best practices
- Khắc phục sự cố
- Ví dụ cập nhật config

#### 5. **rules_api_example.py** (NEW)
- FastAPI endpoints cho phía server cập nhật config
- **Endpoints:**
  - `GET /api/rules/config` - Lấy config hiện tại
  - `POST /api/rules/config/update` - Cập nhật config toàn bộ
  - `POST /api/rules/config/reload` - Reload từ file
  - `POST /api/rules/apps/browser/add` - Thêm browser app
  - `POST /api/rules/apps/browser/remove` - Xóa browser app
  - `POST /api/rules/domains/sensitive/add` - Thêm domain nhạy cảm
  - `GET /api/rules/stats` - Lấy thống kê

#### 6. **rules_cli_manager.py** (NEW)
- CLI tool cho admin quản lý config từ command line
- **Commands:**
  ```bash
  # List
  python rules_cli_manager.py list-apps
  python rules_cli_manager.py list-domains
  
  # Add
  python rules_cli_manager.py add-app opera.exe --type browser
  python rules_cli_manager.py add-domain slack.mycompany.com
  
  # Remove
  python rules_cli_manager.py remove-app telegram.exe --type messaging
  
  # Search
  python rules_cli_manager.py search slack
  
  # Stats
  python rules_cli_manager.py stats
  
  # Export/Import
  python rules_cli_manager.py export config_backup.json
  python rules_cli_manager.py import config_new.json
  ```

## 🎯 Lợi Ích

✓ **Admin có thể tự cập nhật config** mà không cần dev
✓ **No code changes needed** để thêm/xóa ứng dụng hay domain
✓ **API-friendly** - có thể tích hợp với server dashboard
✓ **CLI tool** cho quản lý nhanh
✓ **Backup/Export** dễ dàng
✓ **Reload config on-the-fly** mà không cần restart agent

## 📊 Thống Kê Thay Đổi

- **Dòng code giảm:** ~140+ dòng hardcoded lists từ behavioral_rules.py
- **Files mới:** 5 files (config manager, config example API, CLI tool, guide)
- **Config structure:** Organized dễ maintain
- **Backwards compatible:** Hệ thống vẫn hoạt động 100% nếu config file missing (auto reload)

## 🚀 Cách Sử Dụng

### Option 1: Admin cập nhật file config trực tiếp
```json
// Sửa rules_config.json
{
  "clipboard_paste_rule": {
    "browser_apps": ["chrome.exe", "opera.exe", ...]
  }
}

// Reload trong agent
config_manager.reload_config()
```

### Option 2: Dùng CLI tool
```bash
cd HybridDLP_ED/worker/core

# Thêm app mới
python rules_cli_manager.py add-app opera.exe --type browser

# Thêm domain
python rules_cli_manager.py add-domain slack.mycompany.com

# Xem thống kê
python rules_cli_manager.py stats
```

### Option 3: Dùng API (Server-side)
```python
import requests

# Cập nhật config từ server
new_config = {...}
response = requests.post(
    "http://agent-ip:8000/api/rules/config/update",
    json=new_config
)

# Thêm domain nhạy cảm
response = requests.post(
    "http://agent-ip:8000/api/rules/domains/sensitive/add",
    params={"domain": "slack.com"}
)
```

## ⚙️ Cài Đặt

1. Config file `rules_config.json` đã tạo tại `HybridDLP_ED/worker/core/`
2. Config manager đã integrate vào `behavioral_rules.py`
3. Ready to use - không cần thay đổi gì thêm

## 📝 Các File Liên Quan

- **Config:** `HybridDLP_ED/worker/core/rules_config.json`
- **Manager:** `HybridDLP_ED/worker/core/rules_config_manager.py`
- **Behavioral Rules:** `HybridDLP_ED/worker/core/behavioral_rules.py`
- **API Example:** `HybridDLP_ED/worker/core/rules_api_example.py`
- **CLI Manager:** `HybridDLP_ED/worker/core/rules_cli_manager.py`
- **Guide:** `HybridDLP_ED/worker/core/CONFIG_GUIDE.md`

## 🔄 Cập Nhật Tương Lai

Có thể dễ dàng:
- ✓ Thêm rule mới (thêm vào JSON config)
- ✓ Cập nhật app lists (edit JSON)
- ✓ Customize per deployment (khác config file per env)
- ✓ Tích hợp với admin dashboard (gọi API endpoints)
