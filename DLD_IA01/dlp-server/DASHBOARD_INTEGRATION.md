# Dashboard Rules Configuration - Integration Guide

## 📋 Tóm Tắt

Dashboard bây giờ có thể quản lý behavioral rules configuration mà không cần restart server:
- ✅ Thêm/Xóa keywords, domains, ứng dụng
- ✅ Xem thống kê cấu hình
- ✅ Reload config trực tiếp từ dashboard

## 🎯 Những Gì Đã Được Thêm

### Files Mới Tạo/Sửa:

#### 1. **Endpoints trong main.py**
```python
# Keywords Management
GET    /api/rules/keywords
POST   /api/rules/keywords
DELETE /api/rules/keywords/{keyword}

# Domains Management
GET    /api/rules/domains
POST   /api/rules/domains
DELETE /api/rules/domains/{domain}

# Apps Management
GET    /api/rules/apps?app_type=all|browser|messaging
POST   /api/rules/apps
DELETE /api/rules/apps/{app_name}?app_type=browser|messaging

# Config Management
GET    /api/rules/config
POST   /api/rules/config/reload
GET    /api/rules/stats
```

#### 2. **Config Manager Extensions (rules_config_manager.py)**
Thêm các methods:
- `add_keyword(keyword)`
- `remove_keyword(keyword)`
- `remove_domain(domain)`

#### 3. **UI Components (rules_config_modal.html)**
- Modal dialog với 4 tabs: Keywords, Domains, Apps, Statistics
- Input fields để thêm items
- Tag-based display cho dễ management
- Responsive design

#### 4. **Documentation**
- `RULES_API_GUIDE.md` - API endpoints documentation
- `rules_config_modal.html` - Ready-to-use UI component

## 🚀 Cách Sử Dụng

### 1. Cập Nhật main.py
File đã được update với:
- Import config manager
- 14 endpoints mới
- Error handling

### 2. Cập Nhật rules_config_manager.py
File đã được update với:
- `add_keyword()` method
- `remove_keyword()` method
- `remove_domain()` method

### 3. Tích Hợp UI vào Dashboard
Thêm đoạn này vào `static/index.html`:

```html
<!-- Thêm vào <head> -->
<link rel="stylesheet" href="rules_config_modal.css">

<!-- Thêm vào <body> -->
<!-- Button để mở modal -->
<button onclick="openRulesConfigModal()" class="btn-rules-config">
  ⚙️ Rules Config
</button>

<!-- Modal HTML + JavaScript -->
<script src="rules_config_modal.js"></script>
```

Hoặc copy-paste toàn bộ content từ `rules_config_modal.html` vào file dashboard HTML.

## 🔑 Authentication

Tất cả endpoints yêu cầu:
```
Header: X-Admin-Key: admin-dashboard-secret-key
```

Cập nhật key này trong:
- `dlp-server/main.py`: `DASHBOARD_KEY`
- `rules_config_modal.html`: `const ADMIN_KEY`

## 📊 Ví Dụ API Calls

### Lấy Keywords
```bash
curl -H "X-Admin-Key: admin-dashboard-secret-key" \
  http://localhost:8000/api/rules/keywords
```

### Thêm Keyword
```bash
curl -X POST \
  -H "X-Admin-Key: admin-dashboard-secret-key" \
  -H "Content-Type: application/json" \
  -d '{"keyword":"myapp"}' \
  http://localhost:8000/api/rules/keywords
```

### Thêm Domain
```bash
curl -X POST \
  -H "X-Admin-Key: admin-dashboard-secret-key" \
  -H "Content-Type: application/json" \
  -d '{"domain":"mycompany.slack.com"}' \
  http://localhost:8000/api/rules/domains
```

### Lấy Thống Kê
```bash
curl -H "X-Admin-Key: admin-dashboard-secret-key" \
  http://localhost:8000/api/rules/stats
```

## 🧪 Test Endpoints (Python)

```python
import requests

BASE_URL = "http://localhost:8000/api/rules"
ADMIN_KEY = "admin-dashboard-secret-key"
HEADERS = {"X-Admin-Key": ADMIN_KEY}

# Get keywords
r = requests.get(f"{BASE_URL}/keywords", headers=HEADERS)
print(r.json())

# Add keyword
r = requests.post(
    f"{BASE_URL}/keywords",
    json={"keyword": "test"},
    headers=HEADERS
)
print(r.json())

# Get statistics
r = requests.get(f"{BASE_URL}/stats", headers=HEADERS)
print(r.json())
```

## 📈 Workflow

```
┌─────────────────────────────────────────────────────────────┐
│                    DASHBOARD                                │
│  Click "⚙️ Rules Config" → Opens Modal Dialog              │
└──────────────────┬──────────────────────────────────────────┘
                   │
                   │ Admin thêm keyword: "myapp"
                   │
                   ▼
┌──────────────────────────────────────────────────────────────┐
│          SERVER (main.py)                                    │
│  POST /api/rules/keywords                                   │
│  ├─ Validate keyword                                         │
│  ├─ Check duplicate                                          │
│  ├─ Call config_manager.add_keyword()                       │
│  └─ Save to rules_config.json                               │
└──────────────┬───────────────────────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────────────────────┐
│          CONFIG FILE (rules_config.json)                    │
│  {                                                           │
│    "clipboard_paste_rule": {                               │
│      "sensitive_title_keywords": [                         │
│        "chatgpt", "slack", ..., "myapp"  ← NEW             │
│      ]                                                       │
│    }                                                         │
│  }                                                           │
└──────────────┬───────────────────────────────────────────────┘
               │
               │ (Optional) Admin clicks "Reload Config"
               │
               ▼
┌──────────────────────────────────────────────────────────────┐
│          AGENT (behavioral_rules.py)                        │
│  ClipboardPasteToExternalAppRule.__init__()                │
│  ├─ Load config từ rules_config.json                        │
│  └─ self.sensitive_title_keywords = [                      │
│       "chatgpt", "slack", ..., "myapp"                    │
│     ]                                                       │
│                                                             │
│  Rule bây giờ phát hiện keyword "myapp" trong window title │
└──────────────────────────────────────────────────────────────┘
```

## ✅ Checklist

- [ ] Cập nhật `dlp-server/main.py` (endpoints đã được add)
- [ ] Cập nhật `HybridDLP_ED/worker/core/rules_config_manager.py` (methods đã được add)
- [ ] Copy/Paste `rules_config_modal.html` vào `static/index.html` hoặc tạo separate files
- [ ] Thay đổi `ADMIN_KEY` nếu khác `admin-dashboard-secret-key`
- [ ] Test API endpoints với curl hoặc Postman
- [ ] Test UI modal trên dashboard
- [ ] Deploy lên production

## 🔒 Security Notes

1. **Change Default Key**: Luôn thay đổi `DASHBOARD_KEY` từ giá trị mặc định
2. **HTTPS**: Sử dụng HTTPS trong production để bảo vệ key
3. **Rate Limiting**: Cân nhắc thêm rate limiting cho API
4. **Audit Logging**: Log tất cả changes từ API
5. **Permissions**: Chỉ admin có quyền access `/api/rules` endpoints

## 📞 Troubleshooting

### Endpoints trả về 503 (Service Unavailable)
- Config manager not available
- Kiểm tra path đến `rules_config_manager.py` đúng không

### 401 Unauthorized
- Admin key sai hoặc missing
- Kiểm tra `X-Admin-Key` header

### 409 Conflict (Item already exists)
- Item (keyword, domain, app) đã tồn tại
- Thử xóa rồi thêm lại, hoặc check list trước

### Changes không lưu
- Kiểm tra file permissions trên `rules_config.json`
- Kiểm tra logs của server

## 📚 Liên Kết Files

| File | Mục Đích |
|------|---------|
| `dlp-server/main.py` | API Server với endpoints mới |
| `HybridDLP_ED/worker/core/rules_config_manager.py` | Config manager với methods mới |
| `HybridDLP_ED/worker/core/rules_config.json` | Config file được update |
| `dlp-server/RULES_API_GUIDE.md` | API documentation |
| `dlp-server/rules_config_modal.html` | Ready-to-use UI component |

## 🎉 Tạm Kết

Dashboard giờ đây có đầy đủ chức năng để quản lý behavioral rules configuration:

✨ **Thêm keywords** → Detect hành vi mới
✨ **Thêm domains** → Theo dõi destinations mới
✨ **Thêm apps** → Detect ứng dụng mới
✨ **Xem statistics** → Monitor cấu hình
✨ **Real-time reload** → Thay đổi ngay tức thì

**Không cần code changes, không cần restart, không cần deploy! 🚀**
