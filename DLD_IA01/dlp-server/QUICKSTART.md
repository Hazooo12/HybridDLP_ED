# 🎯 Dashboard Rules Config - Quick Start

## Trong 5 Phút Để Dashboard Có Thể Config Rules

### Step 1: Kiểm Tra Files Đã Update ✓

```
dlp-server/
  └─ main.py                    ✓ (14 endpoints thêm vào)

HybridDLP_ED/worker/core/
  └─ rules_config_manager.py    ✓ (3 methods thêm vào)
```

### Step 2: Copy UI Component

Copy nội dung từ `dlp-server/rules_config_modal.html` vào file dashboard HTML của bạn:

**Option A: Embed vào index.html**
```html
<!-- static/index.html -->

<!-- Thêm này vào <body>, trước </body> -->
<!-- Modal HTML, CSS, JS từ rules_config_modal.html -->

<!-- Thêm button này vào header/navigation -->
<button onclick="openRulesConfigModal()" style="...">
  ⚙️ Rules Config
</button>
```

**Option B: Split into separate files**
```
static/
  ├─ index.html
  ├─ rules_config_modal.html    (import vào index.html)
  └─ js/
      └─ rules_config.js         (JavaScript logic)
```

### Step 3: Update Admin Key

Thay đổi key trong 2 chỗ để match nhau:

**File 1: dlp-server/main.py (line ~25)**
```python
DASHBOARD_KEY = "admin-dashboard-secret-key"  # Change this!
```

**File 2: rules_config_modal.html (line ~315)**
```javascript
const ADMIN_KEY = 'admin-dashboard-secret-key'; // Change this!
```

### Step 4: Start Server

```bash
cd dlp-server
python main.py
# hoặc
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

### Step 5: Test Dashboard

1. Mở dashboard ở `http://localhost:8000`
2. Click button "⚙️ Rules Config"
3. Modal sẽ hiển thị
4. Kiểm tra các tab: Keywords, Domains, Apps, Stats

**Done! 🎉**

---

## 🎮 Sử Dụng Modal

### Keywords Tab
```
1. Nhập keyword (e.g., "myapp")
2. Click "Add Keyword"
3. Keyword xuất hiện trong list
4. Để xóa, click × trên keyword
```

### Domains Tab
```
1. Nhập domain (e.g., "slack.mycompany.com")
2. Click "Add Domain"
3. Domain xuất hiện trong list
4. Để xóa, click × trên domain
```

### Apps Tab
```
1. Nhập app name (e.g., "opera.exe")
2. Chọn type: "Browser" hoặc "Messaging"
3. Click "Add App"
4. App xuất hiện trong section tương ứng
```

### Statistics Tab
```
1. Xem tổng số keywords, domains, apps, v.v.
2. Click "↻ Reload Config" để reload config từ file
```

---

## 🧪 Test Nhanh Endpoints

### Cách 1: Curl (Terminal)

```bash
# Get keywords
curl -H "X-Admin-Key: admin-dashboard-secret-key" \
  http://localhost:8000/api/rules/keywords

# Add keyword
curl -X POST \
  -H "X-Admin-Key: admin-dashboard-secret-key" \
  -H "Content-Type: application/json" \
  -d '{"keyword":"test"}' \
  http://localhost:8000/api/rules/keywords

# Get stats
curl -H "X-Admin-Key: admin-dashboard-secret-key" \
  http://localhost:8000/api/rules/stats
```

### Cách 2: Postman

1. Open Postman
2. GET `http://localhost:8000/api/rules/keywords`
3. Add header: `X-Admin-Key: admin-dashboard-secret-key`
4. Send

### Cách 3: Browser Console

```javascript
// Copy-paste vào browser console
const ADMIN_KEY = 'admin-dashboard-secret-key';

fetch('/api/rules/keywords', {
  headers: { 'X-Admin-Key': ADMIN_KEY }
})
.then(r => r.json())
.then(d => console.log(d))
```

---

## 📝 Common Use Cases

### Case 1: Thêm Ứng Dụng Mới (ChatGPT Desktop)

```
1. Click "⚙️ Rules Config"
2. Go to "Apps" tab
3. Enter: "chatgpt.exe"
4. Select: "Browser"
5. Click "Add App"
✓ Done
```

### Case 2: Monitor Slack Domain Mới

```
1. Click "⚙️ Rules Config"
2. Go to "Domains" tab
3. Enter: "dev-team.slack.com"
4. Click "Add Domain"
✓ Done
```

### Case 3: Add Custom Keyword

```
1. Click "⚙️ Rules Config"
2. Go to "Keywords" tab
3. Enter: "secretapp"
4. Click "Add Keyword"
✓ Done - Từ bây giờ, window title có "secretapp" sẽ được detect
```

---

## 🔄 Config Persistence

```
File: HybridDLP_ED/worker/core/rules_config.json

Khi bạn add keyword via dashboard:
1. API server nhận request
2. Config manager update dictionary
3. Save vào rules_config.json
4. File được persist trên disk
5. Config reload lần tới

✓ Settings KHÔNG mất khi restart server
```

---

## 📊 Expected Response Examples

### Add Keyword - Success
```json
{
  "status": "ok",
  "message": "Keyword 'myapp' added successfully",
  "keyword": "myapp"
}
```

### Add Keyword - Conflict (Already Exists)
```json
{
  "detail": "Keyword 'slack' already exists"
}
```

### Get Keywords - Success
```json
{
  "status": "ok",
  "keywords": ["chatgpt", "slack", "discord", ...],
  "total": 40
}
```

### Get Statistics
```json
{
  "status": "ok",
  "stats": {
    "browser_apps": 6,
    "messaging_apps": 9,
    "sensitive_domains": 60,
    "sensitive_title_keywords": 40,
    "removable_drives": 10,
    "upload_types": 10
  }
}
```

---

## ❌ Troubleshooting

| Problem | Solution |
|---------|----------|
| Button "⚙️ Rules Config" không hiện | Chưa copy modal HTML vào dashboard |
| Click button không làm gì | JavaScript không load |
| Modal hiện nhưng empty | API endpoint fail - check admin key |
| "Keyword already exists" | Keyword đã tồn tại - xóa rồi add lại |
| Changes không save | Check file permissions của rules_config.json |
| 401 Unauthorized | Admin key sai - check header |

---

## 🚀 Next Steps

✅ Dashboard modal đã sẵn sàng
✅ API endpoints đã sẵn sàng
✅ Config manager đã sẵn sàng

**Tiếp theo:**
1. Tích hợp UI vào dashboard HTML
2. Thay đổi admin key
3. Test thêm/xóa keywords, domains, apps
4. Deploy lên production
5. Train admin users trên cách sử dụng

---

## 📚 Full Documentation

📖 **API Guide**: `dlp-server/RULES_API_GUIDE.md`
📖 **Integration**: `dlp-server/DASHBOARD_INTEGRATION.md`
📖 **Config Manager**: `HybridDLP_ED/worker/core/CONFIG_GUIDE.md`

---

**Version**: 1.0  
**Last Updated**: April 3, 2026  
**Status**: ✅ Ready for Production
