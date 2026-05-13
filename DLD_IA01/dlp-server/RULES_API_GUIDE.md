# Rules Configuration API - Dashboard Integration Guide

## Tổng Quan

Dashboard đã được tích hợp với các endpoints để quản lý cấu hình behavioral rules mà không cần restart server hay sửa code. Admin có thể thêm/xóa keywords, domains, apps thông qua API.

## Authentication

Tất cả endpoints yêu cầu header `X-Admin-Key`:
```
X-Admin-Key: admin-dashboard-secret-key
```

## Base URL

```
http://server-ip:8000/api/rules
```

## Các Endpoints

### 1. 🔑 Quản Lý Keywords (Từ Khóa Nhạy Cảm)

#### Lấy danh sách keywords
```http
GET /api/rules/keywords
Header: X-Admin-Key: admin-dashboard-secret-key
```

**Response:**
```json
{
  "status": "ok",
  "keywords": ["chatgpt", "claude", "discord", "gmail", "slack", ...],
  "total": 40
}
```

#### Thêm keyword mới
```http
POST /api/rules/keywords
Header: X-Admin-Key: admin-dashboard-secret-key
Content-Type: application/json

{
  "keyword": "myapp"
}
```

**Response:**
```json
{
  "status": "ok",
  "message": "Keyword 'myapp' added successfully",
  "keyword": "myapp"
}
```

#### Xóa keyword
```http
DELETE /api/rules/keywords/myapp
Header: X-Admin-Key: admin-dashboard-secret-key
```

**Response:**
```json
{
  "status": "ok",
  "message": "Keyword 'myapp' removed successfully"
}
```

---

### 2. 🌐 Quản Lý Domains (Domain Nhạy Cảm)

#### Lấy danh sách domains
```http
GET /api/rules/domains
Header: X-Admin-Key: admin-dashboard-secret-key
```

**Response:**
```json
{
  "status": "ok",
  "domains": ["chat.openai.com", "chatgpt.com", "gmail.com", "slack.com", ...],
  "total": 60
}
```

#### Thêm domain mới
```http
POST /api/rules/domains
Header: X-Admin-Key: admin-dashboard-secret-key
Content-Type: application/json

{
  "domain": "mycompany.slack.com"
}
```

**Response:**
```json
{
  "status": "ok",
  "message": "Domain 'mycompany.slack.com' added successfully",
  "domain": "mycompany.slack.com"
}
```

#### Xóa domain
```http
DELETE /api/rules/domains/mycompany.slack.com
Header: X-Admin-Key: admin-dashboard-secret-key
```

**Response:**
```json
{
  "status": "ok",
  "message": "Domain 'mycompany.slack.com' removed successfully"
}
```

---

### 3. 💾 Quản Lý Applications (Ứng Dụng)

#### Lấy danh sách ứng dụng
```http
GET /api/rules/apps?app_type=all
Header: X-Admin-Key: admin-dashboard-secret-key
```

**Query Parameters:**
- `app_type`: `browser` | `messaging` | `all` (default: `all`)

**Response (app_type=all):**
```json
{
  "status": "ok",
  "data": {
    "browser_apps": ["chrome.exe", "firefox.exe", "msedge.exe", ...],
    "messaging_apps": ["discord.exe", "slack.exe", "teams.exe", ...]
  }
}
```

#### Thêm ứng dụng mới
```http
POST /api/rules/apps
Header: X-Admin-Key: admin-dashboard-secret-key
Content-Type: application/json

{
  "app_name": "opera.exe",
  "app_type": "browser"
}
```

**Response:**
```json
{
  "status": "ok",
  "message": "App 'opera.exe' added to browser_apps",
  "app_name": "opera.exe",
  "app_type": "browser"
}
```

**Hoặc thêm messaging app:**
```json
{
  "app_name": "viber.exe",
  "app_type": "messaging"
}
```

#### Xóa ứng dụng
```http
DELETE /api/rules/apps/opera.exe?app_type=browser
Header: X-Admin-Key: admin-dashboard-secret-key
```

**Query Parameters:**
- `app_type`: `browser` | `messaging`

**Response:**
```json
{
  "status": "ok",
  "message": "App 'opera.exe' removed from browser_apps"
}
```

---

### 4. ⚙️ Quản Lý Toàn Bộ Configuration

#### Lấy toàn bộ config
```http
GET /api/rules/config
Header: X-Admin-Key: admin-dashboard-secret-key
```

**Response:**
```json
{
  "status": "ok",
  "config": {
    "clipboard_paste_rule": {
      "browser_apps": [...],
      "messaging_apps": [...],
      "sensitive_domains": [...],
      "sensitive_title_keywords": [...]
    },
    "usb_rule": {
      "removable_drives": [...]
    },
    "network_rule": {
      "upload_types": [...],
      "browser_apps": [...],
      "desktop_upload_apps": [...],
      "cli_tools": [...],
      "sensitive_domains": [...]
    }
  }
}
```

#### Reload config từ file
```http
POST /api/rules/config/reload
Header: X-Admin-Key: admin-dashboard-secret-key
```

**Response:**
```json
{
  "status": "ok",
  "message": "Rules configuration reloaded successfully"
}
```

#### Lấy thống kê config
```http
GET /api/rules/stats
Header: X-Admin-Key: admin-dashboard-secret-key
```

**Response:**
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

## Ví Dụ JavaScript/Frontend

### Lấy Keywords (trong Dashboard)
```javascript
async function getKeywords() {
  const response = await fetch('/api/rules/keywords', {
    method: 'GET',
    headers: {
      'X-Admin-Key': 'admin-dashboard-secret-key'
    }
  });
  const data = await response.json();
  console.log(data.keywords);
}
```

### Thêm Keyword Mới
```javascript
async function addKeyword(keyword) {
  const response = await fetch('/api/rules/keywords', {
    method: 'POST',
    headers: {
      'X-Admin-Key': 'admin-dashboard-secret-key',
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ keyword: keyword })
  });
  const data = await response.json();
  if (response.ok) {
    console.log(`Keyword '${keyword}' added successfully`);
  } else {
    console.error(data.detail);
  }
}
```

### Xóa Keyword
```javascript
async function removeKeyword(keyword) {
  const response = await fetch(`/api/rules/keywords/${keyword}`, {
    method: 'DELETE',
    headers: {
      'X-Admin-Key': 'admin-dashboard-secret-key'
    }
  });
  const data = await response.json();
  if (response.ok) {
    console.log(`Keyword '${keyword}' removed`);
  } else {
    console.error(data.detail);
  }
}
```

### Thêm Domain
```javascript
async function addDomain(domain) {
  const response = await fetch('/api/rules/domains', {
    method: 'POST',
    headers: {
      'X-Admin-Key': 'admin-dashboard-secret-key',
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ domain: domain })
  });
  const data = await response.json();
  if (response.ok) {
    console.log(`Domain '${domain}' added successfully`);
  }
}
```

### Thêm Ứng Dụng
```javascript
async function addApp(appName, appType) {
  const response = await fetch('/api/rules/apps', {
    method: 'POST',
    headers: {
      'X-Admin-Key': 'admin-dashboard-secret-key',
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ 
      app_name: appName, 
      app_type: appType  // 'browser' or 'messaging'
    })
  });
  const data = await response.json();
  if (response.ok) {
    console.log(`App '${appName}' added to ${appType}_apps`);
  }
}
```

### Lấy Thống Kê
```javascript
async function getStats() {
  const response = await fetch('/api/rules/stats', {
    method: 'GET',
    headers: {
      'X-Admin-Key': 'admin-dashboard-secret-key'
    }
  });
  const data = await response.json();
  console.log(data.stats);
  // Output:
  // {
  //   "browser_apps": 6,
  //   "messaging_apps": 9,
  //   ...
  // }
}
```

---

## Dashboard UI Components (Ví Dụ)

### Keywords Management Panel
```html
<div class="panel">
  <h3>📝 Sensitive Keywords</h3>
  
  <div class="add-keyword">
    <input type="text" id="keywordInput" placeholder="Enter keyword...">
    <button onclick="addKeywordFromUI()">Add Keyword</button>
  </div>
  
  <div class="keywords-list" id="keywordsList">
    <!-- Dynamically populated -->
  </div>
</div>
```

```javascript
async function loadKeywords() {
  const response = await fetch('/api/rules/keywords', {
    headers: { 'X-Admin-Key': getDashboardKey() }
  });
  const data = await response.json();
  
  const list = document.getElementById('keywordsList');
  list.innerHTML = '';
  
  data.keywords.forEach(keyword => {
    const item = document.createElement('div');
    item.className = 'keyword-item';
    item.innerHTML = `
      <span>${keyword}</span>
      <button onclick="removeKeywordFromUI('${keyword}')">Remove</button>
    `;
    list.appendChild(item);
  });
}

async function addKeywordFromUI() {
  const input = document.getElementById('keywordInput');
  const keyword = input.value.trim();
  
  if (!keyword) return;
  
  const response = await fetch('/api/rules/keywords', {
    method: 'POST',
    headers: {
      'X-Admin-Key': getDashboardKey(),
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ keyword })
  });
  
  if (response.ok) {
    input.value = '';
    loadKeywords();
  } else {
    const error = await response.json();
    alert(`Error: ${error.detail}`);
  }
}

async function removeKeywordFromUI(keyword) {
  if (!confirm(`Remove keyword '${keyword}'?`)) return;
  
  const response = await fetch(`/api/rules/keywords/${keyword}`, {
    method: 'DELETE',
    headers: { 'X-Admin-Key': getDashboardKey() }
  });
  
  if (response.ok) {
    loadKeywords();
  }
}
```

---

## Error Handling

### HTTP Status Codes
- `200 OK` - Request thành công
- `400 Bad Request` - Input không hợp lệ (empty keyword, etc.)
- `401 Unauthorized` - Admin key không hợp lệ
- `404 Not Found` - Item không tìm thấy
- `409 Conflict` - Item đã tồn tại
- `500 Internal Error` - Lỗi server

### Response Errors
```json
{
  "detail": "Keyword 'mykey' already exists"
}
```

---

## Best Practices

1. **Validate Input** - Kiểm tra keyword/domain/app trước khi gửi
2. **Reload Config** - Sau khi thêm/xóa, reload config để agent nhận thay đổi
3. **Cache Results** - Cache keywords/domains list để không gọi API quá nhiều
4. **Display Stats** - Hiển thị số lượng keywords/domains/apps trên dashboard
5. **Confirmation Dialog** - Hỏi xác nhận trước khi xóa
6. **Error Messages** - Hiển thị error message thân thiện cho user

---

## Quy Trình Cập Nhật Config Từ Dashboard

### Bước 1: Admin thêm keyword/domain
```
Dashboard → Input keyword → Click Add
```

### Bước 2: API Server nhận request
```
POST /api/rules/keywords
→ Validate & Add to config
→ Save to rules_config.json
```

### Bước 3: Config được reload (tùy chọn)
```
POST /api/rules/config/reload
→ Agents reload config
→ Behavioral rules được cập nhật
```

### Bước 4: Agent áp dụng config mới
```
ClipboardPasteToExternalAppRule.__init__()
→ Load từ config_manager.get_sensitive_title_keywords()
→ Keyword mới được sử dụng ngay
```

---

## Liên Kết Files

- **Server:** `dlp-server/main.py`
- **Config Manager:** `HybridDLP_ED/worker/core/rules_config_manager.py`
- **Config File:** `HybridDLP_ED/worker/core/rules_config.json`
