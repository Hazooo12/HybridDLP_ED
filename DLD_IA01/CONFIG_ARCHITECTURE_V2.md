# Rules Configuration Architecture (v2)

## Tổng Quan

Luồng config mới được thiết kế để tách biệt hoàn toàn:
- **Admin Server** (dlp-server): Quản lý rules config tập trung
- **Endpoint Agents**: Pull config từ admin thông qua Tailscale, apply rules

## Kiến Trúc Mới

```
┌─────────────────────────────────────────────────────────────┐
│                   ADMIN DASHBOARD                           │
│                  (dlp-server/main.py)                       │
│                                                             │
│  Admin config rules: Domains, Keywords, Apps, Drives       │
│  → Store trong SQLite database (dlp_events.db)             │
│  → API endpoints: /api/rules/*                             │
│                                                             │
│  API Endpoints:                                             │
│  - GET  /api/rules/config                                  │
│  - GET  /api/rules/keywords                                │
│  - POST /api/rules/keywords                                │
│  - GET  /api/rules/domains                                 │
│  - POST /api/rules/domains                                 │
│  - GET  /api/rules/apps                                    │
│  - POST /api/rules/apps                                    │
│  - GET  /api/rules/stats                                   │
└────────────┬────────────────────────────────────────────────┘
             │
             │ Tailscale Network
             │ (HTTP requests via Tailscale IP)
             │
    ┌────────▼─────────────────────────────────────────────────┐
    │              ENDPOINT AGENT                              │
    │        (HybridDLP_ED/agent/boot.py)                      │
    │                                                          │
    │  1. Khởi tạo config_sync (config_sync_init.py)          │
    │  2. config_sync periodically pull config từ server      │
    │  3. Lưu config local (rules_config.json)                │
    │  4. Reload behavioral_rules khi config thay đổi         │
    │                                                          │
    │  Components:                                             │
    │  - config_sync.py: Background sync từ server            │
    │  - config_sync_init.py: Bootstrap config_sync           │
    │  - config_provider.py: Unified config interface         │
    │  - behavioral_rules.py: Sử dụng config từ config_sync   │
    └────────────────────────────────────────────────────────┘
```

## Files Được Tạo/Sửa

### Admin Server (dlp-server/)

#### 1. `rules_storage.py` (NEW)
- Quản lý lưu trữ config rules trong SQLite database
- Không phụ thuộc vào HybridDLP_ED
- Key methods:
  - `get_config()`: Lấy toàn bộ config
  - `update_config()`: Cập nhật config
  - `add_sensitive_domain()`, `remove_sensitive_domain()`
  - `add_browser_app()`, `remove_browser_app()`
  - `get_config_stats()`: Thống kê config

#### 2. `main.py` (MODIFIED)
- Removed: Import từ `rules_config_manager` (HybridDLP_ED)
- Added: Import từ `rules_storage.py` (local)
- Updated: Tất cả `/api/rules/*` endpoints sử dụng `get_rules_storage()`
- Endpoints:
  - `GET /api/rules/config` - Lấy config
  - `GET /api/rules/keywords` - Lấy keywords
  - `POST /api/rules/keywords` - Thêm keyword
  - `DELETE /api/rules/keywords/{kw}` - Xóa keyword
  - `GET /api/rules/domains` - Lấy domains
  - `POST /api/rules/domains` - Thêm domain
  - `DELETE /api/rules/domains/{domain}` - Xóa domain
  - `GET /api/rules/apps?app_type=browser|messaging|all` - Lấy apps
  - `POST /api/rules/apps` - Thêm app
  - `DELETE /api/rules/apps/{app}`- Xóa app
  - `GET /api/rules/stats` - Thống kê

### Endpoint Agent (HybridDLP_ED/agent/)

#### 1. `config_sync.py` (NEW)
- Background thread để pull config từ admin server qua Tailscale
- Key methods:
  - `start()`: Bắt đầu sync background
  - `stop()`: Dừng sync
  - `get_browser_apps()`, `get_messaging_apps()`, etc.
  - `set_on_config_updated(callback)`: Set callback khi config thay đổi
  
- Tính năng:
  - Periodically fetch config (default: 30 giây)
  - Detect config changes bằng SHA256 hash
  - Lưu config local (rules_config.json)
  - Backup to file khi thay đổi

#### 2. `config_sync_init.py` (NEW)
- Bootstrap script để khởi tạo config_sync
- `initialize_config_sync()`: Khởi tạo từ config.py
- `on_config_updated()`: Callback khi config thay đổi

#### 3. `boot.py` (MODIFIED)
- Added: Khởi tạo config_sync trước khi chạy system tray
- Gọi `initialize_config_sync()` sau khi setup

### Endpoint Worker (HybridDLP_ED/worker/core/)

#### 1. `config_provider.py` (NEW)
- Unified interface để lấy config từ:
  1. config_sync (realtime từ server - priority 1)
  2. rules_config_manager (local file - fallback)
  
- Key methods:
  - `get_browser_apps()`, `get_messaging_apps()`, etc.
  - Automatically prioritize config_sync nếu available

#### 2. `behavioral_rules.py` (MODIFIED)
- Changed: Import từ `config_provider` thay vì `rules_config_manager`
- Tổng lợi ích:
  - Rules automatically use latest config từ server
  - Khi admin cập nhật config → agents tự động pick up trong 30 giây
  - Không cần restart agents

## Luồng Config Update

### Admin cập nhật config:

```
1. Admin vào Dashboard (dlp-server)
   ↓
2. Chỉnh sửa Rules Config (Keywords, Domains, Apps)
   ↓
3. API call: PUT /api/rules/domains (add "example.com")
   ↓
4. Server cập nhật database (rules_config)
   ↓
5. Backup to file (rules_config.json)
   ↓
6. Agents periodically call: GET /api/rules/config
   ↓
7. Agents detect hash change → Save locally
   ↓
8. Callback: on_config_updated() triggered
   ↓
9. Behavioral rules reload config từ config_provider
   ↓
10. Next event check sử dụng config mới
```

## Cách Sử Dụng

### 1. Admin Config qua Dashboard

```
GET /api/rules/keywords?x-admin-key=admin123

POST /api/rules/keywords
Headers:
  X-Admin-Key: admin123
Body:
  {"keyword": "sensitive-info"}

DELETE /api/rules/keywords/old-keyword?x-admin-key=admin123

GET /api/rules/config?x-admin-key=admin123

GET /api/rules/stats?x-admin-key=admin123
```

### 2. Agent Auto-sync

Config sync chạy tự động sau khi boot.py khởi động:

```python
# Trong boot.py
from config_sync_init import initialize_config_sync

config_sync = initialize_config_sync()
# ✓ Config được pull từ server setiap 30 giây
# ✓ Local cache: HybridDLP_ED/agent/runtime/rules_config.json
# ✓ Behavioral rules automatically reload khi config thay đổi
```

### 3. Manual Config Check

```python
# Từ agent code
from config_sync import get_config_sync

sync = get_config_sync()
if sync:
    domains = sync.get_sensitive_domains()
    keywords = sync.get_sensitive_title_keywords()
```

## Tailscale Configuration

Admin server IP (Tailscale) được lưu trong:
```
HybridDLP_ED/agent/runtime/config/config.json
{
  "server_url": "http://100.x.x.x:8000",
  "api_key": "dlp-key-..."
}
```

Config sync tự động extract IP từ server_url.

## Database Schema

Admin server lưu config trong SQLite table:

```sql
CREATE TABLE rules_config (
    id INTEGER PRIMARY KEY,
    key TEXT UNIQUE NOT NULL,  -- Always "main"
    config_json TEXT NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## Error Handling

### Agent Connection Error
- Nếu agent không thể kết nối server: **Silent fail** (không crash)
- Agent sử dụng config local (last cached version)
- Retry setiap 30 giây

### Config Parse Error
- Nếu JSON format sai: Log warning, use previous valid config
- Backup file memastikan config selalu available

## Performance

| Metric | Value |
|--------|-------|
| Sync interval | 30 giây |
| Config size | ~200KB average |
| HTTP timeout | 10 giây |
| Local cache | Disk-based JSON |
| Hash computation | SHA256 (instant) |
| Memory usage | ~1MB per agent |

## Migration từ V1

Nếu bạn đang dùng V1 (rules_config.json ở worker/core/):

```bash
# 1. Copy rules_config.json từ worker/core/
cp HybridDLP_ED/worker/core/rules_config.json HybridDLP_ED/agent/runtime/

# 2. Admin server sẽ auto-import config từ /api/rules/config khi first time
# 3. Restart agents - config sync sẽ initialize automatically
```

## Testing

### Test Admin API

```bash
# List keywords
curl -H "X-Admin-Key: admin123" \
  http://localhost:8000/api/rules/keywords

# Add keyword
curl -X POST \
  -H "X-Admin-Key: admin123" \
  -H "Content-Type: application/json" \
  -d '{"keyword": "test-keyword"}' \
  http://localhost:8000/api/rules/keywords

# Get config
curl -H "X-Admin-Key: admin123" \
  http://localhost:8000/api/rules/config
```

### Test Agent Sync

```bash
# Monitor config sync (on endpoint machine)
tail -f logs/config_sync.log  # Check if sync is working
cat agent/runtime/rules_config.json  # Check local cache
```

## Future Enhancements

- [ ] Config versioning (track all changes)
- [ ] Config approval workflow (require admin approval for changes)
- [ ] Real-time WebSocket push (instead of polling)
- [ ] Config rollback capability
- [ ] A/B testing different configs per machine group
