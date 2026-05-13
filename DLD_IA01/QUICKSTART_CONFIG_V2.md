# Quick Start: Rules Configuration Management (v2)

## Tóm Tắt Thay Đổi

**Trước đây (V1):**
- Admin phải edit file `rules_config.json` trực tiếp trên từng endpoint
- Config không được đồng bộ tự động
- Khó quản lý nhiều máy

**Bây giờ (V2):**
- ✅ Admin quản lý config tập trung trên Dashboard
- ✅ Configs tự động sync từ admin → tất cả endpoints (qua Tailscale)
- ✅ Changes áp dụng trong 30 giây
- ✅ Quản lý dễ dàng qua Web UI

## Setup

### Bước 1: Cập nhật Admin Server (dlp-server)

```bash
cd dlp-server

# Ensure requirements installed
pip install fastapi httpx loguru

# Run server
uvicorn main:app --host 0.0.0.0 --port 8000
```

**Lần đầu tiên:**
- Server sẽ auto-create database schema
- Default config được load từ `rules_storage.DEFAULT_CONFIG`

### Bước 2: Cập nhật Endpoint Agents

```bash
cd HybridDLP_ED

# Ensure dependencies
pip install -r agent/requirements.txt

# Run agent (config_sync sẽ auto-init)
python -m agent.boot
```

**Lần đầu tiên:**
- Agent sẽ connect tới admin server (qua Tailscale)
- Pull config và lưu locally
- Start periodical sync (30 giây)

**Tùy chọn:** Nếu bạn đã có rules_config.json cũ:

```bash
# Copy file cũ vào runtime folder
cp worker/core/rules_config.json agent/runtime/

# Config này sẽ được sử dụng nếu server không available
```

## Cách Sử Dụng

### 1. Access Dashboard

```
Admin: http://100.91.22.25:8080
Password: (setup wizard)
```

Chọn tab: **"Rules Config"** → See UI để manage rules

### 2. Add Sensitive Domain

**Method**: POST
```bash
curl -X POST \
  -H "X-Admin-Key: admin123" \
  -H "Content-Type: application/json" \
  -d '{"domain": "mycompany.slack.com"}' \
  http://100.91.22.25:8000/api/rules/domains
```

**Result:**
- ✓ Domain added to server database
- ✓ Agents pull config in next 30 seconds
- ✓ Behavioral rules sử dụng domain baru immediately

### 3. Add Sensitive Keyword

```bash
curl -X POST \
  -H "X-Admin-Key: admin123" \
  -H "Content-Type: application/json" \
  -d '{"keyword": "project-alpha"}' \
  http://100.91.22.25:8000/api/rules/keywords
```

### 4. Add Browser Application

```bash
curl -X POST \
  -H "X-Admin-Key: admin123" \
  -H "Content-Type: application/json" \
  -d '{"app_name": "edge.exe", "app_type": "browser"}' \
  http://100.91.22.25:8000/api/rules/apps
```

### 5. List Current Config

```bash
curl -H "X-Admin-Key: admin123" \
  http://100.91.22.25:8000/api/rules/config
```

Response:
```json
{
  "status": "ok",
  "config": {
    "clipboard_paste_rule": {
      "browser_apps": ["chrome.exe", "edge.exe", ...],
      "messaging_apps": ["teams.exe", ...],
      "sensitive_domains": ["chatgpt.com", ...],
      "sensitive_title_keywords": [...]
    },
    "usb_rule": {
      "removable_drives": ["e:", "f:", ...]
    },
    "network_rule": {...}
  }
}
```

## Troubleshooting

### Problem: Agent không connect tới server

**Solution:**
1. Check Tailscale IP trong agent config:
   ```
   cat HybridDLP_ED/agent/runtime/config/config.json
   ```

2. Verify server is running:
   ```bash
   curl http://100.91.22.25:8000/api/rules/config \
     -H "X-Admin-Key: admin123"
   ```

3. Check logs:
   ```bash
   # Agent
   tail -f HybridDLP_ED/agent/logs/*.log | grep -i "config"
   
   # Server
   tail -f dlp-server/logs/*.log | grep -i "config"
   ```

### Problem: Changes not reflected on agent

**Solution:**
1. Check if agent is running (should see "Config Sync" in logs)

2. Force sync (wait 30 seconds or restart agent):
   ```bash
   # Check local cache
   cat HybridDLP_ED/agent/runtime/rules_config.json
   ```

3. Check if server has the new config:
   ```bash
   curl http://100.91.22.25:8000/api/rules/domains \
     -H "X-Admin-Key: admin123"
   ```

### Problem: Server throws 401 error

**Solution:**
- Make sure admin key is correct:
  ```
  X-Admin-Key: admin123  # In dlp-server/main.py
  ```

## API Reference

### Keywords

```bash
# List
GET /api/rules/keywords
  Header: X-Admin-Key: admin123

# Add
POST /api/rules/keywords
  Header: X-Admin-Key: admin123
  Body: {"keyword": "string"}

# Delete
DELETE /api/rules/keywords/{keyword}
  Header: X-Admin-Key: admin123
```

### Domains

```bash
# List
GET /api/rules/domains
  Header: X-Admin-Key: admin123

# Add
POST /api/rules/domains
  Header: X-Admin-Key: admin123
  Body: {"domain": "example.com"}

# Delete
DELETE /api/rules/domains/{domain}
  Header: X-Admin-Key: admin123
```

### Apps

```bash
# List (browser|messaging|all)
GET /api/rules/apps?app_type=browser
  Header: X-Admin-Key: admin123

# Add
POST /api/rules/apps
  Header: X-Admin-Key: admin123
  Body: {"app_name": "chrome.exe", "app_type": "browser"}

# Delete
DELETE /api/rules/apps/{app_name}?app_type=browser
  Header: X-Admin-Key: admin123
```

### Config

```bash
# Get full config
GET /api/rules/config
  Header: X-Admin-Key: admin123

# Get statistics
GET /api/rules/stats
  Header: X-Admin-Key: admin123

# Reload (deprecated - auto-reload when changed)
POST /api/rules/config/reload
  Header: X-Admin-Key: admin123
```

## Files to Remember

| File | Purpose |
|------|---------|
| `dlp-server/rules_storage.py` | Config storage (Admin) |
| `dlp-server/main.py` | API endpoints (Admin) |
| `HybridDLP_ED/agent/config_sync.py` | Background sync (Agent) |
| `HybridDLP_ED/agent/config_sync_init.py` | Bootstrap (Agent) |
| `HybridDLP_ED/agent/boot.py` | Entry point (Agent) |
| `HybridDLP_ED/worker/core/config_provider.py` | Config interface (Worker) |
| `HybridDLP_ED/worker/core/behavioral_rules.py` | Uses config_provider (Worker) |

## Monitoring

### Check Agent Sync Status

```bash
# Check if config_sync is running (via logs)
grep -i "config sync" agent/logs/app.log

# Check local cache timestamp
ls -la agent/runtime/rules_config.json
stat agent/runtime/rules_config.json
```

### Check Server Status

```bash
curl http://100.91.22.25:8000/api/rules/stats \
  -H "X-Admin-Key: admin123"
```

Output:
```json
{
  "status": "ok",
  "stats": {
    "browser_apps": 7,
    "messaging_apps": 9,
    "sensitive_domains": 50,
    "sensitive_title_keywords": 40,
    "removable_drives": 4,
    "upload_types": 10
  }
}
```

## Advanced

### Custom Sync Interval

Edit `HybridDLP_ED/agent/config_sync_init.py`:

```python
config_sync = init_config_sync(
    server_ip=server_ip,
    api_key=api_key,
    local_config_path=...,
    sync_interval=60,  # Sync every 60 seconds (default: 30)
    on_config_updated=...
)
```

### Disable Config Sync

If you want to use local config only (no sync):

```python
# In boot.py - comment out or skip:
# config_sync = initialize_config_sync()
```

Then agent will use `agent/runtime/rules_config.json` (local file).

---

**Need Help?** Check detailed architecture in [CONFIG_ARCHITECTURE_V2.md](CONFIG_ARCHITECTURE_V2.md)
