"""
main.py — FastAPI server trung tâm cho DLP
Chạy: uvicorn main:app --host 0.0.0.0 --port 8000
"""
import secrets
import hashlib
import sys
from pathlib import Path
from fastapi import FastAPI, Request, Header, HTTPException, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
import uvicorn

from database import init_db, insert_event, insert_batch, query_events, get_stats, get_machines, \
    insert_agent, get_agents, get_agent, delete_agent, update_agent_last_connection

# Import rules storage (quản lý config trên server, KHÔNG phụ thuộc vào HybridDLP_ED)
from rules_storage import get_rules_storage

# ============================================================
# API KEYS — được load từ database + default keys
# Format: "api-key-value": "Tên máy hiển thị trên dashboard"
#
# Cách tạo key mới:
#   python -c "import secrets; print(secrets.token_urlsafe(32))"
# ============================================================

# Default agents (nếu database trống)
DEFAULT_AGENT_KEYS = {
    "dlp-key-may-ketoan-01":  "PC-KeToan-01",
    "dlp-key-may-nhansu-02":  "PC-NhanSu-02",
    "dlp-key-may-admin":      "PC-Admin",
    "laptop-cua-phu1":         "Laptop-Cua-Phu",
}

# AGENT_KEYS sẽ được load từ database
AGENT_KEYS = {}

# Key riêng cho dashboard (admin xem)
DASHBOARD_KEY = "admin123"

# ============================================================
app = FastAPI(title="DLP Central Server", version="1.0")
init_db()


# Khởi tạo agents: sync default keys + load all từ database
def init_agents():
    """
    Khởi tạo agents:
    1. Sync default keys vào DB (nếu chưa có)
    2. Load ALL agents từ database vào AGENT_KEYS
    """
    global AGENT_KEYS
    
    # Bước 1: Insert default keys nếu chưa tồn tại
    for api_key, machine_name in DEFAULT_AGENT_KEYS.items():
        if not get_agent(api_key):
            insert_agent(api_key, machine_name, machine_name)
            print(f"[INIT] Added default agent: {api_key}")
    
    # Bước 2: Load ALL agents từ database
    try:
        agents_response = get_agents()
        
        # get_agents() có thể trả về dict hoặc list
        if isinstance(agents_response, dict):
            # API response format
            agents = agents_response.get('data', [])
        elif isinstance(agents_response, list):
            # Direct list format
            agents = agents_response
        else:
            agents = []
        
        if agents:
            for agent in agents:
                api_key = agent.get('api_key') if isinstance(agent, dict) else None
                machine_name = agent.get('machine_name') if isinstance(agent, dict) else None
                if api_key and machine_name:
                    AGENT_KEYS[api_key] = machine_name
            print(f"[INIT] Loaded {len(AGENT_KEYS)} agents from database")
        else:
            # Fallback to default keys nếu không thể load từ DB
            AGENT_KEYS.update(DEFAULT_AGENT_KEYS)
            print(f"[INIT] Loaded {len(AGENT_KEYS)} default agents")
    except Exception as e:
        print(f"[INIT] Error loading agents: {e}, using defaults")
        AGENT_KEYS.update(DEFAULT_AGENT_KEYS)
    
    print(f"[INIT] Active API keys: {list(AGENT_KEYS.keys())}")


init_agents()


# ---- Helper xác thực ----
def require_agent(x_api_key: str | None) -> str:
    """Trả về machine_name nếu hợp lệ, raise 401 nếu không."""
    if not x_api_key or x_api_key not in AGENT_KEYS:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return AGENT_KEYS[x_api_key]


def require_dashboard(x_admin_key: str | None) -> bool:
    """Xác thực dashboard key."""
    if not x_admin_key or x_admin_key != DASHBOARD_KEY:
        raise HTTPException(status_code=401, detail="Invalid admin key")
    return True


# ============================================================
# ENDPOINT: Nhận event từ DLP agent
# ============================================================

@app.post("/api/events")
async def receive_event(
    request: Request,
    x_api_key: str = Header(None)
):
    """Nhận 1 event đơn lẻ từ endpoint."""
    machine = require_agent(x_api_key)
    data = await request.json()
    new_id = insert_event(machine, data)
    update_agent_last_connection(x_api_key)  # Cập nhật last connection
    return {"status": "ok", "id": new_id, "machine": machine}


@app.post("/api/events/batch")
async def receive_batch(
    request: Request,
    x_api_key: str = Header(None)
):
    """Nhận nhiều events cùng lúc (list). Hiệu quả hơn khi gửi theo đợt."""
    machine = require_agent(x_api_key)
    data = await request.json()

    if not isinstance(data, list):
        raise HTTPException(status_code=400, detail="Payload must be a JSON array")

    count = insert_batch(machine, data)
    update_agent_last_connection(x_api_key)  # Cập nhật last connection
    return {"status": "ok", "saved": count, "machine": machine}


# ============================================================
# ENDPOINT: Dashboard đọc dữ liệu
# ============================================================

@app.get("/api/events")
async def list_events(
    limit:      int   = Query(500, le=2000),
    action:     str   = Query(None),
    min_risk:   float = Query(0),
    max_risk:   float = Query(10),
    machine:    str   = Query(None),
):
    """Truy vấn events với filter — dashboard gọi endpoint này."""
    return query_events(
        limit=limit,
        action=action,
        min_risk=min_risk,
        max_risk=max_risk,
        machine=machine,
    )


@app.get("/api/stats")
async def stats():
    """KPI tổng hợp cho dashboard header."""
    return get_stats()


@app.get("/api/machines")
async def machines():
    """Danh sách máy đã kết nối."""
    return get_machines()


@app.get("/api/events/{event_id}")
async def get_event_detail(event_id: int):
    """Lấy chi tiết một event theo ID."""
    conn = __import__('sqlite3').connect("dlp_events.db")
    conn.row_factory = __import__('sqlite3').Row
    row = conn.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
    conn.close()
    
    if not row:
        raise HTTPException(status_code=404, detail="Event not found")
    
    import json
    result = dict(row)
    result["keywords"] = json.loads(result["keywords"] or "[]")
    result["is_clipboard"] = bool(result["is_clipboard"])
    return result


# ============================================================
# ENDPOINT: Quản lý Agents
# ============================================================

@app.get("/api/agents")
async def list_agents():
    """Lấy danh sách tất cả agents và trạng thái kết nối."""
    return get_agents()


@app.post("/api/agents")
async def create_agent(
    request: Request,
    x_admin_key: str = Header(None)
):
    """Tạo agent key mới (yêu cầu dashboard key)."""
    require_dashboard(x_admin_key)
    
    data = await request.json()
    api_key = data.get("api_key")
    machine_name = data.get("machine_name")
    display_name = data.get("display_name", machine_name)
    
    if not api_key or not machine_name:
        raise HTTPException(status_code=400, detail="api_key and machine_name are required")
    
    if insert_agent(api_key, machine_name, display_name):
        # Thêm vào AGENT_KEYS để agent có thể kết nối ngay
        AGENT_KEYS[api_key] = machine_name
        return {"status": "ok", "api_key": api_key}
    else:
        raise HTTPException(status_code=409, detail="API key already exists")


@app.delete("/api/agents/{api_key}")
async def remove_agent(
    api_key: str,
    x_admin_key: str = Header(None)
):
    """Xóa agent (yêu cầu dashboard key)."""
    require_dashboard(x_admin_key)
    
    if delete_agent(api_key):
        # Xóa khỏi AGENT_KEYS để agent không thể kết nối nữa
        if api_key in AGENT_KEYS:
            del AGENT_KEYS[api_key]
        return {"status": "ok", "deleted": api_key}
    else:
        raise HTTPException(status_code=404, detail="Agent not found")


# ============================================================
# ENDPOINT: Debug & Management
# ============================================================

@app.get("/api/debug/agent-keys")
async def debug_agent_keys(x_admin_key: str = Header(None)):
    """🔍 Debug: Kiểm tra hiện tại AGENT_KEYS có gì"""
    require_dashboard(x_admin_key)
    
    return {
        "status": "ok",
        "agent_keys": AGENT_KEYS,
        "total": len(AGENT_KEYS),
        "keys": list(AGENT_KEYS.keys())
    }


@app.post("/api/debug/reload-agents")
async def reload_agents_endpoint(x_admin_key: str = Header(None)):
    """🔄 Reload AGENT_KEYS từ database (không cần restart server)"""
    require_dashboard(x_admin_key)
    
    try:
        init_agents()
        return {
            "status": "ok",
            "message": "Agents reloaded from database",
            "total": len(AGENT_KEYS),
            "agent_keys": AGENT_KEYS
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================
# ENDPOINT: Quản lý Rules Configuration (Keywords, Domains, Apps)
# ============================================================

# ----- KEYWORDS ENDPOINTS -----

@app.get("/api/rules/keywords")
async def list_keywords(x_admin_key: str = Header(None)):
    """Lấy danh sách tất cả sensitive title keywords."""
    require_dashboard(x_admin_key)
    
    try:
        storage = get_rules_storage()
        keywords = storage.get_sensitive_title_keywords()
        return {
            "status": "ok",
            "keywords": sorted(keywords),
            "total": len(keywords)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/rules/keywords")
async def add_keyword(
    request: Request,
    x_admin_key: str = Header(None)
):
    """Thêm sensitive keyword mới."""
    require_dashboard(x_admin_key)
    
    try:
        data = await request.json()
        keyword = data.get("keyword", "").strip().lower()
        
        if not keyword:
            raise HTTPException(status_code=400, detail="Keyword cannot be empty")
        
        storage = get_rules_storage()
        
        # Kiểm tra keyword đã tồn tại
        existing_keywords = storage.get_sensitive_title_keywords()
        if keyword in existing_keywords:
            raise HTTPException(status_code=409, detail=f"Keyword '{keyword}' already exists")
        
        # Thêm keyword
        if storage.add_sensitive_keyword(keyword):
            return {
                "status": "ok",
                "message": f"Keyword '{keyword}' added successfully",
                "keyword": keyword
            }
        else:
            raise HTTPException(status_code=500, detail="Failed to add keyword")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/api/rules/keywords/{keyword}")
async def remove_keyword(
    keyword: str,
    x_admin_key: str = Header(None)
):
    """Xóa sensitive keyword."""
    require_dashboard(x_admin_key)
    
    try:
        keyword = keyword.strip().lower()
        storage = get_rules_storage()
        
        # Kiểm tra keyword tồn tại
        existing_keywords = storage.get_sensitive_title_keywords()
        if keyword not in existing_keywords:
            raise HTTPException(status_code=404, detail=f"Keyword '{keyword}' not found")
        
        # Xóa keyword
        if storage.remove_sensitive_keyword(keyword):
            return {
                "status": "ok",
                "message": f"Keyword '{keyword}' removed successfully"
            }
        else:
            raise HTTPException(status_code=500, detail="Failed to remove keyword")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ----- DOMAINS ENDPOINTS -----

@app.get("/api/rules/domains")
async def list_domains(x_admin_key: str = Header(None)):
    """Lấy danh sách tất cả sensitive domains."""
    require_dashboard(x_admin_key)
    
    try:
        storage = get_rules_storage()
        domains = storage.get_sensitive_domains()
        return {
            "status": "ok",
            "domains": sorted(domains),
            "total": len(domains)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/rules/domains")
async def add_domain(
    request: Request,
    x_admin_key: str = Header(None)
):
    """Thêm sensitive domain mới."""
    require_dashboard(x_admin_key)
    
    try:
        data = await request.json()
        domain = data.get("domain", "").strip().lower()
        
        if not domain:
            raise HTTPException(status_code=400, detail="Domain cannot be empty")
        
        storage = get_rules_storage()
        
        # Kiểm tra domain đã tồn tại
        existing_domains = storage.get_sensitive_domains()
        if domain in existing_domains:
            raise HTTPException(status_code=409, detail=f"Domain '{domain}' already exists")
        
        # Thêm domain
        if storage.add_sensitive_domain(domain):
            return {
                "status": "ok",
                "message": f"Domain '{domain}' added successfully",
                "domain": domain
            }
        else:
            raise HTTPException(status_code=500, detail="Failed to add domain")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/api/rules/domains/{domain}")
async def remove_domain(
    domain: str,
    x_admin_key: str = Header(None)
):
    """Xóa sensitive domain."""
    require_dashboard(x_admin_key)
    
    try:
        domain = domain.strip().lower()
        storage = get_rules_storage()
        
        # Kiểm tra domain tồn tại
        existing_domains = storage.get_sensitive_domains()
        if domain not in existing_domains:
            raise HTTPException(status_code=404, detail=f"Domain '{domain}' not found")
        
        # Xóa domain
        if storage.remove_sensitive_domain(domain):
            return {
                "status": "ok",
                "message": f"Domain '{domain}' removed successfully"
            }
        else:
            raise HTTPException(status_code=500, detail="Failed to remove domain")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
        
        return {
            "status": "ok",
            "message": f"Domain '{domain}' removed successfully"
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ----- APPS ENDPOINTS -----

@app.get("/api/rules/apps")
async def list_apps(
    app_type: str = Query("all", regex="^(browser|messaging|all)$"),
    x_admin_key: str = Header(None)
):
    """Lấy danh sách ứng dụng (browser, messaging, hoặc cả hai)."""
    require_dashboard(x_admin_key)
    
    try:
        storage = get_rules_storage()
        result = {}
        
        if app_type in ["browser", "all"]:
            result["browser_apps"] = sorted(storage.get_browser_apps())
        
        if app_type in ["messaging", "all"]:
            result["messaging_apps"] = sorted(storage.get_messaging_apps())
        
        return {
            "status": "ok",
            "data": result
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/rules/apps")
async def add_app(
    request: Request,
    x_admin_key: str = Header(None)
):
    """Thêm ứng dụng mới (browser hoặc messaging)."""
    require_dashboard(x_admin_key)
    
    try:
        data = await request.json()
        app_name = data.get("app_name", "").strip().lower()
        app_type = data.get("app_type", "browser").strip().lower()
        
        if not app_name:
            raise HTTPException(status_code=400, detail="App name cannot be empty")
        
        if app_type not in ["browser", "messaging"]:
            raise HTTPException(status_code=400, detail="App type must be 'browser' or 'messaging'")
        
        storage = get_rules_storage()
        
        # Kiểm tra app đã tồn tại
        if app_type == "browser":
            existing_apps = storage.get_browser_apps()
            if app_name in existing_apps:
                raise HTTPException(status_code=409, detail=f"App '{app_name}' already exists")
            
            if storage.add_browser_app(app_name):
                return {
                    "status": "ok",
                    "message": f"Browser app '{app_name}' added successfully",
                    "app_name": app_name,
                    "app_type": app_type
                }
        else:
            existing_apps = storage.get_messaging_apps()
            if app_name in existing_apps:
                raise HTTPException(status_code=409, detail=f"App '{app_name}' already exists")
            
            if storage.add_messaging_app(app_name):
                return {
                    "status": "ok",
                    "message": f"Messaging app '{app_name}' added successfully",
                    "app_name": app_name,
                    "app_type": app_type
                }
        
        raise HTTPException(status_code=500, detail="Failed to add app")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/api/rules/apps/{app_name}")
async def remove_app(
    app_name: str,
    app_type: str = Query("browser", regex="^(browser|messaging)$"),
    x_admin_key: str = Header(None)
):
    """Xóa ứng dụng."""
    require_dashboard(x_admin_key)
    
    try:
        app_name = app_name.strip().lower()
        storage = get_rules_storage()
        
        # Kiểm tra app tồn tại
        if app_type == "browser":
            existing_apps = storage.get_browser_apps()
            if app_name not in existing_apps:
                raise HTTPException(status_code=404, detail=f"App '{app_name}' not found")
            
            if storage.remove_browser_app(app_name):
                return {
                    "status": "ok",
                    "message": f"Browser app '{app_name}' removed successfully"
                }
        else:
            existing_apps = storage.get_messaging_apps()
            if app_name not in existing_apps:
                raise HTTPException(status_code=404, detail=f"App '{app_name}' not found")
            
            if storage.remove_messaging_app(app_name):
                return {
                    "status": "ok",
                    "message": f"Messaging app '{app_name}' removed successfully"
                }
        
        raise HTTPException(status_code=500, detail="Failed to remove app")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ----- CONFIG ENDPOINTS -----

@app.get("/api/rules/config")
async def get_config(
    x_admin_key: str = Header(None),
    x_api_key: str = Header(None)
):
    """Lấy toàn bộ rules configuration.
    
    Có thể gọi từ:
    - Admin: với X-Admin-Key header
    - Agent: với X-API-Key header
    """
    # Cần X-Admin-Key HOẶC X-API-Key
    if not x_admin_key and not x_api_key:
        raise HTTPException(status_code=401, detail="Missing X-Admin-Key or X-API-Key header")
    
    # Kiểm tra admin key
    if x_admin_key:
        if x_admin_key != DASHBOARD_KEY:
            raise HTTPException(status_code=401, detail="Invalid admin key")
    # Kiểm tra agent key
    elif x_api_key:
        if x_api_key not in AGENT_KEYS:
            raise HTTPException(status_code=401, detail="Invalid API key")
    
    try:
        storage = get_rules_storage()
        config = storage.get_config()
        
        return {
            "status": "ok",
            "config": config
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/rules/config/reload")
async def reload_config(
    x_admin_key: str = Header(None),
    x_api_key: str = Header(None)
):
    """Reload rules config từ file (sau khi admin cập nhật).
    
    Có thể gọi từ:
    - Admin: với X-Admin-Key header
    - Agent: với X-API-Key header
    """
    # Cần X-Admin-Key HOẶC X-API-Key
    if not x_admin_key and not x_api_key:
        raise HTTPException(status_code=401, detail="Missing X-Admin-Key or X-API-Key header")
    
    # Kiểm tra admin key
    if x_admin_key:
        if x_admin_key != DASHBOARD_KEY:
            raise HTTPException(status_code=401, detail="Invalid admin key")
    # Kiểm tra agent key
    elif x_api_key:
        if x_api_key not in AGENT_KEYS:
            raise HTTPException(status_code=401, detail="Invalid API key")
    
    try:
        storage = get_rules_storage()
        # Re-init to reload from DB
        config = storage.get_config()
        
        return {
            "status": "ok",
            "message": "Rules configuration reloaded successfully"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/rules/stats")
async def get_rules_stats(
    x_admin_key: str = Header(None),
    x_api_key: str = Header(None)
):
    """Lấy thống kê rules configuration.
    
    Có thể gọi từ:
    - Admin: với X-Admin-Key header
    - Agent: với X-API-Key header
    """
    # Cần X-Admin-Key HOẶC X-API-Key
    if not x_admin_key and not x_api_key:
        raise HTTPException(status_code=401, detail="Missing X-Admin-Key or X-API-Key header")
    
    # Kiểm tra admin key
    if x_admin_key:
        if x_admin_key != DASHBOARD_KEY:
            raise HTTPException(status_code=401, detail="Invalid admin key")
    # Kiểm tra agent key
    elif x_api_key:
        if x_api_key not in AGENT_KEYS:
            raise HTTPException(status_code=401, detail="Invalid API key")
    
    try:
        storage = get_rules_storage()
        stats = storage.get_config_stats()
        
        return {
            "status": "ok",
            "stats": stats
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================
# SERVE DASHBOARD
# ============================================================
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/", response_class=HTMLResponse)
async def dashboard():
    return FileResponse("static/index.html")


# ============================================================
if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
