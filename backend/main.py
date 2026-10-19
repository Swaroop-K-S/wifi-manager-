"""
FastAPI God-Mode Wi-Fi Commander Server (Primary & Guest Networks)
Real-time REST API, WebSocket streams, and Guest Wi-Fi management.
"""
import asyncio
import os
from pathlib import Path
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional

from backend.database import get_db
from backend.traffic_engine import traffic_engine
from backend.captive_portal import captive_app

app = FastAPI(title="Wi-Fi God Mode Command Center (Primary & Guest)", version="2.2")

# Request Schemas
class DeviceLimitRequest(BaseModel):
    limit_kbps: int

class DeviceLagRequest(BaseModel):
    latency_ms: int

class DeviceRenameRequest(BaseModel):
    custom_name: str

class DeviceIdentifyRequest(BaseModel):
    brand: str
    model_name: str
    custom_name: str
    device_type: Optional[str] = "phone"

class SelfIdentifyRequest(BaseModel):
    user_agent: str

class SwitchNetworkRequest(BaseModel):
    network_type: str # 'primary' or 'guest'

class GuestLimitRequest(BaseModel):
    bandwidth_cap_mbps: int

class AddRuleRequest(BaseModel):
    rule_type: str
    target: str
    reason: Optional[str] = "Admin God Mode Policy"

class CustomDeviceRequest(BaseModel):
    ip: str
    mac: str
    name: str
    device_type: str
    network_type: Optional[str] = "primary"
    vendor: Optional[str] = "Manual Entry"

connected_clients = set()

# Middleware to intercept connecting device User-Agents
@app.middleware("http")
async def intercept_device_agent(request: Request, call_next):
    client_ip = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent", "")
    
    if client_ip and client_ip != "127.0.0.1" and user_agent:
        try:
            traffic_engine.record_client_device(client_ip, user_agent)
        except Exception:
            pass
            
    response = await call_next(request)
    return response

# General Status
@app.get("/api/status")
async def get_network_status():
    return traffic_engine.get_full_snapshot()

@app.post("/api/scan")
async def trigger_rescan():
    traffic_engine.sync_real_devices()
    return {"status": "success", "message": "Subnet rescan completed", "snapshot": traffic_engine.get_full_snapshot()}

# Per Device Controls
@app.post("/api/devices/{mac}/block")
async def toggle_device_block(mac: str):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT is_blocked, custom_name, hostname FROM devices WHERE mac = ?", (mac,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Device not found")
    
    new_state = 0 if row["is_blocked"] else 1
    cursor.execute("UPDATE devices SET is_blocked = ? WHERE mac = ?", (new_state, mac))
    conn.commit()
    conn.close()
    
    dev_name = row["custom_name"] or row["hostname"]
    action_text = "BLOCKED" if new_state == 1 else "UNBLOCKED"
    return {"status": "success", "mac": mac, "is_blocked": bool(new_state), "message": f"{dev_name} is now {action_text}"}

@app.post("/api/devices/{mac}/pause")
async def toggle_device_pause(mac: str):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT is_paused, custom_name, hostname FROM devices WHERE mac = ?", (mac,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Device not found")
        
    new_state = 0 if row["is_paused"] else 1
    cursor.execute("UPDATE devices SET is_paused = ? WHERE mac = ?", (new_state, mac))
    conn.commit()
    conn.close()
    
    dev_name = row["custom_name"] or row["hostname"]
    state_str = "PAUSED" if new_state == 1 else "RESUMED"
    return {"status": "success", "mac": mac, "is_paused": bool(new_state), "message": f"Internet for {dev_name} is now {state_str}"}

@app.post("/api/devices/{mac}/network")
async def switch_device_network(mac: str, req: SwitchNetworkRequest):
    """Move a device between Primary and Guest network."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE devices SET network_type = ? WHERE mac = ?", (req.network_type, mac))
    conn.commit()
    conn.close()
    return {"status": "success", "mac": mac, "network_type": req.network_type}

@app.post("/api/devices/{mac}/limit")
async def set_bandwidth_limit(mac: str, req: DeviceLimitRequest):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE devices SET bandwidth_limit_kbps = ? WHERE mac = ?", (req.limit_kbps, mac))
    conn.commit()
    conn.close()
    return {"status": "success", "mac": mac, "limit_kbps": req.limit_kbps}

@app.post("/api/devices/{mac}/lag")
async def set_device_lag(mac: str, req: DeviceLagRequest):
    """Sets artificial latency (Lag Switch) on a target client."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE devices SET artificial_latency_ms = ? WHERE mac = ?", (req.latency_ms, mac))
    conn.commit()
    conn.close()
    return {"status": "success", "mac": mac, "artificial_latency_ms": req.latency_ms}

class DeviceTypeRequest(BaseModel):
    device_type: str

@app.post("/api/devices/{mac}/type")
async def set_device_type(mac: str, req: DeviceTypeRequest):
    """Set device category (phone, laptop, tablet, smart_tv, console, iot)."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE devices SET device_type = ? WHERE mac = ?", (req.device_type, mac))
    conn.commit()
    conn.close()
    return {"status": "success", "mac": mac, "device_type": req.device_type}

@app.post("/api/devices/{mac}/rename")
async def rename_device(mac: str, req: DeviceRenameRequest):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE devices SET custom_name = ? WHERE mac = ?", (req.custom_name, mac))
    conn.commit()
    conn.close()
    return {"status": "success", "mac": mac, "custom_name": req.custom_name}

@app.post("/api/devices/{mac}/identify")
async def manually_identify_device(mac: str, req: DeviceIdentifyRequest):
    """Admin identification of device brand, company, and model name."""
    conn = get_db()
    cursor = conn.cursor()
    vendor_str = f"{req.brand} Electronics" if req.brand == "Samsung" else f"{req.brand}"
    cursor.execute("""
        UPDATE devices SET 
            brand = ?, 
            model_name = ?, 
            custom_name = ?, 
            hostname = ?, 
            vendor = ?, 
            device_type = ? 
        WHERE mac = ?
    """, (req.brand, req.model_name, req.custom_name, req.custom_name, vendor_str, req.device_type, mac))
    conn.commit()
    conn.close()
    return {"status": "success", "mac": mac, "brand": req.brand, "model_name": req.model_name, "custom_name": req.custom_name}

@app.post("/api/identify-me")
async def self_identify_client(req: SelfIdentifyRequest, request: Request):
    """Automatically fingerprints connecting mobile device from browser User-Agent."""
    client_ip = request.client.host if request.client else None
    if client_ip and client_ip not in ("127.0.0.1", "::1", "localhost") and req.user_agent:
        traffic_engine.record_client_device(client_ip, req.user_agent)
        return {"status": "success", "ip": client_ip, "message": "Device fingerprinted"}
    return {"status": "ignored"}

@app.get("/api/devices/{mac}/history")
async def get_device_history(mac: str):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT domain, url_path, category, protocol, port, bytes_transferred, action_taken, timestamp 
        FROM activity_logs 
        WHERE device_mac = ? 
        ORDER BY id DESC LIMIT 100
    """, (mac,))
    rows = [dict(r) for r in cursor.fetchall()]
    
    cursor.execute("SELECT * FROM devices WHERE mac = ?", (mac,))
    dev = dict(cursor.fetchone() or {})
    conn.close()
    
    return {"device": dev, "logs": rows}

# Guest Network Specific Controls
@app.post("/api/guest/toggle")
async def toggle_guest_network():
    """Enable or disable Guest Wi-Fi access entirely."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT is_enabled FROM guest_network_config WHERE id = 1")
    row = cursor.fetchone()
    current = row[0] if row else 1
    new_state = 0 if current else 1
    cursor.execute("UPDATE guest_network_config SET is_enabled = ? WHERE id = 1", (new_state,))
    
    # If disabled, pause all guest devices
    if new_state == 0:
        cursor.execute("UPDATE devices SET is_paused = 1 WHERE network_type = 'guest'")
    else:
        cursor.execute("UPDATE devices SET is_paused = 0 WHERE network_type = 'guest'")
        
    conn.commit()
    conn.close()
    msg = "Guest Wi-Fi is now ACTIVATED" if new_state == 1 else "Guest Wi-Fi is now SHUT DOWN"
    return {"status": "success", "is_enabled": bool(new_state), "message": msg}

@app.post("/api/guest/isolate")
async def toggle_guest_isolation():
    """Toggle Guest LAN Isolation (prevents guests from accessing admin PC & shares)."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT is_isolated FROM guest_network_config WHERE id = 1")
    row = cursor.fetchone()
    current = row[0] if row else 1
    new_state = 0 if current else 1
    cursor.execute("UPDATE guest_network_config SET is_isolated = ? WHERE id = 1", (new_state,))
    conn.commit()
    conn.close()
    msg = "Guest LAN Isolation ENGAGED (Local Network Protected)" if new_state == 1 else "Guest LAN Isolation DISABLED"
    return {"status": "success", "is_isolated": bool(new_state), "message": msg}

@app.post("/api/guest/limit")
async def set_guest_bandwidth_cap(req: GuestLimitRequest):
    """Set maximum bandwidth speed for the entire Guest Wi-Fi network."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE guest_network_config SET bandwidth_cap_mbps = ? WHERE id = 1", (req.bandwidth_cap_mbps,))
    conn.commit()
    conn.close()
    return {"status": "success", "bandwidth_cap_mbps": req.bandwidth_cap_mbps, "message": f"Guest bandwidth capped at {req.bandwidth_cap_mbps} Mbps"}

@app.post("/api/guest/kickall")
async def kick_all_guests():
    """Disconnect/block all devices on the guest network."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE devices SET is_blocked = 1 WHERE network_type = 'guest'")
    conn.commit()
    conn.close()
    return {"status": "success", "message": "All Guest devices disconnected"}

# Firewall Endpoints
@app.post("/api/firewall/rule")
async def add_firewall_rule(req: AddRuleRequest):
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO blacklist_rules (rule_type, target, is_active, reason)
            VALUES (?, ?, 1, ?)
        """, (req.rule_type, req.target.strip().lower(), req.reason))
        conn.commit()
        rule_id = cursor.lastrowid
    except Exception:
        conn.close()
        raise HTTPException(status_code=400, detail="Rule already exists")
    conn.close()
    return {"status": "success", "rule_id": rule_id, "target": req.target}

@app.delete("/api/firewall/rule/{rule_id}")
async def delete_firewall_rule(rule_id: int):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM blacklist_rules WHERE id = ?", (rule_id,))
    conn.commit()
    conn.close()
    return {"status": "success", "message": f"Rule {rule_id} removed"}

@app.post("/api/godmode/killswitch")
async def toggle_emergency_killswitch():
    conn = get_db()
    cursor = conn.cursor()
    local_ip = traffic_engine.scanner.local_ip
    gateway_ip = traffic_engine.scanner.gateway_ip
    
    cursor.execute("SELECT COUNT(*) FROM devices WHERE is_blocked = 0 AND ip != ? AND ip != ?", (local_ip, gateway_ip))
    unblocked_count = cursor.fetchone()[0]
    
    if unblocked_count > 0:
        cursor.execute("UPDATE devices SET is_blocked = 1 WHERE ip != ? AND ip != ?", (local_ip, gateway_ip))
        action = "ACTIVATED (ALL NON-ADMIN DEVICES FROZEN)"
        state = True
    else:
        cursor.execute("UPDATE devices SET is_blocked = 0")
        action = "DEACTIVATED (ALL DEVICES RESTORED)"
        state = False
        
    conn.commit()
    conn.close()
    return {"status": "success", "killswitch_active": state, "message": f"God Mode Kill Switch {action}"}

# God Rules & Chronos Schedules Endpoints
@app.get("/api/schedules")
async def get_god_schedules():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM god_schedules ORDER BY id ASC")
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return {"schedules": rows}

@app.post("/api/schedules/{rule_id}/toggle")
async def toggle_god_schedule(rule_id: int):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT is_active, rule_name FROM god_schedules WHERE id = ?", (rule_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Schedule rule not found")
    new_state = 0 if row["is_active"] else 1
    cursor.execute("UPDATE god_schedules SET is_active = ? WHERE id = ?", (new_state, rule_id))
    conn.commit()
    conn.close()
    return {"status": "success", "rule_id": rule_id, "is_active": bool(new_state), "rule_name": row["rule_name"]}

@app.websocket("/ws")
async def websocket_telemetry_stream(websocket: WebSocket):
    await websocket.accept()
    connected_clients.add(websocket)
    try:
        while True:
            snapshot = traffic_engine.get_full_snapshot()
            await websocket.send_json(snapshot)
            await asyncio.sleep(1.0)
    except WebSocketDisconnect:
        connected_clients.remove(websocket)
    except Exception:
        if websocket in connected_clients:
            connected_clients.remove(websocket)

# Mount Captive Lockout Portal
app.mount("/captive", captive_app)

FRONTEND_DIR = Path(__file__).parent.parent / "frontend"
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")

@app.get("/")
async def serve_index():
    index_file = FRONTEND_DIR / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return {"message": "Wi-Fi God Mode Command Center API is running."}

@app.get("/manifest.json")
async def serve_manifest():
    return FileResponse(FRONTEND_DIR / "manifest.json")
