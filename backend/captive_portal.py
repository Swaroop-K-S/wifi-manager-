"""
Captive Lockout Portal Server
Serves a custom cyber-styled Quarantine / Bedtime Lockout screen to blocked devices.
"""
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse

captive_app = FastAPI(title="AetherShield Captive Portal")

CAPTIVE_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AETHER SHIELD // ACCESS QUARANTINED</title>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Outfit:wght@600;800;900&display=swap" rel="stylesheet">
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      background: #060911;
      color: #f1f5f9;
      font-family: 'Outfit', sans-serif;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 24px;
      overflow: hidden;
      position: relative;
    }
    .glow-sphere {
      position: absolute;
      width: 450px;
      height: 450px;
      border-radius: 50%;
      background: radial-gradient(circle, rgba(239, 68, 68, 0.3) 0%, transparent 70%);
      filter: blur(100px);
      pointer-events: none;
    }
    .lockout-card {
      position: relative;
      z-index: 2;
      background: rgba(15, 23, 42, 0.85);
      backdrop-filter: blur(20px);
      border: 1px solid rgba(239, 68, 68, 0.45);
      box-shadow: 0 25px 60px rgba(0, 0, 0, 0.8), 0 0 35px rgba(239, 68, 68, 0.3);
      border-radius: 20px;
      max-width: 520px;
      width: 100%;
      padding: 40px 32px;
      text-align: center;
    }
    .shield-icon {
      width: 72px;
      height: 72px;
      margin: 0 auto 20px auto;
      border-radius: 50%;
      background: rgba(239, 68, 68, 0.15);
      border: 2px solid #ef4444;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 2rem;
      animation: pulse-red 2s infinite ease-in-out;
    }
    @keyframes pulse-red {
      0%, 100% { box-shadow: 0 0 15px rgba(239, 68, 68, 0.4); transform: scale(1); }
      50% { box-shadow: 0 0 30px rgba(239, 68, 68, 0.8); transform: scale(1.05); }
    }
    h1 {
      font-size: 1.6rem;
      font-weight: 900;
      letter-spacing: -0.5px;
      color: #fff;
      margin-bottom: 8px;
    }
    h1 span { color: #ef4444; }
    .badge {
      display: inline-block;
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.72rem;
      font-weight: 700;
      background: rgba(239, 68, 68, 0.2);
      color: #fca5a5;
      border: 1px solid rgba(239, 68, 68, 0.4);
      padding: 3px 10px;
      border-radius: 9999px;
      margin-bottom: 20px;
    }
    p {
      color: #94a3b8;
      font-size: 0.95rem;
      line-height: 1.5;
      margin-bottom: 24px;
    }
    .info-box {
      background: rgba(0, 0, 0, 0.4);
      border: 1px solid rgba(255, 255, 255, 0.08);
      border-radius: 12px;
      padding: 16px;
      text-align: left;
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.8rem;
      margin-bottom: 24px;
    }
    .info-row {
      display: flex;
      justify-content: space-between;
      margin-bottom: 6px;
    }
    .info-row:last-child { margin-bottom: 0; }
    .label { color: #64748b; }
    .val { color: #38bdf8; font-weight: 700; }
    .val.danger { color: #f87171; }
    .footer-note {
      font-size: 0.75rem;
      color: #475569;
    }
  </style>
</head>
<body>
  <div class="glow-sphere"></div>
  <div class="lockout-card">
    <div class="shield-icon">🔒</div>
    <div class="badge">GOD MODE SECURITY ACTIVE</div>
    <h1>INTERNET ACCESS <span>QUARANTINED</span></h1>
    <p>This device's connection to the Wi-Fi gateway has been temporarily paused by <strong>Network Administrator (Swaroop)</strong>.</p>
    
    <div class="info-box">
      <div class="info-row">
        <span class="label">TARGET IP:</span>
        <span class="val">{{client_ip}}</span>
      </div>
      <div class="info-row">
        <span class="label">ROUTER GATEWAY:</span>
        <span class="val">192.168.1.1 (SWAR00P)</span>
      </div>
      <div class="info-row">
        <span class="label">POLICY STATUS:</span>
        <span class="val danger">PAUSED / ISOLATED</span>
      </div>
      <div class="info-row">
        <span class="label">ENFORCED BY:</span>
        <span class="val">AetherShield Commander</span>
      </div>
    </div>

    <div class="footer-note">Contact the network administrator to restore internet access.</div>
  </div>
</body>
</html>
"""

@captive_app.get("/{full_path:path}", response_class=HTMLResponse)
async def serve_lockout(request: Request, full_path: str = ""):
    client_ip = request.client.host if request.client else "Target Client"
    html = CAPTIVE_HTML_TEMPLATE.replace("{{client_ip}}", client_ip)
    return HTMLResponse(content=html, status_code=200)
