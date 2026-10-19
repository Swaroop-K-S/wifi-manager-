"""
AETHER SHIELD // NETGOD
Main Application Launcher
Starts the FastAPI & WebSocket backend on 0.0.0.0:8000 and launches browser.
"""
import sys
import os
import socket
import webbrowser
import threading
import time

def get_local_ip():
    """Detect local LAN IP for mobile Android access."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def print_banner(local_ip, port=8000):
    banner = f"""
========================================================================
    ___    ______ _____ _    _ ______ _____     _____ _    _ _____ ______ _      _____  
   / _ \  |  ____|_   _| |  | |  ____|  __ \   / ____| |  | |_   _|  ____| |    |  __ \ 
  / /_\ \ | |__    | | | |__| | |__  | |__) | | (___ | |__| | | | | |__  | |    | |  | |
 / / _ \ \|  __|   | | |  __  |  __| |  _  /   \___ \|  __  | | | |  __| | |    | |  | |
/ / / \ \ \ |____ _| |_| |  | | |____| | \ \   ____) | |  | |_| |_| |____| |____| |__| |
/_/ /   \_\______|_____|_|  |_|______|_|  \_\ |_____/|_|  |_|_____|______|______|_____/ 
                                                                                        
                    WI-FI ROUTER GOD MODE COMMAND CENTER
========================================================================

  [+] Server Engine: FastAPI + Uvicorn + WebSockets
  [+] Telemetry: Live ARP Sniffer & Deep Packet Activity Stream
  
  >> LOCAL ACCESS (This PC):
     http://localhost:{port}

  >> ANDROID MOBILE ACCESS (From your Phone):
     http://{local_ip}:{port}
     (Scan the QR code on the dashboard or type the URL above in Chrome)

========================================================================
[!] Press Ctrl+C in this terminal to shutdown.
"""
    print(banner)

def open_browser(port=8000):
    time.sleep(1.2)
    webbrowser.open(f"http://localhost:{port}")

if __name__ == "__main__":
    import uvicorn
    local_ip = get_local_ip()
    port = 8000
    
    print_banner(local_ip, port)
    
    # Auto launch browser in background
    threading.Thread(target=open_browser, args=(port,), daemon=True).start()
    
    # Start server binding on all interfaces
    uvicorn.run("backend.main:app", host="0.0.0.0", port=port, log_level="info")
