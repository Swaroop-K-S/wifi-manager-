"""
Traffic Telemetry and Real Activity Engine (Connection Bandwidth, Bands & Classification)
Listens to live DNS queries on UDP 53 and real network socket connections.
Monitors Primary Wi-Fi and Guest Wi-Fi clients with connection types, frequency bands, and link rates.
"""
import time
import threading
import psutil
from typing import Dict, List, Any
from backend.database import get_db
from backend.network_scanner import NetworkScanner
from backend.dns_server import LiveDNSServer
from backend.real_activity_monitor import RealActivityMonitor
from backend.sentinel_ai import sentinel_ai
from backend.scheduler import god_scheduler
from backend.device_fingerprinter import device_fingerprinter, mdns_listener
from backend.scapy_engine import live_sniffer
from backend.packet_shaper import packet_shaper
from backend.captive_portal import start_port80_redirector

class TrafficEngine:
    def __init__(self):
        self.scanner = NetworkScanner()
        self.dns_server = LiveDNSServer(host="0.0.0.0", port=53)
        self.socket_monitor = RealActivityMonitor()
        
        self.running = False
        self.thread = None
        self.lock = threading.Lock()
        
        self.prev_net_io = psutil.net_io_counters()
        self.prev_time = time.time()
        self.current_download_mbps = 0.0
        self.current_upload_mbps = 0.0
        
        self.guest_download_mbps = 0.0
        self.guest_upload_mbps = 0.0
        
        self.recent_activities = []
        
        self.dns_server.start(
            query_callback=self.on_dns_query,
            blacklist_checker=self.check_domain_blocked
        )
        
        self.sync_real_devices()

    def sync_real_devices(self):
        """Discovers physical hardware and stores detailed Wi-Fi connection metrics & device brands/models."""
        conn = get_db()
        cursor = conn.cursor()
        
        real_devs = self.scanner.scan_network_real()
        for d in real_devs:
            ip = d["ip"]
            is_guest = ip.startswith("192.168.137.")
            net_type = "guest" if is_guest else "primary"
            
            cursor.execute("SELECT mac, custom_name, hostname, vendor, brand, model_name, is_blocked, is_paused, network_type FROM devices WHERE mac = ?", (d["mac"],))
            row = cursor.fetchone()
            if row:
                existing_custom = row["custom_name"]
                existing_vendor = row["vendor"]
                existing_brand = row["brand"]
                existing_model = row["model_name"]
                
                final_hostname = d["hostname"]
                final_vendor = existing_vendor if existing_vendor and "Private" not in existing_vendor and existing_vendor != "Generic" else d["vendor"]
                final_brand = existing_brand if existing_brand and existing_brand != "Generic" else d.get("brand", "Generic")
                final_model = existing_model if existing_model else d.get("model_name", "")
                final_custom = existing_custom if existing_custom and not any(k in existing_custom for k in ["Client (", "Mobile Phone (", "Smartphone", "Wi-Fi Client", "Generic"]) else d["hostname"]

                cursor.execute("""
                    UPDATE devices SET 
                        ip = ?, hostname = ?, custom_name = ?, vendor = ?, brand = ?, model_name = ?, device_type = ?, 
                        connection_type = ?, wifi_band = ?, channel = ?, 
                        link_rate_mbps = ?, signal_percent = ?, signal_dbm = ?,
                        status = 'online', last_seen = CURRENT_TIMESTAMP 
                    WHERE mac = ?
                """, (
                    d["ip"], final_hostname, final_custom, final_vendor, final_brand, final_model, d["device_type"],
                    d["connection_type"], d["wifi_band"], d["channel"],
                    d["link_rate_mbps"], d["signal_percent"], d["signal_dbm"],
                    d["mac"]
                ))
            else:
                cursor.execute("""
                    INSERT INTO devices (
                        mac, ip, hostname, custom_name, vendor, brand, model_name, device_type, 
                        os_info, network_type, connection_type, wifi_band, 
                        channel, link_rate_mbps, signal_percent, signal_dbm, status
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'online')
                """, (
                    d["mac"], d["ip"], d["hostname"], d["hostname"], d["vendor"], d.get("brand", "Generic"), d.get("model_name", ""), d["device_type"],
                    "Physical Network Client", net_type, d["connection_type"], d["wifi_band"],
                    d["channel"], d["link_rate_mbps"], d["signal_percent"], d["signal_dbm"]
                ))
                
        conn.commit()
        conn.close()

    def record_client_device(self, client_ip: str, user_agent: str):
        """Interprets incoming HTTP user-agent to fingerprint the connecting smartphone or PC model."""
        if not client_ip or client_ip in ("127.0.0.1", "::1", "localhost"):
            return
            
        info = device_fingerprinter.identify_user_agent(user_agent)
        if not info:
            return
            
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT mac, custom_name FROM devices WHERE ip = ?", (client_ip,))
        row = cursor.fetchone()
        if row:
            mac = row["mac"]
            cursor.execute("""
                UPDATE devices SET 
                    custom_name = ?, 
                    hostname = ?, 
                    vendor = ?, 
                    brand = ?, 
                    model_name = ?, 
                    os_info = ?, 
                    device_type = ?,
                    last_seen = CURRENT_TIMESTAMP
                WHERE mac = ?
            """, (
                info["display_name"],
                info["display_name"],
                info["vendor"],
                info["brand"],
                info["model_name"],
                info["os_info"],
                info["device_type"],
                mac
            ))
        else:
            mac = f"dev:{client_ip.split('.')[-1]}"
            cursor.execute("""
                INSERT INTO devices (
                    mac, ip, hostname, custom_name, vendor, brand, model_name,
                    device_type, os_info, network_type, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'primary', 'online')
            """, (
                mac, client_ip, info["display_name"], info["display_name"],
                info["vendor"], info["brand"], info["model_name"],
                info["device_type"], info["os_info"]
            ))
        conn.commit()
        conn.close()

    def check_domain_blocked(self, domain: str) -> bool:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT target FROM blacklist_rules WHERE is_active = 1 AND rule_type = 'domain'")
        blocked_domains = [row[0].lower() for row in cursor.fetchall()]
        conn.close()
        
        d = domain.lower()
        return any(target in d for target in blocked_domains)

    def on_dns_query(self, client_ip: str, domain: str, is_blocked: bool, payload_len: int):
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT is_blocked, is_paused, custom_name, hostname, network_type FROM devices WHERE ip = ?", (client_ip,))
        row = cursor.fetchone()
        
        device_name = f"Client ({client_ip})"
        net_type = "guest" if client_ip.startswith("192.168.137.") else "primary"
        
        if row:
            if row["is_blocked"] or row["is_paused"]:
                is_blocked = True
            device_name = row["custom_name"] or row["hostname"]
            net_type = row["network_type"] or net_type
            
        action = "BLOCKED" if is_blocked else "ALLOWED"
        timestamp = time.strftime("%H:%M:%S")

        category = "DNS Query"
        d = domain.lower()
        if any(k in d for k in ["youtube", "googlevideo", "netflix", "spotify"]):
            category = "Streaming"
        elif any(k in d for k in ["instagram", "tiktok", "facebook", "whatsapp", "twitter"]):
            category = "Social Media"
        elif any(k in d for k in ["chatgpt", "openai", "github", "anthropic"]):
            category = "Dev & AI"
        elif any(k in d for k in ["steam", "discord", "xbox", "playstation"]):
            category = "Gaming"

        log_item = {
            "device_mac": "real:dns",
            "device_ip": client_ip,
            "device_name": device_name,
            "network_type": net_type,
            "domain": domain,
            "url_path": "DNS Lookup (UDP/53)",
            "category": category,
            "protocol": "DNS",
            "port": 53,
            "bytes_transferred": payload_len,
            "action_taken": action,
            "timestamp": timestamp
        }

        cursor.execute("""
            INSERT INTO activity_logs (device_mac, device_ip, network_type, domain, url_path, category, protocol, port, bytes_transferred, action_taken)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (log_item["device_mac"], client_ip, net_type, domain, log_item["url_path"], category, "DNS", 53, payload_len, action))
        
        # Vendor DNS detection (e.g. samsungcloud.com -> Samsung Electronics)
        vendor_info = device_fingerprinter.identify_from_dns(domain)
        if vendor_info:
            cursor.execute("SELECT mac, vendor, brand, custom_name FROM devices WHERE ip = ?", (client_ip,))
            d_row = cursor.fetchone()
            if d_row and ("Smartphone" in (d_row["vendor"] or "") or "Mobile Device" in (d_row["vendor"] or "") or not d_row["vendor"] or d_row["brand"] == "Generic"):
                brand = vendor_info["brand"]
                vendor_full = vendor_info["vendor"]
                new_name = f"{brand} Galaxy Smartphone" if brand == "Samsung" else f"{brand} Device"
                cursor.execute("""
                    UPDATE devices SET 
                        vendor = ?, brand = ?, custom_name = COALESCE(NULLIF(custom_name, ''), ?)
                    WHERE ip = ?
                """, (vendor_full, brand, new_name, client_ip))

        conn.commit()
        conn.close()

        with self.lock:
            self.recent_activities.insert(0, log_item)
            self.recent_activities = self.recent_activities[:60]

    def tick(self):
        now = time.time()
        dt = max(0.5, now - self.prev_time)
        
        curr_net_io = psutil.net_io_counters()
        bytes_recv = max(0, curr_net_io.bytes_recv - self.prev_net_io.bytes_recv)
        bytes_sent = max(0, curr_net_io.bytes_sent - self.prev_net_io.bytes_sent)
        self.prev_net_io = curr_net_io
        self.prev_time = now
        
        self.current_download_mbps = round((bytes_recv * 8) / (dt * 1_000_000), 2)
        self.current_upload_mbps = round((bytes_sent * 8) / (dt * 1_000_000), 2)
        
        active_sockets = self.socket_monitor.capture_live_connections()
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute("""
            UPDATE devices SET 
                total_download_bytes = total_download_bytes + ?,
                total_upload_bytes = total_upload_bytes + ?,
                last_seen = CURRENT_TIMESTAMP
            WHERE ip = ?
        """, (bytes_recv, bytes_sent, self.scanner.local_ip))
        
        for s in active_sockets:
            if s.get("is_new"):
                log_entry = {
                    "device_mac": "local:sock",
                    "device_ip": s["device_ip"],
                    "device_name": f"{s['process']} (This PC)",
                    "network_type": "primary",
                    "domain": s["domain"],
                    "url_path": s["url_path"],
                    "category": s["category"],
                    "protocol": s["protocol"],
                    "port": s["port"],
                    "bytes_transferred": 1500,
                    "action_taken": "ALLOWED",
                    "timestamp": s["timestamp"]
                }
                
                cursor.execute("""
                    INSERT INTO activity_logs (device_mac, device_ip, network_type, domain, url_path, category, protocol, port, bytes_transferred, action_taken)
                    VALUES (?, ?, 'primary', ?, ?, ?, ?, ?, ?, 'ALLOWED')
                """, (log_entry["device_mac"], log_entry["device_ip"], log_entry["domain"], log_entry["url_path"], log_entry["category"], log_entry["protocol"], log_entry["port"], log_entry["bytes_transferred"]))
                
                with self.lock:
                    self.recent_activities.insert(0, log_entry)
                    self.recent_activities = self.recent_activities[:60]

        cursor.execute("DELETE FROM activity_logs WHERE id NOT IN (SELECT id FROM activity_logs ORDER BY id DESC LIMIT 500)")
        conn.commit()
        conn.close()

    def start_background_loop(self):
        if self.running:
            return
        self.running = True
        
        try:
            live_sniffer.start()
        except Exception as e:
            print("Scapy live sniffer start error:", e)

        try:
            mdns_listener.start()
        except Exception as e:
            print("mDNS listener start error:", e)

        try:
            packet_shaper.start()
        except Exception as e:
            print("Kernel packet shaper start error:", e)

        try:
            start_port80_redirector(redirect_port=8000)
        except Exception as e:
            print("Port-80 redirector start error:", e)

        try:
            god_scheduler.start_loop()
        except Exception as e:
            print("God scheduler startup error:", e)

        def _loop():
            while self.running:
                try:
                    self.tick()
                except Exception as e:
                    print("Telemetry tick error:", e)
                time.sleep(1.2)
                
        self.thread = threading.Thread(target=_loop, daemon=True)
        self.thread.start()

    def get_full_snapshot(self) -> Dict[str, Any]:
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM devices ORDER BY status ASC, total_download_bytes DESC")
        devices_raw = [dict(row) for row in cursor.fetchall()]
        
        cursor.execute("SELECT * FROM blacklist_rules ORDER BY id DESC")
        rules_raw = [dict(row) for row in cursor.fetchall()]
        
        cursor.execute("SELECT * FROM guest_network_config WHERE id = 1")
        guest_cfg = dict(cursor.fetchone() or {})

        cursor.execute("SELECT * FROM god_schedules ORDER BY id ASC")
        schedules_raw = [dict(row) for row in cursor.fetchall()]
        
        total_dl_bytes = sum(d["total_download_bytes"] for d in devices_raw)
        total_ul_bytes = sum(d["total_upload_bytes"] for d in devices_raw)
        
        primary_devices = []
        guest_devices = []
        
        for d in devices_raw:
            ip = d["ip"]
            rates = live_sniffer.get_device_rates(ip)
            is_local = (ip == self.scanner.local_ip)
            
            if is_local:
                d["current_dl_kbps"] = max(rates["current_dl_kbps"], round((self.current_download_mbps * 1024) / 8, 1))
                d["current_ul_kbps"] = max(rates["current_ul_kbps"], round((self.current_upload_mbps * 1024) / 8, 1))
            else:
                d["current_dl_kbps"] = rates["current_dl_kbps"]
                d["current_ul_kbps"] = rates["current_ul_kbps"]
                
            d["latency_ms"] = rates.get("latency_ms", d.get("latency_ms", 2))
            d["packet_count"] = rates.get("packet_count", 0)
                
            # Sentinel AI behavioral inference (fused with DPI app telemetry)
            d["sentinel"] = sentinel_ai.analyze_device_traffic(
                ip=d["ip"],
                current_dl_kbps=d["current_dl_kbps"],
                current_ul_kbps=d["current_ul_kbps"],
                detected_app=rates.get("current_app"),
                last_domain=rates.get("last_domain"),
            )

            if d.get("network_type") == "guest":
                guest_devices.append(d)
            else:
                primary_devices.append(d)
            
        with self.lock:
            combined = list(live_sniffer.recent_activities) + list(self.recent_activities)
            seen_events = set()
            clean_stream = []
            for item in combined:
                key = (item["timestamp"], item["domain"], item["device_ip"])
                if key not in seen_events:
                    seen_events.add(key)
                    clean_stream.append(item)
            recent_stream = sorted(clean_stream, key=lambda x: x["timestamp"], reverse=True)[:60]
            
        guest_dl_bytes = sum(d["total_download_bytes"] for d in guest_devices)
        guest_ul_bytes = sum(d["total_upload_bytes"] for d in guest_devices)
        
        conn.close()
        
        return {
            "gateway_ip": self.scanner.gateway_ip,
            "local_ip": self.scanner.local_ip,
            "wlan_meta": self.scanner.wlan_meta,
            "total_download_mbps": self.current_download_mbps,
            "total_upload_mbps": self.current_upload_mbps,
            "total_download_gb": round(total_dl_bytes / (1024**3), 3),
            "total_upload_gb": round(total_ul_bytes / (1024**3), 3),
            "active_devices_count": len([d for d in devices_raw if not d["is_blocked"] and d["status"] == "online"]),
            "blocked_devices_count": len([d for d in devices_raw if d["is_blocked"]]),
            "primary_devices": primary_devices,
            "guest_devices": guest_devices,
            "devices": devices_raw,
            "recent_activity": recent_stream[:40],
            "guest_activity": [a for a in recent_stream if a.get("network_type") == "guest"][:30],
            "guest_stats": {
                "active_guests": len([d for d in guest_devices if not d["is_blocked"]]),
                "download_mbps": round(self.guest_download_mbps, 2),
                "upload_mbps": round(self.guest_upload_mbps, 2),
                "total_download_gb": round(guest_dl_bytes / (1024**3), 3),
                "total_upload_gb": round(guest_ul_bytes / (1024**3), 3)
            },
            "guest_config": guest_cfg,
            "blacklist_rules": rules_raw,
            "god_schedules": schedules_raw,
            "dns_server_active": self.dns_server.running,
            "timestamp": time.strftime("%H:%M:%S")
        }

traffic_engine = TrafficEngine()
traffic_engine.start_background_loop()
