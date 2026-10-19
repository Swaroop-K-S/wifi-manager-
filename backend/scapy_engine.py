"""
AETHER SHIELD // SCAPY LIVE PACKET SNIFFER & GOD-MODE ROUTING ENGINE
Captures real 802.11 Wi-Fi frames in promiscuous mode using Scapy + Npcap.
Features:
- Dynamic active Wi-Fi adapter discovery
- Real-time download & upload byte throughput per device
- Live DNS queries & responses (UDP 53)
- Live TLS Client Hello SNI (Server Name Indication on HTTPS / port 443)
- Live HTTP Host headers
- Real latency, packet metrics, and active ICMP link tracking
- Transparent God-Mode bridge for target smartphone traffic inspection
"""

import threading
import time
import re
import socket
import subprocess
from datetime import datetime
from collections import defaultdict
from typing import Dict, Any, Optional, List

import scapy.all as scapy
from backend.database import get_db

def get_best_wifi_iface() -> str:
    """Finds the actual active Wi-Fi interface in Scapy's Windows interface registry."""
    try:
        from scapy.arch.windows import get_windows_if_list
        for iface in get_windows_if_list():
            desc = (iface.get("description") or "").lower()
            ips = iface.get("ips", [])
            if any(ip.startswith("192.168.1.") for ip in ips):
                if any(k in desc for k in ["wi-fi", "wireless", "802.11", "mt7920", "wlan"]):
                    return iface.get("name", "Wi-Fi")
    except Exception:
        pass
    return "Wi-Fi"

def extract_tls_sni(payload: bytes) -> Optional[str]:
    """Lightweight zero-dependency TLS SNI parser for Client Hello handshakes."""
    if not payload or len(payload) < 43:
        return None
    # ContentType 0x16 (Handshake), HandshakeType 0x01 (Client Hello)
    if payload[0] == 0x16 and payload[5] == 0x01:
        try:
            pos = 43
            if pos >= len(payload): return None
            sess_len = payload[pos]
            pos += 1 + sess_len
            if pos + 2 > len(payload): return None
            cs_len = int.from_bytes(payload[pos:pos+2], 'big')
            pos += 2 + cs_len
            if pos >= len(payload): return None
            comp_len = payload[pos]
            pos += 1 + comp_len
            if pos + 2 > len(payload): return None
            ext_total_len = int.from_bytes(payload[pos:pos+2], 'big')
            pos += 2
            end_ext = min(len(payload), pos + ext_total_len)
            while pos + 4 <= end_ext:
                ext_type = int.from_bytes(payload[pos:pos+2], 'big')
                ext_len = int.from_bytes(payload[pos+2:pos+4], 'big')
                pos += 4
                if ext_type == 0:  # server_name extension
                    if pos + 5 <= end_ext:
                        server_name_len = int.from_bytes(payload[pos+3:pos+5], 'big')
                        sni = payload[pos+5:pos+5+server_name_len].decode('utf-8', errors='ignore')
                        return sni.strip()
                pos += ext_len
        except Exception:
            pass
    return None

def categorize_domain(domain: str) -> str:
    d = domain.lower()
    if any(k in d for k in ["youtube", "netflix", "spotify", "twitch", "primevideo", "hotstar", "disney", "googlevideo", "video"]):
        return "Streaming"
    elif any(k in d for k in ["instagram", "tiktok", "facebook", "whatsapp", "twitter", "x.com", "reddit", "snapchat", "telegram"]):
        return "Social Media"
    elif any(k in d for k in ["chatgpt", "openai", "github", "anthropic", "claude", "gemini", "gitlab", "stackoverflow"]):
        return "Dev & AI"
    elif any(k in d for k in ["steam", "discord", "xbox", "playstation", "epicgames", "roblox", "riot"]):
        return "Gaming"
    elif any(k in d for k in ["drive.google", "dropbox", "onedrive", "icloud", "aws", "azure", "samsungcloud"]):
        return "Cloud & Storage"
    return "Web Traffic"

class LivePacketSniffer:
    def __init__(self):
        self.iface = get_best_wifi_iface()
        self.running = False
        self.lock = threading.Lock()
        
        # Real-time traffic rate accounting per IP
        self.ip_traffic = defaultdict(lambda: {
            "sec_dl_bytes": 0,
            "sec_ul_bytes": 0,
            "current_dl_kbps": 0.0,
            "current_ul_kbps": 0.0,
            "total_dl_bytes": 0,
            "total_ul_bytes": 0,
            "packet_count": 0,
            "latency_ms": 2,
            "last_seen": time.time()
        })
        
        self.recent_activities: List[Dict[str, Any]] = []
        self.prev_rate_tick = time.time()
        self.sniff_thread: Optional[threading.Thread] = None
        self.rate_thread: Optional[threading.Thread] = None
        self.probe_thread: Optional[threading.Thread] = None
        self.bridge_thread: Optional[threading.Thread] = None

        # Network topology nodes
        self.gateway_ip = "192.168.1.1"
        self.gateway_mac = "b4:86:18:de:58:5a"
        self.local_mac = "60:48:ba:06:67:3e"
        self.target_phone_ip = "192.168.1.46"
        self.target_phone_mac = "1e:ee:e8:57:31:21"

    def start(self):
        if self.running:
            return
        self.running = True
        self.iface = get_best_wifi_iface()
        
        self.sniff_thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self.sniff_thread.start()
        
        self.rate_thread = threading.Thread(target=self._rate_calc_loop, daemon=True)
        self.rate_thread.start()

        self.probe_thread = threading.Thread(target=self._active_probe_loop, daemon=True)
        self.probe_thread.start()

        self.bridge_thread = threading.Thread(target=self._arp_bridge_loop, daemon=True)
        self.bridge_thread.start()
        print(f"[SCAPY ENGINE] Real-time promiscuous packet engine running on interface '{self.iface}'")

    def stop(self):
        self.running = False

    def _sniff_loop(self):
        while self.running:
            try:
                scapy.sniff(
                    iface=self.iface,
                    prn=self._process_packet,
                    store=False,
                    timeout=3,
                    promisc=True
                )
            except Exception as e:
                time.sleep(1)

    def _process_packet(self, pkt):
        length = len(pkt)
        now_ts = datetime.now().strftime("%H:%M:%S")

        src_ip = None
        dst_ip = None
        proto_name = "ETH"
        port = 0
        extracted_domain = None

        if pkt.haslayer(scapy.IP):
            src_ip = pkt[scapy.IP].src
            dst_ip = pkt[scapy.IP].dst
            proto_num = pkt[scapy.IP].proto
            proto_name = "TCP" if proto_num == 6 else ("UDP" if proto_num == 17 else "IP")
        elif pkt.haslayer(scapy.IPv6):
            src_ip = pkt[scapy.IPv6].src
            dst_ip = pkt[scapy.IPv6].dst
            proto_name = "IPv6"

        # Update per-device byte accumulators
        with self.lock:
            if src_ip:
                self.ip_traffic[src_ip]["sec_ul_bytes"] += length
                self.ip_traffic[src_ip]["total_ul_bytes"] += length
                self.ip_traffic[src_ip]["packet_count"] += 1
                self.ip_traffic[src_ip]["last_seen"] = time.time()
            if dst_ip:
                self.ip_traffic[dst_ip]["sec_dl_bytes"] += length
                self.ip_traffic[dst_ip]["total_dl_bytes"] += length
                self.ip_traffic[dst_ip]["packet_count"] += 1
                self.ip_traffic[dst_ip]["last_seen"] = time.time()

        # Check DNS queries
        if pkt.haslayer(scapy.DNSQR):
            try:
                qname = pkt[scapy.DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
                if qname and not qname.endswith(".in-addr.arpa"):
                    extracted_domain = qname
                    proto_name = "DNS"
                    port = 53
            except Exception:
                pass

        # Check TLS SNI / HTTPS
        if not extracted_domain and pkt.haslayer(scapy.TCP):
            port = pkt[scapy.TCP].dport
            if port == 443 and pkt.haslayer(scapy.Raw):
                payload = bytes(pkt[scapy.Raw].load)
                sni = extract_tls_sni(payload)
                if sni:
                    extracted_domain = sni
                    proto_name = "HTTPS/TLS"

        # Check HTTP Host header
        if not extracted_domain and pkt.haslayer(scapy.TCP):
            if pkt[scapy.TCP].dport in (80, 8080) and pkt.haslayer(scapy.Raw):
                try:
                    raw_text = bytes(pkt[scapy.Raw].load).decode('latin1', errors='ignore')
                    m = re.search(r'Host:\s*([^\r\n:]+)', raw_text, re.IGNORECASE)
                    if m:
                        extracted_domain = m.group(1).strip()
                        proto_name = "HTTP"
                except Exception:
                    pass

        # Check mDNS (5353) / SSDP (1900)
        if not extracted_domain and pkt.haslayer(scapy.UDP):
            if pkt[scapy.UDP].dport == 5353 and pkt.haslayer(scapy.Raw):
                raw_bytes = bytes(pkt[scapy.Raw].load)
                for chunk in raw_bytes.split(b'\x00'):
                    chunk_str = chunk.decode('latin1', errors='ignore').strip()
                    if "." in chunk_str and len(chunk_str) > 4:
                        extracted_domain = chunk_str
                        proto_name = "mDNS"
                        break

        # Log real-time activity event if domain was captured
        if extracted_domain and src_ip:
            client_ip = src_ip if src_ip.startswith("192.168.1.") else dst_ip
            if client_ip and client_ip.startswith("192.168.1."):
                category = categorize_domain(extracted_domain)
                self._record_activity(client_ip, extracted_domain, category, proto_name, port or 443, length, now_ts)

    def _record_activity(self, client_ip: str, domain: str, category: str, protocol: str, port: int, payload_len: int, timestamp: str):
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute("SELECT custom_name, hostname, brand, network_type FROM devices WHERE ip = ?", (client_ip,))
        row = cursor.fetchone()
        dev_name = (row["custom_name"] if row and row["custom_name"] else (row["hostname"] if row else f"Device ({client_ip})"))
        net_type = row["network_type"] if row and row["network_type"] else "primary"
        
        # Check firewall rules
        cursor.execute("SELECT * FROM blacklist_rules WHERE is_active = 1")
        rules = cursor.fetchall()
        action = "ALLOWED"
        for r in rules:
            if r["rule_type"] == "domain" and r["target"].lower() in domain.lower():
                action = "BLOCKED"
                break
            elif r["rule_type"] == "category" and r["target"].lower() == category.lower():
                action = "BLOCKED"
                break

        cursor.execute("""
            INSERT INTO activity_logs (device_mac, device_ip, network_type, domain, url_path, category, protocol, port, bytes_transferred, action_taken)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (f"real:{client_ip}", client_ip, net_type, domain, f"Live {protocol} Wire", category, protocol, port, payload_len, action))
        conn.commit()
        conn.close()

        item = {
            "device_mac": f"real:{client_ip}",
            "device_ip": client_ip,
            "device_name": dev_name,
            "network_type": net_type,
            "domain": domain,
            "url_path": f"Live {protocol} Wire",
            "category": category,
            "protocol": protocol,
            "port": port,
            "bytes_transferred": payload_len,
            "action_taken": action,
            "timestamp": timestamp
        }

        with self.lock:
            self.recent_activities.insert(0, item)
            self.recent_activities = self.recent_activities[:80]

    def _rate_calc_loop(self):
        """Calculates exact KB/s throughput per device every 1 second and syncs to SQLite."""
        while self.running:
            time.sleep(1.0)
            now = time.time()
            dt = max(0.5, now - self.prev_rate_tick)
            self.prev_rate_tick = now

            conn = get_db()
            cursor = conn.cursor()

            with self.lock:
                for ip, data in list(self.ip_traffic.items()):
                    if not ip.startswith("192.168.1."):
                        continue
                        
                    dl_bytes = data["sec_dl_bytes"]
                    ul_bytes = data["sec_ul_bytes"]
                    data["sec_dl_bytes"] = 0
                    data["sec_ul_bytes"] = 0

                    data["current_dl_kbps"] = round(dl_bytes / (dt * 1024), 1)
                    data["current_ul_kbps"] = round(ul_bytes / (dt * 1024), 1)

                    if dl_bytes > 0 or ul_bytes > 0:
                        cursor.execute("""
                            UPDATE devices SET 
                                total_download_bytes = total_download_bytes + ?,
                                total_upload_bytes = total_upload_bytes + ?,
                                status = 'online',
                                last_seen = CURRENT_TIMESTAMP
                            WHERE ip = ?
                        """, (dl_bytes, ul_bytes, ip))

            conn.commit()
            conn.close()

    def _active_probe_loop(self):
        """Active non-blocking ICMP round-trip latency & link-health probe."""
        while self.running:
            time.sleep(2.0)
            ips_to_probe = ["192.168.1.1", "192.168.1.46", "192.168.1.35", "192.168.1.39"]
            for ip in ips_to_probe:
                try:
                    t0 = time.time()
                    res = subprocess.run(["ping", "-n", "1", "-w", "180", ip], stdout=subprocess.PIPE, text=True)
                    elapsed_ms = int((time.time() - t0) * 1000)
                    if "TTL=" in res.stdout:
                        match = re.search(r'time[=<]([0-9]+)ms', res.stdout, re.IGNORECASE)
                        lat = int(match.group(1)) if match else elapsed_ms
                        with self.lock:
                            self.ip_traffic[ip]["latency_ms"] = max(1, lat)
                            self.ip_traffic[ip]["last_seen"] = time.time()
                            # Account for probe ICMP frame exchange in live counters
                            self.ip_traffic[ip]["sec_dl_bytes"] += 74
                            self.ip_traffic[ip]["sec_ul_bytes"] += 74
                            self.ip_traffic[ip]["total_dl_bytes"] += 74
                            self.ip_traffic[ip]["total_ul_bytes"] += 74
                except Exception:
                    pass

    def _arp_bridge_loop(self):
        """God-Mode transparent ARP bridge to monitor target phone traffic in real-time."""
        while self.running:
            time.sleep(4.0)
            try:
                # Announce to router that target phone is at our MAC
                pkt_to_router = scapy.ARP(
                    op=2,
                    pdst=self.gateway_ip,
                    hwdst=self.gateway_mac,
                    psrc=self.target_phone_ip
                )
                scapy.send(pkt_to_router, iface=self.iface, verbose=False)
            except Exception:
                pass

    def get_device_rates(self, ip: str) -> Dict[str, Any]:
        with self.lock:
            data = self.ip_traffic[ip]
            return {
                "current_dl_kbps": data["current_dl_kbps"],
                "current_ul_kbps": data["current_ul_kbps"],
                "total_dl_bytes": data["total_dl_bytes"],
                "total_ul_bytes": data["total_ul_bytes"],
                "latency_ms": data["latency_ms"],
                "packet_count": data["packet_count"]
            }

# Global singleton
live_sniffer = LivePacketSniffer()
