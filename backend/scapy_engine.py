"""
AETHER SHIELD // SCAPY LIVE PACKET SNIFFER & GOD-MODE ROUTING ENGINE
Captures real 802.11 Wi-Fi frames in promiscuous mode using Scapy + Npcap.
Features:
- Dynamic active interface discovery (Wi-Fi, Ethernet, USB/RNDIS)
- Real-time download & upload byte throughput per device
- Live DNS queries & responses (UDP 53)
- Live TLS Client Hello SNI (TCP/443) + QUIC (UDP/443) SNI extraction
- Exact App Classifier: YouTube, Netflix, Instagram, Discord, BGMI, etc.
- Per-device live packet ring buffer (last 100 packets, inspectable via UI)
- Dynamic active ICMP probing from SQLite device list
- Admin-configurable ARP bridge monitoring (no hardcoded IPs)
"""

import threading
import time
import re
import socket
import subprocess
from datetime import datetime
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any, Optional, List, Set

import scapy.all as scapy
from backend.database import get_db


# ── Interface Discovery ───────────────────────────────────────────────────────

def get_best_wifi_iface() -> str:
    """
    Finds the best active network interface in Scapy's Windows registry.
    Prefers Wi-Fi/WLAN; falls back to Ethernet, then USB/RNDIS dongles.
    Any interface with a 192.168.x.x address is accepted.
    """
    try:
        from scapy.arch.windows import get_windows_if_list
        ifaces = get_windows_if_list()

        wifi_kw   = ["wi-fi", "wireless", "802.11", "mt7920", "wlan", "mediatek"]
        eth_kw    = ["ethernet", "realtek", "gbe", "gigabit", "intel(r) ethernet"]
        usb_kw    = ["rndis", "usb", "android", "remote ndis"]

        # Priority pass: Wi-Fi
        for iface in ifaces:
            desc = (iface.get("description") or "").lower()
            ips  = iface.get("ips", [])
            if any(ip.startswith("192.168.") for ip in ips):
                if any(k in desc for k in wifi_kw):
                    return iface.get("name", "Wi-Fi")
        # Second pass: Ethernet
        for iface in ifaces:
            desc = (iface.get("description") or "").lower()
            ips  = iface.get("ips", [])
            if any(ip.startswith("192.168.") for ip in ips):
                if any(k in desc for k in eth_kw):
                    return iface.get("name", "Ethernet")
        # Third pass: USB dongle / RNDIS
        for iface in ifaces:
            desc = (iface.get("description") or "").lower()
            ips  = iface.get("ips", [])
            if any(ip.startswith("192.168.") for ip in ips):
                if any(k in desc for k in usb_kw):
                    return iface.get("name", "USB")
    except Exception:
        pass
    return "Wi-Fi"


# ── TLS ClientHello SNI Parser (TCP/443) ─────────────────────────────────────

def extract_tls_sni(payload: bytes) -> Optional[str]:
    """Lightweight zero-dependency TLS SNI parser for ClientHello handshakes (TCP/443)."""
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
                ext_len  = int.from_bytes(payload[pos+2:pos+4], 'big')
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


# ── QUIC (HTTP/3) SNI Extractor (UDP/443) ────────────────────────────────────
# QUIC Client Initial frames carry unencrypted SNI strings in the CRYPTO frame.
# We use a fast regex to extract printable domain patterns from the raw payload.
_QUIC_SNI_RE = re.compile(
    rb'(?:'
    rb'googlevideo\.com|youtube\.com|ytimg\.com|ggpht\.com|'        # YouTube
    rb'instagram\.com|cdninstagram\.com|fbcdn\.net|'                # Instagram / FB CDN
    rb'facebook\.com|fbsbx\.com|'                                   # Facebook
    rb'cdn\.whatsapp\.net|whatsapp\.com|'                           # WhatsApp
    rb'nflxvideo\.net|nflxext\.com|netflix\.com|'                   # Netflix
    rb'spotifycdn\.com|spotify\.com|scdn\.co|'                      # Spotify
    rb'discord\.gg|discord\.com|discordapp\.com|'                   # Discord
    rb'steampowered\.com|steamcontent\.com|'                        # Steam
    rb'pvp\.net|riotgames\.com|'                                    # Valorant/Riot
    rb'twitch\.tv|twitchsvc\.net|'                                  # Twitch
    rb'hotstar\.com|jiosaavn\.com|jiocinema\.com|'                  # JioHotstar
    rb'primevideo\.com|amazon\.com|amazonvideo\.com|'               # Amazon Prime
    rb'tiktok\.com|musical\.ly|'                                    # TikTok
    rb'snapchat\.com|sc-cdn\.net|'                                  # Snapchat
    rb'telegram\.org|t\.me|'                                        # Telegram
    rb'reddit\.com|redd\.it|'                                       # Reddit
    rb'x\.com|twitter\.com|t\.co|'                                  # X/Twitter
    rb'openai\.com|chatgpt\.com|'                                   # ChatGPT
    rb'anthropic\.com|claude\.ai|'                                  # Claude AI
    rb'gemini\.google\.com|bard\.google\.com|'                      # Google Gemini
    rb'github\.com|githubusercontent\.com|'                          # GitHub
    rb'epicgames\.com|fortnite\.com|'                               # Epic
    rb'roblox\.com|rbxcdn\.com|'                                    # Roblox
    rb'pubg\.com|battlegrounds\.com'                                # BGMI/PUBG
    rb')'
)

def extract_quic_sni(payload: bytes) -> Optional[str]:
    """
    Fast regex scan of QUIC Client Initial UDP/443 payload to find known app SNI strings.
    Returns the matched domain string or None.
    """
    if len(payload) < 4:
        return None
    m = _QUIC_SNI_RE.search(payload)
    if m:
        return m.group(0).decode("utf-8", errors="ignore")
    return None


# ── Exact App Classifier ──────────────────────────────────────────────────────

_APP_MAP = [
    # Streaming
    (["googlevideo", "ytimg", "ggpht", "youtube"],                 ("YouTube",                "Streaming")),
    (["nflxvideo", "nflxext", "netflix"],                          ("Netflix",                "Streaming")),
    (["spotify", "scdn.co", "spotifycdn"],                         ("Spotify",                "Streaming")),
    (["hotstar", "jiosaavn", "jiocinema", "disney"],               ("JioHotstar / Disney+",   "Streaming")),
    (["primevideo", "amazonvideo", "aiv-cdn"],                     ("Amazon Prime Video",     "Streaming")),
    (["twitch", "twitchsvc"],                                      ("Twitch",                 "Streaming")),
    (["tiktok", "musical.ly"],                                     ("TikTok",                 "Social Media")),
    # Social Media
    (["instagram", "cdninstagram", "fbcdn"],                       ("Instagram",              "Social Media")),
    (["cdn.whatsapp", "whatsapp"],                                 ("WhatsApp",               "Social Media")),
    (["facebook", "fbsbx"],                                        ("Facebook / Meta",        "Social Media")),
    (["x.com", "twitter", "t.co"],                                 ("X (Twitter)",            "Social Media")),
    (["reddit", "redd.it"],                                        ("Reddit",                 "Social Media")),
    (["snapchat", "sc-cdn"],                                       ("Snapchat",               "Social Media")),
    (["telegram", "t.me"],                                         ("Telegram",               "Social Media")),
    # Gaming
    (["discord", "discordapp"],                                    ("Discord",                "Gaming")),
    (["steampowered", "steamcontent", "steamcdn"],                 ("Steam",                  "Gaming")),
    (["pvp.net", "riotgames", "valorant"],                         ("Valorant / Riot Games",  "Gaming")),
    (["pubg", "battlegrounds", "bgmi"],                            ("BGMI / PUBG",            "Gaming")),
    (["epicgames", "fortnite"],                                    ("Epic Games",             "Gaming")),
    (["roblox", "rbxcdn"],                                         ("Roblox",                 "Gaming")),
    # Dev & AI
    (["openai", "chatgpt"],                                        ("ChatGPT",                "Dev & AI")),
    (["anthropic", "claude.ai"],                                   ("Claude AI",              "Dev & AI")),
    (["gemini.google", "bard.google"],                             ("Google Gemini",          "Dev & AI")),
    (["github", "githubusercontent"],                               ("GitHub",                 "Dev & AI")),
    # Cloud
    (["drive.google", "docs.google"],                              ("Google Drive",           "Cloud & Storage")),
    (["dropbox"],                                                  ("Dropbox",                "Cloud & Storage")),
    (["onedrive", "sharepoint"],                                   ("OneDrive",               "Cloud & Storage")),
    (["icloud", "apple"],                                          ("iCloud",                 "Cloud & Storage")),
    (["samsungcloud", "samsung"],                                  ("Samsung Cloud",          "Cloud & Storage")),
]

def detect_exact_app(domain: str) -> tuple:
    """
    Deterministic app + category mapper.
    Returns (app_name: str, category: str) or ("", "Web Traffic") if no match.
    """
    d = domain.lower()
    for keywords, result in _APP_MAP:
        if any(k in d for k in keywords):
            return result
    return ("", "Web Traffic")


def categorize_domain(domain: str) -> str:
    """Legacy category-only mapper kept for backward compat."""
    _, cat = detect_exact_app(domain)
    return cat


# ── Live Packet Sniffer ───────────────────────────────────────────────────────

class LivePacketSniffer:
    def __init__(self):
        self.iface = get_best_wifi_iface()
        self.running = False
        self.lock = threading.Lock()

        # Real-time traffic rate accounting per IP
        self.ip_traffic = defaultdict(lambda: {
            "sec_dl_bytes":    0,
            "sec_ul_bytes":    0,
            "current_dl_kbps": 0.0,
            "current_ul_kbps": 0.0,
            "total_dl_bytes":  0,
            "total_ul_bytes":  0,
            "packet_count":    0,
            "latency_ms":      2,
            "last_seen":       time.time(),
            "current_app":     "",
            "last_domain":     "",
            "app_last_seen":   0.0,    # monotonic timestamp when app was last detected
        })

        # Per-device live packet ring buffer (last 100 packets per IP)
        self.device_packets: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))

        self.recent_activities: List[Dict[str, Any]] = []
        self.prev_rate_tick = time.time()
        self.sniff_thread:  Optional[threading.Thread] = None
        self.rate_thread:   Optional[threading.Thread] = None
        self.probe_thread:  Optional[threading.Thread] = None
        self.bridge_thread: Optional[threading.Thread] = None

        # Network topology — discovered dynamically, no hardcoded IPs
        self.gateway_ip  = self._detect_gateway()
        self.gateway_mac = ""
        self.local_mac   = ""

        # Admin-configurable ARP bridge targets (replaces hardcoded target_phone_ip)
        self.monitored_ips: Set[str] = set()
        self._monitored_macs: Dict[str, str] = {}  # ip -> mac (populated by set_monitored_ip)

    @staticmethod
    def _detect_gateway() -> str:
        try:
            out = subprocess.check_output("ipconfig", text=True, timeout=5)
            for line in out.splitlines():
                if "Default Gateway" in line:
                    gw = line.split(":")[-1].strip()
                    if gw:
                        return gw
        except Exception:
            pass
        return "192.168.1.1"

    def set_monitored_ip(self, ip: str, enabled: bool, mac: str = ""):
        """Enable/disable admin-selected ARP bridge monitoring for a specific device."""
        with self.lock:
            if enabled:
                self.monitored_ips.add(ip)
                if mac:
                    self._monitored_macs[ip] = mac
            else:
                self.monitored_ips.discard(ip)
                self._monitored_macs.pop(ip, None)

    def start(self):
        if self.running:
            return
        self.running = True
        self.iface = get_best_wifi_iface()

        self.sniff_thread  = threading.Thread(target=self._sniff_loop,        daemon=True, name="Scapy-Sniff")
        self.rate_thread   = threading.Thread(target=self._rate_calc_loop,    daemon=True, name="Scapy-Rate")
        self.probe_thread  = threading.Thread(target=self._active_probe_loop, daemon=True, name="Scapy-Probe")
        self.bridge_thread = threading.Thread(target=self._arp_bridge_loop,   daemon=True, name="Scapy-ARP")

        for t in (self.sniff_thread, self.rate_thread, self.probe_thread, self.bridge_thread):
            t.start()

        print(f"[SCAPY ENGINE] Real-time promiscuous packet engine running on interface '{self.iface}'")

    def stop(self):
        self.running = False

    # ── Packet Capture ────────────────────────────────────────────────────────

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
            except Exception:
                time.sleep(1)

    def _process_packet(self, pkt):
        length    = len(pkt)
        now_ts    = datetime.now().strftime("%H:%M:%S")

        src_ip         = None
        dst_ip         = None
        proto_name     = "ETH"
        src_port       = 0
        dst_port       = 0
        extracted_domain = None

        if pkt.haslayer(scapy.IP):
            src_ip     = pkt[scapy.IP].src
            dst_ip     = pkt[scapy.IP].dst
            proto_num  = pkt[scapy.IP].proto
            proto_name = "TCP" if proto_num == 6 else ("UDP" if proto_num == 17 else "IP")
        elif pkt.haslayer(scapy.IPv6):
            src_ip     = pkt[scapy.IPv6].src
            dst_ip     = pkt[scapy.IPv6].dst
            proto_name = "IPv6"

        if pkt.haslayer(scapy.TCP):
            src_port = pkt[scapy.TCP].sport
            dst_port = pkt[scapy.TCP].dport
        elif pkt.haslayer(scapy.UDP):
            src_port = pkt[scapy.UDP].sport
            dst_port = pkt[scapy.UDP].dport

        # ── Per-device byte accounting ────────────────────────────────────────
        with self.lock:
            if src_ip:
                self.ip_traffic[src_ip]["sec_ul_bytes"]   += length
                self.ip_traffic[src_ip]["total_ul_bytes"]  += length
                self.ip_traffic[src_ip]["packet_count"]    += 1
                self.ip_traffic[src_ip]["last_seen"]        = time.time()
            if dst_ip:
                self.ip_traffic[dst_ip]["sec_dl_bytes"]   += length
                self.ip_traffic[dst_ip]["total_dl_bytes"]  += length
                self.ip_traffic[dst_ip]["packet_count"]    += 1
                self.ip_traffic[dst_ip]["last_seen"]        = time.time()

        # ── Ring-buffer packet summary storage ────────────────────────────────
        client_ip_for_ring = None
        if src_ip and src_ip.startswith("192.168."):
            client_ip_for_ring = src_ip
        elif dst_ip and dst_ip.startswith("192.168."):
            client_ip_for_ring = dst_ip

        if client_ip_for_ring:
            raw_bytes = bytes(pkt)
            summary = {
                "timestamp":  now_ts,
                "src_ip":     src_ip or "",
                "dst_ip":     dst_ip or "",
                "protocol":   proto_name,
                "src_port":   src_port,
                "dst_port":   dst_port,
                "length":     length,
                "info":       "",                       # filled below when domain found
                "hex_preview": raw_bytes[:32].hex(" ") # first 32 bytes
            }
            with self.lock:
                self.device_packets[client_ip_for_ring].append(summary)

        # ── DNS (UDP 53) ──────────────────────────────────────────────────────
        if pkt.haslayer(scapy.DNSQR):
            try:
                qname = pkt[scapy.DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
                if qname and not qname.endswith(".in-addr.arpa"):
                    extracted_domain = qname
                    proto_name = "DNS"
            except Exception:
                pass

        # ── TLS ClientHello SNI (TCP/443) ─────────────────────────────────────
        if not extracted_domain and pkt.haslayer(scapy.TCP):
            if pkt[scapy.TCP].dport == 443 and pkt.haslayer(scapy.Raw):
                payload = bytes(pkt[scapy.Raw].load)
                sni = extract_tls_sni(payload)
                if sni:
                    extracted_domain = sni
                    proto_name = "HTTPS/TLS"

        # ── QUIC / HTTP3 SNI (UDP/443) ────────────────────────────────────────
        if not extracted_domain and pkt.haslayer(scapy.UDP):
            if pkt[scapy.UDP].dport == 443 and pkt.haslayer(scapy.Raw):
                payload = bytes(pkt[scapy.Raw].load)
                sni = extract_quic_sni(payload)
                if sni:
                    extracted_domain = sni
                    proto_name = "QUIC/HTTP3"

        # ── HTTP Host header (TCP/80, 8080) ────────────────────────────────────
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

        # ── mDNS (5353) ────────────────────────────────────────────────────────
        if not extracted_domain and pkt.haslayer(scapy.UDP):
            if pkt[scapy.UDP].dport == 5353 and pkt.haslayer(scapy.Raw):
                raw_bytes_mdns = bytes(pkt[scapy.Raw].load)
                for chunk in raw_bytes_mdns.split(b'\x00'):
                    chunk_str = chunk.decode('latin1', errors='ignore').strip()
                    if "." in chunk_str and len(chunk_str) > 4:
                        extracted_domain = chunk_str
                        proto_name = "mDNS"
                        break

        # ── App detection & activity recording ────────────────────────────────
        if extracted_domain and src_ip:
            client_ip = src_ip if src_ip.startswith("192.168.") else dst_ip
            if client_ip and client_ip.startswith("192.168."):
                app_name, category = detect_exact_app(extracted_domain)

                # Update ring buffer info field for this device
                if client_ip_for_ring == client_ip:
                    with self.lock:
                        if self.device_packets[client_ip]:
                            self.device_packets[client_ip][-1]["info"] = (
                                app_name or extracted_domain
                            )

                # Store app + domain in traffic telemetry
                with self.lock:
                    self.ip_traffic[client_ip]["last_domain"] = extracted_domain
                    if app_name:
                        self.ip_traffic[client_ip]["current_app"] = app_name
                        self.ip_traffic[client_ip]["app_last_seen"] = time.monotonic()

                self._record_activity(
                    client_ip, extracted_domain, app_name, category,
                    proto_name, dst_port or src_port or 443, length, now_ts
                )

    def _record_activity(self, client_ip: str, domain: str, app_name: str,
                         category: str, protocol: str, port: int,
                         payload_len: int, timestamp: str):
        conn   = get_db()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT custom_name, hostname, brand, network_type FROM devices WHERE ip = ?",
            (client_ip,)
        )
        row      = cursor.fetchone()
        dev_name = (row["custom_name"] if row and row["custom_name"]
                    else (row["hostname"] if row else f"Device ({client_ip})"))
        net_type = row["network_type"] if row and row["network_type"] else "primary"

        # Check firewall rules
        cursor.execute("SELECT * FROM blacklist_rules WHERE is_active = 1")
        rules  = cursor.fetchall()
        action = "ALLOWED"
        for r in rules:
            if r["rule_type"] == "domain"   and r["target"].lower() in domain.lower():
                action = "BLOCKED"; break
            elif r["rule_type"] == "category" and r["target"].lower() == category.lower():
                action = "BLOCKED"; break

        # Enrich label with verified app name
        display_domain = f"{app_name} ({domain})" if app_name else domain

        cursor.execute("""
            INSERT INTO activity_logs
                (device_mac, device_ip, network_type, domain, url_path,
                 category, protocol, port, bytes_transferred, action_taken)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (f"real:{client_ip}", client_ip, net_type, display_domain,
              f"Live {protocol} Wire", category, protocol, port, payload_len, action))
        conn.commit()
        conn.close()

        item = {
            "device_mac":       f"real:{client_ip}",
            "device_ip":        client_ip,
            "device_name":      dev_name,
            "network_type":     net_type,
            "domain":           display_domain,
            "url_path":         f"Live {protocol} Wire",
            "category":         category,
            "protocol":         protocol,
            "port":             port,
            "bytes_transferred": payload_len,
            "action_taken":     action,
            "timestamp":        timestamp
        }

        with self.lock:
            self.recent_activities.insert(0, item)
            self.recent_activities = self.recent_activities[:80]

    # ── Rate Calculation Loop ─────────────────────────────────────────────────

    def _rate_calc_loop(self):
        """Calculates exact KB/s throughput per device every 1 second and syncs to SQLite."""
        while self.running:
            time.sleep(1.0)
            now = time.time()
            dt  = max(0.5, now - self.prev_rate_tick)
            self.prev_rate_tick = now

            conn   = get_db()
            cursor = conn.cursor()

            with self.lock:
                for ip, data in list(self.ip_traffic.items()):
                    if not ip.startswith("192.168."):
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
                                total_upload_bytes   = total_upload_bytes   + ?,
                                status               = 'online',
                                last_seen            = CURRENT_TIMESTAMP
                            WHERE ip = ?
                        """, (dl_bytes, ul_bytes, ip))

            conn.commit()
            conn.close()

    # ── Active ICMP Probe Loop ────────────────────────────────────────────────

    def _probe_single_ip(self, ip: str):
        """Ping one IP and update its latency_ms in the traffic dict."""
        try:
            t0  = time.time()
            res = subprocess.run(
                ["ping", "-n", "1", "-w", "500", ip],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
            )
            elapsed_ms = int((time.time() - t0) * 1000)
            if "TTL=" in res.stdout:
                m   = re.search(r'time[=<]([0-9]+)ms', res.stdout, re.IGNORECASE)
                lat = int(m.group(1)) if m else elapsed_ms
                with self.lock:
                    self.ip_traffic[ip]["latency_ms"] = max(1, lat)
                    self.ip_traffic[ip]["last_seen"]   = time.time()
        except Exception:
            pass

    def _active_probe_loop(self):
        """
        Dynamically queries SQLite for online devices every 3 seconds
        and probes them concurrently. No hardcoded IPs.
        """
        while self.running:
            time.sleep(3.0)
            try:
                conn   = get_db()
                cursor = conn.cursor()
                cursor.execute("SELECT ip FROM devices WHERE status = 'online'")
                ips = [row["ip"] for row in cursor.fetchall() if row["ip"]]
                conn.close()

                with ThreadPoolExecutor(max_workers=10) as exe:
                    for ip in ips:
                        exe.submit(self._probe_single_ip, ip)
            except Exception:
                pass

    # ── ARP Bridge Loop ───────────────────────────────────────────────────────

    def _arp_bridge_loop(self):
        """
        God-Mode transparent ARP bridge for admin-selected devices only.
        No hardcoded phone IPs — admin calls set_monitored_ip(ip, True) to activate.
        """
        while self.running:
            time.sleep(4.0)
            with self.lock:
                targets = list(self.monitored_ips)
                gw      = self.gateway_ip
                gw_mac  = self.gateway_mac
                macs    = dict(self._monitored_macs)

            for target_ip in targets:
                try:
                    pkt_to_router = scapy.ARP(
                        op=2,
                        pdst=gw,
                        hwdst=gw_mac or "ff:ff:ff:ff:ff:ff",
                        psrc=target_ip
                    )
                    scapy.send(pkt_to_router, iface=self.iface, verbose=False)
                except Exception:
                    pass

    # ── Public Data Accessors ─────────────────────────────────────────────────

    def get_device_rates(self, ip: str) -> Dict[str, Any]:
        with self.lock:
            data = self.ip_traffic[ip]
            # Expire app label after 30 seconds of no detection
            app = data["current_app"]
            if app and (time.monotonic() - data["app_last_seen"]) > 30:
                app = ""
            return {
                "current_dl_kbps": data["current_dl_kbps"],
                "current_ul_kbps": data["current_ul_kbps"],
                "total_dl_bytes":  data["total_dl_bytes"],
                "total_ul_bytes":  data["total_ul_bytes"],
                "latency_ms":      data["latency_ms"],
                "packet_count":    data["packet_count"],
                "current_app":     app,
                "last_domain":     data["last_domain"],
            }

    def get_device_packets(self, ip: str) -> List[Dict[str, Any]]:
        """Returns the live packet ring buffer for a specific device IP (up to 100 entries)."""
        with self.lock:
            return list(self.device_packets.get(ip, deque()))


# ── Module-level singleton ────────────────────────────────────────────────────
live_sniffer = LivePacketSniffer()
