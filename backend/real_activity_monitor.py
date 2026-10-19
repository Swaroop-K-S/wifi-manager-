"""
Real Live Activity and Sockets Monitor
Inspects real established TCP/UDP network connections, resolves domains,
associates client processes, and categorizes actual live web traffic.
"""
import socket
import time
import psutil
from typing import Dict, List, Any

# Fast in-memory cache for IP -> Domain mapping to prevent reverse DNS lag
DNS_REVERSE_CACHE: Dict[str, str] = {
    "127.0.0.1": "localhost",
    "8.8.8.8": "dns.google",
    "1.1.1.1": "one.one.one.one (Cloudflare)",
    "1.0.0.1": "one.one.one.one (Cloudflare)"
}

# Domain Category Classifier
def classify_domain(domain: str) -> str:
    d = domain.lower()
    if any(k in d for k in ["youtube", "googlevideo", "netflix", "spotify", "twitch", "primevideo", "disney", "hulu", "vimeo"]):
        return "Streaming"
    if any(k in d for k in ["instagram", "tiktok", "facebook", "whatsapp", "twitter", "reddit", "telegram", "snapchat", "linkedin"]):
        return "Social Media"
    if any(k in d for k in ["steam", "discord", "epicgames", "riotgames", "valve", "ea.com", "blizzard", "xbox", "playstation"]):
        return "Gaming"
    if any(k in d for k in ["github", "openai", "chatgpt", "anthropic", "claude", "stackoverflow", "gitlab", "docker", "aws", "azure"]):
        return "Dev & AI"
    if any(k in d for k in ["drive.google", "dropbox", "onedrive", "icloud", "box.com"]):
        return "Cloud & Storage"
    if any(k in d for k in ["doubleclick", "adservice", "analytics", "telemetry", "tracker", "beacon"]):
        return "Ads & Trackers"
    return "Web Browsing"

class RealActivityMonitor:
    def __init__(self):
        self.seen_signatures = set()

    def resolve_ip(self, ip: str) -> str:
        """Resolves an IP to its real hostname with caching."""
        if ip in DNS_REVERSE_CACHE:
            return DNS_REVERSE_CACHE[ip]
        if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.16.") or ip == "127.0.0.1":
            DNS_REVERSE_CACHE[ip] = "LAN Host"
            return "LAN Host"
        try:
            name, _, _ = socket.gethostbyaddr(ip)
            # Simplify hostname: e.g. "maa05s01-in-f14.1e100.net" -> "1e100.net (Google)"
            cleaned = name.lower()
            if "1e100.net" in cleaned or "google" in cleaned:
                cleaned = "google.com / youtube"
            elif "fbcdn" in cleaned or "facebook" in cleaned or "meta" in cleaned:
                cleaned = "instagram.com / meta"
            elif "cloudfront" in cleaned or "aws" in cleaned:
                cleaned = "aws.amazon.com"
            elif "akamaitechnologies" in cleaned or "akamai" in cleaned:
                cleaned = "akamai.net (CDN)"
            elif "cloudflare" in cleaned:
                cleaned = "cloudflare.com"
            elif "github" in cleaned:
                cleaned = "github.com"
            elif "discord" in cleaned:
                cleaned = "discord.gg"
            elif "steam" in cleaned:
                cleaned = "steampowered.com"
            DNS_REVERSE_CACHE[ip] = cleaned
            return cleaned
        except Exception:
            DNS_REVERSE_CACHE[ip] = ip
            return ip

    def capture_live_connections(self) -> List[Dict[str, Any]]:
        """
        Gathers real active TCP/UDP connections currently established
        on this PC and its network interfaces.
        """
        events = []
        try:
            conns = psutil.net_connections(kind="inet")
            active_conns = [c for c in conns if c.status in ("ESTABLISHED", "SYN_SENT") and c.raddr]
            
            for c in active_conns[:20]: # Process top active connections
                r_ip = c.raddr.ip
                r_port = c.raddr.port
                l_ip = c.laddr.ip if c.laddr else "192.168.1.44"
                
                # Ignore loopback
                if r_ip == "127.0.0.1" or r_ip.startswith("::"):
                    continue

                sig = f"{c.pid}_{r_ip}_{r_port}"
                is_new = sig not in self.seen_signatures
                self.seen_signatures.add(sig)
                if len(self.seen_signatures) > 300:
                    self.seen_signatures.clear()

                # Get process name
                proc_name = "Network Service"
                if c.pid:
                    try:
                        proc_name = psutil.Process(c.pid).name()
                    except Exception:
                        pass

                domain = self.resolve_ip(r_ip)
                category = classify_domain(domain)
                if "steam" in proc_name.lower():
                    category = "Gaming"
                elif "discord" in proc_name.lower():
                    category = "Gaming"
                elif "spotify" in proc_name.lower():
                    category = "Streaming"
                elif "code" in proc_name.lower() or "git" in proc_name.lower():
                    category = "Dev & AI"

                events.append({
                    "device_ip": l_ip,
                    "target_ip": r_ip,
                    "domain": domain,
                    "url_path": f":{r_port} ({proc_name})",
                    "category": category,
                    "protocol": "TCP" if c.type == socket.SOCK_STREAM else "UDP",
                    "port": r_port,
                    "process": proc_name,
                    "is_new": is_new,
                    "timestamp": time.strftime("%H:%M:%S")
                })
        except Exception as e:
            print("Capture error:", e)

        return events
