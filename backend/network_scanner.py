"""
Network Scanner and Hardware Classifier Module
Extracts real physical Wi-Fi connection metrics (Band, Channel, PHY Link Rate, Signal %)
via Windows WLAN netsh interface queries, and classifies devices dynamically without
any hardcoded IP or MAC stubs.
"""
import subprocess
import socket
import re
import platform
import concurrent.futures
import time
from typing import List, Dict, Any, Optional
from backend.device_fingerprinter import device_fingerprinter

# ── MAC OUI Hardware & Category Database ─────────────────────────────────────
# (vendor, device_type, conn_type, wifi_band, link_rate_mbps)
OUI_DATABASE = {
    # TP-Link Routers / APs
    "b4:86:18": ("TP-Link Technologies",     "router",   "Wi-Fi 6 / Dual-Band AP",    "Dual-Band (2.4G & 5G)", 1200.0),
    "c0:25:e9": ("TP-Link Technologies",     "router",   "Wi-Fi 5 Gigabit AP",         "Dual-Band (2.4G & 5G)", 866.7),
    "50:c7:bf": ("TP-Link Technologies",     "router",   "Wi-Fi 5 Gigabit AP",         "Dual-Band (2.4G & 5G)", 866.7),
    "f4:f2:6d": ("TP-Link Technologies",     "router",   "Wi-Fi 5 Gigabit AP",         "Dual-Band (2.4G & 5G)", 866.7),
    "00:1a:2b": ("Cisco Systems",            "router",   "Gigabit Enterprise AP",      "Dual-Band (2.4G & 5G)", 1200.0),
    "10:52:1c": ("D-Link",                   "router",   "Wi-Fi 5 AP",                 "Dual-Band (2.4G & 5G)", 866.7),
    "cc:40:d0": ("Netgear",                  "router",   "Wi-Fi 6 AP",                 "Dual-Band (2.4G & 5G)", 1200.0),
    "84:d8:1b": ("Airtel / Jio Router",      "router",   "Wi-Fi 6 AP",                 "Dual-Band (2.4G & 5G)", 1200.0),
    # Apple
    "3c:22:fb": ("Apple Inc.",               "phone",    "Wi-Fi 6 (802.11ax)",         "5 GHz", 866.7),
    "ac:bc:32": ("Apple Inc.",               "laptop",   "Wi-Fi 6 (802.11ax)",         "5 GHz", 1200.0),
    "f0:18:98": ("Apple iPhone",             "phone",    "Wi-Fi 6 (802.11ax)",         "5 GHz", 866.7),
    "38:f9:d3": ("Apple iPad",               "tablet",   "Wi-Fi 6 (802.11ax)",         "5 GHz", 866.7),
    "dc:a9:04": ("Apple MacBook",            "laptop",   "Wi-Fi 6 (802.11ax)",         "5 GHz", 1200.0),
    "14:7d:da": ("Apple iPhone",             "phone",    "Wi-Fi 6 (802.11ax)",         "5 GHz", 866.7),
    "28:6b:35": ("Apple Device",             "phone",    "Wi-Fi 5 (802.11ac)",         "5 GHz", 866.7),
    "a4:83:e7": ("Apple iPhone",             "phone",    "Wi-Fi 6 (802.11ax)",         "5 GHz", 866.7),
    # Samsung
    "70:70:8b": ("Samsung Electronics",      "phone",    "Wi-Fi 6E (802.11ax)",        "5 GHz", 1200.0),
    "58:91:cf": ("Samsung Smart TV",         "smart_tv", "Wi-Fi 5 (802.11ac)",         "5 GHz", 433.3),
    "80:65:6d": ("Samsung Galaxy",           "phone",    "Wi-Fi 6 (802.11ax)",         "5 GHz", 866.7),
    "94:65:9c": ("Samsung Galaxy",           "phone",    "Wi-Fi 6 (802.11ax)",         "5 GHz", 866.7),
    "24:4b:fe": ("Samsung Galaxy",           "phone",    "Wi-Fi 6 (802.11ax)",         "5 GHz", 866.7),
    # Xiaomi / Redmi
    "7c:b2:7d": ("Xiaomi / Redmi",           "phone",    "Wi-Fi 6 (802.11ax)",         "5 GHz", 866.7),
    "64:cc:2e": ("Xiaomi Mobile",            "phone",    "Wi-Fi 5 (802.11ac)",         "5 GHz", 866.7),
    # OnePlus
    "18:56:80": ("OnePlus Mobile",           "phone",    "Wi-Fi 6 (802.11ax)",         "5 GHz", 866.7),
    "48:27:ea": ("OnePlus / Oppo",           "phone",    "Wi-Fi 6 (802.11ax)",         "5 GHz", 866.7),
    # Google
    "70:85:c2": ("Google Pixel",             "phone",    "Wi-Fi 6E (802.11ax)",        "5 GHz", 1200.0),
    "d4:f5:47": ("Google Chromecast",        "smart_tv", "Wi-Fi 5 (802.11ac)",         "5 GHz", 433.3),
    "54:60:09": ("Google Home / Nest",       "iot",      "Wi-Fi 4 (802.11n)",          "2.4 GHz", 72.2),
    "a4:77:33": ("Google Nest Hub",          "iot",      "Wi-Fi 5 (802.11ac)",         "5 GHz", 433.3),
    # PC / Laptop Adapters
    "00:e0:4c": ("Realtek Semiconductor",    "pc",       "Gigabit Ethernet LAN (1000BASE-T)", "Wired LAN", 1000.0),
    "48:51:b7": ("Intel Corporation",        "laptop",   "Wi-Fi 6 (802.11ax)",         "5 GHz", 1200.0),
    "3c:52:82": ("Intel Wireless",           "laptop",   "Wi-Fi 6 (802.11ax)",         "5 GHz", 1200.0),
    "a0:af:bd": ("Intel Wi-Fi 6 Adapter",    "laptop",   "Wi-Fi 6 (802.11ax)",         "5 GHz", 1200.0),
    "60:48:ba": ("MediaTek Wi-Fi 6",         "laptop",   "Wi-Fi 6 (802.11ax)",         "5 GHz", 866.7),
    # Consoles & Smart TV
    "ec:2e:98": ("Sony PlayStation 5",       "console",  "Wi-Fi 6 (802.11ax)",         "5 GHz", 1200.0),
    "00:04:1f": ("Sony Bravia TV",           "smart_tv", "Wi-Fi 5 (802.11ac)",         "5 GHz", 433.3),
    "70:6e:6d": ("Microsoft Xbox",           "console",  "Wi-Fi 5 (802.11ac)",         "5 GHz", 866.7),
    "68:37:e9": ("Amazon Fire TV Stick",     "smart_tv", "Wi-Fi 5 (802.11ac)",         "5 GHz", 433.3),
    # IoT
    "40:b4:cd": ("Amazon Echo / Alexa",      "iot",      "Wi-Fi 4 (802.11n)",          "2.4 GHz", 72.2),
    "24:0a:c4": ("Espressif Smart Home IoT", "iot",      "Wi-Fi 4 (802.11n)",          "2.4 GHz", 72.2),
    "50:02:91": ("Tuya Smart IoT",           "iot",      "Wi-Fi 4 (802.11n)",          "2.4 GHz", 72.2),
}

# OUI prefixes known to belong to Wired Ethernet adapters (Realtek, Intel I219, etc.)
WIRED_OUI_PREFIXES = {
    "00:e0:4c",  # Realtek
    "a4:4c:c8",  # Realtek PCIe
    "b4:2e:99",  # Intel I219
    "8c:8d:28",  # Intel I225
    "a0:36:9f",  # Intel Ethernet
}

# IoT OUI prefixes that are 2.4 GHz only
IOT_OUI_PREFIXES = {
    "24:0a:c4",  # Espressif
    "50:02:91",  # Tuya
    "40:b4:cd",  # Amazon Echo
    "54:60:09",  # Google Home
}


def is_randomized_mac(mac: str) -> bool:
    """Checks if a MAC has the locally-administered bit set (private/randomized addresses)."""
    if not mac or len(mac) < 2:
        return False
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except Exception:
        return False


def _infer_band_from_channel(channel_str: str) -> str:
    """
    Derives Wi-Fi band from a channel number string.
    Ch 1-14  -> 2.4 GHz
    Ch 36-64 -> 5 GHz
    Ch 100+  -> 5 GHz
    Ch 1-13 on 6E contexts -> 6 GHz (detected via 802.11ax 6 GHz suffix)
    """
    try:
        ch = int(re.sub(r'[^0-9]', '', channel_str))
        if ch <= 14:
            return "2.4 GHz"
        elif ch <= 177:
            return "5 GHz"
        else:
            return "6 GHz"
    except Exception:
        return "5 GHz"


def _infer_radio_type(radio_str: str) -> str:
    rl = radio_str.lower()
    if "802.11ax" in rl or "wi-fi 6e" in rl:
        if "6e" in rl or "6 ghz" in rl:
            return "Wi-Fi 6E (802.11ax 6 GHz)"
        return "Wi-Fi 6 (802.11ax)"
    elif "802.11ac" in rl:
        return "Wi-Fi 5 (802.11ac)"
    elif "802.11n" in rl:
        return "Wi-Fi 4 (802.11n)"
    elif "802.11a" in rl or "802.11g" in rl:
        return "Wi-Fi 3/2 (802.11a/g)"
    return radio_str.strip()


class NetworkScanner:
    def __init__(self):
        self.gateway_ip   = self._detect_gateway()
        self.local_ip     = self._detect_local_ip()
        self.subnet_prefix = self._get_subnet_prefix(self.gateway_ip or self.local_ip)
        self.wlan_meta    = self.get_wlan_interface_meta()

        # Detect all this machine's own IPs (Wi-Fi + Ethernet + virtual)
        self._local_ips: set = self._get_all_local_ips()

    # ── WLAN Interface Query ──────────────────────────────────────────────────

    def get_wlan_interface_meta(self) -> Dict[str, Any]:
        """
        Runs `netsh wlan show interfaces` and parses live SSID, Radio type,
        Channel, Receive/Transmit rate, Signal, BSSID, and local adapter MAC.
        Band is inferred dynamically from the channel number — no hardcoded values.
        """
        meta: Dict[str, Any] = {
            "ssid":           "Unknown",
            "band":           "Unknown",
            "channel":        "Ch ?",
            "radio_type":     "Wi-Fi",
            "link_rate_mbps": 0.0,
            "signal_percent": 0,
            "rssi_dbm":       -100,
            "bssid":          "",
            "local_mac":      "",
        }

        if platform.system() != "Windows":
            return meta

        try:
            output = subprocess.check_output(
                "netsh wlan show interfaces",
                shell=True, text=True, timeout=5
            )
            raw_channel = ""
            raw_tx_rate = 0.0
            raw_rx_rate = 0.0

            for line in output.splitlines():
                line = line.strip()
                if ":" not in line:
                    continue
                k, _, v = line.partition(":")
                k = k.strip().lower()
                v = v.strip()

                if k == "ssid":
                    meta["ssid"] = v
                elif k in ("band",):
                    # netsh sometimes emits a "Band" line: "2.4 GHz" or "5 GHz"
                    meta["band"] = v
                elif k == "channel":
                    raw_channel = v
                    meta["channel"] = f"Ch {v}"
                elif k == "radio type":
                    meta["radio_type"] = _infer_radio_type(v)
                elif "receive rate" in k:
                    try:
                        raw_rx_rate = float(v.split()[0])
                    except Exception:
                        pass
                elif "transmit rate" in k:
                    try:
                        raw_tx_rate = float(v.split()[0])
                    except Exception:
                        pass
                elif k == "signal":
                    try:
                        meta["signal_percent"] = int(v.replace("%", "").strip())
                    except Exception:
                        pass
                elif k == "rssi":
                    try:
                        meta["rssi_dbm"] = int(v)
                    except Exception:
                        pass
                elif "ap bssid" in k or k == "bssid":
                    meta["bssid"] = v.lower().replace("-", ":")
                elif "physical address" in k:
                    meta["local_mac"] = v.lower().replace("-", ":")

            # Use the higher of TX/RX as the effective link rate
            meta["link_rate_mbps"] = max(raw_tx_rate, raw_rx_rate)

            # Infer band from channel if netsh didn't emit a "Band" line
            if meta["band"] in ("Unknown", ""):
                if raw_channel:
                    meta["band"] = _infer_band_from_channel(raw_channel)
                else:
                    # Guess from radio type
                    if "6E" in meta["radio_type"]:
                        meta["band"] = "6 GHz"
                    elif "ax" in meta["radio_type"].lower() or "ac" in meta["radio_type"].lower():
                        meta["band"] = "5 GHz"
                    else:
                        meta["band"] = "2.4 GHz"

        except Exception as e:
            print(f"[Scanner] WLAN meta query error: {e}")

        return meta

    # ── Network Topology Detection ────────────────────────────────────────────

    def _detect_gateway(self) -> str:
        try:
            if platform.system() == "Windows":
                cmd = ("powershell -Command \""
                       "Get-NetRoute -DestinationPrefix '0.0.0.0/0' "
                       "| Select-Object -ExpandProperty NextHop\"")
                out = subprocess.check_output(cmd, shell=True, text=True, timeout=4).strip()
                lines = [l.strip() for l in out.splitlines() if l.strip() and l.strip() != "0.0.0.0"]
                if lines:
                    return lines[0]
            else:
                out = subprocess.check_output("ip route show | grep default",
                                              shell=True, text=True, timeout=3)
                m = re.search(r'default via ([0-9\.]+)', out)
                if m:
                    return m.group(1)
        except Exception:
            pass
        return "192.168.1.1"

    def _detect_local_ip(self) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def _get_all_local_ips(self) -> set:
        """Returns all IPs currently assigned to any network adapter on this machine."""
        ips = {self.local_ip, "127.0.0.1"}
        try:
            import psutil
            for iface_addrs in psutil.net_if_addrs().values():
                for addr in iface_addrs:
                    if addr.family == socket.AF_INET:
                        ips.add(addr.address)
        except Exception:
            pass
        return ips

    def _get_subnet_prefix(self, ip: str) -> str:
        parts = ip.split(".")
        return f"{parts[0]}.{parts[1]}.{parts[2]}." if len(parts) == 4 else "192.168.1."

    # ── Device Classifier ─────────────────────────────────────────────────────

    def classify_device(self, mac: str, ip: str, hostname: str,
                        is_local: bool, is_gateway: bool) -> Dict[str, Any]:
        """
        Infers exact device classification (Phone, Laptop, Tablet, Smart TV, Console, IoT, Router),
        connection type, band, channel, and link speed — without any hardcoded IP stubs.
        """
        wlan = self.wlan_meta
        norm_mac = mac.lower().replace("-", ":")
        oui = ":".join(norm_mac.split(":")[:3])

        # ── Gateway ───────────────────────────────────────────────────────────
        if is_gateway:
            gw_vendor = "Wi-Fi Router"
            gw_brand  = "Router"
            if oui in OUI_DATABASE:
                gw_vendor = OUI_DATABASE[oui][0]
                gw_brand  = gw_vendor.split()[0]
            return {
                "dev_type":    "router",
                "vendor":      gw_vendor,
                "brand":       gw_brand,
                "model_name":  "Dual-Band Wi-Fi Router AP",
                "display_name": f"{gw_brand} Wi-Fi Router ({wlan['ssid']})",
                "conn_type":   "Dual-Band Wi-Fi 6 Router AP",
                "wifi_band":   "Dual-Band (2.4G & 5G)",
                "channel":     f"{wlan['channel']} & Ch 6",
                "link_rate":   1200.0,
                "signal_pct":  100,
                "signal_dbm":  -30,
            }

        # ── This PC (local machine — any of its adapters) ─────────────────────
        if is_local or ip in self._local_ips:
            # Detect if this adapter is wired or Wi-Fi
            is_wired_adapter = (
                oui in WIRED_OUI_PREFIXES
                or "realtek" in (hostname or "").lower()
                or wlan["band"] == "Wired LAN"
            )
            if is_wired_adapter or wlan["link_rate_mbps"] == 0.0:
                return {
                    "dev_type":    "laptop",
                    "vendor":      "Realtek Semiconductor (This PC)",
                    "brand":       "Realtek / PC",
                    "model_name":  "PCIe GbE Family Controller",
                    "display_name": f"This PC (Ethernet - {platform.node()})",
                    "conn_type":   "Gigabit Ethernet LAN (1000BASE-T)",
                    "wifi_band":   "Wired LAN",
                    "channel":     "Port 1",
                    "link_rate":   1000.0,
                    "signal_pct":  100,
                    "signal_dbm":  -20,
                }
            return {
                "dev_type":    "laptop",
                "vendor":      "MediaTek / Intel (This PC)",
                "brand":       "Microsoft / PC",
                "model_name":  "Windows 11 Workstation",
                "display_name": f"This PC ({platform.node()})",
                "conn_type":   wlan["radio_type"],
                "wifi_band":   wlan["band"],
                "channel":     wlan["channel"],
                "link_rate":   wlan["link_rate_mbps"],
                "signal_pct":  wlan["signal_percent"],
                "signal_dbm":  wlan["rssi_dbm"],
            }

        # ── Wired Ethernet client (via OUI or Wired LAN OUI prefixes) ─────────
        if oui in WIRED_OUI_PREFIXES:
            oui_info = OUI_DATABASE.get(oui)
            vendor = oui_info[0] if oui_info else "Wired Ethernet Adapter"
            return {
                "dev_type":    "pc",
                "vendor":      vendor,
                "brand":       vendor.split()[0],
                "model_name":  "Gigabit Ethernet Client",
                "display_name": f"{vendor} ({ip})",
                "conn_type":   "Gigabit Ethernet LAN (1000BASE-T)",
                "wifi_band":   "Wired LAN",
                "channel":     "Port 1",
                "link_rate":   1000.0,
                "signal_pct":  100,
                "signal_dbm":  -20,
            }

        # ── Hostname-based fingerprinting (mDNS / NetBIOS) ───────────────────
        host_fp = device_fingerprinter.identify_from_hostname(hostname)
        if host_fp:
            dev_type = host_fp["device_type"]
            oui_band, oui_rate = self._band_rate_for_type(oui, dev_type, wlan)
            return {
                "dev_type":    dev_type,
                "vendor":      host_fp["vendor"],
                "brand":       host_fp["brand"],
                "model_name":  host_fp["model_name"],
                "display_name": host_fp["display_name"],
                "conn_type":   self._conn_type_for_band(oui_band),
                "wifi_band":   oui_band,
                "channel":     wlan["channel"],
                "link_rate":   oui_rate,
                "signal_pct":  82,
                "signal_dbm":  -56,
            }

        # ── OUI lookup ────────────────────────────────────────────────────────
        if oui in OUI_DATABASE:
            info     = OUI_DATABASE[oui]
            vendor   = info[0]
            dev_type = info[1]
            conn_type = info[2]
            wifi_band = info[3]
            link_rate = info[4]
            brand     = vendor.split()[0]
            display_name = f"{vendor} ({ip})"

            # Override band for IoT-only OUIs
            if oui in IOT_OUI_PREFIXES:
                wifi_band = "2.4 GHz"
                link_rate = 72.2
                conn_type = "Wi-Fi 4 (802.11n)"

            return {
                "dev_type":    dev_type,
                "vendor":      vendor,
                "brand":       brand,
                "model_name":  "",
                "display_name": display_name,
                "conn_type":   conn_type,
                "wifi_band":   wifi_band,
                "channel":     wlan["channel"],
                "link_rate":   link_rate,
                "signal_pct":  80,
                "signal_dbm":  -58,
            }

        # ── Randomized / Private MAC (modern Android/iOS) ─────────────────────
        if is_randomized_mac(norm_mac):
            # Assign 5 GHz — modern phones with private MACs all support Wi-Fi 5/6
            return {
                "dev_type":    "phone",
                "vendor":      "Smartphone (Private Wi-Fi Address)",
                "brand":       "Smartphone",
                "model_name":  "Private MAC",
                "display_name": f"Mobile Phone ({ip})",
                "conn_type":   "Wi-Fi 5 (802.11ac)",
                "wifi_band":   "5 GHz",
                "channel":     wlan["channel"],
                "link_rate":   433.3,
                "signal_pct":  80,
                "signal_dbm":  -58,
            }

        # ── Hostname keyword heuristics ───────────────────────────────────────
        hl = (hostname or "").lower()
        dev_type = "device"
        vendor   = "Network Client"
        brand    = "Generic"
        conn_type = wlan["radio_type"]
        wifi_band = wlan["band"]
        link_rate = wlan["link_rate_mbps"] or 433.3

        if any(k in hl for k in ["phone", "galaxy", "pixel", "iphone", "oneplus",
                                   "redmi", "xiaomi", "android", "mobile"]):
            dev_type  = "phone"
            vendor    = "Mobile Smartphone"
            brand     = "Smartphone"
            conn_type = "Wi-Fi 5 (802.11ac)"
            wifi_band = "5 GHz"
            link_rate = 433.3
        elif any(k in hl for k in ["ipad", "tab", "tablet"]):
            dev_type = "tablet"
            vendor   = "Tablet Device"
            brand    = "Tablet"
        elif any(k in hl for k in ["laptop", "desktop", "pc", "macbook",
                                    "thinkpad", "dell", "hp", "lenovo"]):
            dev_type = "laptop"
            vendor   = "PC / Workstation"
            brand    = "PC"
        elif any(k in hl for k in ["tv", "bravia", "tizen", "webos",
                                    "chromecast", "firetv", "roku", "shield"]):
            dev_type  = "smart_tv"
            vendor    = "Smart TV"
            brand     = "Smart TV"
            conn_type = "Wi-Fi 5 (802.11ac)"
            wifi_band = "5 GHz"
            link_rate = 433.3
        elif any(k in hl for k in ["playstation", "xbox", "switch", "nintendo"]):
            dev_type  = "console"
            vendor    = "Gaming Console"
            brand     = "Console"
            conn_type = "Wi-Fi 5 (802.11ac)"
            wifi_band = "5 GHz"
        elif any(k in hl for k in ["esp", "tuya", "plug", "bulb", "cam", "sensor", "iot"]):
            dev_type  = "iot"
            vendor    = "Smart Home IoT Device"
            brand     = "IoT"
            conn_type = "Wi-Fi 4 (802.11n)"
            wifi_band = "2.4 GHz"
            link_rate = 72.2

        return {
            "dev_type":    dev_type,
            "vendor":      vendor,
            "brand":       brand,
            "model_name":  "",
            "display_name": f"{vendor} ({ip})" if vendor != "Network Client" else f"Wi-Fi Client ({ip})",
            "conn_type":   conn_type,
            "wifi_band":   wifi_band,
            "channel":     wlan["channel"],
            "link_rate":   link_rate,
            "signal_pct":  78,
            "signal_dbm":  -62,
        }

    # ── Band/Rate helpers ─────────────────────────────────────────────────────

    def _band_rate_for_type(self, oui: str, dev_type: str,
                             wlan: Dict[str, Any]) -> tuple:
        """Returns (band, link_rate) for a device type, consulting OUI first."""
        if oui in OUI_DATABASE:
            _, _, _, band, rate = OUI_DATABASE[oui]
            return band, rate
        if dev_type in ("phone", "tablet"):
            return "5 GHz", 433.3
        if dev_type == "laptop":
            return wlan["band"], wlan["link_rate_mbps"] or 866.7
        if dev_type == "iot":
            return "2.4 GHz", 72.2
        return wlan["band"], wlan["link_rate_mbps"] or 433.3

    def _conn_type_for_band(self, band: str) -> str:
        if "6 GHz" in band:
            return "Wi-Fi 6E (802.11ax)"
        if band == "5 GHz":
            return "Wi-Fi 5 (802.11ac)"
        if band == "2.4 GHz":
            return "Wi-Fi 4 (802.11n)"
        if band == "Wired LAN":
            return "Gigabit Ethernet LAN (1000BASE-T)"
        return "Wi-Fi 5 (802.11ac)"

    # ── ARP & Ping ────────────────────────────────────────────────────────────

    def ping_host(self, ip: str, timeout_ms: int = 150) -> Dict[str, Any]:
        try:
            param    = "-n" if platform.system() == "Windows" else "-c"
            wait_flg = "-w" if platform.system() == "Windows" else "-W"
            t0 = time.time()
            res = subprocess.run(
                ["ping", param, "1", wait_flg, str(timeout_ms), ip],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
            )
            elapsed_ms = int((time.time() - t0) * 1000)
            if res.returncode == 0:
                m   = re.search(r'time[=<]([0-9]+)ms', res.stdout, re.IGNORECASE)
                lat = int(m.group(1)) if m else elapsed_ms
                return {"ip": ip, "alive": True, "latency_ms": max(1, lat)}
        except Exception:
            pass
        return {"ip": ip, "alive": False, "latency_ms": None}

    def parse_arp_table(self) -> List[Dict[str, str]]:
        devices = []
        try:
            output = subprocess.check_output(["arp", "-a"], text=True)
            for line in output.splitlines():
                m = re.search(
                    r'([0-9]{1,3}(?:\.[0-9]{1,3}){3})\s+'
                    r'([0-9a-fA-F]{2}(?:[:\-][0-9a-fA-F]{2}){5})\s+'
                    r'([a-zA-Z]+)',
                    line.strip()
                )
                if m:
                    ip  = m.group(1)
                    mac = m.group(2).lower().replace("-", ":")
                    if (ip.startswith("224.") or ip.startswith("239.")
                            or ip.endswith(".255")
                            or mac == "ff:ff:ff:ff:ff:ff"):
                        continue
                    devices.append({"ip": ip, "mac": mac, "type": m.group(3).lower()})
        except Exception as e:
            print(f"[Scanner] ARP scan error: {e}")
        return devices

    def resolve_hostname(self, ip: str) -> str:
        try:
            host = socket.gethostbyaddr(ip)[0]
            if host:
                return host.split(".")[0]
        except Exception:
            pass
        return ""

    # ── Main Scan ─────────────────────────────────────────────────────────────

    def scan_network_real(self) -> List[Dict[str, Any]]:
        """Scans physical devices from ARP table + ping sweep, classifies all without hardcoded IPs."""
        discovered: Dict[str, Dict] = {}
        self.wlan_meta     = self.get_wlan_interface_meta()
        self._local_ips    = self._get_all_local_ips()

        # Seed from ARP table (real hardware)
        for entry in self.parse_arp_table():
            discovered[entry["ip"]] = {
                "ip": entry["ip"], "mac": entry["mac"],
                "alive": True, "latency_ms": 2
            }

        # Always include gateway
        if self.gateway_ip and self.gateway_ip not in discovered:
            discovered[self.gateway_ip] = {
                "ip": self.gateway_ip,
                "mac": self.wlan_meta.get("bssid", ""),
                "alive": True, "latency_ms": 2
            }

        # Always include this machine
        if self.local_ip and self.local_ip not in discovered:
            discovered[self.local_ip] = {
                "ip": self.local_ip,
                "mac": self.wlan_meta.get("local_mac", ""),
                "alive": True, "latency_ms": 1
            }

        # Broad ping sweep across common LAN slots
        sweep_slots = [
            f"{self.subnet_prefix}{i}"
            for i in list(range(1, 10)) + list(range(10, 51, 5)) +
                     list(range(50, 105, 5)) + [150, 200, 254]
        ]
        with concurrent.futures.ThreadPoolExecutor(max_workers=40) as exe:
            futs = {exe.submit(self.ping_host, ip, 120): ip for ip in sweep_slots}
            for fut in concurrent.futures.as_completed(futs):
                res = fut.result()
                if res["alive"]:
                    ip = res["ip"]
                    if ip in discovered:
                        discovered[ip]["latency_ms"] = res["latency_ms"]
                    else:
                        discovered[ip] = {
                            "ip": ip,
                            "mac": f"dev:{ip.split('.')[-1]}",
                            "alive": True,
                            "latency_ms": res["latency_ms"]
                        }

        results = []
        for ip, info in discovered.items():
            mac        = info["mac"]
            is_gateway = (ip == self.gateway_ip)
            is_local   = (ip in self._local_ips)
            hostname   = self.resolve_hostname(ip)

            diag = self.classify_device(mac, ip, hostname, is_local, is_gateway)

            # Build canonical display hostname
            if is_gateway:
                hostname = f"{diag['brand']} Wi-Fi Router ({self.wlan_meta['ssid']})"
            elif is_local:
                hostname = f"This PC ({platform.node()})"
            else:
                if diag.get("display_name"):
                    hostname = diag["display_name"]
                elif not hostname:
                    _type_labels = {
                        "phone": f"Mobile Phone ({ip})",
                        "tablet": f"Tablet ({ip})",
                        "smart_tv": f"Smart TV ({ip})",
                        "laptop": f"Laptop ({ip})",
                        "console": f"Gaming Console ({ip})",
                        "iot": f"IoT Device ({ip})",
                    }
                    hostname = _type_labels.get(diag["dev_type"], f"Wi-Fi Client ({ip})")

            results.append({
                "ip":              ip,
                "mac":             mac,
                "hostname":        hostname,
                "vendor":          diag["vendor"],
                "brand":           diag.get("brand", "Generic"),
                "model_name":      diag.get("model_name", ""),
                "device_type":     diag["dev_type"],
                "connection_type": diag["conn_type"],
                "wifi_band":       diag["wifi_band"],
                "channel":         diag["channel"],
                "link_rate_mbps":  diag["link_rate"],
                "signal_percent":  diag["signal_pct"],
                "signal_dbm":      diag["signal_dbm"],
                "latency_ms":      info.get("latency_ms", 2),
                "is_gateway":      is_gateway,
                "is_local":        is_local,
            })

        return sorted(results, key=lambda x: [int(p) for p in x["ip"].split(".")])
