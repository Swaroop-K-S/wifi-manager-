"""
Device Fingerprinting and Hardware Model Identifier Module
Specialized engine for decoding exact device company, marketing model names
(e.g., Samsung Galaxy M15 5G, Apple iPhone 15 Pro, OnePlus 12R, etc.)
from HTTP User-Agents, mDNS/Zeroconf broadcasts, DNS vendor telemetry, and MAC OUIs.

Phase 3: Added real-time Zeroconf mDNS listener (MDNSDeviceListener) that auto-updates
SQLite when devices broadcast _airplay, _googlecast, _companion-link or _services_ records.
"""
import re
import threading
import logging
from typing import Dict, Any, Optional, List

log = logging.getLogger("DeviceFingerprinter")

# ── Samsung Model Database ────────────────────────────────────────────────────
SAMSUNG_MODELS = {
    # M-Series
    "SM-M156B": ("Samsung", "Galaxy M15 5G",  "Samsung Galaxy M15 5G",  "phone"),
    "SM-M156M": ("Samsung", "Galaxy M15 5G",  "Samsung Galaxy M15 5G",  "phone"),
    "SM-M156E": ("Samsung", "Galaxy M15 5G",  "Samsung Galaxy M15 5G",  "phone"),
    "SM-M155F": ("Samsung", "Galaxy M15",     "Samsung Galaxy M15",     "phone"),
    "SM-M146B": ("Samsung", "Galaxy M14 5G",  "Samsung Galaxy M14 5G",  "phone"),
    "SM-M145F": ("Samsung", "Galaxy M14",     "Samsung Galaxy M14",     "phone"),
    "SM-M346B": ("Samsung", "Galaxy M34 5G",  "Samsung Galaxy M34 5G",  "phone"),
    "SM-M356B": ("Samsung", "Galaxy M35 5G",  "Samsung Galaxy M35 5G",  "phone"),
    "SM-M546B": ("Samsung", "Galaxy M54 5G",  "Samsung Galaxy M54 5G",  "phone"),
    "SM-M556B": ("Samsung", "Galaxy M55 5G",  "Samsung Galaxy M55 5G",  "phone"),
    "SM-M135F": ("Samsung", "Galaxy M13",     "Samsung Galaxy M13",     "phone"),
    "SM-M127F": ("Samsung", "Galaxy M12",     "Samsung Galaxy M12",     "phone"),
    "SM-M045F": ("Samsung", "Galaxy M04",     "Samsung Galaxy M04",     "phone"),
    # A-Series
    "SM-A156B": ("Samsung", "Galaxy A15 5G",  "Samsung Galaxy A15 5G",  "phone"),
    "SM-A155F": ("Samsung", "Galaxy A15",     "Samsung Galaxy A15",     "phone"),
    "SM-A256B": ("Samsung", "Galaxy A25 5G",  "Samsung Galaxy A25 5G",  "phone"),
    "SM-A356B": ("Samsung", "Galaxy A35 5G",  "Samsung Galaxy A35 5G",  "phone"),
    "SM-A556B": ("Samsung", "Galaxy A55 5G",  "Samsung Galaxy A55 5G",  "phone"),
    "SM-A546B": ("Samsung", "Galaxy A54 5G",  "Samsung Galaxy A54 5G",  "phone"),
    "SM-A346B": ("Samsung", "Galaxy A34 5G",  "Samsung Galaxy A34 5G",  "phone"),
    "SM-A146B": ("Samsung", "Galaxy A14 5G",  "Samsung Galaxy A14 5G",  "phone"),
    "SM-A055F": ("Samsung", "Galaxy A05",     "Samsung Galaxy A05",     "phone"),
    "SM-A546E": ("Samsung", "Galaxy A54 5G",  "Samsung Galaxy A54 5G",  "phone"),
    "SM-A736B": ("Samsung", "Galaxy A73 5G",  "Samsung Galaxy A73 5G",  "phone"),
    # S-Series
    "SM-S928B": ("Samsung", "Galaxy S24 Ultra","Samsung Galaxy S24 Ultra","phone"),
    "SM-S928U": ("Samsung", "Galaxy S24 Ultra","Samsung Galaxy S24 Ultra","phone"),
    "SM-S926B": ("Samsung", "Galaxy S24+",    "Samsung Galaxy S24+",    "phone"),
    "SM-S921B": ("Samsung", "Galaxy S24",     "Samsung Galaxy S24",     "phone"),
    "SM-S918B": ("Samsung", "Galaxy S23 Ultra","Samsung Galaxy S23 Ultra","phone"),
    "SM-S916B": ("Samsung", "Galaxy S23+",    "Samsung Galaxy S23+",    "phone"),
    "SM-S911B": ("Samsung", "Galaxy S23",     "Samsung Galaxy S23",     "phone"),
    "SM-S711B": ("Samsung", "Galaxy S23 FE",  "Samsung Galaxy S23 FE",  "phone"),
    "SM-S906B": ("Samsung", "Galaxy S22+",    "Samsung Galaxy S22+",    "phone"),
    "SM-S901B": ("Samsung", "Galaxy S22",     "Samsung Galaxy S22",     "phone"),
    # Z-Series Foldables
    "SM-F956B": ("Samsung", "Galaxy Z Fold 6","Samsung Galaxy Z Fold 6","phone"),
    "SM-F741B": ("Samsung", "Galaxy Z Flip 6","Samsung Galaxy Z Flip 6","phone"),
    "SM-F946B": ("Samsung", "Galaxy Z Fold 5","Samsung Galaxy Z Fold 5","phone"),
    "SM-F731B": ("Samsung", "Galaxy Z Flip 5","Samsung Galaxy Z Flip 5","phone"),
    "SM-F936B": ("Samsung", "Galaxy Z Fold 4","Samsung Galaxy Z Fold 4","phone"),
    # Tablets
    "SM-X910":  ("Samsung", "Galaxy Tab S9 Ultra","Samsung Galaxy Tab S9 Ultra","tablet"),
    "SM-X810":  ("Samsung", "Galaxy Tab S9+", "Samsung Galaxy Tab S9+", "tablet"),
    "SM-X710":  ("Samsung", "Galaxy Tab S9",  "Samsung Galaxy Tab S9",  "tablet"),
    "SM-X210":  ("Samsung", "Galaxy Tab A9+", "Samsung Galaxy Tab A9+", "tablet"),
    "SM-X110":  ("Samsung", "Galaxy Tab A9",  "Samsung Galaxy Tab A9",  "tablet"),
}

# ── Apple Models ──────────────────────────────────────────────────────────────
APPLE_MODELS = {
    "iPhone17,1": ("Apple", "iPhone 16 Pro Max", "Apple iPhone 16 Pro Max", "phone"),
    "iPhone17,2": ("Apple", "iPhone 16 Pro",     "Apple iPhone 16 Pro",     "phone"),
    "iPhone16,1": ("Apple", "iPhone 15 Pro",     "Apple iPhone 15 Pro",     "phone"),
    "iPhone16,2": ("Apple", "iPhone 15 Pro Max", "Apple iPhone 15 Pro Max", "phone"),
    "iPhone15,4": ("Apple", "iPhone 15",         "Apple iPhone 15",         "phone"),
    "iPhone15,5": ("Apple", "iPhone 15 Plus",    "Apple iPhone 15 Plus",    "phone"),
    "iPhone15,2": ("Apple", "iPhone 14 Pro",     "Apple iPhone 14 Pro",     "phone"),
    "iPhone15,3": ("Apple", "iPhone 14 Pro Max", "Apple iPhone 14 Pro Max", "phone"),
    "iPhone14,7": ("Apple", "iPhone 14",         "Apple iPhone 14",         "phone"),
    "iPhone14,8": ("Apple", "iPhone 14 Plus",    "Apple iPhone 14 Plus",    "phone"),
    "iPhone14,2": ("Apple", "iPhone 13 Pro",     "Apple iPhone 13 Pro",     "phone"),
    "iPhone13,2": ("Apple", "iPhone 12",         "Apple iPhone 12",         "phone"),
    "iPhone12,1": ("Apple", "iPhone 11",         "Apple iPhone 11",         "phone"),
}

# ── OnePlus / Oppo Models ─────────────────────────────────────────────────────
ONEPLUS_MODELS = {
    "CPH2581": ("OnePlus", "OnePlus 12",          "OnePlus 12",             "phone"),
    "CPH2573": ("OnePlus", "OnePlus 12R",         "OnePlus 12R",            "phone"),
    "CPH2493": ("OnePlus", "Nord CE 3 Lite 5G",   "OnePlus Nord CE 3 Lite 5G","phone"),
    "CPH2449": ("OnePlus", "OnePlus 11 5G",       "OnePlus 11 5G",          "phone"),
    "CPH2551": ("OnePlus", "OnePlus Open",        "OnePlus Open Foldable",  "phone"),
    "CPH2269": ("OnePlus", "Nord 2T 5G",          "OnePlus Nord 2T 5G",     "phone"),
    "CPH2399": ("OnePlus", "Nord CE 2 Lite 5G",   "OnePlus Nord CE 2 Lite 5G","phone"),
}

# ── Xiaomi / Redmi / POCO Models ─────────────────────────────────────────────
XIAOMI_MODELS = {
    "2312DRA50G": ("Xiaomi", "Redmi Note 13 Pro 5G","Redmi Note 13 Pro 5G","phone"),
    "23127PN0CG": ("Xiaomi", "Xiaomi 14",           "Xiaomi 14 5G",        "phone"),
    "2311DRK48G": ("Xiaomi", "POCO X6 Pro 5G",      "POCO X6 Pro 5G",      "phone"),
    "22101316G":  ("Xiaomi", "Xiaomi 12 Pro",        "Xiaomi 12 Pro",       "phone"),
    "21081111RG": ("Xiaomi", "Redmi Note 10 Pro",    "Redmi Note 10 Pro",   "phone"),
}

# ── Vendor DNS Telemetry Signatures ──────────────────────────────────────────
VENDOR_DNS_SIGNATURES = [
    (r'(samsungcloud|samsungdm|samsungosp|samsungqbe|samsungapps|secb2b)\.com',
     "Samsung", "Samsung Electronics"),
    (r'(apple|icloud|aaplimg|mzstatic)\.com',
     "Apple", "Apple Inc."),
    (r'(oneplus|heytapmobile|coloros)\.com',
     "OnePlus", "OnePlus / Oppo"),
    (r'(xiaomi|miui|mi-img)\.com',
     "Xiaomi", "Xiaomi Communications"),
    (r'(google|1e100)\.net|google\.com',
     "Google", "Google LLC"),
    (r'(microsoft|windowsupdate|msftncsi)\.com',
     "Microsoft", "Microsoft Corporation"),
]

# ── mDNS Service Types to Listen For ─────────────────────────────────────────
MDNS_SERVICES = [
    "_services._dns-sd._udp.local.",
    "_googlecast._tcp.local.",
    "_airplay._tcp.local.",
    "_companion-link._tcp.local.",
    "_raop._tcp.local.",           # AirPlay audio
    "_sleep-proxy._udp.local.",    # Apple devices
    "_http._tcp.local.",
    "_ipp._tcp.local.",
    "_printer._tcp.local.",
    "_smb._tcp.local.",
]


# ── Zeroconf mDNS Listener ────────────────────────────────────────────────────

class MDNSDeviceListener:
    """
    Background Zeroconf mDNS browser that discovers devices by their advertised
    service names and updates the SQLite devices table in real time.

    Devices announce themselves as e.g.:
        iPhone-15-Pro._airplay._tcp.local.
        Swaroop-s-MacBook._companion-link._tcp.local.
        Living-Room-TV._googlecast._tcp.local.

    We extract the hostname prefix, fingerprint it, resolve the IP, and update
    the DB entry for that IP.
    """

    def __init__(self):
        self._zeroconf = None
        self._browsers: List[Any] = []
        self._running  = False
        self._lock     = threading.Lock()
        self._seen_keys: set = set()   # (ip, service_name) pairs already processed

    def start(self):
        """Start the Zeroconf instance and service browsers in a daemon thread."""
        if self._running:
            return
        t = threading.Thread(target=self._run, daemon=True, name="MDNS-Listener")
        t.start()

    def _run(self):
        try:
            from zeroconf import Zeroconf, ServiceBrowser
        except ImportError:
            log.warning("[mDNS] zeroconf not installed — mDNS listener disabled. "
                        "Run: pip install zeroconf")
            return

        try:
            self._zeroconf = Zeroconf()
            self._running  = True
            for svc in MDNS_SERVICES:
                browser = ServiceBrowser(self._zeroconf, svc, handlers=[self._on_service_state_change])
                self._browsers.append(browser)
            log.info("[mDNS] Zeroconf listener active on %d service types.", len(MDNS_SERVICES))
            print(f"[MDNS LISTENER] Zeroconf active — watching {len(MDNS_SERVICES)} service types")
            # Keep thread alive
            import time
            while self._running:
                time.sleep(5)
        except Exception as e:
            log.error("[mDNS] Zeroconf start error: %s", e)
        finally:
            if self._zeroconf:
                try:
                    self._zeroconf.close()
                except Exception:
                    pass

    def stop(self):
        self._running = False
        if self._zeroconf:
            try:
                self._zeroconf.close()
            except Exception:
                pass

    def _on_service_state_change(self, zeroconf, service_type, name, state_change):
        """Called by Zeroconf when a service is added/updated/removed."""
        try:
            from zeroconf import ServiceStateChange
            if state_change not in (ServiceStateChange.Added, ServiceStateChange.Updated):
                return

            info = zeroconf.get_service_info(service_type, name)
            if not info:
                return

            # Extract IP address(es) from the service info
            import socket as _socket
            addresses = []
            for addr_bytes in (info.addresses or []):
                try:
                    addresses.append(_socket.inet_ntoa(addr_bytes))
                except Exception:
                    pass
            if not addresses:
                return

            # The service name e.g.: "iPhone-15-Pro._airplay._tcp.local."
            # Extract the human-readable device label (before the first dot)
            raw_name = name.replace(service_type, "").strip(".").strip()
            hostname = raw_name.split(".")[0].replace("-", " ").strip()

            for ip in addresses:
                if not ip.startswith("192.168.") and not ip.startswith("10."):
                    continue
                key = (ip, service_type)
                with self._lock:
                    if key in self._seen_keys:
                        continue
                    self._seen_keys.add(key)

                self._update_device_from_mdns(ip, hostname, service_type, info)

        except Exception as e:
            log.debug("[mDNS] Service state change handler error: %s", e)

    def _update_device_from_mdns(self, ip: str, mdns_hostname: str,
                                  service_type: str, info: Any):
        """Fingerprint the mDNS hostname and update SQLite."""
        try:
            fp = DeviceFingerprinter.identify_from_hostname(mdns_hostname)

            # Infer from service type if hostname didn't match
            if not fp:
                if "_googlecast" in service_type:
                    fp = {
                        "brand": "Google", "model_name": "Chromecast / Google TV",
                        "display_name": f"{mdns_hostname} (Google Cast)",
                        "vendor": "Google LLC", "device_type": "smart_tv",
                    }
                elif "_airplay" in service_type or "_companion-link" in service_type or "_raop" in service_type:
                    fp = {
                        "brand": "Apple", "model_name": "Apple Device (AirPlay)",
                        "display_name": f"{mdns_hostname} (Apple)",
                        "vendor": "Apple Inc.", "device_type": "phone",
                    }
                elif "_printer" in service_type or "_ipp" in service_type:
                    fp = {
                        "brand": "Printer", "model_name": "Network Printer",
                        "display_name": f"{mdns_hostname} (Printer)",
                        "vendor": "Network Printer", "device_type": "iot",
                    }

            from backend.database import get_db
            conn   = get_db()
            cursor = conn.cursor()
            cursor.execute("SELECT mac, custom_name, brand FROM devices WHERE ip = ?", (ip,))
            row = cursor.fetchone()

            if fp:
                if row:
                    # Only update if brand/model is not yet set or is Generic
                    existing_brand = row["brand"] or ""
                    if existing_brand in ("", "Generic", "Smartphone", "Mobile Device"):
                        cursor.execute("""
                            UPDATE devices SET
                                hostname     = ?,
                                custom_name  = COALESCE(NULLIF(custom_name, ''), ?),
                                brand        = ?,
                                model_name   = ?,
                                vendor       = ?,
                                device_type  = ?,
                                last_seen    = CURRENT_TIMESTAMP
                            WHERE ip = ?
                        """, (
                            fp["display_name"], fp["display_name"],
                            fp["brand"], fp["model_name"],
                            fp["vendor"], fp["device_type"], ip
                        ))
                        log.info("[mDNS] Updated device %s -> %s", ip, fp["display_name"])
                        print(f"[MDNS] ✓ {ip} identified as {fp['display_name']} via mDNS ({service_type})")
                else:
                    # Insert new device discovered purely via mDNS
                    import hashlib
                    fake_mac = "md:" + hashlib.md5(ip.encode()).hexdigest()[:9]
                    cursor.execute("""
                        INSERT OR IGNORE INTO devices
                            (mac, ip, hostname, custom_name, vendor, brand, model_name,
                             device_type, network_type, status)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'primary', 'online')
                    """, (
                        fake_mac, ip, fp["display_name"], fp["display_name"],
                        fp["vendor"], fp["brand"], fp["model_name"], fp["device_type"]
                    ))
                    print(f"[MDNS] ✓ New device {ip} -> {fp['display_name']} via {service_type}")

            conn.commit()
            conn.close()

        except Exception as e:
            log.debug("[mDNS] DB update error for %s: %s", ip, e)


# ── Core Fingerprinter Class ──────────────────────────────────────────────────

class DeviceFingerprinter:
    @staticmethod
    def identify_user_agent(ua: str) -> Optional[Dict[str, Any]]:
        """
        Parses HTTP User-Agent strings from browsers/webviews to extract exact device model.
        Example UA: 'Mozilla/5.0 (Linux; Android 14; SM-M156B Build/UP1A.231005.007; wv)...'
        """
        if not ua:
            return None

        # 1. Samsung SM-xxxx model code
        samsung_match = re.search(r'\b(SM-[A-Z0-9]{4,6})\b', ua, re.IGNORECASE)
        if samsung_match:
            model_code = samsung_match.group(1).upper()
            if model_code in SAMSUNG_MODELS:
                brand, model_name, display_name, dev_type = SAMSUNG_MODELS[model_code]
            else:
                brand = "Samsung"
                dev_type = "phone"
                if model_code.startswith("SM-M"):
                    sn = model_code[4:6]
                    model_name = f"Galaxy M{sn} 5G"
                elif model_code.startswith("SM-A"):
                    sn = model_code[4:6]
                    model_name = f"Galaxy A{sn} 5G"
                elif model_code.startswith("SM-S"):
                    model_name = "Galaxy S Series Flagship"
                elif model_code.startswith("SM-F"):
                    model_name = "Galaxy Z Fold/Flip"
                elif model_code.startswith(("SM-T", "SM-X")):
                    model_name = "Galaxy Tab"
                    dev_type = "tablet"
                else:
                    model_name = f"Galaxy ({model_code})"
                display_name = f"Samsung {model_name}"

            android_ver = "Android"
            aver_m = re.search(r'Android\s+([0-9\.]+)', ua)
            if aver_m:
                android_ver = f"Android {aver_m.group(1)}"

            return {
                "brand": brand, "model_name": model_name,
                "model_code": model_code, "display_name": display_name,
                "vendor": "Samsung Electronics", "device_type": dev_type,
                "os_info": f"{android_ver} • One UI",
            }

        # 2. Explicit Samsung text (Galaxy M15, Galaxy S24, etc.)
        gal_match = re.search(
            r'(Galaxy\s*(M15|M14|M35|M55|A15|A25|A35|A55|S23|S24|Z\s*Fold|Z\s*Flip)'
            r'|SM-M156|SM-A156|M15\s*5G)',
            ua, re.IGNORECASE
        )
        if gal_match:
            raw = gal_match.group(0).upper()
            model_name = "Galaxy Smartphone"
            display_name = "Samsung Galaxy Phone"
            # Try to get specific series
            m = re.search(r'(M15|M14|M35|M55|A15|A25|A35|A55|S23|S24)', raw)
            if m:
                code_part = m.group(1)
                model_name   = f"Galaxy {code_part}"
                display_name = f"Samsung Galaxy {code_part}"
            return {
                "brand": "Samsung", "model_name": model_name,
                "model_code": raw, "display_name": display_name,
                "vendor": "Samsung Electronics", "device_type": "phone",
                "os_info": "Android • One UI",
            }

        # 3. OnePlus CPHxxxx
        op_match = re.search(r'\b(CPH[0-9]{4})\b', ua, re.IGNORECASE)
        if op_match:
            code = op_match.group(1).upper()
            if code in ONEPLUS_MODELS:
                brand, model_name, display_name, dev_type = ONEPLUS_MODELS[code]
            else:
                brand, model_name, display_name, dev_type = (
                    "OnePlus", f"OnePlus ({code})", f"OnePlus ({code})", "phone"
                )
            return {
                "brand": brand, "model_name": model_name,
                "model_code": code, "display_name": display_name,
                "vendor": "OnePlus / Oppo", "device_type": dev_type,
                "os_info": "OxygenOS / Android",
            }

        # 4. Xiaomi / Redmi model codes
        for code, info in XIAOMI_MODELS.items():
            if code.lower() in ua.lower():
                brand, model_name, display_name, dev_type = info
                return {
                    "brand": brand, "model_name": model_name,
                    "model_code": code, "display_name": display_name,
                    "vendor": "Xiaomi Communications", "device_type": dev_type,
                    "os_info": "MIUI / Android",
                }

        # 5. Apple device strings
        if "iPhone" in ua:
            # Try to extract model identifier like iPhone16,1
            im = re.search(r'(iPhone[0-9]+,[0-9]+)', ua)
            if im and im.group(1) in APPLE_MODELS:
                b, mn, dn, dt = APPLE_MODELS[im.group(1)]
                return {
                    "brand": b, "model_name": mn, "model_code": im.group(1),
                    "display_name": dn, "vendor": "Apple Inc.",
                    "device_type": dt, "os_info": "iOS",
                }
            ios_m = re.search(r'OS ([0-9_]+)', ua)
            ios_v = ios_m.group(1).replace("_", ".") if ios_m else ""
            return {
                "brand": "Apple", "model_name": "iPhone",
                "model_code": "iPhone", "display_name": "Apple iPhone",
                "vendor": "Apple Inc.", "device_type": "phone",
                "os_info": f"iOS {ios_v}".strip(),
            }
        elif "iPad" in ua:
            return {
                "brand": "Apple", "model_name": "iPad",
                "model_code": "iPad", "display_name": "Apple iPad",
                "vendor": "Apple Inc.", "device_type": "tablet",
                "os_info": "iPadOS",
            }
        elif "Macintosh" in ua or "Mac OS X" in ua:
            return {
                "brand": "Apple", "model_name": "MacBook / Mac",
                "model_code": "Mac", "display_name": "Apple MacBook / Mac",
                "vendor": "Apple Inc.", "device_type": "laptop",
                "os_info": "macOS",
            }

        # 6. Windows PC
        if "Windows NT" in ua:
            ver = "11" if "Windows NT 10.0" in ua else "10"
            return {
                "brand": "Microsoft / PC", "model_name": f"Windows {ver} PC",
                "model_code": "WinPC", "display_name": f"Windows {ver} Workstation",
                "vendor": "Microsoft / Intel / MediaTek",
                "device_type": "laptop", "os_info": f"Windows {ver} x64",
            }

        return None

    @staticmethod
    def identify_from_dns(domain: str) -> Optional[Dict[str, str]]:
        """Identifies device vendor based on queried DNS telemetry domains."""
        d = domain.lower()
        for pattern, brand, vendor in VENDOR_DNS_SIGNATURES:
            if re.search(pattern, d):
                return {"brand": brand, "vendor": vendor}
        return None

    @staticmethod
    def identify_from_hostname(hostname: str) -> Optional[Dict[str, Any]]:
        """
        Identifies device brand and model from mDNS hostname, NetBIOS name,
        or any string broadcast by the device itself.
        """
        if not hostname:
            return None
        hl = hostname.upper()
        h_clean = hostname.replace("-", " ").replace("_", " ")

        # Samsung model codes
        samsung_re = re.search(r'\b(SM-[A-Z0-9]{4,6})\b', hl)
        if samsung_re:
            code = samsung_re.group(1)
            if code in SAMSUNG_MODELS:
                b, mn, dn, dt = SAMSUNG_MODELS[code]
                return {
                    "brand": b, "model_name": mn, "model_code": code,
                    "display_name": dn, "vendor": "Samsung Electronics",
                    "device_type": dt,
                }

        # Galaxy series keyword
        gal_re = re.search(r'GALAXY[\s\-]*(M15|M14|M35|M55|A15|A25|A35|A55|S23|S24|Z|NOTE)', hl)
        if gal_re or "SAMSUNG" in hl or "GALAXY" in hl:
            series = gal_re.group(1) if gal_re else ""
            model_name   = f"Galaxy {series}".strip() if series else "Galaxy Smartphone"
            display_name = f"Samsung {model_name}"
            return {
                "brand": "Samsung", "model_name": model_name,
                "model_code": f"SM-{series}" if series else "Galaxy",
                "display_name": display_name,
                "vendor": "Samsung Electronics", "device_type": "phone",
            }

        # Apple patterns: iPhone-15-Pro, iPhone15Pro, MacBook-Air, etc.
        if re.search(r'IPHONE[\s\-]?([0-9]+)?[\s\-]?(PRO|PLUS|MAX|MINI)?', hl):
            parts = re.findall(r'[A-Z0-9]+', hl)
            model_hint = " ".join(p.capitalize() for p in parts if p not in ("IPHONE",))
            model_name = f"iPhone {model_hint}".strip() if model_hint else "iPhone"
            return {
                "brand": "Apple", "model_name": model_name,
                "model_code": "iPhone", "display_name": f"Apple {model_name}",
                "vendor": "Apple Inc.", "device_type": "phone",
            }
        if "IPAD" in hl:
            return {
                "brand": "Apple", "model_name": "iPad",
                "model_code": "iPad", "display_name": "Apple iPad",
                "vendor": "Apple Inc.", "device_type": "tablet",
            }
        if "MACBOOK" in hl or "IMAC" in hl or "MAC-MINI" in hl or "MAC MINI" in hl:
            return {
                "brand": "Apple", "model_name": "MacBook / Mac",
                "model_code": "Mac", "display_name": "Apple MacBook / Mac",
                "vendor": "Apple Inc.", "device_type": "laptop",
            }

        # OnePlus
        op_re = re.search(r'\b(CPH[0-9]{4})\b', hl)
        if op_re:
            code = op_re.group(1)
            if code in ONEPLUS_MODELS:
                b, mn, dn, dt = ONEPLUS_MODELS[code]
                return {
                    "brand": b, "model_name": mn, "model_code": code,
                    "display_name": dn, "vendor": "OnePlus / Oppo", "device_type": dt,
                }

        # Xiaomi
        for code in XIAOMI_MODELS:
            if code in hl:
                b, mn, dn, dt = XIAOMI_MODELS[code]
                return {
                    "brand": b, "model_name": mn, "model_code": code,
                    "display_name": dn, "vendor": "Xiaomi Communications", "device_type": dt,
                }

        # Chromecast / Google Cast
        if "CHROMECAST" in hl or "GOOGLECAST" in hl or "GOOGLE-CAST" in hl:
            return {
                "brand": "Google", "model_name": "Chromecast",
                "model_code": "CC", "display_name": f"{h_clean} (Chromecast)",
                "vendor": "Google LLC", "device_type": "smart_tv",
            }

        # Generic TV hints
        if re.search(r'(BRAVIA|TIZEN|WEBOS|FIRETV|ROKU|SHIELD|ANDROIDTV|SMARTTV)', hl):
            return {
                "brand": "Smart TV", "model_name": "Smart TV",
                "model_code": "TV", "display_name": h_clean,
                "vendor": "Smart TV Manufacturer", "device_type": "smart_tv",
            }

        return None


# ── Module-Level Singletons ───────────────────────────────────────────────────
device_fingerprinter = DeviceFingerprinter()
mdns_listener        = MDNSDeviceListener()
